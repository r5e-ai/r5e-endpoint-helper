//! Zero-dependency HTTP/1.1 client, auto-chunking batch shipper, `0600` enrolled state persistence,
//! and workload record builder for `A8` Workload Record Admission & Session Opening:
//! - `POST /v1/evidence/sessions` (`open_session_over_http`)
//! - `POST /v1/evidence/records` (`ship_records_over_http`, `ship_records_batches_over_http`,
//!   `EnrolledEndpointSession::ship_to_gateway`)
//! - `POST /v1/authority/badges/revoke` (`revoke_badge_over_http`)
//!
//! Security & wire guarantees:
//! - Bearer tokens are redacted in `Debug` implementations and scrubbed from any error body text
//!   so tokens never leak in `Debug`, `Display`, or CLI stderr output.
//! - Saved enrolled state files (`EnrolledStateFile`) containing the workload's ephemeral Ed25519
//!   signing seed are persisted exclusively with `0600` file permissions on Unix.
//! - Batch shipping automatically splits record sets into chunks of `<= 64` records and well under
//!   `8_000_000` bytes while preserving per-stream consecutive `seq` ordering and carrying
//!   deduplicated `keys`, `CaptureProfile` blobs, referenced inline content `blobs`, and optional
//!   `authority`.

use crate::attestation::{
    base_v2_schema_map, decode_strict_base64, encode_canonical_json, write_secret_file_0600,
    BlobEntry, CaptureProfile, EndpointBundleRecorder, EnrolledEndpointSession, PublicKeyEntry,
    SignedEndpointRecord,
};
use crate::claim_http::{
    is_valid_bytes_ref, is_valid_evidence_ref, is_valid_uri_identity, parse_http_base_url,
    read_chunked_body, ClaimError, SubmitGrantsRequest,
};
use crate::mcp_stdio::DescriptorObservation;
use crate::outbox_cipher::{
    decrypt_outbox_parts, encrypt_outbox_parts, EncryptedOutboxQueueFile, OutboxKey,
    ENCRYPTED_OUTBOX_QUEUE_FORMAT,
};
use crate::policy_gate::{EnforcementOutcome, GateVerdict, Posture};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

pub const OPEN_SESSION_PATH: &str = "/v1/evidence/sessions";
pub const ADMIT_RECORDS_PATH: &str = "/v1/evidence/records";
pub const REVOKE_BADGE_PATH: &str = "/v1/authority/badges/revoke";

/// Maximum records per `POST /v1/evidence/records` request (`A8` §2.1).
pub const MAX_RECORDS_PER_BATCH: usize = 64;

/// Target maximum serialized JSON body bytes per `POST /v1/evidence/records` batch, keeping a
/// generous safety margin below the gateway's `8_000_000` byte `Plug.Parsers` cap (`A8` §2.1).
pub const MAX_BATCH_BODY_BYTES: usize = 6_000_000;

/// Hard upper bound (`< 8_000_000` bytes) for any single-record HTTP request body.
pub const HARD_MAX_REQUEST_BODY_BYTES: usize = 7_800_000;

pub const ENROLLED_STATE_FORMAT: &str = "r5e.endpoint-enrolled-state/v1";

/// Kinds that `A8` §1.1 / §2.2 forbids inside `POST /v1/evidence/records` `records` (gateway-owned
/// structural, authority, publication, seal/checkpoint, and retention kinds).
const FORBIDDEN_WORKLOAD_RECORD_KINDS: &[&str] = &[
    "provenance.r5e.io/v2/ChainStarted",
    "provenance.r5e.io/v2/Deployment",
    "provenance.r5e.io/v2/RootsChanged",
    "provenance.r5e.io/v2/RootChangeApproval",
    "provenance.r5e.io/v2/Endorsement",
    "provenance.r5e.io/v2/Badge",
    "provenance.r5e.io/v2/Succession",
    "provenance.r5e.io/v2/Revocation",
    "provenance.r5e.io/v2/EpochSeal",
    "provenance.r5e.io/v2/Checkpoint",
    "provenance.r5e.io/v2/DefinitionPublished",
    "provenance.r5e.io/v2/PublishedView",
    "provenance.r5e.io/v2/RetentionHold",
    "provenance.r5e.io/v2/RetentionHoldRelease",
    "provenance.r5e.io/v2/PayloadDisposition",
];

/// Returns `true` iff `kind_or_path` (either `"ToolCall"` or `"provenance.r5e.io/v2/ToolCall"`)
/// is admissible as a workload operational record on `POST /v1/evidence/records`.
pub fn is_admissible_workload_kind(kind_or_path: &str) -> bool {
    let normalized = normalize_workload_kind(kind_or_path);
    !normalized.is_empty() && !FORBIDDEN_WORKLOAD_RECORD_KINDS.contains(&normalized.as_str())
}

/// Expands bare Provenance v2 kind names (`"ToolCall"`) to `"provenance.r5e.io/v2/ToolCall"`,
/// passing already-qualified `<pkg>/v<N>/<Kind>` paths through unchanged.
pub fn normalize_workload_kind(raw: &str) -> String {
    let trimmed = raw.trim();
    if !trimmed.is_empty() && !trimmed.contains('/') {
        format!("provenance.r5e.io/v2/{trimmed}")
    } else {
        trimmed.to_string()
    }
}

/// Bearer-authenticated HTTP client configuration for `A8` evidence and badge-revocation routes.
///
/// Redacts `bearer_token` in `Debug` output so credentials never leak into logs or panic messages.
#[derive(Clone)]
pub struct EvidenceClientConfig {
    pub gateway_base_url: String,
    pub bearer_token: String,
    pub timeout: Duration,
}

impl fmt::Debug for EvidenceClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EvidenceClientConfig")
            .field("gateway_base_url", &self.gateway_base_url)
            .field("bearer_token", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl EvidenceClientConfig {
    pub fn new(gateway_base_url: impl Into<String>, bearer_token: impl Into<String>) -> Self {
        Self {
            gateway_base_url: gateway_base_url.into(),
            bearer_token: bearer_token.into(),
            timeout: Duration::from_secs(30),
        }
    }
}

/// Structured errors returned by `A8` HTTP operations (`open-session`, `ship-records`, `revoke-badge`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceHttpError {
    /// `400` (`malformed_request`, `too_many_records`)
    BadRequest {
        error_code: Option<String>,
        body: String,
    },
    /// `401` (`unauthenticated`)
    Unauthenticated {
        error_code: Option<String>,
        body: String,
    },
    /// `403` (`forbidden`, policy denial)
    Forbidden {
        error_code: Option<String>,
        body: String,
    },
    /// `404` (`badge_not_found`, route not mounted)
    NotFound {
        error_code: Option<String>,
        body: String,
    },
    /// `409` (`session_not_opened`, `session_belongs_to_another_principal`, `not_next_in_stream`,
    /// `stream_fork_refused`, `gateway_has_no_endorsement`, `already_revoked`)
    Conflict {
        error_code: Option<String>,
        body: String,
    },
    /// `413` (`too_large`)
    PayloadTooLarge {
        error_code: Option<String>,
        body: String,
    },
    /// `422` (`profile_retention_mismatch`, `authority_ended`, `no_standing`,
    /// `kind_not_admissible_from_workload`, `bad_signature`, `profile_not_carried`, etc.)
    Unprocessable {
        error_code: Option<String>,
        finding: Option<String>,
        body: String,
    },
    /// `503` (`deployment_not_claimed`)
    ServiceUnavailable {
        error_code: Option<String>,
        body: String,
    },
    /// Unexpected HTTP status
    HttpStatus {
        status: u16,
        error_code: Option<String>,
        body: String,
    },
    /// Local pre-flight validation refusal
    Validation(String),
    /// Socket, HTTP framing, or JSON parse failure
    Transport(String),
}

impl EvidenceHttpError {
    pub fn error_code(&self) -> Option<&str> {
        match self {
            Self::BadRequest { error_code, .. }
            | Self::Unauthenticated { error_code, .. }
            | Self::Forbidden { error_code, .. }
            | Self::NotFound { error_code, .. }
            | Self::Conflict { error_code, .. }
            | Self::PayloadTooLarge { error_code, .. }
            | Self::Unprocessable { error_code, .. }
            | Self::ServiceUnavailable { error_code, .. }
            | Self::HttpStatus { error_code, .. } => error_code.as_deref(),
            Self::Validation(_) | Self::Transport(_) => None,
        }
    }

    pub fn finding(&self) -> Option<&str> {
        match self {
            Self::Unprocessable { finding, .. } => finding.as_deref(),
            _ => None,
        }
    }

    pub fn http_status(&self) -> Option<u16> {
        match self {
            Self::BadRequest { .. } => Some(400),
            Self::Unauthenticated { .. } => Some(401),
            Self::Forbidden { .. } => Some(403),
            Self::NotFound { .. } => Some(404),
            Self::Conflict { .. } => Some(409),
            Self::PayloadTooLarge { .. } => Some(413),
            Self::Unprocessable { .. } => Some(422),
            Self::ServiceUnavailable { .. } => Some(503),
            Self::HttpStatus { status, .. } => Some(*status),
            Self::Validation(_) | Self::Transport(_) => None,
        }
    }
}

impl fmt::Display for EvidenceHttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadRequest { error_code, body } => {
                write!(f, "bad request (400 {:?}): {body}", error_code)
            }
            Self::Unauthenticated { error_code, body } => {
                write!(f, "unauthenticated (401 {:?}): {body}", error_code)
            }
            Self::Forbidden { error_code, body } => {
                write!(f, "forbidden (403 {:?}): {body}", error_code)
            }
            Self::NotFound { error_code, body } => {
                write!(f, "not found (404 {:?}): {body}", error_code)
            }
            Self::Conflict { error_code, body } => {
                write!(f, "conflict (409 {:?}): {body}", error_code)
            }
            Self::PayloadTooLarge { error_code, body } => {
                write!(f, "payload too large (413 {:?}): {body}", error_code)
            }
            Self::Unprocessable {
                error_code,
                finding,
                body,
            } => write!(
                f,
                "unprocessable record/request (422 error={:?} finding={:?}): {body}",
                error_code, finding
            ),
            Self::ServiceUnavailable { error_code, body } => {
                write!(f, "service unavailable (503 {:?}): {body}", error_code)
            }
            Self::HttpStatus {
                status,
                error_code,
                body,
            } => write!(f, "HTTP {status} ({:?}): {body}", error_code),
            Self::Validation(msg) => write!(f, "evidence validation refused: {msg}"),
            Self::Transport(msg) => write!(f, "evidence transport error: {msg}"),
        }
    }
}

impl std::error::Error for EvidenceHttpError {}

fn scrub_secret(text: String, secret: &str) -> String {
    let trimmed = secret.trim();
    if !trimmed.is_empty() && text.contains(trimmed) {
        text.replace(trimmed, "[REDACTED]")
    } else {
        text
    }
}

pub fn classify_evidence_error(
    status: u16,
    body_bytes: &[u8],
    bearer_token_to_scrub: &str,
) -> EvidenceHttpError {
    let raw_body = String::from_utf8_lossy(body_bytes).into_owned();
    let body = scrub_secret(raw_body, bearer_token_to_scrub);
    let parsed = serde_json::from_slice::<Value>(body_bytes).ok();
    let error_code = parsed
        .as_ref()
        .and_then(|v| v.get("error"))
        .and_then(Value::as_str)
        .map(|s| scrub_secret(s.to_string(), bearer_token_to_scrub));
    let finding = parsed
        .as_ref()
        .and_then(|v| v.get("finding"))
        .and_then(Value::as_str)
        .map(|s| scrub_secret(s.to_string(), bearer_token_to_scrub));

    match status {
        400 => EvidenceHttpError::BadRequest { error_code, body },
        401 => EvidenceHttpError::Unauthenticated { error_code, body },
        403 => EvidenceHttpError::Forbidden { error_code, body },
        404 => EvidenceHttpError::NotFound { error_code, body },
        409 => EvidenceHttpError::Conflict { error_code, body },
        413 => EvidenceHttpError::PayloadTooLarge { error_code, body },
        422 => EvidenceHttpError::Unprocessable {
            error_code,
            finding,
            body,
        },
        503 => EvidenceHttpError::ServiceUnavailable { error_code, body },
        other => EvidenceHttpError::HttpStatus {
            status: other,
            error_code,
            body,
        },
    }
}

/// Request body for `POST /v1/evidence/sessions` (`A8` §3.1).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenSessionRequest {
    /// Optional raw client session identifier (`1..=128` UTF-8 bytes, passed raw without
    /// pre-encoding so the gateway derives `urn:r5e:session:<tenant>:<fp>.<encoded_id>`).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "clientSessionId"
    )]
    pub client_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Map<String, Value>>,
}

/// Response (`201 Created` for newly opened sessions; `200 OK` without `ref`/`seq` for
/// already-open sessions) from `POST /v1/evidence/sessions` (`A8` §3.1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenedSessionResponse {
    pub session: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ref")]
    pub record_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default)]
    pub already_open: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "httpStatus"
    )]
    pub http_status: Option<u16>,
}

/// Request body for `POST /v1/evidence/records` (`A8` §2.1).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShipRecordsRequest {
    pub records: Vec<SignedEndpointRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<PublicKeyEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blobs: Vec<BlobEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<SubmitGrantsRequest>,
}

/// Per-record admission receipt in `POST /v1/evidence/records` responses (`A8` §2.5).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdmittedRecordReceipt {
    #[serde(rename = "ref")]
    pub record_ref: String,
    pub stream: String,
    pub seq: u64,
    pub status: String,
    #[serde(default, rename = "contentHeld")]
    pub content_held: Vec<String>,
    #[serde(default, rename = "contentMissing")]
    pub content_missing: Vec<String>,
}

/// Response (`201 Created` / `200 OK`) from `POST /v1/evidence/records` (`A8` §2.5).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShipRecordsResponse {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "httpStatus"
    )]
    pub http_status: Option<u16>,
    pub admitted: Vec<AdmittedRecordReceipt>,
}

impl ShipRecordsResponse {
    pub fn newly_admitted_count(&self) -> usize {
        self.admitted
            .iter()
            .filter(|a| a.status == "admitted")
            .count()
    }

    pub fn already_admitted_count(&self) -> usize {
        self.admitted
            .iter()
            .filter(|a| a.status == "already_admitted")
            .count()
    }

    pub fn all_already_admitted(&self) -> bool {
        !self.admitted.is_empty() && self.admitted.iter().all(|a| a.status == "already_admitted")
    }
}

/// Opens an anchored gateway session via `POST /v1/evidence/sessions` (`A8` §3.1).
pub fn open_session_over_http(
    gateway_url: &str,
    bearer_token: &str,
    request: &OpenSessionRequest,
) -> Result<OpenedSessionResponse, EvidenceHttpError> {
    if let Some(ref client_id) = request.client_session_id {
        if client_id.is_empty() || client_id.len() > 128 {
            return Err(EvidenceHttpError::Validation(format!(
                "OpenSessionRequest.clientSessionId must be 1..=128 UTF-8 bytes, got {} bytes",
                client_id.len()
            )));
        }
    }
    if let Some(ref w) = request.workload {
        if !is_valid_uri_identity(w) {
            return Err(EvidenceHttpError::Validation(format!(
                "OpenSessionRequest.workload must be a valid URI identity, got {w:?}"
            )));
        }
    }
    if let Some(ref p) = request.purpose {
        if p.trim().is_empty() {
            return Err(EvidenceHttpError::Validation(
                "OpenSessionRequest.purpose must be non-empty when present".to_string(),
            ));
        }
    }
    let mut normalized_req = request.clone();
    if let Some(ref det) = request.details {
        let flat =
            crate::attestation::normalize_a9_details(det).map_err(EvidenceHttpError::Validation)?;
        normalized_req.details = Some(flat);
    }

    let cfg = EvidenceClientConfig::new(gateway_url, bearer_token);
    let req_val = serde_json::to_value(&normalized_req)
        .map_err(|e| EvidenceHttpError::Validation(format!("serialize OpenSessionRequest: {e}")))?;
    let body_bytes = encode_canonical_json(&req_val)
        .map_err(|e| EvidenceHttpError::Validation(format!("canonical OpenSessionRequest: {e}")))?;

    let (status, resp_bytes) = post_json_bearer_http11(&cfg, OPEN_SESSION_PATH, &body_bytes)?;
    if status != 201 && status != 200 {
        return Err(classify_evidence_error(status, &resp_bytes, bearer_token));
    }

    let mut opened: OpenedSessionResponse = serde_json::from_slice(&resp_bytes).map_err(|e| {
        EvidenceHttpError::Transport(format!("parse {status} OpenSessionResponse JSON: {e}"))
    })?;
    if !is_valid_uri_identity(&opened.session) {
        return Err(EvidenceHttpError::Validation(format!(
            "gateway returned invalid session URN: {:?}",
            opened.session
        )));
    }
    if let Some(ref r) = opened.record_ref {
        if !is_valid_evidence_ref(r) {
            return Err(EvidenceHttpError::Validation(format!(
                "gateway returned invalid session anchor ref: {r:?}"
            )));
        }
    } else if status == 201 {
        return Err(EvidenceHttpError::Validation(
            "gateway returned 201 Created on open-session without 'ref'".to_string(),
        ));
    }
    if let Some(seq) = opened.seq {
        if seq == 0 {
            return Err(EvidenceHttpError::Validation(
                "gateway returned session seq == 0 (expected >= 1)".to_string(),
            ));
        }
    } else if status == 201 {
        return Err(EvidenceHttpError::Validation(
            "gateway returned 201 Created on open-session without 'seq'".to_string(),
        ));
    }
    opened.http_status = Some(status);
    opened.already_open = status == 200;
    Ok(opened)
}

#[derive(Debug, Clone)]
struct ParsedWorkloadRecord {
    record: SignedEndpointRecord,
    stream: String,
    seq: u64,
    signer_keyids: BTreeSet<String>,
    referenced_blob_refs: BTreeSet<String>,
}

fn collect_bytes_refs_in_value(val: &Value, out: &mut BTreeSet<String>) {
    match val {
        Value::String(s) => {
            if is_valid_bytes_ref(s) {
                out.insert(s.clone());
            }
        }
        Value::Array(arr) => {
            for item in arr {
                collect_bytes_refs_in_value(item, out);
            }
        }
        Value::Object(map) => {
            for v in map.values() {
                collect_bytes_refs_in_value(v, out);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn parse_and_validate_workload_record(
    rec: &SignedEndpointRecord,
) -> Result<ParsedWorkloadRecord, EvidenceHttpError> {
    if !is_valid_evidence_ref(&rec.record_ref) {
        return Err(EvidenceHttpError::Validation(format!(
            "invalid workload record ref: {:?}",
            rec.record_ref
        )));
    }
    let payload_bytes = decode_strict_base64(&rec.envelope.payload).map_err(|e| {
        EvidenceHttpError::Validation(format!("invalid base64 payload on {}: {e}", rec.record_ref))
    })?;
    let parsed: Value = serde_json::from_slice(&payload_bytes).map_err(|e| {
        EvidenceHttpError::Validation(format!("invalid payload JSON on {}: {e}", rec.record_ref))
    })?;
    let api_version = parsed
        .get("apiVersion")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            EvidenceHttpError::Validation(format!("missing apiVersion on {}", rec.record_ref))
        })?;
    let kind = parsed.get("kind").and_then(Value::as_str).ok_or_else(|| {
        EvidenceHttpError::Validation(format!("missing kind on {}", rec.record_ref))
    })?;
    let kind_path = if kind.contains('/') {
        kind.to_string()
    } else {
        format!("{api_version}/{kind}")
    };
    if !is_admissible_workload_kind(&kind_path) {
        return Err(EvidenceHttpError::Validation(format!(
            "kind {kind_path} on {} is not admissible in workload POST /v1/evidence/records",
            rec.record_ref
        )));
    }

    let stream = parsed
        .get("stream")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            EvidenceHttpError::Validation(format!("missing stream on {}", rec.record_ref))
        })?
        .to_string();
    let seq = parsed
        .get("seq")
        .and_then(Value::as_u64)
        .filter(|&s| s >= 1)
        .ok_or_else(|| {
            EvidenceHttpError::Validation(format!("invalid seq on {}", rec.record_ref))
        })?;

    let mut signer_keyids = BTreeSet::new();
    if let Some(issuer) = parsed.get("issuer").and_then(Value::as_str) {
        signer_keyids.insert(issuer.to_string());
    }
    for sig in &rec.envelope.signatures {
        signer_keyids.insert(sig.keyid.clone());
    }

    let mut referenced_blob_refs = BTreeSet::new();
    collect_bytes_refs_in_value(&parsed, &mut referenced_blob_refs);

    Ok(ParsedWorkloadRecord {
        record: rec.clone(),
        stream,
        seq,
        signer_keyids,
        referenced_blob_refs,
    })
}

/// Splits a [`ShipRecordsRequest`] into batches of at most [`MAX_RECORDS_PER_BATCH`] (`64`)
/// records and `<= MAX_BATCH_BODY_BYTES` bytes while preserving per-stream consecutive `seq`
/// order, deduplicating `keys` and `blobs`.
pub fn chunk_ship_records_request(
    request: &ShipRecordsRequest,
) -> Result<Vec<ShipRecordsRequest>, EvidenceHttpError> {
    if request.records.is_empty() {
        return Err(EvidenceHttpError::Validation(
            "ShipRecordsRequest.records must contain at least 1 record".to_string(),
        ));
    }

    // Deduplicate input keys and blobs while preserving deterministic order, and index profile
    // blobs' nested `bytes:sha256:...` refs (such as `deploymentPolicyRef`).
    let mut keys_by_id: BTreeMap<String, PublicKeyEntry> = BTreeMap::new();
    for k in &request.keys {
        keys_by_id
            .entry(k.keyid.clone())
            .or_insert_with(|| k.clone());
    }

    let mut blobs_by_ref: BTreeMap<String, BlobEntry> = BTreeMap::new();
    let mut nested_blob_refs: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for b in &request.blobs {
        blobs_by_ref
            .entry(b.blob_ref.clone())
            .or_insert_with(|| b.clone());
        if !nested_blob_refs.contains_key(&b.blob_ref) {
            let mut nested = BTreeSet::new();
            if let Ok(decoded) = decode_strict_base64(&b.base64) {
                if let Ok(val) = serde_json::from_slice::<Value>(&decoded) {
                    collect_bytes_refs_in_value(&val, &mut nested);
                }
            }
            nested_blob_refs.insert(b.blob_ref.clone(), nested);
        }
    }

    // Parse records and sort per-stream by ascending `seq` (preserving stream encounter order).
    let mut stream_first_seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut parsed_records: Vec<ParsedWorkloadRecord> = Vec::with_capacity(request.records.len());
    for rec in &request.records {
        let p = parse_and_validate_workload_record(rec)?;
        let next_idx = stream_first_seen.len();
        stream_first_seen
            .entry(p.stream.clone())
            .or_insert(next_idx);
        parsed_records.push(p);
    }
    parsed_records.sort_by_key(|p| (stream_first_seen[&p.stream], p.seq));

    // Verify per-stream strict monotonicity (no duplicate seq within a request; consecutive seqs when >1).
    let mut prev_seq_by_stream: BTreeMap<&str, u64> = BTreeMap::new();
    for p in &parsed_records {
        if let Some(&prev_seq) = prev_seq_by_stream.get(p.stream.as_str()) {
            if p.seq != prev_seq + 1 {
                return Err(EvidenceHttpError::Validation(format!(
                    "non-consecutive seq on stream {}: saw seq {} immediately after seq {}",
                    p.stream, p.seq, prev_seq
                )));
            }
        }
        prev_seq_by_stream.insert(p.stream.as_str(), p.seq);
    }

    let build_batch = |slice: &[ParsedWorkloadRecord],
                       include_all_unreferenced_blobs: bool|
     -> Result<(ShipRecordsRequest, usize), EvidenceHttpError> {
        let mut needed_keys = BTreeSet::new();
        let mut needed_blobs = BTreeSet::new();
        for item in slice {
            needed_keys.extend(item.signer_keyids.iter().cloned());
            for bref in &item.referenced_blob_refs {
                if blobs_by_ref.contains_key(bref) {
                    needed_blobs.insert(bref.clone());
                    if let Some(nested) = nested_blob_refs.get(bref) {
                        for nb in nested {
                            if blobs_by_ref.contains_key(nb) {
                                needed_blobs.insert(nb.clone());
                            }
                        }
                    }
                }
            }
        }

        let batch_keys: Vec<PublicKeyEntry> = if needed_keys
            .iter()
            .all(|kid| keys_by_id.contains_key(kid))
            && !needed_keys.is_empty()
        {
            needed_keys
                .iter()
                .filter_map(|kid| keys_by_id.get(kid).cloned())
                .collect()
        } else {
            keys_by_id.values().cloned().collect()
        };

        let batch_blobs: Vec<BlobEntry> = if include_all_unreferenced_blobs {
            blobs_by_ref.values().cloned().collect()
        } else {
            needed_blobs
                .iter()
                .filter_map(|r| blobs_by_ref.get(r).cloned())
                .collect()
        };

        let req = ShipRecordsRequest {
            records: slice.iter().map(|p| p.record.clone()).collect(),
            keys: batch_keys,
            blobs: batch_blobs,
            authority: request.authority.clone(),
        };
        let val = serde_json::to_value(&req)
            .map_err(|e| EvidenceHttpError::Validation(format!("serialize batch: {e}")))?;
        let bytes = encode_canonical_json(&val)
            .map_err(|e| EvidenceHttpError::Validation(format!("canonicalize batch: {e}")))?;
        Ok((req, bytes.len()))
    };

    // Fast path: <= 64 records and total canonical JSON <= MAX_BATCH_BODY_BYTES.
    if parsed_records.len() <= MAX_RECORDS_PER_BATCH {
        let (single, len) = build_batch(&parsed_records, true)?;
        if len <= MAX_BATCH_BODY_BYTES {
            return Ok(vec![single]);
        }
    }

    let mut batches = Vec::new();
    let mut start = 0usize;
    while start < parsed_records.len() {
        let max_end = (start + MAX_RECORDS_PER_BATCH).min(parsed_records.len());
        let mut chosen_end = start + 1;
        let (mut best_batch, first_len) = build_batch(&parsed_records[start..chosen_end], false)?;
        if first_len > HARD_MAX_REQUEST_BODY_BYTES {
            return Err(EvidenceHttpError::Validation(format!(
                "single record {} batch size ({} bytes) exceeds gateway limit ({} bytes)",
                parsed_records[start].record.record_ref, first_len, HARD_MAX_REQUEST_BODY_BYTES
            )));
        }

        while chosen_end < max_end {
            let trial_end = chosen_end + 1;
            let (trial_batch, trial_len) = build_batch(&parsed_records[start..trial_end], false)?;
            if trial_len > MAX_BATCH_BODY_BYTES {
                break;
            }
            best_batch = trial_batch;
            chosen_end = trial_end;
        }

        batches.push(best_batch);
        start = chosen_end;
    }

    Ok(batches)
}

/// Ships workload operational records via `POST /v1/evidence/records` (`A8` §2), automatically
/// splitting into `<= 64`-record batches (`< 6 MiB` per HTTP request) and returning each batch's
/// [`ShipRecordsResponse`].
pub fn ship_records_batches_over_http(
    gateway_url: &str,
    bearer_token: &str,
    request: &ShipRecordsRequest,
) -> Result<Vec<ShipRecordsResponse>, EvidenceHttpError> {
    let batches = chunk_ship_records_request(request)?;
    let cfg = EvidenceClientConfig::new(gateway_url, bearer_token);
    let mut responses = Vec::with_capacity(batches.len());

    for batch in &batches {
        let val = serde_json::to_value(batch)
            .map_err(|e| EvidenceHttpError::Validation(format!("serialize batch: {e}")))?;
        let body_bytes = encode_canonical_json(&val)
            .map_err(|e| EvidenceHttpError::Validation(format!("canonicalize batch: {e}")))?;
        let (status, resp_bytes) = post_json_bearer_http11(&cfg, ADMIT_RECORDS_PATH, &body_bytes)?;
        if status != 201 && status != 200 {
            return Err(classify_evidence_error(status, &resp_bytes, bearer_token));
        }
        let mut parsed_resp: ShipRecordsResponse =
            serde_json::from_slice(&resp_bytes).map_err(|e| {
                EvidenceHttpError::Transport(format!(
                    "parse {status} ShipRecordsResponse JSON: {e}"
                ))
            })?;
        parsed_resp.http_status = Some(status);
        responses.push(parsed_resp);
    }

    Ok(responses)
}

/// Ships workload operational records via `POST /v1/evidence/records` (`A8` §2), automatically
/// chunking into `<= 64`-record batches while aggregating all `admitted` receipts in order.
pub fn ship_records_over_http(
    gateway_url: &str,
    bearer_token: &str,
    request: &ShipRecordsRequest,
) -> Result<ShipRecordsResponse, EvidenceHttpError> {
    let batch_responses = ship_records_batches_over_http(gateway_url, bearer_token, request)?;
    let mut combined_admitted = Vec::new();
    let mut any_201 = false;
    for resp in batch_responses {
        if resp.http_status == Some(201) {
            any_201 = true;
        }
        combined_admitted.extend(resp.admitted);
    }
    Ok(ShipRecordsResponse {
        http_status: Some(if any_201 { 201 } else { 200 }),
        admitted: combined_admitted,
    })
}

/// Revokes a gateway-minted `Badge` via `POST /v1/authority/badges/revoke` (`A8` §4.6).
pub fn revoke_badge_over_http(
    gateway_url: &str,
    bearer_token: &str,
    badge_ref: &str,
    reason: &str,
) -> Result<Value, EvidenceHttpError> {
    let badge_trimmed = badge_ref.trim();
    if !is_valid_evidence_ref(badge_trimmed) {
        return Err(EvidenceHttpError::Validation(format!(
            "badge_ref must be a valid evidence:sha256:... reference, got {badge_ref:?}"
        )));
    }
    if reason.trim().is_empty() {
        return Err(EvidenceHttpError::Validation(
            "revocation reason must be non-empty".to_string(),
        ));
    }

    let cfg = EvidenceClientConfig::new(gateway_url, bearer_token);
    let body_val = json!({
        "badge": badge_trimmed,
        "reason": reason,
    });
    let body_bytes = encode_canonical_json(&body_val)
        .map_err(|e| EvidenceHttpError::Validation(format!("canonicalize revoke body: {e}")))?;

    let (status, resp_bytes) = post_json_bearer_http11(&cfg, REVOKE_BADGE_PATH, &body_bytes)?;
    if status != 201 && status != 200 {
        return Err(classify_evidence_error(status, &resp_bytes, bearer_token));
    }
    serde_json::from_slice(&resp_bytes)
        .map_err(|e| EvidenceHttpError::Transport(format!("parse {status} badge revoke JSON: {e}")))
}

/// Builds a [`ShipRecordsRequest`] from an [`EndpointBundleRecorder`], filtering out non-workload
/// records (`Badge`, `Endorsement`, `DefinitionPublished`, etc.), always carrying every operational
/// record's `profileRef` blob, and carrying inline content blobs iff `include_payload_blobs` is `true`.
pub fn build_ship_request_from_recorder(
    recorder: &EndpointBundleRecorder,
    issuer_filter: Option<&str>,
    skip_record_refs: &BTreeSet<String>,
    include_payload_blobs: bool,
    authority: Option<SubmitGrantsRequest>,
) -> Result<ShipRecordsRequest, EvidenceHttpError> {
    let mut workload_records = Vec::new();
    let mut profile_refs = BTreeSet::new();
    let mut all_referenced_blobs = BTreeSet::new();
    let mut signer_ids = BTreeSet::new();

    for rec in recorder.records() {
        if skip_record_refs.contains(&rec.record_ref) {
            continue;
        }
        let Ok(payload_bytes) = decode_strict_base64(&rec.envelope.payload) else {
            continue;
        };
        let Ok(parsed) = serde_json::from_slice::<Value>(&payload_bytes) else {
            continue;
        };
        let Some(api_version) = parsed.get("apiVersion").and_then(Value::as_str) else {
            continue;
        };
        let Some(kind) = parsed.get("kind").and_then(Value::as_str) else {
            continue;
        };
        let kind_path = if kind.contains('/') {
            kind.to_string()
        } else {
            format!("{api_version}/{kind}")
        };
        if !is_admissible_workload_kind(&kind_path) {
            continue;
        }
        let issuer = parsed.get("issuer").and_then(Value::as_str).unwrap_or("");
        if let Some(expected_issuer) = issuer_filter {
            if issuer != expected_issuer {
                continue;
            }
        }
        if let Some(pref) = parsed.get("profileRef").and_then(Value::as_str) {
            profile_refs.insert(pref.to_string());
        }
        collect_bytes_refs_in_value(&parsed, &mut all_referenced_blobs);
        if !issuer.is_empty() {
            signer_ids.insert(issuer.to_string());
        }
        for sig in &rec.envelope.signatures {
            signer_ids.insert(sig.keyid.clone());
        }
        workload_records.push(rec.clone());
    }

    let keys: Vec<PublicKeyEntry> = signer_ids
        .iter()
        .filter_map(|kid| recorder.public_key_entry(kid))
        .collect();

    let mut blobs = Vec::new();
    let mut added_blobs = BTreeSet::new();
    // Always carry every workload record's `CaptureProfile` blob (`A8` §2.3 — omitting profileRef
    // returns `422 profile_not_carried` rather than missing-content tolerance).
    for pref in &profile_refs {
        if let Some(entry) = recorder.blob_entry(pref) {
            added_blobs.insert(pref.clone());
            blobs.push(entry);
        }
    }
    if include_payload_blobs {
        // Also carry `deploymentPolicyRef` inside carried profiles + all content blobs in record bodies.
        for pref in &profile_refs {
            if let Some((b64, _)) = recorder.blobs().get(pref) {
                if let Ok(raw) = decode_strict_base64(b64) {
                    if let Ok(val) = serde_json::from_slice::<Value>(&raw) {
                        collect_bytes_refs_in_value(&val, &mut all_referenced_blobs);
                    }
                }
            }
        }
        for bref in &all_referenced_blobs {
            if !added_blobs.contains(bref) {
                if let Some(entry) = recorder.blob_entry(bref) {
                    added_blobs.insert(bref.clone());
                    blobs.push(entry);
                }
            }
        }
    }

    Ok(ShipRecordsRequest {
        records: workload_records,
        keys,
        blobs,
        authority,
    })
}

impl EnrolledEndpointSession {
    /// Ships this enrolled session's recorded operational workload records (excluding `Badge`,
    /// `Endorsement`, and `DefinitionPublished`), signer key (`PublicKeyEntry`), local
    /// `CaptureProfile` blob, and (when `include_payload_blobs` is `true`) inline payload blobs
    /// to `<gateway_url>/v1/evidence/records` in `<= 64`-record batches (`A8` §2 / §4).
    pub fn ship_to_gateway(
        &self,
        gateway_url: &str,
        bearer_token: &str,
        include_payload_blobs: bool,
    ) -> Result<Vec<ShipRecordsResponse>, EvidenceHttpError> {
        let mut req = build_ship_request_from_recorder(
            &self.recorder,
            Some(&self.helper_keyid),
            &BTreeSet::new(),
            include_payload_blobs,
            None,
        )?;
        if req.keys.is_empty() {
            req.keys.push(self.public_key_entry());
        }
        ship_records_batches_over_http(gateway_url, bearer_token, &req)
    }
}

/// Loads a `r5e.provenance-export/v2` bundle JSON file (or directory containing `bundle.json` /
/// `export.json`) and extracts a [`ShipRecordsRequest`] ready for `ship_records_over_http`.
pub fn load_ship_request_from_bundle_path(
    bundle_path: &Path,
    include_payload_blobs: bool,
    authority: Option<SubmitGrantsRequest>,
) -> Result<ShipRecordsRequest, EvidenceHttpError> {
    let resolved_file = if bundle_path.is_dir() {
        let candidates = ["bundle.json", "export.json", "provenance-bundle.json"];
        candidates
            .iter()
            .map(|name| bundle_path.join(name))
            .find(|p| p.is_file())
            .ok_or_else(|| {
                EvidenceHttpError::Validation(format!(
                    "bundle directory {} does not contain bundle.json or export.json",
                    bundle_path.display()
                ))
            })?
    } else {
        bundle_path.to_path_buf()
    };

    let raw = fs::read_to_string(&resolved_file).map_err(|e| {
        EvidenceHttpError::Validation(format!(
            "cannot read bundle {}: {e}",
            resolved_file.display()
        ))
    })?;
    let val: Value = serde_json::from_str(&raw).map_err(|e| {
        EvidenceHttpError::Validation(format!(
            "invalid JSON in bundle {}: {e}",
            resolved_file.display()
        ))
    })?;

    let records_val = val
        .get("records")
        .ok_or_else(|| {
            EvidenceHttpError::Validation(format!(
                "bundle {} missing 'records' array",
                resolved_file.display()
            ))
        })?
        .clone();
    let all_records: Vec<SignedEndpointRecord> = serde_json::from_value(records_val)
        .map_err(|e| EvidenceHttpError::Validation(format!("parse bundle records: {e}")))?;

    let all_keys: Vec<PublicKeyEntry> = match val.get("keys") {
        Some(kv) => serde_json::from_value(kv.clone())
            .map_err(|e| EvidenceHttpError::Validation(format!("parse bundle keys: {e}")))?,
        None => Vec::new(),
    };
    let all_blobs: Vec<BlobEntry> = match val.get("blobs") {
        Some(bv) => serde_json::from_value(bv.clone())
            .map_err(|e| EvidenceHttpError::Validation(format!("parse bundle blobs: {e}")))?,
        None => Vec::new(),
    };

    let blobs_map: BTreeMap<String, BlobEntry> = all_blobs
        .into_iter()
        .map(|b| (b.blob_ref.clone(), b))
        .collect();
    let keys_map: BTreeMap<String, PublicKeyEntry> =
        all_keys.into_iter().map(|k| (k.keyid.clone(), k)).collect();

    let mut workload_records = Vec::new();
    let mut profile_refs = BTreeSet::new();
    let mut content_refs = BTreeSet::new();
    let mut signer_ids = BTreeSet::new();

    for rec in all_records {
        let Ok(payload_bytes) = decode_strict_base64(&rec.envelope.payload) else {
            continue;
        };
        let Ok(parsed) = serde_json::from_slice::<Value>(&payload_bytes) else {
            continue;
        };
        let Some(api_version) = parsed.get("apiVersion").and_then(Value::as_str) else {
            continue;
        };
        let Some(kind) = parsed.get("kind").and_then(Value::as_str) else {
            continue;
        };
        let kind_path = if kind.contains('/') {
            kind.to_string()
        } else {
            format!("{api_version}/{kind}")
        };
        if !is_admissible_workload_kind(&kind_path) {
            continue;
        }
        if let Some(pref) = parsed.get("profileRef").and_then(Value::as_str) {
            profile_refs.insert(pref.to_string());
        }
        collect_bytes_refs_in_value(&parsed, &mut content_refs);
        if let Some(issuer) = parsed.get("issuer").and_then(Value::as_str) {
            signer_ids.insert(issuer.to_string());
        }
        for sig in &rec.envelope.signatures {
            signer_ids.insert(sig.keyid.clone());
        }
        workload_records.push(rec);
    }

    if workload_records.is_empty() {
        return Err(EvidenceHttpError::Validation(format!(
            "bundle {} contains zero admissible operational workload records",
            resolved_file.display()
        )));
    }

    let keys: Vec<PublicKeyEntry> = signer_ids
        .iter()
        .filter_map(|kid| keys_map.get(kid).cloned())
        .collect();

    let mut blobs = Vec::new();
    let mut added = BTreeSet::new();
    for pref in &profile_refs {
        if let Some(b) = blobs_map.get(pref) {
            added.insert(pref.clone());
            blobs.push(b.clone());
        }
    }
    if include_payload_blobs {
        for pref in &profile_refs {
            if let Some(b) = blobs_map.get(pref) {
                if let Ok(raw) = decode_strict_base64(&b.base64) {
                    if let Ok(v) = serde_json::from_slice::<Value>(&raw) {
                        collect_bytes_refs_in_value(&v, &mut content_refs);
                    }
                }
            }
        }
        for bref in &content_refs {
            if !added.contains(bref) {
                if let Some(b) = blobs_map.get(bref) {
                    added.insert(bref.clone());
                    blobs.push(b.clone());
                }
            }
        }
    }

    Ok(ShipRecordsRequest {
        records: workload_records,
        keys,
        blobs,
        authority,
    })
}

/// Persistent `0600` enrolled badge & stream state file created by `enrol-badge` and updated by
/// `open-session`, `record-event`, and `ship-bundle`.
#[derive(Clone, Serialize, Deserialize)]
pub struct EnrolledStateFile {
    pub format: String,
    pub gateway_url: String,
    /// Ephemeral workload Ed25519 32-byte seed in base64 (redacted in `Debug`, persisted `0600`).
    pub workload_seed_b64: String,
    pub subject_key_id: String,
    pub holder: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    pub badge_ref: String,
    pub stream_prefix: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acts_for: Option<String>,
    pub actor_prefixes: Vec<String>,
    pub granted_kinds: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub local_profile_ref: String,
    pub deployment_policy_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<Value>,
    pub capture_profile: CaptureProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_urn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_anchor_ref: Option<String>,
    pub recorder: EndpointBundleRecorder,
    #[serde(default)]
    pub shipped_record_refs: Vec<String>,
}

impl fmt::Debug for EnrolledStateFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrolledStateFile")
            .field("format", &self.format)
            .field("gateway_url", &self.gateway_url)
            .field("workload_seed_b64", &"[REDACTED]")
            .field("subject_key_id", &self.subject_key_id)
            .field("badge_ref", &self.badge_ref)
            .field("stream_prefix", &self.stream_prefix)
            .field("local_profile_ref", &self.local_profile_ref)
            .field("retention", &self.retention)
            .field("session_urn", &self.session_urn)
            .finish()
    }
}

impl EnrolledStateFile {
    pub fn from_enrolled_session(
        gateway_url: impl Into<String>,
        holder: impl Into<String>,
        purpose: Option<String>,
        session: &EnrolledEndpointSession,
    ) -> Self {
        let seed_bytes = session.helper_key.to_bytes();
        Self {
            format: ENROLLED_STATE_FORMAT.to_string(),
            gateway_url: gateway_url.into(),
            workload_seed_b64: BASE64_STANDARD.encode(seed_bytes),
            subject_key_id: session.helper_keyid.clone(),
            holder: holder.into(),
            workload: session.workload.clone(),
            purpose,
            badge_ref: session.badge_ref.clone(),
            stream_prefix: session.stream_prefix.clone(),
            acts_for: session.acts_for.clone(),
            actor_prefixes: session.actor_prefixes.clone(),
            granted_kinds: session.granted_kinds.clone(),
            not_before: session.not_before.clone(),
            not_after: session.not_after.clone(),
            local_profile_ref: session.local_profile_ref.clone(),
            deployment_policy_ref: session.deployment_policy_ref.clone(),
            retention: session.retention.clone(),
            capture_profile: session.capture_profile.clone(),
            session_urn: None,
            session_anchor_ref: None,
            recorder: session.recorder.clone(),
            shipped_record_refs: Vec::new(),
        }
    }

    pub fn signing_key(&self) -> Result<SigningKey, String> {
        let raw = decode_strict_base64(&self.workload_seed_b64)
            .map_err(|e| format!("invalid workload_seed_b64 in enrolled state: {e}"))?;
        let seed: [u8; 32] = raw.try_into().map_err(|_| {
            "workload_seed_b64 in enrolled state must decode to 32 bytes".to_string()
        })?;
        Ok(SigningKey::from_bytes(&seed))
    }

    /// Selects a default admissible `actor` URI covered by `self.actor_prefixes` (and compatible
    /// with `A8` §3.3 session principal matching).
    pub fn default_actor(&self) -> String {
        if let Some(ref w) = self.workload {
            if self.actor_prefixes.iter().any(|p| w.starts_with(p)) {
                return w.clone();
            }
        }
        if let Some(first_prefix) = self.actor_prefixes.first() {
            if first_prefix.ends_with(':') {
                return format!("{first_prefix}{}", self.holder);
            }
            return first_prefix.clone();
        }
        if let Some(ref af) = self.acts_for {
            return af.clone();
        }
        format!("urn:r5e:workload:{}", self.holder)
    }

    /// Appends a signed operational record onto `format!("{}{}", self.stream_prefix, stream_suffix)`.
    pub fn append_workload_record(
        &mut self,
        stream_suffix: &str,
        kind: &str,
        actor: &str,
        session_urn: Option<&str>,
        captured_at: &str,
        mut body: Value,
    ) -> Result<SignedEndpointRecord, String> {
        let (kind_path, short_kind) =
            if let Some(short) = kind.strip_prefix("provenance.r5e.io/v2/") {
                (kind.to_string(), short.to_string())
            } else {
                (format!("provenance.r5e.io/v2/{kind}"), kind.to_string())
            };
        if !is_admissible_workload_kind(&kind_path) {
            return Err(format!(
                "kind {kind_path} is not admissible as a workload operational record"
            ));
        }
        let schemas = base_v2_schema_map();
        let schema_ref = schemas
            .get(&kind_path)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("unknown base Provenance v2 kind: {kind_path}"))?;

        crate::attestation::validate_and_normalize_v2_body(&short_kind, &mut body)?;

        let sk = self.signing_key()?;
        let mut env = Map::new();
        env.insert(
            "apiVersion".to_string(),
            Value::String("provenance.r5e.io/v2".to_string()),
        );
        env.insert("kind".to_string(), Value::String(short_kind));
        env.insert(
            "schemaRef".to_string(),
            Value::String(schema_ref.to_string()),
        );
        env.insert(
            "profileRef".to_string(),
            Value::String(self.local_profile_ref.clone()),
        );
        env.insert("actor".to_string(), Value::String(actor.to_string()));
        if let Some(ref acts_for) = self.acts_for {
            env.insert("onBehalfOf".to_string(), Value::String(acts_for.clone()));
        }
        if let Some(sess) = session_urn {
            env.insert("session".to_string(), Value::String(sess.to_string()));
        }
        env.insert(
            "capturedAt".to_string(),
            Value::String(captured_at.to_string()),
        );
        env.insert("body".to_string(), body);

        let full_stream = format!("{}{}", self.stream_prefix, stream_suffix);
        self.recorder
            .append_stream_record(&[&sk], &full_stream, env)
    }

    /// Loads a Cedar policy source string from `cedar_policy_path` (or falls back to the Cedar
    /// policy blob already stored under `self.deployment_policy_ref`), stores its bytes in
    /// `self.recorder` (`text/plain`), and returns `(cedar_src, policy_blob_ref)`.
    pub fn resolve_and_store_cedar_policy(
        &mut self,
        cedar_policy_path: Option<&Path>,
    ) -> Result<(String, String), String> {
        if let Some(path) = cedar_policy_path {
            let bytes = fs::read(path)
                .map_err(|e| format!("cannot read Cedar policy file {}: {e}", path.display()))?;
            let src = String::from_utf8(bytes.clone()).map_err(|e| {
                format!(
                    "Cedar policy file {} is not valid UTF-8: {e}",
                    path.display()
                )
            })?;
            let policy_ref = self.recorder.put_blob(&bytes, Some("text/plain"));
            return Ok((src, policy_ref));
        }

        if let Some((b64, _)) = self.recorder.blobs().get(&self.deployment_policy_ref) {
            let bytes = decode_strict_base64(b64).map_err(|e| {
                format!(
                    "invalid base64 for stored deploymentPolicyRef {}: {e}",
                    self.deployment_policy_ref
                )
            })?;
            let src = String::from_utf8(bytes).map_err(|e| {
                format!(
                    "stored deploymentPolicyRef {} is not valid UTF-8 Cedar source: {e}",
                    self.deployment_policy_ref
                )
            })?;
            return Ok((src, self.deployment_policy_ref.clone()));
        }

        Err("no Cedar policy supplied: pass --cedar-policy <FILE> (or enrol with --cedar-policy <FILE>)".to_string())
    }

    /// Appends a signed `provenance.r5e.io/v2/PolicyDecision` record for a local `exec` or
    /// `mcp-proxy` Cedar evaluation.
    #[allow(clippy::too_many_arguments)]
    pub fn append_policy_decision_record(
        &mut self,
        stream_suffix: &str,
        actor: &str,
        session_urn: Option<&str>,
        captured_at: &str,
        subject_ref: &str,
        input_refs: &[String],
        verdict: &GateVerdict,
        posture: Posture,
        action_name: &str,
        target_name: &str,
    ) -> Result<SignedEndpointRecord, String> {
        let mut unique_input_refs = Vec::with_capacity(input_refs.len());
        for r in input_refs {
            if !unique_input_refs.contains(r) {
                unique_input_refs.push(r.clone());
            }
        }

        let mut eval = Map::new();
        eval.insert(
            "policyRef".to_string(),
            Value::String(verdict.policy_bundle_ref.clone()),
        );
        eval.insert(
            "outcome".to_string(),
            Value::String(verdict.cedar_decision.clone()),
        );
        eval.insert("inputRefs".to_string(), json!(unique_input_refs));

        let reason_opt = verdict.agent_message.clone().or_else(|| {
            if verdict.outcome == EnforcementOutcome::ObservedWouldWithhold {
                Some(format!(
                    "Observed policy withhold in observe posture for {action_name} ({target_name})"
                ))
            } else {
                None
            }
        });
        if let Some(reason) = reason_opt.filter(|s| !s.trim().is_empty()) {
            eval.insert("reason".to_string(), Value::String(reason));
        }

        let joined_policy_ids = crate::attestation::truncate_utf8_bytes(
            &verdict.matching_policy_ids.join(","),
            crate::attestation::MAX_DETAILS_VALUE_BYTES,
        );
        let bounded_action = crate::attestation::truncate_utf8_bytes(
            action_name,
            crate::attestation::MAX_DETAILS_VALUE_BYTES,
        );
        let bounded_target = crate::attestation::truncate_utf8_bytes(
            target_name,
            crate::attestation::MAX_DETAILS_VALUE_BYTES,
        );

        let details = json!({
            "posture": posture,
            "enforcementOutcome": verdict.outcome,
            "matchingPolicyIds": joined_policy_ids,
            "matchingPolicyCount": verdict.matching_policy_ids.len() as i64,
            "offlineMode": verdict.offline_mode,
            "action": bounded_action,
            "target": bounded_target,
        });

        let body = json!({
            "subject": subject_ref,
            "evaluation": Value::Object(eval),
            "details": details,
        });
        self.append_workload_record(
            stream_suffix,
            "PolicyDecision",
            actor,
            session_urn,
            captured_at,
            body,
        )
    }

    /// Appends a signed `provenance.r5e.io/v2/ToolCall` record with inline `body.policy`
    /// (`decisionRef` pointing to `policy_decision_ref`, `policyRef` matching `verdict.policy_bundle_ref`)
    /// and top-level `body.callId` (`A9` §2) so `VERIFY-V2` §6.3 `profile_bounds` (`policyRequiredKinds`)
    /// holds in both `enforce` and `observe` postures.
    #[allow(clippy::too_many_arguments)]
    pub fn append_gated_tool_call_record(
        &mut self,
        stream_suffix: &str,
        actor: &str,
        session_urn: Option<&str>,
        captured_at: &str,
        tool_name: &str,
        call_id: Option<&str>,
        content_ref: &str,
        content_size: usize,
        input_refs: &[String],
        verdict: &GateVerdict,
        policy_decision_ref: &str,
        details: Option<Map<String, Value>>,
    ) -> Result<SignedEndpointRecord, String> {
        if let Some(cid) = call_id {
            crate::attestation::validate_call_id(cid, "ToolCall.body.callId")?;
        }
        let mut unique_input_refs = Vec::with_capacity(input_refs.len());
        for r in input_refs {
            if !unique_input_refs.contains(r) {
                unique_input_refs.push(r.clone());
            }
        }

        let mut policy_obj = Map::new();
        policy_obj.insert(
            "policyRef".to_string(),
            Value::String(verdict.policy_bundle_ref.clone()),
        );
        policy_obj.insert(
            "outcome".to_string(),
            Value::String(verdict.cedar_decision.clone()),
        );
        policy_obj.insert("inputRefs".to_string(), json!(unique_input_refs));
        policy_obj.insert(
            "decisionRef".to_string(),
            Value::String(policy_decision_ref.to_string()),
        );
        if verdict.outcome == EnforcementOutcome::ObservedWouldWithhold {
            policy_obj.insert(
                "reason".to_string(),
                Value::String(format!(
                    "Observed policy withhold in observe posture for {tool_name}"
                )),
            );
        } else if let Some(ref msg) = verdict.agent_message {
            if !msg.trim().is_empty() {
                policy_obj.insert("reason".to_string(), Value::String(msg.clone()));
            }
        }

        let mut body_map = Map::new();
        body_map.insert("tool".to_string(), Value::String(tool_name.to_string()));
        if let Some(cid) = call_id {
            body_map.insert("callId".to_string(), Value::String(cid.to_string()));
        }
        body_map.insert(
            "contentRef".to_string(),
            Value::String(content_ref.to_string()),
        );
        body_map.insert(
            "mediaType".to_string(),
            Value::String("application/json".to_string()),
        );
        body_map.insert("size".to_string(), json!(content_size as i64));
        body_map.insert("policy".to_string(), Value::Object(policy_obj));
        if let Some(det) = details {
            let flat = crate::attestation::normalize_a9_details(&det)?;
            if !flat.is_empty() {
                body_map.insert("details".to_string(), Value::Object(flat));
            }
        }

        self.append_workload_record(
            stream_suffix,
            "ToolCall",
            actor,
            session_urn,
            captured_at,
            Value::Object(body_map),
        )
    }

    /// Appends a signed `provenance.r5e.io/v2/ToolResult` record linked via `body.call` to `tool_call_ref`
    /// and optional top-level `body.callId` (`A9` §2).
    #[allow(clippy::too_many_arguments)]
    pub fn append_tool_result_record(
        &mut self,
        stream_suffix: &str,
        actor: &str,
        session_urn: Option<&str>,
        captured_at: &str,
        tool_call_ref: &str,
        call_id: Option<&str>,
        content_ref: &str,
        media_type: &str,
        content_size: usize,
        outcome: &str,
        reason: Option<&str>,
        details: Option<Map<String, Value>>,
    ) -> Result<SignedEndpointRecord, String> {
        if !is_valid_evidence_ref(tool_call_ref) {
            return Err(format!(
                "ToolResult.body.call must be a valid evidence:sha256:<64hex> ToolCall ref, got {tool_call_ref:?}"
            ));
        }
        if let Some(cid) = call_id {
            crate::attestation::validate_call_id(cid, "ToolResult.body.callId")?;
        }
        if media_type.trim().is_empty() {
            return Err("ToolResult.body.mediaType must be non-empty".to_string());
        }

        let mut body_map = Map::new();
        body_map.insert("call".to_string(), Value::String(tool_call_ref.to_string()));
        if let Some(cid) = call_id {
            body_map.insert("callId".to_string(), Value::String(cid.to_string()));
        }
        body_map.insert(
            "contentRef".to_string(),
            Value::String(content_ref.to_string()),
        );
        body_map.insert(
            "mediaType".to_string(),
            Value::String(media_type.to_string()),
        );
        body_map.insert("size".to_string(), json!(content_size as i64));
        body_map.insert("outcome".to_string(), Value::String(outcome.to_string()));
        if let Some(r) = reason.filter(|s| !s.trim().is_empty()) {
            body_map.insert("reason".to_string(), Value::String(r.to_string()));
        }
        if let Some(det) = details {
            let flat = crate::attestation::normalize_a9_details(&det)?;
            if !flat.is_empty() {
                body_map.insert("details".to_string(), Value::Object(flat));
            }
        }

        self.append_workload_record(
            stream_suffix,
            "ToolResult",
            actor,
            session_urn,
            captured_at,
            Value::Object(body_map),
        )
    }

    /// Stores the canonical `tools/list` descriptor bytes in `self.recorder` and appends a signed
    /// `provenance.r5e.io/v2/Observation` (`topic: "mcp_tools_pinned"` or `"mcp_descriptor_rug_pull"`).
    pub fn append_mcp_descriptor_observation(
        &mut self,
        stream_suffix: &str,
        actor: &str,
        session_urn: Option<&str>,
        captured_at: &str,
        server_id: &str,
        obs: &DescriptorObservation,
    ) -> Result<SignedEndpointRecord, String> {
        let stored_ref = self
            .recorder
            .put_blob(&obs.canonical_bytes, Some("application/json"));
        debug_assert_eq!(stored_ref, obs.descriptor_sha256);

        let topic = if obs.rug_pull_detected {
            "mcp_descriptor_rug_pull"
        } else {
            "mcp_tools_pinned"
        };
        let joined_tool_names = crate::attestation::truncate_utf8_bytes(
            &obs.tool_names.join(","),
            crate::attestation::MAX_DETAILS_VALUE_BYTES,
        );
        let bounded_server_id = crate::attestation::truncate_utf8_bytes(
            server_id,
            crate::attestation::MAX_DETAILS_VALUE_BYTES,
        );
        let body = json!({
            "topic": topic,
            "contentRefs": [stored_ref],
            "details": {
                "serverId": bounded_server_id,
                "toolNames": joined_tool_names,
                "toolCount": obs.tool_names.len() as i64,
                "rugPullDetected": obs.rug_pull_detected,
            }
        });
        self.append_workload_record(
            stream_suffix,
            "Observation",
            actor,
            session_urn,
            captured_at,
            body,
        )
    }

    /// Saves the state file with strict `0600` permissions on Unix.
    pub fn save_0600(&self, path: &Path, force: bool) -> Result<(), String> {
        let val = serde_json::to_value(self)
            .map_err(|e| format!("serialize enrolled state JSON: {e}"))?;
        let bytes = encode_canonical_json(&val)?;
        write_secret_file_0600(path, &bytes, force)
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("cannot read state file {}: {e}", path.display()))?;
        let parsed: Self = serde_json::from_str(&raw)
            .map_err(|e| format!("invalid state file JSON in {}: {e}", path.display()))?;
        if parsed.format != ENROLLED_STATE_FORMAT {
            return Err(format!(
                "unsupported state file format {:?} in {}",
                parsed.format,
                path.display()
            ));
        }
        Ok(parsed)
    }
}

pub const OUTBOX_QUEUE_FORMAT: &str = "r5e.endpoint-outbox/v1";
pub const OUTBOX_QUEUE_FILENAME: &str = "outbox-queue.json";

/// Ensures `outbox_dir` exists and carries `0700` owner-only directory permissions on Unix.
pub fn ensure_outbox_dir_0700(outbox_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(outbox_dir).map_err(|e| {
        format!(
            "cannot create outbox directory {}: {e}",
            outbox_dir.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(outbox_dir, fs::Permissions::from_mode(0o700)).map_err(|e| {
            format!(
                "cannot set 0700 permissions on outbox directory {}: {e}",
                outbox_dir.display()
            )
        })?;
    }
    Ok(())
}

/// Durable `0600` offline spool file (`<outbox_dir>/outbox-queue.json`) holding signed workload
/// records, signer keys, and referenced profile/content blobs while the gateway is unreachable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboxQueueFile {
    pub format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_url: Option<String>,
    pub records: Vec<SignedEndpointRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<PublicKeyEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blobs: Vec<BlobEntry>,
}

impl Default for OutboxQueueFile {
    fn default() -> Self {
        Self {
            format: OUTBOX_QUEUE_FORMAT.to_string(),
            gateway_url: None,
            records: Vec::new(),
            keys: Vec::new(),
            blobs: Vec::new(),
        }
    }
}

impl OutboxQueueFile {
    pub fn queue_file_path(outbox_dir: &Path) -> std::path::PathBuf {
        outbox_dir.join(OUTBOX_QUEUE_FILENAME)
    }

    pub fn load_or_empty(outbox_dir: &Path) -> Result<Self, String> {
        Self::load_or_empty_with_key(outbox_dir, None)
    }

    pub fn load_or_empty_with_key(
        outbox_dir: &Path,
        outbox_key: Option<&OutboxKey>,
    ) -> Result<Self, String> {
        let qpath = Self::queue_file_path(outbox_dir);
        if !qpath.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(&qpath)
            .map_err(|e| format!("cannot read outbox file {}: {e}", qpath.display()))?;
        let probe: Value = serde_json::from_str(&raw)
            .map_err(|e| format!("invalid outbox JSON in {}: {e}", qpath.display()))?;
        let fmt_str = probe
            .get("format")
            .and_then(Value::as_str)
            .unwrap_or_default();

        if fmt_str == ENCRYPTED_OUTBOX_QUEUE_FORMAT {
            let Some(key) = outbox_key else {
                return Err(format!(
                    "outbox file {} is encrypted ({ENCRYPTED_OUTBOX_QUEUE_FORMAT}), but no outbox encryption key was provided (pass --outbox-key-file <PATH> or set R5E_OUTBOX_KEY_FILE)",
                    qpath.display()
                ));
            };
            let enc: EncryptedOutboxQueueFile = serde_json::from_str(&raw).map_err(|e| {
                format!("invalid encrypted outbox JSON in {}: {e}", qpath.display())
            })?;
            let (gateway_url, records, keys, blobs) = decrypt_outbox_parts(key, &enc)
                .map_err(|e| format!("cannot decrypt outbox file {}: {e}", qpath.display()))?;
            return Ok(Self {
                format: OUTBOX_QUEUE_FORMAT.to_string(),
                gateway_url,
                records,
                keys,
                blobs,
            });
        }

        if fmt_str == OUTBOX_QUEUE_FORMAT {
            if outbox_key.is_some() {
                return Err(format!(
                    "outbox file {} is unencrypted ({OUTBOX_QUEUE_FORMAT}) while an outbox encryption key was supplied; flush or remove the legacy plaintext outbox before using --outbox-key-file",
                    qpath.display()
                ));
            }
            let parsed: Self = serde_json::from_str(&raw)
                .map_err(|e| format!("invalid outbox JSON in {}: {e}", qpath.display()))?;
            return Ok(parsed);
        }

        Err(format!(
            "unsupported outbox format {:?} in {}",
            fmt_str,
            qpath.display()
        ))
    }

    pub fn save_0600(&self, outbox_dir: &Path) -> Result<(), String> {
        self.save_with_key_0600(outbox_dir, None)
    }

    pub fn save_with_key_0600(
        &self,
        outbox_dir: &Path,
        outbox_key: Option<&OutboxKey>,
    ) -> Result<(), String> {
        ensure_outbox_dir_0700(outbox_dir)?;
        let qpath = Self::queue_file_path(outbox_dir);
        let bytes = if let Some(key) = outbox_key {
            let enc = encrypt_outbox_parts(
                key,
                self.gateway_url.as_deref(),
                &self.records,
                &self.keys,
                &self.blobs,
            )?;
            let val = serde_json::to_value(&enc)
                .map_err(|e| format!("serialize encrypted outbox queue JSON: {e}"))?;
            encode_canonical_json(&val)?
        } else {
            let val = serde_json::to_value(self)
                .map_err(|e| format!("serialize outbox queue JSON: {e}"))?;
            encode_canonical_json(&val)?
        };
        write_secret_file_0600(&qpath, &bytes, true)
    }

    pub fn enqueue_request(&mut self, gateway_url: Option<&str>, req: &ShipRecordsRequest) {
        if let Some(u) = gateway_url.map(str::trim).filter(|s| !s.is_empty()) {
            self.gateway_url = Some(u.to_string());
        }
        for rec in &req.records {
            if !self.records.iter().any(|r| r.record_ref == rec.record_ref) {
                self.records.push(rec.clone());
            }
        }
        for k in &req.keys {
            if !self.keys.iter().any(|ek| ek.keyid == k.keyid) {
                self.keys.push(k.clone());
            }
        }
        for b in &req.blobs {
            if !self.blobs.iter().any(|eb| eb.blob_ref == b.blob_ref) {
                self.blobs.push(b.clone());
            }
        }
    }

    pub fn remove_admitted(&mut self, admitted_refs: &BTreeSet<String>) {
        self.records
            .retain(|r| !admitted_refs.contains(&r.record_ref));
        if self.records.is_empty() {
            self.keys.clear();
            self.blobs.clear();
        }
    }
}

/// Summary returned by [`flush_outbox_over_http`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlushOutboxResult {
    pub pending_before: usize,
    pub pending_after: usize,
    pub flushed: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    pub admitted: Vec<AdmittedRecordReceipt>,
}

/// Flushes pending signed workload records and blobs from `outbox_dir` (`0700` dir, `0600` queue
/// file) to `<gateway_url>/v1/evidence/records` in `<= 64`-record batches, removing each admitted
/// (`"admitted"` / `"already_admitted"`) batch immediately from disk.
pub fn flush_outbox_over_http(
    outbox_dir: &Path,
    gateway_url_override: Option<&str>,
    bearer_token: &str,
    authority: Option<SubmitGrantsRequest>,
) -> Result<FlushOutboxResult, EvidenceHttpError> {
    flush_outbox_over_http_with_key(
        outbox_dir,
        gateway_url_override,
        bearer_token,
        authority,
        None,
    )
}

/// Flushes pending signed workload records and blobs from `outbox_dir` (supporting both legacy
/// plaintext outboxes when `outbox_key` is `None` and `ChaCha20-Poly1305` encrypted outboxes when
/// `outbox_key` is `Some(...)`).
pub fn flush_outbox_over_http_with_key(
    outbox_dir: &Path,
    gateway_url_override: Option<&str>,
    bearer_token: &str,
    authority: Option<SubmitGrantsRequest>,
    outbox_key: Option<&OutboxKey>,
) -> Result<FlushOutboxResult, EvidenceHttpError> {
    ensure_outbox_dir_0700(outbox_dir).map_err(EvidenceHttpError::Validation)?;
    let mut queue = OutboxQueueFile::load_or_empty_with_key(outbox_dir, outbox_key)
        .map_err(EvidenceHttpError::Validation)?;
    let pending_before = queue.records.len();
    if pending_before == 0 {
        queue
            .save_with_key_0600(outbox_dir, outbox_key)
            .map_err(EvidenceHttpError::Validation)?;
        return Ok(FlushOutboxResult {
            pending_before: 0,
            pending_after: 0,
            flushed: 0,
            http_status: None,
            admitted: Vec::new(),
        });
    }

    let effective_gw = gateway_url_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| queue.gateway_url.clone())
        .ok_or_else(|| {
            EvidenceHttpError::Validation(
                "flush-outbox requires --gateway-url (no gateway_url stored in outbox queue)"
                    .to_string(),
            )
        })?;

    let ship_req = ShipRecordsRequest {
        records: queue.records.clone(),
        keys: queue.keys.clone(),
        blobs: queue.blobs.clone(),
        authority,
    };
    let batches = chunk_ship_records_request(&ship_req)?;
    let cfg = EvidenceClientConfig::new(&effective_gw, bearer_token);

    let mut all_admitted = Vec::new();
    let mut any_201 = false;

    for batch in &batches {
        let val = serde_json::to_value(batch)
            .map_err(|e| EvidenceHttpError::Validation(format!("serialize outbox batch: {e}")))?;
        let body_bytes = encode_canonical_json(&val).map_err(|e| {
            EvidenceHttpError::Validation(format!("canonicalize outbox batch: {e}"))
        })?;
        let (status, resp_bytes) = post_json_bearer_http11(&cfg, ADMIT_RECORDS_PATH, &body_bytes)?;
        if status != 201 && status != 200 {
            return Err(classify_evidence_error(status, &resp_bytes, bearer_token));
        }
        if status == 201 {
            any_201 = true;
        }
        let parsed_resp: ShipRecordsResponse =
            serde_json::from_slice(&resp_bytes).map_err(|e| {
                EvidenceHttpError::Transport(format!(
                    "parse {status} outbox ShipRecordsResponse JSON: {e}"
                ))
            })?;
        let batch_admitted_refs: BTreeSet<String> = parsed_resp
            .admitted
            .iter()
            .filter(|a| a.status == "admitted" || a.status == "already_admitted")
            .map(|a| a.record_ref.clone())
            .collect();
        queue.remove_admitted(&batch_admitted_refs);
        queue
            .save_with_key_0600(outbox_dir, outbox_key)
            .map_err(EvidenceHttpError::Validation)?;
        all_admitted.extend(parsed_resp.admitted);
    }

    let pending_after = queue.records.len();
    Ok(FlushOutboxResult {
        pending_before,
        pending_after,
        flushed: pending_before.saturating_sub(pending_after),
        http_status: Some(if any_201 { 201 } else { 200 }),
        admitted: all_admitted,
    })
}

/// Persists `st` (`0600`), optionally queues unshipped workload records into `outbox_dir`
/// (`0700` dir, `0600` file), and optionally ships immediately via `POST /v1/evidence/records`.
///
/// If `ship` fails while `outbox_dir` is `Some(...)`, the signed records remain safely spooled in
/// `outbox_dir` and `Ok(None)` is returned after emitting a redacted diagnostic to `stderr`.
pub fn persist_outbox_and_ship_state(
    st: &mut EnrolledStateFile,
    state_path: &Path,
    outbox_dir: Option<&Path>,
    ship: bool,
    gateway_url_override: Option<&str>,
    bearer_token: Option<&str>,
    authority: Option<SubmitGrantsRequest>,
) -> Result<Option<ShipRecordsResponse>, String> {
    persist_outbox_and_ship_state_with_key(
        st,
        state_path,
        outbox_dir,
        None,
        ship,
        gateway_url_override,
        bearer_token,
        authority,
    )
}

/// Key-aware variant of [`persist_outbox_and_ship_state`]: when `outbox_key` is `Some(...)`,
/// `outbox_dir/outbox-queue.json` is sealed at rest using `ChaCha20-Poly1305` (`r5e.endpoint-outbox-encrypted/v1`).
#[allow(clippy::too_many_arguments)]
pub fn persist_outbox_and_ship_state_with_key(
    st: &mut EnrolledStateFile,
    state_path: &Path,
    outbox_dir: Option<&Path>,
    outbox_key: Option<&OutboxKey>,
    ship: bool,
    gateway_url_override: Option<&str>,
    bearer_token: Option<&str>,
    authority: Option<SubmitGrantsRequest>,
) -> Result<Option<ShipRecordsResponse>, String> {
    st.save_0600(state_path, true)?;

    let skip_set: BTreeSet<String> = st.shipped_record_refs.iter().cloned().collect();
    let mut delta_req = build_ship_request_from_recorder(
        &st.recorder,
        Some(&st.subject_key_id),
        &skip_set,
        true,
        authority,
    )
    .map_err(|e| e.to_string())?;

    if delta_req.records.is_empty() {
        return Ok(None);
    }
    if delta_req.keys.is_empty() {
        if let Ok(sk) = st.signing_key() {
            let pub_bytes = sk.verifying_key().to_bytes();
            delta_req.keys.push(PublicKeyEntry {
                keyid: st.subject_key_id.clone(),
                algorithm: "ed25519".to_string(),
                bytes: BASE64_STANDARD.encode(pub_bytes),
            });
        }
    }

    let effective_gw = gateway_url_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&st.gateway_url)
        .to_string();

    if let Some(dir) = outbox_dir {
        ensure_outbox_dir_0700(dir)?;
        let mut queue = OutboxQueueFile::load_or_empty_with_key(dir, outbox_key)?;
        queue.enqueue_request(Some(&effective_gw), &delta_req);
        queue.save_with_key_0600(dir, outbox_key)?;
    }

    if !ship {
        return Ok(None);
    }

    let token = bearer_token.ok_or_else(|| {
        "shipping requires a bearer token (set --bearer-token-env or --bearer-token-file)"
            .to_string()
    })?;

    match ship_records_over_http(&effective_gw, token, &delta_req) {
        Ok(resp) => {
            let mut admitted_refs = BTreeSet::new();
            for item in &resp.admitted {
                if item.status == "admitted" || item.status == "already_admitted" {
                    admitted_refs.insert(item.record_ref.clone());
                    if !st.shipped_record_refs.iter().any(|r| r == &item.record_ref) {
                        st.shipped_record_refs.push(item.record_ref.clone());
                    }
                }
            }
            st.save_0600(state_path, true)?;
            if let Some(dir) = outbox_dir {
                let mut queue = OutboxQueueFile::load_or_empty_with_key(dir, outbox_key)?;
                queue.remove_admitted(&admitted_refs);
                queue.save_with_key_0600(dir, outbox_key)?;
            }
            Ok(Some(resp))
        }
        Err(err) => {
            if let Some(dir) = outbox_dir {
                eprintln!(
                    "r5e-endpoint-helper: warning: POST /v1/evidence/records failed ({err}); {} signed record(s) queued in outbox {}",
                    delta_req.records.len(),
                    dir.display()
                );
                Ok(None)
            } else {
                Err(format!("POST /v1/evidence/records failed: {err}"))
            }
        }
    }
}

fn map_claim_transport_err(err: ClaimError) -> EvidenceHttpError {
    match err {
        ClaimError::Transport(msg) => EvidenceHttpError::Transport(msg),
        other => EvidenceHttpError::Transport(other.to_string()),
    }
}

fn post_json_bearer_http11(
    cfg: &EvidenceClientConfig,
    path: &str,
    json_body: &[u8],
) -> Result<(u16, Vec<u8>), EvidenceHttpError> {
    if cfg.bearer_token.trim().is_empty() {
        return Err(EvidenceHttpError::Validation(
            "bearer token is empty".to_string(),
        ));
    }
    if cfg.bearer_token.contains('\r') || cfg.bearer_token.contains('\n') {
        return Err(EvidenceHttpError::Validation(
            "bearer token contains illegal CR/LF characters".to_string(),
        ));
    }
    let (connect_addr, host_header, base_path) =
        parse_http_base_url(&cfg.gateway_base_url).map_err(map_claim_transport_err)?;
    let full_path = format!("{base_path}{path}");

    let mut stream = TcpStream::connect(&connect_addr)
        .map_err(|e| EvidenceHttpError::Transport(format!("connect {connect_addr}: {e}")))?;
    let _ = stream.set_read_timeout(Some(cfg.timeout));
    let _ = stream.set_write_timeout(Some(cfg.timeout));

    let req_head = format!(
        "POST {full_path} HTTP/1.1\r\nHost: {host_header}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        cfg.bearer_token,
        json_body.len()
    );

    stream
        .write_all(req_head.as_bytes())
        .and_then(|_| stream.write_all(json_body))
        .and_then(|_| stream.flush())
        .map_err(|e| EvidenceHttpError::Transport(format!("write POST {full_path}: {e}")))?;

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .map_err(|e| EvidenceHttpError::Transport(format!("read status line: {e}")))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| {
            EvidenceHttpError::Transport(format!("malformed HTTP status line: {status_line:?}"))
        })?
        .parse()
        .map_err(|e| EvidenceHttpError::Transport(format!("invalid HTTP status: {e}")))?;

    let mut content_length: Option<usize> = None;
    let mut is_chunked = false;
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| EvidenceHttpError::Transport(format!("read header: {e}")))?;
        let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, val)) = trimmed.split_once(':') {
            let name_lc = name.trim().to_ascii_lowercase();
            let val_trim = val.trim();
            if name_lc == "content-length" {
                content_length = val_trim.parse::<usize>().ok();
            } else if name_lc == "transfer-encoding"
                && val_trim.to_ascii_lowercase().contains("chunked")
            {
                is_chunked = true;
            }
        }
    }

    let body = if is_chunked {
        read_chunked_body(&mut reader).map_err(map_claim_transport_err)?
    } else if let Some(len) = content_length {
        let mut buf = vec![0u8; len];
        reader
            .read_exact(&mut buf)
            .map_err(|e| EvidenceHttpError::Transport(format!("read body ({len}B): {e}")))?;
        buf
    } else {
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .map_err(|e| EvidenceHttpError::Transport(format!("read body EOF: {e}")))?;
        buf
    };

    Ok((status, body))
}
