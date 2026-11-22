//! HTTP/1.1 (`http://` and `https://` via `rustls`) client and offline verifier for the R5E Deployment Claim,
//! Gateway Grant, and Grant Revocation Ceremonies (`A6-claim-exchange.md` & `A6-start-schemas-and-codes.md`):
//! - `GET  /v1/deployment`
//! - `POST /v1/deployment/claim/prepare`
//! - `POST /v1/deployment/claim/finalize`
//! - `POST /v1/deployment/grants`
//! - `POST /v1/deployment/revocations`
//!
//! Enforces strict offline cryptographic and structural verification of `bootstrapKey`,
//! `bootstrapProfile`, `ChainStarted`, the cited `DefinitionPublished` publication, and the
//! prepared `Deployment` draft *before* the claiming root key signs anything, and verifies
//! the 2-signature `Deployment` record and distinct `gatewayKey` upon finalization.

use crate::attestation::{
    base_v2_schema_map, bytes_ref, decode_strict_base64, dsse_pae, ed25519_key_id,
    encode_canonical_json, evidence_ref, generate_os_random_bytes, sign_v2_record_multi, BlobEntry,
    DsseSignature, PublicKeyEntry, SignedEndpointRecord, SubjectPublicKey,
    PROVENANCE_V2_PAYLOAD_TYPE, REVOCATION_SCHEMA_REF,
};
use crate::http_transport::send_http11_request;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

pub const DEPLOYMENT_STATUS_PATH: &str = "/v1/deployment";
pub const PREPARE_CLAIM_PATH: &str = "/v1/deployment/claim/prepare";
pub const FINALIZE_CLAIM_PATH: &str = "/v1/deployment/claim/finalize";
pub const DEPLOYMENT_GRANTS_PATH: &str = "/v1/deployment/grants";
pub const DEPLOYMENT_REVOCATIONS_PATH: &str = "/v1/deployment/revocations";

pub const MAX_REVOCATION_RECORDS: usize = 16;
pub const MAX_REVOCATION_BODY_BYTES: usize = 256 * 1024;

/// Operational guidance surfaced in CLI help and output when revoking grants.
pub const REVOCATION_ROTATION_SAFETY_NOTE: &str = "When rotating gateway grants, submit the replacement grant (grant-gateway) BEFORE revoking the old grant (revoke-grant) unless intentionally stripping all gateway standing.";

/// Default gateway `Endorsement` kinds granted by a root on `POST /v1/deployment/grants`
/// (including `A7` §6.5 retention-stream kinds `RetentionHold`, `RetentionHoldRelease`, and
/// `PayloadDisposition`, plus `A8` §2.2 workload operational kinds `Disclosure` and
/// `Verification` — 16 kinds total).
pub fn default_gateway_grant_kinds() -> Vec<String> {
    vec![
        "provenance.r5e.io/v2/SessionOpened".to_string(),
        "provenance.r5e.io/v2/SessionClosed".to_string(),
        "provenance.r5e.io/v2/PolicyDecision".to_string(),
        "provenance.r5e.io/v2/ToolCall".to_string(),
        "provenance.r5e.io/v2/ToolResult".to_string(),
        "provenance.r5e.io/v2/Observation".to_string(),
        "provenance.r5e.io/v2/ModelCall".to_string(),
        "provenance.r5e.io/v2/ModelResponse".to_string(),
        "provenance.r5e.io/v2/Disclosure".to_string(),
        "provenance.r5e.io/v2/Verification".to_string(),
        "provenance.r5e.io/v2/EpochSeal".to_string(),
        "provenance.r5e.io/v2/Badge".to_string(),
        "provenance.r5e.io/v2/Checkpoint".to_string(),
        "provenance.r5e.io/v2/RetentionHold".to_string(),
        "provenance.r5e.io/v2/RetentionHoldRelease".to_string(),
        "provenance.r5e.io/v2/PayloadDisposition".to_string(),
    ]
}

/// Default operational workload kinds requested during `enrol-badge` (`A8` §2.2 / §4):
/// `SessionOpened`, `SessionClosed`, `PolicyDecision`, `ToolCall`, `ToolResult`,
/// `Observation`, `Disclosure`, and `Verification`.
pub fn default_workload_badge_kinds() -> Vec<String> {
    vec![
        "provenance.r5e.io/v2/SessionOpened".to_string(),
        "provenance.r5e.io/v2/SessionClosed".to_string(),
        "provenance.r5e.io/v2/PolicyDecision".to_string(),
        "provenance.r5e.io/v2/ToolCall".to_string(),
        "provenance.r5e.io/v2/ToolResult".to_string(),
        "provenance.r5e.io/v2/Observation".to_string(),
        "provenance.r5e.io/v2/Disclosure".to_string(),
        "provenance.r5e.io/v2/Verification".to_string(),
    ]
}

#[derive(Debug, Clone)]
pub struct ClaimClientConfig {
    /// Base HTTP URL such as `"http://127.0.0.1:4000"` (optional path prefix supported).
    pub gateway_base_url: String,
    pub timeout: Duration,
}

impl ClaimClientConfig {
    pub fn new(gateway_base_url: impl Into<String>) -> Self {
        Self {
            gateway_base_url: gateway_base_url.into(),
            timeout: Duration::from_secs(15),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimError {
    /// `400` (`malformed_request`)
    BadRequest {
        error_code: Option<String>,
        body: String,
    },
    /// `403` (`wrong_claim_code`)
    Forbidden {
        error_code: Option<String>,
        body: String,
    },
    /// `404` (`evidence_not_recorded_here` or route not mounted yet)
    NotFound {
        error_code: Option<String>,
        body: String,
    },
    /// `409` (`already_claimed`, `not_started`, `not_claimed`, `stream_fork_refused`)
    Conflict {
        error_code: Option<String>,
        body: String,
    },
    /// `413` (`too_large`)
    PayloadTooLarge {
        error_code: Option<String>,
        body: String,
    },
    /// `422` (`claimed_by_is_not_a_root`, `threshold_exceeds_roots`, `duplicate_root`,
    /// `recovery_key_is_a_root`, `unreadable_public_key`, `ticket_does_not_match`,
    /// `ticket_expired`, `bad_signature`, `signature_is_not_the_claimants`, grant findings,
    /// or revocation findings `only_revocations`, `not_entitled`, `unreadable_grant`,
    /// `profile_not_carried`, `stream_not_admissible`)
    Unprocessable {
        error_code: Option<String>,
        body: String,
    },
    /// Other unexpected HTTP status (e.g. `503 deployment_not_claimed`, `500`)
    HttpStatus {
        status: u16,
        error_code: Option<String>,
        body: String,
    },
    /// Local pre-signing or post-finalization cryptographic / bounds refusal
    Validation(String),
    /// Socket, HTTP framing, or JSON parse failure
    Transport(String),
}

impl ClaimError {
    pub fn error_code(&self) -> Option<&str> {
        match self {
            Self::BadRequest { error_code, .. }
            | Self::Forbidden { error_code, .. }
            | Self::NotFound { error_code, .. }
            | Self::Conflict { error_code, .. }
            | Self::PayloadTooLarge { error_code, .. }
            | Self::Unprocessable { error_code, .. }
            | Self::HttpStatus { error_code, .. } => error_code.as_deref(),
            Self::Validation(_) | Self::Transport(_) => None,
        }
    }

    pub fn http_status(&self) -> Option<u16> {
        match self {
            Self::BadRequest { .. } => Some(400),
            Self::Forbidden { .. } => Some(403),
            Self::NotFound { .. } => Some(404),
            Self::Conflict { .. } => Some(409),
            Self::PayloadTooLarge { .. } => Some(413),
            Self::Unprocessable { .. } => Some(422),
            Self::HttpStatus { status, .. } => Some(*status),
            Self::Validation(_) | Self::Transport(_) => None,
        }
    }
}

impl fmt::Display for ClaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadRequest { error_code, body } => {
                write!(f, "bad claim request (400 {:?}): {body}", error_code)
            }
            Self::Forbidden { error_code, body } => {
                write!(f, "claim forbidden (403 {:?}): {body}", error_code)
            }
            Self::NotFound { error_code, body } => {
                write!(f, "claim route not found (404 {:?}): {body}", error_code)
            }
            Self::Conflict { error_code, body } => {
                write!(f, "claim conflict (409 {:?}): {body}", error_code)
            }
            Self::PayloadTooLarge { error_code, body } => {
                write!(f, "payload too large (413 {:?}): {body}", error_code)
            }
            Self::Unprocessable { error_code, body } => {
                write!(f, "unprocessable claim (422 {:?}): {body}", error_code)
            }
            Self::HttpStatus {
                status,
                error_code,
                body,
            } => write!(f, "HTTP {status} ({:?}): {body}", error_code),
            Self::Validation(msg) => write!(f, "claim validation refused: {msg}"),
            Self::Transport(msg) => write!(f, "claim transport error: {msg}"),
        }
    }
}

impl std::error::Error for ClaimError {}

pub fn classify_claim_error(status: u16, body_bytes: &[u8]) -> ClaimError {
    let body = String::from_utf8_lossy(body_bytes).into_owned();
    let error_code = serde_json::from_slice::<Value>(body_bytes)
        .ok()
        .and_then(|v| {
            v.get("error")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        });
    match status {
        400 => ClaimError::BadRequest { error_code, body },
        403 => ClaimError::Forbidden { error_code, body },
        404 => ClaimError::NotFound { error_code, body },
        409 => ClaimError::Conflict { error_code, body },
        413 => ClaimError::PayloadTooLarge { error_code, body },
        422 => ClaimError::Unprocessable { error_code, body },
        other => ClaimError::HttpStatus {
            status: other,
            error_code,
            body,
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeploymentClaimState {
    #[serde(rename = "not_started")]
    NotStarted,
    #[serde(rename = "unclaimed")]
    Unclaimed,
    #[serde(rename = "claimed")]
    Claimed,
}

/// Summary of a held gateway authority grant advertised by `GET /v1/deployment` (`grants`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentGrantSummary {
    #[serde(rename = "ref")]
    pub grant_ref: String,
    pub issuer: String,
    #[serde(rename = "notBefore")]
    pub not_before: String,
    #[serde(rename = "notAfter")]
    pub not_after: String,
    #[serde(default, rename = "mayEndorse")]
    pub may_endorse: bool,
    #[serde(default)]
    pub revoked: bool,
    #[serde(default)]
    pub active: bool,
}

/// Response from `GET /v1/deployment`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentStatusResponse {
    #[serde(default)]
    pub deployment: Option<String>,
    pub state: DeploymentClaimState,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "chainStarted"
    )]
    pub chain_started: Option<SignedEndpointRecord>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "bootstrapKey"
    )]
    pub bootstrap_key: Option<PublicKeyEntry>,
    #[serde(default)]
    pub chain: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "deploymentRecord"
    )]
    pub deployment_record: Option<SignedEndpointRecord>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "gatewayKey"
    )]
    pub gateway_key: Option<PublicKeyEntry>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "streamPrefix"
    )]
    pub stream_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<DeploymentGrantSummary>,
}

/// Root declaration sent in `POST /v1/deployment/claim/prepare`.
///
/// Note (`A6-claim-exchange.md`): `key` is intentionally NOT sent on `prepare`; the gateway
/// derives `key` from `publicKey`, and `verify_and_countersign_prepared_claim` verifies that
/// every `body.roots[i].key` in the prepared `Deployment` matches `ed25519_key_id(publicKey)`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PrepareClaimRootEntry {
    #[serde(rename = "publicKey")]
    pub public_key: SubjectPublicKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
}

/// Custodian quorum member declared in `Deployment`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CustodianEntry {
    pub identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

fn option_slice_is_none_or_empty<T>(val: &Option<Vec<T>>) -> bool {
    val.as_ref().is_none_or(Vec::is_empty)
}

/// Request body for `POST /v1/deployment/claim/prepare`.
///
/// Custom `Debug` implementation redacts `code` so claim codes never appear in debug logs.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrepareClaimRequest {
    pub code: String,
    #[serde(rename = "claimedBy")]
    pub claimed_by: String,
    pub roots: Vec<PrepareClaimRootEntry>,
    pub threshold: usize,
    #[serde(
        default,
        skip_serializing_if = "option_slice_is_none_or_empty",
        rename = "recoveryKeys"
    )]
    pub recovery_keys: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "option_slice_is_none_or_empty")]
    pub custodians: Option<Vec<CustodianEntry>>,
}

impl fmt::Debug for PrepareClaimRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrepareClaimRequest")
            .field("code", &"[REDACTED]")
            .field("claimed_by", &self.claimed_by)
            .field("roots", &self.roots)
            .field("threshold", &self.threshold)
            .field("recovery_keys", &self.recovery_keys)
            .field("custodians", &self.custodians)
            .finish()
    }
}

/// Carried publication set inside `PreparedClaimResponse`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CarriedPublicationSet {
    #[serde(default)]
    pub records: Vec<SignedEndpointRecord>,
    #[serde(default)]
    pub keys: Vec<PublicKeyEntry>,
    #[serde(default)]
    pub blobs: Vec<BlobEntry>,
}

/// Response `200` from `POST /v1/deployment/claim/prepare`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreparedClaimResponse {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub payload: String,
    pub ticket: String,
    pub expires: String,
    #[serde(rename = "chainStarted")]
    pub chain_started: SignedEndpointRecord,
    #[serde(rename = "bootstrapKey")]
    pub bootstrap_key: PublicKeyEntry,
    pub publication: CarriedPublicationSet,
    #[serde(rename = "bootstrapProfile")]
    pub bootstrap_profile: BlobEntry,
}

/// Structured offline inspection summary returned by `verify_and_countersign_prepared_claim`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreparedClaimInspection {
    pub deployment: String,
    #[serde(rename = "startStream")]
    pub start_stream: String,
    #[serde(rename = "chainStartedRef")]
    pub chain_started_ref: String,
    #[serde(rename = "draftDeploymentRef")]
    pub draft_deployment_ref: String,
    #[serde(rename = "bootstrapKeyId")]
    pub bootstrap_key_id: String,
    #[serde(rename = "claimedByKeyId")]
    pub claimed_by_key_id: String,
    #[serde(rename = "publicationRef")]
    pub publication_ref: String,
    #[serde(rename = "publisherKeyId")]
    pub publisher_key_id: String,
    #[serde(rename = "publisherTrusted")]
    pub publisher_trusted: bool,
    #[serde(rename = "definitionCount")]
    pub definition_count: usize,
}

/// Request body for `POST /v1/deployment/claim/finalize`.
///
/// Custom `Debug` implementation redacts `code` so claim codes never appear in debug logs.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalizeClaimRequest {
    pub code: String,
    pub payload: String,
    pub ticket: String,
    #[serde(rename = "rootSignature")]
    pub root_signature: DsseSignature,
}

impl fmt::Debug for FinalizeClaimRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FinalizeClaimRequest")
            .field("code", &"[REDACTED]")
            .field("payload", &self.payload)
            .field("ticket", &self.ticket)
            .field("root_signature", &self.root_signature)
            .finish()
    }
}

/// Result of verifying and countersigning a prepared claim offline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPreparedClaim {
    pub finalize_request: FinalizeClaimRequest,
    pub inspection: PreparedClaimInspection,
}

/// Response `201` (or idempotent `200`) from `POST /v1/deployment/claim/finalize`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalizedClaimResponse {
    #[serde(rename = "deploymentRecord")]
    pub deployment_record: SignedEndpointRecord,
    pub chain: String,
    #[serde(rename = "chainStarted")]
    pub chain_started: SignedEndpointRecord,
    #[serde(rename = "gatewayKey")]
    pub gateway_key: PublicKeyEntry,
    #[serde(rename = "streamPrefix")]
    pub stream_prefix: String,
}

/// Parameters for building a root's gateway `Endorsement` (`POST /v1/deployment/grants`).
#[derive(Debug, Clone)]
pub struct GatewayGrantParams {
    pub gateway_key_id: String,
    /// Deployment stream prefix, e.g. `"urn:r5e:stream:acme-prod:"`.
    pub stream_prefix: String,
    /// Sequence position on `urn:r5e:stream:<deployment>:authority:root:<root_hex>` (default `1`).
    pub seq: u64,
    /// Required when `seq > 1`; must be `None` when `seq == 1`.
    pub previous: Option<String>,
    /// Envelope `actor` (must match `"urn:r5e:"` prefix, e.g. `"urn:r5e:operator:root"`).
    pub actor: String,
    /// Full Provenance v2 kind paths granted to the gateway.
    pub kinds: Vec<String>,
    /// Granted `actorPrefixes` on the `Endorsement` (default `["urn:r5e:"]`).
    pub actor_prefixes: Vec<String>,
    /// Whether the gateway may issue downstream `Badge` / `Endorsement` grants (default `true`).
    pub may_endorse: bool,
    /// Optional fixed timestamp for deterministic testing; defaults to `Utc::now()`.
    pub captured_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Optional explicit RFC 3339 `Endorsement.body.notBefore` override (e.g. `chain_started.capturedAt - 60s`
    /// during root rotation so pre-rotation `EpochSeal` records stay within the new root's grant window).
    /// When `None`, defaults to `now - 60s`.
    pub not_before_override: Option<String>,
    /// Validity window in seconds (`notBefore = not_before_override.unwrap_or(now - 60s)`, `notAfter = now + ttl_seconds`).
    pub ttl_seconds: u64,
}

impl GatewayGrantParams {
    pub fn new(gateway_key_id: impl Into<String>, stream_prefix: impl Into<String>) -> Self {
        Self {
            gateway_key_id: gateway_key_id.into(),
            stream_prefix: stream_prefix.into(),
            seq: 1,
            previous: None,
            actor: "urn:r5e:operator:root".to_string(),
            kinds: default_gateway_grant_kinds(),
            actor_prefixes: vec!["urn:r5e:".to_string()],
            may_endorse: true,
            captured_at: None,
            not_before_override: None,
            ttl_seconds: 86_400 * 30,
        }
    }
}

/// Carried grant set sent to `POST /v1/deployment/grants`.
///
/// Per `A6-claim-exchange.md` ("After Carbon's review"):
/// `blobs` contains ONLY the capture profiles cited by `records` (never extra policy blobs),
/// and `keys` contains ONLY the signers of `records`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubmitGrantsRequest {
    pub records: Vec<SignedEndpointRecord>,
    pub keys: Vec<PublicKeyEntry>,
    pub blobs: Vec<BlobEntry>,
}

/// Output of `build_root_gateway_grant`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltGatewayGrant {
    pub root_key_id: String,
    pub root_stream: String,
    pub root_profile_ref: String,
    pub endorsement: SignedEndpointRecord,
    pub request: SubmitGrantsRequest,
}

/// Parsed response from `POST /v1/deployment/grants` (`201` or idempotent `200`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitGrantsResponse {
    pub status: u16,
    pub recorded_refs: Vec<String>,
    pub raw: Value,
}

/// Parameters for building a `Revocation` (`POST /v1/deployment/revocations`).
#[derive(Debug, Clone)]
pub struct GrantRevocationParams {
    /// `evidence:sha256:...` reference of the `Endorsement` or `Badge` being revoked.
    pub target: String,
    /// Deployment stream prefix, e.g. `"urn:r5e:stream:acme-prod:"`.
    pub stream_prefix: String,
    /// Optional non-empty human-readable reason recorded in `Revocation.body.reason`.
    pub reason: Option<String>,
    /// Optional structured metadata recorded in `Revocation.body.details`.
    pub details: Option<Map<String, Value>>,
    /// Envelope `actor` (must match `"urn:r5e:"` prefix, default `"urn:r5e:operator:root"`).
    pub actor: String,
    /// Optional token suffix for `urn:r5e:stream:<deployment>:authority:revocation:<token>`.
    /// When `None`, a 16-byte OS-random lowercase hex token is generated.
    pub revocation_token: Option<String>,
    /// Optional fixed timestamp for deterministic testing or floor clamping; defaults to `Utc::now()`.
    pub captured_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl GrantRevocationParams {
    pub fn new(target: impl Into<String>, stream_prefix: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            stream_prefix: stream_prefix.into(),
            reason: None,
            details: None,
            actor: "urn:r5e:operator:root".to_string(),
            revocation_token: None,
            captured_at: None,
        }
    }
}

/// Carried revocation set sent to `POST /v1/deployment/revocations` (max 16 records, max 256 KiB).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubmitRevocationsRequest {
    pub records: Vec<SignedEndpointRecord>,
    pub keys: Vec<PublicKeyEntry>,
    pub blobs: Vec<BlobEntry>,
}

/// Output of `build_grant_revocation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltGrantRevocation {
    pub revoker_key_id: String,
    pub revocation_stream: String,
    pub profile_ref: String,
    pub revocation: SignedEndpointRecord,
    pub request: SubmitRevocationsRequest,
}

/// Output of `build_grant_revocations_batch` (`1..=16` `Revocation` records packaged into one
/// `SubmitRevocationsRequest` with deduplicated `keys` and `blobs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltGrantRevocationBatch {
    pub revoker_key_id: String,
    pub items: Vec<BuiltGrantRevocation>,
    pub request: SubmitRevocationsRequest,
}

/// Parsed response from `POST /v1/deployment/revocations` (`201` or idempotent `200`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitRevocationsResponse {
    pub status: u16,
    pub recorded_refs: Vec<String>,
    pub raw: Value,
}

/// Complete outcome of `execute_claim_ceremony`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimCeremonyOutcome {
    pub inspection: PreparedClaimInspection,
    pub finalized: FinalizedClaimResponse,
    pub gateway_grant: Option<(BuiltGatewayGrant, SubmitGrantsResponse)>,
}

/// `GET /v1/deployment` (returns both typed response and raw JSON value so callers can inspect
/// any carried start-stream records such as `deploymentRecord`, `startHead`, or `rootsChanged`).
pub fn get_deployment_status_raw(
    cfg: &ClaimClientConfig,
) -> Result<(DeploymentStatusResponse, Value), ClaimError> {
    let (status, resp_bytes) = request_http11(cfg, "GET", DEPLOYMENT_STATUS_PATH, None)?;
    if status != 200 {
        return Err(classify_claim_error(status, &resp_bytes));
    }
    let raw: Value = serde_json::from_slice(&resp_bytes)
        .map_err(|e| ClaimError::Transport(format!("parse GET /v1/deployment JSON: {e}")))?;
    let parsed: DeploymentStatusResponse = serde_json::from_value(raw.clone())
        .map_err(|e| ClaimError::Transport(format!("parse GET /v1/deployment typed JSON: {e}")))?;
    Ok((parsed, raw))
}

/// `GET /v1/deployment`
pub fn get_deployment_status(
    cfg: &ClaimClientConfig,
) -> Result<DeploymentStatusResponse, ClaimError> {
    get_deployment_status_raw(cfg).map(|(parsed, _)| parsed)
}

/// `POST /v1/deployment/claim/prepare`
pub fn prepare_deployment_claim(
    cfg: &ClaimClientConfig,
    req: &PrepareClaimRequest,
) -> Result<PreparedClaimResponse, ClaimError> {
    let body = serde_json::to_vec(req)
        .map_err(|e| ClaimError::Transport(format!("serialize prepare claim request: {e}")))?;
    let (status, resp_bytes) = request_http11(cfg, "POST", PREPARE_CLAIM_PATH, Some(&body))?;
    if status != 200 {
        return Err(classify_claim_error(status, &resp_bytes));
    }
    serde_json::from_slice(&resp_bytes)
        .map_err(|e| ClaimError::Transport(format!("parse prepare claim 200 JSON: {e}")))
}

/// `POST /v1/deployment/claim/finalize` (without post-finalize verification; prefer
/// `finalize_and_verify_deployment_claim` or `execute_claim_ceremony`).
pub fn finalize_deployment_claim(
    cfg: &ClaimClientConfig,
    req: &FinalizeClaimRequest,
) -> Result<FinalizedClaimResponse, ClaimError> {
    let body = serde_json::to_vec(req)
        .map_err(|e| ClaimError::Transport(format!("serialize finalize claim request: {e}")))?;
    let (status, resp_bytes) = request_http11(cfg, "POST", FINALIZE_CLAIM_PATH, Some(&body))?;
    if status != 201 && status != 200 {
        return Err(classify_claim_error(status, &resp_bytes));
    }
    serde_json::from_slice(&resp_bytes)
        .map_err(|e| ClaimError::Transport(format!("parse finalize claim {status} JSON: {e}")))
}

/// `POST /v1/deployment/claim/finalize` + strict post-finalization verification.
pub fn finalize_and_verify_deployment_claim(
    cfg: &ClaimClientConfig,
    req: &FinalizeClaimRequest,
    expected_bootstrap_key: &PublicKeyEntry,
    expected_chain_started_ref: &str,
) -> Result<FinalizedClaimResponse, ClaimError> {
    let finalized = finalize_deployment_claim(cfg, req)?;
    verify_finalized_claim(
        req,
        expected_bootstrap_key,
        expected_chain_started_ref,
        &finalized,
    )
    .map_err(ClaimError::Validation)?;
    Ok(finalized)
}

/// `POST /v1/deployment/grants`
pub fn submit_deployment_grants(
    cfg: &ClaimClientConfig,
    req: &SubmitGrantsRequest,
) -> Result<SubmitGrantsResponse, ClaimError> {
    let body = encode_canonical_json(
        &serde_json::to_value(req)
            .map_err(|e| ClaimError::Transport(format!("serialize grants request: {e}")))?,
    )
    .map_err(ClaimError::Validation)?;
    let (status, resp_bytes) = request_http11(cfg, "POST", DEPLOYMENT_GRANTS_PATH, Some(&body))?;
    if status != 201 && status != 200 {
        return Err(classify_claim_error(status, &resp_bytes));
    }
    let raw: Value = serde_json::from_slice(&resp_bytes)
        .map_err(|e| ClaimError::Transport(format!("parse grants {status} JSON: {e}")))?;
    let recorded_refs = extract_recorded_refs(&raw);
    Ok(SubmitGrantsResponse {
        status,
        recorded_refs,
        raw,
    })
}

/// `POST /v1/deployment/revocations` (max 16 records, max 256 KiB).
pub fn submit_deployment_revocations(
    cfg: &ClaimClientConfig,
    req: &SubmitRevocationsRequest,
) -> Result<SubmitRevocationsResponse, ClaimError> {
    if req.records.is_empty() {
        return Err(ClaimError::Validation(
            "revocation request must carry at least 1 Revocation record".to_string(),
        ));
    }
    if req.records.len() > MAX_REVOCATION_RECORDS {
        return Err(ClaimError::Validation(format!(
            "revocation request carries {} records (maximum allowed is {MAX_REVOCATION_RECORDS})",
            req.records.len()
        )));
    }
    let body = encode_canonical_json(
        &serde_json::to_value(req)
            .map_err(|e| ClaimError::Transport(format!("serialize revocations request: {e}")))?,
    )
    .map_err(ClaimError::Validation)?;
    if body.len() > MAX_REVOCATION_BODY_BYTES {
        return Err(ClaimError::Validation(format!(
            "revocation request body is {} bytes (maximum allowed is {MAX_REVOCATION_BODY_BYTES})",
            body.len()
        )));
    }
    let (status, resp_bytes) =
        request_http11(cfg, "POST", DEPLOYMENT_REVOCATIONS_PATH, Some(&body))?;
    if status != 201 && status != 200 {
        return Err(classify_claim_error(status, &resp_bytes));
    }
    let raw: Value = if resp_bytes.iter().all(u8::is_ascii_whitespace) {
        json!({})
    } else {
        serde_json::from_slice(&resp_bytes)
            .map_err(|e| ClaimError::Transport(format!("parse revocations {status} JSON: {e}")))?
    };
    let recorded_refs = extract_recorded_refs(&raw);
    Ok(SubmitRevocationsResponse {
        status,
        recorded_refs,
        raw,
    })
}

/// Parses an RFC 3339 `"capturedAt"` timestamp from a signed Provenance v2 record's canonical payload.
pub fn record_captured_at_utc(rec: &SignedEndpointRecord) -> Option<chrono::DateTime<chrono::Utc>> {
    let payload_bytes = decode_strict_base64(&rec.envelope.payload).ok()?;
    let val: Value = serde_json::from_slice(&payload_bytes).ok()?;
    let ts = val.get("capturedAt")?.as_str()?;
    chrono::DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

fn collect_status_captured_at(val: &Value, out: &mut Vec<chrono::DateTime<chrono::Utc>>) {
    match val {
        Value::Object(map) => {
            if let Some(ts) = map.get("capturedAt").and_then(Value::as_str) {
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
                    out.push(dt.with_timezone(&chrono::Utc));
                }
            }
            if let Some(payload_b64) = map
                .get("envelope")
                .and_then(Value::as_object)
                .and_then(|env| env.get("payload"))
                .and_then(Value::as_str)
            {
                if let Ok(payload_bytes) = decode_strict_base64(payload_b64) {
                    if let Ok(payload_val) = serde_json::from_slice::<Value>(&payload_bytes) {
                        if let Some(ts) = payload_val.get("capturedAt").and_then(Value::as_str) {
                            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
                                out.push(dt.with_timezone(&chrono::Utc));
                            }
                        }
                    }
                }
            } else if map.get("payloadType").and_then(Value::as_str)
                == Some(PROVENANCE_V2_PAYLOAD_TYPE)
            {
                if let Some(payload_b64) = map.get("payload").and_then(Value::as_str) {
                    if let Ok(payload_bytes) = decode_strict_base64(payload_b64) {
                        if let Ok(payload_val) = serde_json::from_slice::<Value>(&payload_bytes) {
                            if let Some(ts) = payload_val.get("capturedAt").and_then(Value::as_str)
                            {
                                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
                                    out.push(dt.with_timezone(&chrono::Utc));
                                }
                            }
                        }
                    }
                }
            }
            for child in map.values() {
                collect_status_captured_at(child, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_status_captured_at(item, out);
            }
        }
        _ => {}
    }
}

/// Returns the latest `capturedAt` timestamp across all signed records carried in a raw
/// `GET /v1/deployment` JSON response (`chainStarted`, `deploymentRecord`, `startHead`,
/// `rootsChanged`, etc.) so subsequent authority grants/revocations never predate the
/// active root's `admitted_at`.
pub fn latest_status_captured_at_utc(raw_status: &Value) -> Option<chrono::DateTime<chrono::Utc>> {
    let mut found = Vec::new();
    collect_status_captured_at(raw_status, &mut found);
    found.into_iter().max()
}

/// Rounds `dt` up to the next whole microsecond when sub-microsecond nanoseconds are non-zero,
/// guaranteeing that formatting `max(Utc::now(), ceil_to_micros(floor))` with
/// `SecondsFormat::Micros` never truncates below `floor`.
pub fn ceil_to_micros(dt: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
    let rem_ns = dt.timestamp_subsec_nanos() % 1_000;
    if rem_ns == 0 {
        dt
    } else {
        dt + chrono::Duration::nanoseconds(i64::from(1_000 - rem_ns))
    }
}

pub(crate) fn stream_prefix_from_status(status: &DeploymentStatusResponse) -> Option<String> {
    if let Some(ref sp) = status.stream_prefix {
        return Some(sp.clone());
    }
    if let Some(ref dep) = status.deployment {
        return Some(format!("urn:r5e:stream:{dep}:"));
    }
    if let Some(ref cs) = status.chain_started {
        if let Ok(bytes) = decode_strict_base64(&cs.envelope.payload) {
            if let Ok(val) = serde_json::from_slice::<Value>(&bytes) {
                if let Some(dep) = val
                    .get("body")
                    .and_then(|b| b.get("deployment"))
                    .and_then(Value::as_str)
                {
                    return Some(format!("urn:r5e:stream:{dep}:"));
                }
            }
        }
    }
    None
}

/// Builds, signs, and submits a single `Revocation` (`POST /v1/deployment/revocations`),
/// querying `GET /v1/deployment` to resolve the deployment stream prefix (when not explicitly
/// supplied) and clamping `capturedAt >= ceil_to_micros(latest start head capturedAt)`.
pub fn execute_revoke_grant_ceremony(
    cfg: &ClaimClientConfig,
    signer_key: &SigningKey,
    target_grant_ref: impl Into<String>,
    reason: Option<String>,
    explicit_stream_prefix: Option<String>,
    actor: impl Into<String>,
) -> Result<(BuiltGrantRevocation, SubmitRevocationsResponse), ClaimError> {
    let fetched = if explicit_stream_prefix.is_none() {
        Some(get_deployment_status_raw(cfg)?)
    } else {
        get_deployment_status_raw(cfg).ok()
    };

    let resolved_prefix = match explicit_stream_prefix.or_else(|| {
        fetched
            .as_ref()
            .and_then(|(status, _)| stream_prefix_from_status(status))
    }) {
        Some(sp) => sp,
        None => {
            return Err(ClaimError::Validation(
                "could not determine deployment stream prefix from GET /v1/deployment; pass --deployment <slug> or --stream-prefix <prefix>"
                    .to_string(),
            ));
        }
    };

    let mut params = GrantRevocationParams::new(target_grant_ref, resolved_prefix);
    params.reason = reason;
    params.actor = actor.into();
    if let Some((_, ref raw_status)) = fetched {
        if let Some(admitted_floor) = latest_status_captured_at_utc(raw_status) {
            params.captured_at = Some(std::cmp::max(
                chrono::Utc::now(),
                ceil_to_micros(admitted_floor),
            ));
        }
    }

    let built = build_grant_revocation(signer_key, &params).map_err(ClaimError::Validation)?;
    let resp = submit_deployment_revocations(cfg, &built.request)?;
    Ok((built, resp))
}

/// Selects all unrevoked grant `evidence:sha256:...` references issued by `issuer_key_id` from
/// `GET /v1/deployment`, failing closed when `grants` is absent or when no unrevoked grants match.
pub fn select_unrevoked_grants_by_issuer(
    status: &DeploymentStatusResponse,
    raw_status: Option<&Value>,
    issuer_key_id: &str,
) -> Result<Vec<String>, String> {
    if !is_valid_key_id(issuer_key_id) {
        return Err(format!(
            "invalid --issuer key ID ({issuer_key_id}): expected key:<alg>:sha256:<64-lower-hex>"
        ));
    }
    if let Some(raw) = raw_status {
        if raw.get("grants").is_none() {
            return Err(
                "GET /v1/deployment did not return a 'grants' list (deployment may be unclaimed or gateway predates grant listing); pass --target <evidence:sha256:...> explicitly"
                    .to_string(),
            );
        }
    }
    let unrevoked: Vec<String> = status
        .grants
        .iter()
        .filter(|g| g.issuer == issuer_key_id && !g.revoked)
        .map(|g| g.grant_ref.clone())
        .collect();
    if unrevoked.is_empty() {
        if status
            .grants
            .iter()
            .any(|g| g.issuer == issuer_key_id && g.revoked)
        {
            return Err(format!(
                "all held grants issued by {issuer_key_id} in GET /v1/deployment are already revoked"
            ));
        }
        return Err(format!(
            "no unrevoked grants issued by {issuer_key_id} found in GET /v1/deployment"
        ));
    }
    Ok(unrevoked)
}

/// Queries `GET /v1/deployment`, selects all unrevoked held grants with `grant.issuer == issuer_key_id`
/// (plus any `additional_targets`), builds up to `16` single-record `Revocation` envelopes in one
/// `SubmitRevocationsRequest`, and submits them to `POST /v1/deployment/revocations`.
pub fn execute_revoke_issuer_grants_ceremony(
    cfg: &ClaimClientConfig,
    signer_key: &SigningKey,
    issuer_key_id: &str,
    additional_targets: &[String],
    reason: Option<String>,
    explicit_stream_prefix: Option<String>,
    actor: impl Into<String>,
) -> Result<(BuiltGrantRevocationBatch, SubmitRevocationsResponse), ClaimError> {
    let (status, raw_status) = get_deployment_status_raw(cfg)?;
    let mut targets = select_unrevoked_grants_by_issuer(&status, Some(&raw_status), issuer_key_id)
        .map_err(ClaimError::Validation)?;
    for extra in additional_targets {
        if !targets.iter().any(|t| t == extra) {
            targets.push(extra.clone());
        }
    }

    let resolved_prefix = match explicit_stream_prefix
        .or_else(|| stream_prefix_from_status(&status))
    {
        Some(sp) => sp,
        None => {
            return Err(ClaimError::Validation(
                "could not determine deployment stream prefix from GET /v1/deployment; pass --deployment <slug> or --stream-prefix <prefix>"
                    .to_string(),
            ));
        }
    };

    let captured_at = latest_status_captured_at_utc(&raw_status)
        .map(|floor| std::cmp::max(chrono::Utc::now(), ceil_to_micros(floor)));

    let batch = build_grant_revocations_batch(
        signer_key,
        &targets,
        resolved_prefix,
        reason,
        actor,
        captured_at,
    )
    .map_err(ClaimError::Validation)?;
    let resp = submit_deployment_revocations(cfg, &batch.request)?;
    Ok((batch, resp))
}

/// Runs the complete operator Deployment Claim (& optional Gateway Grant) ceremony against a
/// live gateway, refusing before signing if any offline check fails.
#[allow(clippy::too_many_arguments)]
pub fn execute_claim_ceremony(
    cfg: &ClaimClientConfig,
    claimed_by_signing_key: &SigningKey,
    prepare_req: &PrepareClaimRequest,
    trusted_publishers: &[String],
    allow_untrusted_publisher: bool,
    grant_gateway: bool,
    grant_ttl_seconds: u64,
    grant_actor: &str,
    grant_kinds: Option<Vec<String>>,
) -> Result<ClaimCeremonyOutcome, ClaimError> {
    let prepared = prepare_deployment_claim(cfg, prepare_req)?;
    let verified = verify_and_countersign_prepared_claim(
        claimed_by_signing_key,
        prepare_req,
        &prepared,
        trusted_publishers,
        allow_untrusted_publisher,
    )
    .map_err(ClaimError::Validation)?;

    let finalized = finalize_and_verify_deployment_claim(
        cfg,
        &verified.finalize_request,
        &prepared.bootstrap_key,
        &verified.inspection.chain_started_ref,
    )?;

    let gateway_grant = if grant_gateway {
        let mut params = GatewayGrantParams::new(
            finalized.gateway_key.keyid.clone(),
            finalized.stream_prefix.clone(),
        );
        if let Some(admitted_at) = record_captured_at_utc(&finalized.deployment_record) {
            params.captured_at = Some(std::cmp::max(
                chrono::Utc::now(),
                ceil_to_micros(admitted_at),
            ));
        }
        params.ttl_seconds = grant_ttl_seconds;
        params.actor = grant_actor.to_string();
        if let Some(kinds) = grant_kinds {
            params.kinds = kinds;
        }
        let built = build_root_gateway_grant(claimed_by_signing_key, &params)
            .map_err(ClaimError::Validation)?;
        let resp = submit_deployment_grants(cfg, &built.request)?;
        Some((built, resp))
    } else {
        None
    };

    Ok(ClaimCeremonyOutcome {
        inspection: verified.inspection,
        finalized,
        gateway_grant,
    })
}

/// Performs all 5 offline pre-signing verifications on `PreparedClaimResponse` BEFORE
/// signing `dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, payload_bytes)` as Signer 2 (`claimedBy`).
/// Verifies every offline cryptographic & structural invariant on a gateway-prepared claim
/// (`PreparedClaimResponse`) against `req` and `claiming_root_pubkey` (`ed25519`, `es256`, or `es384`)
/// BEFORE any private or hardware signing occurs, returning `(PreparedClaimInspection, dsse_pae_bytes)`.
pub fn verify_prepared_claim_for_public_signer(
    claiming_root_pubkey: &PublicKeyEntry,
    req: &PrepareClaimRequest,
    prepared: &PreparedClaimResponse,
    trusted_publishers: &[String],
    allow_untrusted_publisher: bool,
) -> Result<(PreparedClaimInspection, Vec<u8>), String> {
    if req.code.is_empty() {
        return Err("claim code must be non-empty".to_string());
    }
    let (_, _, expected_claimed_by_keyid) = parse_and_verify_v2_pubkey(
        &claiming_root_pubkey.algorithm,
        &claiming_root_pubkey.bytes,
        Some(&claiming_root_pubkey.keyid),
        "claiming_root_pubkey",
    )?;
    let expected_claimed_by_b64 = &claiming_root_pubkey.bytes;
    if req.claimed_by != expected_claimed_by_keyid {
        return Err(format!(
            "request claimedBy ({}) does not match local signing key ({expected_claimed_by_keyid})",
            req.claimed_by
        ));
    }
    if req.roots.is_empty() {
        return Err("roots must be non-empty".to_string());
    }
    if req.threshold == 0 || req.threshold > req.roots.len() {
        return Err(format!(
            "invalid threshold {}: must satisfy 1 <= threshold <= roots.len() ({})",
            req.threshold,
            req.roots.len()
        ));
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ExpectedRoot {
        key: String,
        public_key: SubjectPublicKey,
        holder: Option<String>,
        custody: Option<String>,
        identity: Option<String>,
    }

    let mut expected_roots = Vec::with_capacity(req.roots.len());
    let mut expected_root_keys = BTreeSet::new();
    let mut saw_claimed_by_in_roots = false;
    for (idx, r) in req.roots.iter().enumerate() {
        let (_, _, r_keyid) = parse_and_verify_v2_pubkey(
            &r.public_key.algorithm,
            &r.public_key.bytes,
            None,
            &format!("req.roots[{idx}].publicKey"),
        )?;
        if let Some(ref h) = r.holder {
            if !is_valid_slug_token(h, false) {
                return Err(format!("invalid req.roots[{idx}].holder: {h}"));
            }
            if h == "agent" {
                return Err(format!(
                    "invalid_deployment_terms: req.roots[{idx}].holder cannot be \"agent\""
                ));
            }
        }
        if let Some(ref c) = r.custody {
            if !is_valid_slug_token(c, false) {
                return Err(format!("invalid req.roots[{idx}].custody: {c}"));
            }
        }
        if let Some(ref id) = r.identity {
            if !is_valid_uri_identity(id) {
                return Err(format!("invalid req.roots[{idx}].identity URI: {id}"));
            }
        }
        if !expected_root_keys.insert(r_keyid.clone()) {
            return Err(format!("duplicate root key in request: {r_keyid}"));
        }
        if r_keyid == expected_claimed_by_keyid {
            if &r.public_key.bytes != expected_claimed_by_b64 {
                return Err("claiming root publicKey bytes mismatch".to_string());
            }
            saw_claimed_by_in_roots = true;
        }
        expected_roots.push(ExpectedRoot {
            key: r_keyid,
            public_key: r.public_key.clone(),
            holder: r.holder.clone(),
            custody: r.custody.clone(),
            identity: r.identity.clone(),
        });
    }
    if !saw_claimed_by_in_roots {
        return Err(format!(
            "claimedBy ({expected_claimed_by_keyid}) is not listed in req.roots"
        ));
    }

    let expected_recovery_keys: &[String] = req.recovery_keys.as_deref().unwrap_or(&[]);
    let mut expected_rk_set = BTreeSet::new();
    for rk in expected_recovery_keys {
        if !is_valid_key_id(rk) {
            return Err(format!("invalid recoveryKey format: {rk}"));
        }
        if !expected_rk_set.insert(rk.clone()) {
            return Err(format!("duplicate recoveryKey in request: {rk}"));
        }
        if expected_root_keys.contains(rk) {
            return Err(format!(
                "recovery_key_is_a_root: recovery key {rk} also appears in roots"
            ));
        }
    }

    let expected_custodians: &[CustodianEntry] = req.custodians.as_deref().unwrap_or(&[]);
    let mut seen_cust_identities = BTreeSet::new();
    let mut seen_cust_keys = BTreeSet::new();
    for c in expected_custodians {
        if !is_valid_uri_identity(&c.identity) {
            return Err(format!("invalid custodian identity URI: {}", c.identity));
        }
        if !seen_cust_identities.insert(c.identity.clone()) {
            return Err(format!("duplicate custodian identity: {}", c.identity));
        }
        if let Some(ref k) = c.key {
            if !is_valid_key_id(k) {
                return Err(format!("invalid custodian key format: {k}"));
            }
            if !seen_cust_keys.insert(k.clone()) {
                return Err(format!("duplicate custodian key: {k}"));
            }
            if expected_root_keys.contains(k) || expected_rk_set.contains(k) {
                return Err(format!(
                    "invalid_deployment_terms: custodian personal key {k} cannot appear in roots or recoveryKeys"
                ));
            }
        }
    }

    // 1. Verify `bootstrapKey`:
    let (bootstrap_alg, bootstrap_pub_bytes, bootstrap_keyid) = parse_and_verify_v2_pubkey(
        &prepared.bootstrap_key.algorithm,
        &prepared.bootstrap_key.bytes,
        Some(&prepared.bootstrap_key.keyid),
        "prepared.bootstrapKey",
    )?;

    // 2. Verify `bootstrapProfile`:
    if !is_valid_bytes_ref(&prepared.bootstrap_profile.blob_ref) {
        return Err(format!(
            "invalid bootstrapProfile.ref: {}",
            prepared.bootstrap_profile.blob_ref
        ));
    }
    let profile_bytes = decode_strict_base64(&prepared.bootstrap_profile.base64)
        .map_err(|e| format!("invalid bootstrapProfile base64: {e}"))?;
    let actual_profile_ref = bytes_ref(&profile_bytes);
    if actual_profile_ref != prepared.bootstrap_profile.blob_ref {
        return Err(format!(
            "bootstrapProfile digest mismatch: expected {}, got {actual_profile_ref}",
            prepared.bootstrap_profile.blob_ref
        ));
    }
    let profile_val: Value = serde_json::from_slice(&profile_bytes)
        .map_err(|e| format!("bootstrapProfile is not valid JSON: {e}"))?;
    let canonical_profile = encode_canonical_json(&profile_val)
        .map_err(|e| format!("bootstrapProfile fails canonical JSON rules: {e}"))?;
    if canonical_profile != profile_bytes {
        return Err("bootstrapProfile is not canonical JSON (VERIFY-V2 §2.1)".to_string());
    }
    if profile_val.get("format").and_then(Value::as_str) != Some("r5e.capture-profile/v2") {
        return Err(format!(
            "unexpected bootstrapProfile format: {:?}",
            profile_val.get("format")
        ));
    }
    let base_schemas = base_v2_schema_map();
    let expected_cs_schema = base_schemas["provenance.r5e.io/v2/ChainStarted"]
        .as_str()
        .expect("ChainStarted in base_v2_schema_map");
    let expected_dep_schema = base_schemas["provenance.r5e.io/v2/Deployment"]
        .as_str()
        .expect("Deployment in base_v2_schema_map");
    let expected_pub_schema = base_schemas["provenance.r5e.io/v2/DefinitionPublished"]
        .as_str()
        .expect("DefinitionPublished in base_v2_schema_map");

    let profile_schemas = profile_val
        .get("schemas")
        .and_then(Value::as_object)
        .ok_or_else(|| "bootstrapProfile missing schemas object".to_string())?;
    if profile_schemas
        .get("provenance.r5e.io/v2/ChainStarted")
        .and_then(Value::as_str)
        != Some(expected_cs_schema)
    {
        return Err(
            "bootstrapProfile schemas[provenance.r5e.io/v2/ChainStarted] does not match base schema ref"
                .to_string(),
        );
    }
    if profile_schemas
        .get("provenance.r5e.io/v2/Deployment")
        .and_then(Value::as_str)
        != Some(expected_dep_schema)
    {
        return Err(
            "bootstrapProfile schemas[provenance.r5e.io/v2/Deployment] does not match base schema ref"
                .to_string(),
        );
    }

    // 3. Verify `chainStarted` envelope, signature, and body:
    if !is_valid_evidence_ref(&prepared.chain_started.record_ref) {
        return Err(format!(
            "invalid chainStarted.ref: {}",
            prepared.chain_started.record_ref
        ));
    }
    if prepared.chain_started.envelope.payload_type != PROVENANCE_V2_PAYLOAD_TYPE {
        return Err(format!(
            "unexpected chainStarted payloadType: {}",
            prepared.chain_started.envelope.payload_type
        ));
    }
    let cs_payload_bytes = decode_strict_base64(&prepared.chain_started.envelope.payload)
        .map_err(|e| format!("invalid chainStarted payload base64: {e}"))?;
    let actual_cs_ref = evidence_ref(&cs_payload_bytes);
    if actual_cs_ref != prepared.chain_started.record_ref {
        return Err(format!(
            "chainStarted.ref mismatch: declared {}, computed {actual_cs_ref}",
            prepared.chain_started.record_ref
        ));
    }
    let cs_val: Value = serde_json::from_slice(&cs_payload_bytes)
        .map_err(|e| format!("chainStarted payload is not valid JSON: {e}"))?;
    if encode_canonical_json(&cs_val)? != cs_payload_bytes {
        return Err("chainStarted payload is not canonical JSON (VERIFY-V2 §2.1)".to_string());
    }
    if prepared.chain_started.envelope.signatures.len() != 1 {
        return Err(format!(
            "chainStarted must have exactly 1 signature, got {}",
            prepared.chain_started.envelope.signatures.len()
        ));
    }
    let cs_sig_entry = &prepared.chain_started.envelope.signatures[0];
    if cs_sig_entry.keyid != bootstrap_keyid {
        return Err(format!(
            "chainStarted signer keyid ({}) does not match bootstrapKey ({bootstrap_keyid})",
            cs_sig_entry.keyid
        ));
    }
    verify_dsse_v2_sig(
        bootstrap_alg,
        &bootstrap_pub_bytes,
        &cs_payload_bytes,
        &cs_sig_entry.sig,
        "chainStarted signature",
    )?;

    if cs_val.get("apiVersion").and_then(Value::as_str) != Some("provenance.r5e.io/v2")
        || cs_val.get("kind").and_then(Value::as_str) != Some("ChainStarted")
    {
        return Err(format!(
            "chainStarted envelope is not provenance.r5e.io/v2 ChainStarted: {:?}/{:?}",
            cs_val.get("apiVersion"),
            cs_val.get("kind")
        ));
    }
    if cs_val.get("schemaRef").and_then(Value::as_str) != Some(expected_cs_schema) {
        return Err("chainStarted schemaRef does not match base ChainStarted schema".to_string());
    }
    if cs_val.get("profileRef").and_then(Value::as_str)
        != Some(prepared.bootstrap_profile.blob_ref.as_str())
    {
        return Err("chainStarted profileRef does not match bootstrapProfile.ref".to_string());
    }
    if cs_val.get("seq").and_then(Value::as_u64) != Some(1) {
        return Err(format!(
            "chainStarted seq must be 1, got {:?}",
            cs_val.get("seq")
        ));
    }
    if cs_val.get("previous") != Some(&Value::Null) {
        return Err("chainStarted previous must be null".to_string());
    }
    if cs_val.get("issuer").and_then(Value::as_str) != Some(bootstrap_keyid.as_str()) {
        return Err("chainStarted issuer does not match bootstrapKey.keyid".to_string());
    }
    let cs_actor = cs_val
        .get("actor")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "chainStarted missing non-empty actor".to_string())?;
    let cs_captured_at = cs_val
        .get("capturedAt")
        .and_then(Value::as_str)
        .ok_or_else(|| "chainStarted missing capturedAt".to_string())?;
    chrono::DateTime::parse_from_rfc3339(cs_captured_at)
        .map_err(|e| format!("invalid chainStarted capturedAt: {e}"))?;

    let cs_body = cs_val
        .get("body")
        .and_then(Value::as_object)
        .ok_or_else(|| "chainStarted missing body object".to_string())?;
    for k in cs_body.keys() {
        if !matches!(
            k.as_str(),
            "deployment"
                | "bootstrap"
                | "bootstrapKey"
                | "publication"
                | "publisher"
                | "definitions"
                | "details"
        ) {
            return Err(format!("unexpected property in ChainStarted.body: {k}"));
        }
    }
    if cs_body.get("bootstrap").and_then(Value::as_str) != Some(bootstrap_keyid.as_str()) {
        return Err("ChainStarted.body.bootstrap does not match bootstrapKey.keyid".to_string());
    }
    let cs_bkey = cs_body
        .get("bootstrapKey")
        .and_then(Value::as_object)
        .ok_or_else(|| "ChainStarted.body missing bootstrapKey object".to_string())?;
    if cs_bkey.len() != 2
        || cs_bkey.get("algorithm").and_then(Value::as_str)
            != Some(prepared.bootstrap_key.algorithm.as_str())
        || cs_bkey.get("bytes").and_then(Value::as_str)
            != Some(prepared.bootstrap_key.bytes.as_str())
    {
        return Err("ChainStarted.body.bootstrapKey does not match bootstrapKey".to_string());
    }

    let deployment = cs_body
        .get("deployment")
        .and_then(Value::as_str)
        .ok_or_else(|| "ChainStarted.body missing deployment".to_string())?;
    if !is_valid_slug_token(deployment, true) {
        return Err(format!(
            "invalid ChainStarted.body.deployment slug: {deployment:?}"
        ));
    }
    let expected_start_stream = format!("urn:r5e:stream:{deployment}:start");
    let cs_stream = cs_val
        .get("stream")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if cs_stream != expected_start_stream {
        return Err(format!(
            "deployment_stream_mismatch: expected {expected_start_stream}, got {cs_stream}"
        ));
    }
    if !profile_binds_record(&profile_val, cs_stream, cs_actor, &bootstrap_keyid) {
        return Err(
            "bootstrapProfile authority.bindings does not cover chainStarted (stream, actor, issuer)"
                .to_string(),
        );
    }

    let cs_publication_ref = cs_body
        .get("publication")
        .and_then(Value::as_str)
        .ok_or_else(|| "ChainStarted.body missing publication".to_string())?;
    if !is_valid_evidence_ref(cs_publication_ref) {
        return Err(format!(
            "invalid ChainStarted.body.publication ref: {cs_publication_ref}"
        ));
    }
    let cs_publisher = cs_body
        .get("publisher")
        .and_then(Value::as_str)
        .ok_or_else(|| "ChainStarted.body missing publisher".to_string())?;
    if !is_valid_key_id(cs_publisher) {
        return Err(format!(
            "invalid ChainStarted.body.publisher keyid: {cs_publisher}"
        ));
    }

    let cs_defs_arr = cs_body
        .get("definitions")
        .and_then(Value::as_array)
        .ok_or_else(|| "ChainStarted.body missing definitions array".to_string())?;
    let cs_defs = parse_definitions_map(cs_defs_arr, "ChainStarted.body.definitions")?;
    if cs_defs
        .get("provenance.r5e.io/v2/ChainStarted")
        .map(String::as_str)
        != Some(expected_cs_schema)
    {
        return Err(
            "definitions_differ_from_publication: ChainStarted.body.definitions does not map ChainStarted to its schemaRef"
                .to_string(),
        );
    }

    // 4. Verify `publication` (`A6-start-schemas-and-codes.md` §3 + `A9` §4 multi-algorithm & domain rules):
    let matching_pubs: Vec<&SignedEndpointRecord> = prepared
        .publication
        .records
        .iter()
        .filter(|r| r.record_ref == cs_publication_ref)
        .collect();
    if matching_pubs.is_empty() {
        return Err(format!(
            "publication_not_carried: {cs_publication_ref} not present in prepared.publication.records"
        ));
    }
    if matching_pubs.len() > 1 {
        return Err(format!(
            "duplicate DefinitionPublished records for {cs_publication_ref}"
        ));
    }
    let pub_rec = matching_pubs[0];
    if pub_rec.envelope.payload_type != PROVENANCE_V2_PAYLOAD_TYPE {
        return Err(format!(
            "cited_publication_mismatch: unexpected payloadType {}",
            pub_rec.envelope.payload_type
        ));
    }
    let pub_payload_bytes = decode_strict_base64(&pub_rec.envelope.payload).map_err(|e| {
        format!("cited_publication_mismatch: invalid publication payload base64: {e}")
    })?;
    if evidence_ref(&pub_payload_bytes) != pub_rec.record_ref {
        return Err(
            "cited_publication_mismatch: DefinitionPublished ref digest mismatch".to_string(),
        );
    }
    let pub_val: Value = serde_json::from_slice(&pub_payload_bytes)
        .map_err(|e| format!("cited_publication_mismatch: invalid publication JSON: {e}"))?;
    if encode_canonical_json(&pub_val)? != pub_payload_bytes {
        return Err(
            "cited_publication_mismatch: DefinitionPublished payload is not canonical JSON"
                .to_string(),
        );
    }
    if pub_val.get("apiVersion").and_then(Value::as_str) != Some("provenance.r5e.io/v2")
        || pub_val.get("kind").and_then(Value::as_str) != Some("DefinitionPublished")
        || pub_val.get("schemaRef").and_then(Value::as_str) != Some(expected_pub_schema)
    {
        return Err(
            "cited_publication_mismatch: cited record is not a valid provenance.r5e.io/v2 DefinitionPublished"
                .to_string(),
        );
    }
    if pub_val.get("issuer").and_then(Value::as_str) != Some(cs_publisher) {
        return Err(format!(
            "cited_publication_mismatch: DefinitionPublished.issuer ({:?}) != ChainStarted.body.publisher ({cs_publisher})",
            pub_val.get("issuer")
        ));
    }
    if pub_rec.envelope.signatures.len() != 1
        || pub_rec.envelope.signatures[0].keyid != cs_publisher
    {
        return Err(
            "cited_publication_mismatch: DefinitionPublished must carry 1 signature by ChainStarted.body.publisher"
                .to_string(),
        );
    }
    let pub_key_entry = prepared
        .publication
        .keys
        .iter()
        .find(|k| k.keyid == cs_publisher)
        .ok_or_else(|| {
            format!(
                "publication_not_verified: publisher key {cs_publisher} missing from prepared.publication.keys"
            )
        })?;
    let (pub_alg, pub_raw_bytes, _) = parse_and_verify_v2_pubkey(
        &pub_key_entry.algorithm,
        &pub_key_entry.bytes,
        Some(cs_publisher),
        "prepared.publication.keys[publisher]",
    )?;
    verify_dsse_v2_sig(
        pub_alg,
        &pub_raw_bytes,
        &pub_payload_bytes,
        &pub_rec.envelope.signatures[0].sig,
        "cited_publication_mismatch (DefinitionPublished signature)",
    )?;

    let pub_defs_arr = pub_val
        .get("body")
        .and_then(Value::as_object)
        .and_then(|b| b.get("definitions"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            "cited_publication_mismatch: DefinitionPublished missing body.definitions".to_string()
        })?;
    let pub_defs = parse_definitions_map(pub_defs_arr, "DefinitionPublished.body.definitions")?;
    if cs_defs != pub_defs {
        return Err(
            "definitions_differ_from_publication: ChainStarted.body.definitions does not match DefinitionPublished.body.definitions"
                .to_string(),
        );
    }

    let publisher_trusted = if !trusted_publishers.is_empty() {
        if !publisher_covers_all_kinds(trusted_publishers, cs_publisher, cs_defs.keys()) {
            return Err(format!(
                "publisher_not_trusted: ChainStarted publisher {cs_publisher} is not trusted for all published kinds in trusted_publishers"
            ));
        }
        true
    } else if allow_untrusted_publisher {
        false
    } else {
        return Err(format!(
            "publisher_not_trusted: ChainStarted publisher {cs_publisher} is not pinned (pass --trusted-publisher {cs_publisher} or --allow-untrusted-publisher)"
        ));
    };

    // 5. Verify draft `Deployment` payload BEFORE signing:
    if prepared.ticket.is_empty() {
        return Err("prepared claim missing ticket".to_string());
    }
    chrono::DateTime::parse_from_rfc3339(&prepared.expires)
        .map_err(|e| format!("invalid prepared claim expires timestamp: {e}"))?;
    if prepared.payload_type != PROVENANCE_V2_PAYLOAD_TYPE {
        return Err(format!(
            "unexpected prepared claim payloadType: {}",
            prepared.payload_type
        ));
    }
    let payload_bytes = decode_strict_base64(&prepared.payload)
        .map_err(|e| format!("invalid prepared Deployment payload base64: {e}"))?;
    let dep_val: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("prepared Deployment payload is not valid JSON: {e}"))?;
    if encode_canonical_json(&dep_val)? != payload_bytes {
        return Err(
            "prepared Deployment payload is not canonical JSON (VERIFY-V2 §2.1)".to_string(),
        );
    }
    let draft_deployment_ref = evidence_ref(&payload_bytes);

    if dep_val.get("apiVersion").and_then(Value::as_str) != Some("provenance.r5e.io/v2")
        || dep_val.get("kind").and_then(Value::as_str) != Some("Deployment")
    {
        return Err(format!(
            "refusing to co-sign non-Deployment record: {:?}/{:?}",
            dep_val.get("apiVersion"),
            dep_val.get("kind")
        ));
    }
    if dep_val.get("schemaRef").and_then(Value::as_str) != Some(expected_dep_schema) {
        return Err(
            "prepared Deployment schemaRef does not match base Deployment schema".to_string(),
        );
    }
    if let Some(published_dep_schema) = cs_defs.get("provenance.r5e.io/v2/Deployment") {
        if published_dep_schema != expected_dep_schema {
            return Err(
                "published Deployment schemaRef does not match base Deployment schema".to_string(),
            );
        }
    }
    if dep_val.get("profileRef").and_then(Value::as_str)
        != Some(prepared.bootstrap_profile.blob_ref.as_str())
    {
        return Err(
            "prepared Deployment profileRef does not match bootstrapProfile.ref".to_string(),
        );
    }
    if dep_val.get("stream").and_then(Value::as_str) != Some(cs_stream) {
        return Err(format!(
            "prepared Deployment stream ({:?}) does not match ChainStarted stream ({cs_stream})",
            dep_val.get("stream")
        ));
    }
    if dep_val.get("seq").and_then(Value::as_u64) != Some(2) {
        return Err(format!(
            "prepared Deployment seq must be 2, got {:?}",
            dep_val.get("seq")
        ));
    }
    if dep_val.get("previous").and_then(Value::as_str)
        != Some(prepared.chain_started.record_ref.as_str())
    {
        return Err("prepared Deployment previous does not equal chainStarted.ref".to_string());
    }
    if dep_val.get("issuer").and_then(Value::as_str) != Some(bootstrap_keyid.as_str()) {
        return Err("prepared Deployment issuer does not equal bootstrapKey.keyid".to_string());
    }
    let dep_actor = dep_val
        .get("actor")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "prepared Deployment missing non-empty actor".to_string())?;
    let dep_captured_at = dep_val
        .get("capturedAt")
        .and_then(Value::as_str)
        .ok_or_else(|| "prepared Deployment missing capturedAt".to_string())?;
    chrono::DateTime::parse_from_rfc3339(dep_captured_at)
        .map_err(|e| format!("invalid prepared Deployment capturedAt: {e}"))?;
    if !profile_binds_record(&profile_val, cs_stream, dep_actor, &bootstrap_keyid) {
        return Err(
            "bootstrapProfile authority.bindings does not cover prepared Deployment (stream, actor, issuer)"
                .to_string(),
        );
    }

    let dep_body = dep_val
        .get("body")
        .and_then(Value::as_object)
        .ok_or_else(|| "prepared Deployment missing body object".to_string())?;
    for k in dep_body.keys() {
        if !matches!(
            k.as_str(),
            "accepts"
                | "bootstrap"
                | "claimedBy"
                | "roots"
                | "threshold"
                | "recoveryKeys"
                | "custodians"
                | "details"
        ) {
            return Err(format!("unexpected property in Deployment.body: {k}"));
        }
    }
    if dep_body.get("accepts").and_then(Value::as_str)
        != Some(prepared.chain_started.record_ref.as_str())
    {
        return Err(format!(
            "accepts_is_not_chain_started: Deployment.body.accepts ({:?}) != chainStarted.ref ({})",
            dep_body.get("accepts"),
            prepared.chain_started.record_ref
        ));
    }
    if dep_body.get("bootstrap").and_then(Value::as_str) != Some(bootstrap_keyid.as_str()) {
        return Err("Deployment.body.bootstrap does not match bootstrapKey.keyid".to_string());
    }
    if dep_body.get("claimedBy").and_then(Value::as_str) != Some(expected_claimed_by_keyid.as_str())
    {
        return Err(format!(
            "Deployment.body.claimedBy ({:?}) does not match local claiming root ({expected_claimed_by_keyid})",
            dep_body.get("claimedBy")
        ));
    }
    let actual_threshold = dep_body
        .get("threshold")
        .and_then(Value::as_u64)
        .ok_or_else(|| "Deployment.body missing integer threshold".to_string())?;
    if actual_threshold != req.threshold as u64 {
        return Err(format!(
            "Deployment.body.threshold mismatch: requested {}, got {actual_threshold}",
            req.threshold
        ));
    }

    let actual_roots_arr = dep_body
        .get("roots")
        .and_then(Value::as_array)
        .ok_or_else(|| "Deployment.body missing roots array".to_string())?;
    if actual_roots_arr.len() != expected_roots.len() {
        return Err(format!(
            "Deployment.body.roots length mismatch: requested {}, got {}",
            expected_roots.len(),
            actual_roots_arr.len()
        ));
    }
    let mut actual_roots = Vec::with_capacity(actual_roots_arr.len());
    let mut seen_actual_root_keys = BTreeSet::new();
    for (idx, item) in actual_roots_arr.iter().enumerate() {
        let obj = item
            .as_object()
            .ok_or_else(|| format!("Deployment.body.roots[{idx}] is not an object"))?;
        for k in obj.keys() {
            if !matches!(
                k.as_str(),
                "key" | "publicKey" | "holder" | "custody" | "identity"
            ) {
                return Err(format!(
                    "unexpected property in Deployment.body.roots[{idx}]: {k}"
                ));
            }
        }
        let key_str = obj
            .get("key")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("Deployment.body.roots[{idx}] missing key"))?;
        let pk_obj = obj
            .get("publicKey")
            .and_then(Value::as_object)
            .ok_or_else(|| format!("Deployment.body.roots[{idx}] missing publicKey"))?;
        if pk_obj.len() != 2 {
            return Err(format!(
                "Deployment.body.roots[{idx}].publicKey has unexpected fields"
            ));
        }
        let alg = pk_obj
            .get("algorithm")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let bytes = pk_obj
            .get("bytes")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let (_, _, derived_key) = parse_and_verify_v2_pubkey(
            alg,
            bytes,
            Some(key_str),
            &format!("Deployment.body.roots[{idx}]"),
        )?;
        if !seen_actual_root_keys.insert(derived_key.clone()) {
            return Err(format!(
                "duplicate root key in Deployment.body.roots: {derived_key}"
            ));
        }
        let holder = extract_optional_str(obj, "holder", &format!("roots[{idx}].holder"))?;
        let custody = extract_optional_str(obj, "custody", &format!("roots[{idx}].custody"))?;
        let identity = extract_optional_str(obj, "identity", &format!("roots[{idx}].identity"))?;
        actual_roots.push(ExpectedRoot {
            key: derived_key,
            public_key: SubjectPublicKey {
                algorithm: alg.to_string(),
                bytes: bytes.to_string(),
            },
            holder,
            custody,
            identity,
        });
    }
    let mut actual_roots_sorted = actual_roots;
    actual_roots_sorted.sort_by(|a, b| a.key.cmp(&b.key));
    let mut expected_roots_sorted = expected_roots;
    expected_roots_sorted.sort_by(|a, b| a.key.cmp(&b.key));
    if actual_roots_sorted != expected_roots_sorted {
        return Err(
            "Deployment.body.roots does not match requested roots and attributes".to_string(),
        );
    }

    // Verify `recoveryKeys`:
    if expected_recovery_keys.is_empty() {
        if dep_body.contains_key("recoveryKeys") {
            return Err(
                "Deployment.body includes unrequested recoveryKeys when none were requested"
                    .to_string(),
            );
        }
    } else {
        let rk_arr = dep_body
            .get("recoveryKeys")
            .and_then(Value::as_array)
            .ok_or_else(|| "Deployment.body missing requested recoveryKeys array".to_string())?;
        if rk_arr.len() != expected_recovery_keys.len() {
            return Err(format!(
                "Deployment.body.recoveryKeys length mismatch: requested {}, got {}",
                expected_recovery_keys.len(),
                rk_arr.len()
            ));
        }
        let mut actual_rk_set = BTreeSet::new();
        for item in rk_arr {
            let s = item
                .as_str()
                .ok_or_else(|| "Deployment.body.recoveryKeys contains non-string".to_string())?;
            if seen_actual_root_keys.contains(s) {
                return Err(format!(
                    "Deployment.body.recoveryKeys overlaps root key {s}"
                ));
            }
            if !actual_rk_set.insert(s.to_string()) {
                return Err(format!(
                    "duplicate key in Deployment.body.recoveryKeys: {s}"
                ));
            }
        }
        if actual_rk_set != expected_rk_set {
            return Err(
                "Deployment.body.recoveryKeys does not match requested recoveryKeys".to_string(),
            );
        }
    }

    // Verify `custodians`:
    if expected_custodians.is_empty() {
        if dep_body.contains_key("custodians") {
            return Err(
                "Deployment.body includes unrequested custodians when none were requested"
                    .to_string(),
            );
        }
    } else {
        let cust_arr = dep_body
            .get("custodians")
            .and_then(Value::as_array)
            .ok_or_else(|| "Deployment.body missing requested custodians array".to_string())?;
        if cust_arr.len() != expected_custodians.len() {
            return Err(format!(
                "Deployment.body.custodians length mismatch: requested {}, got {}",
                expected_custodians.len(),
                cust_arr.len()
            ));
        }
        let mut actual_custs = Vec::with_capacity(cust_arr.len());
        let mut actual_cust_ids = BTreeSet::new();
        let mut actual_cust_keys = BTreeSet::new();
        for (idx, item) in cust_arr.iter().enumerate() {
            let obj = item
                .as_object()
                .ok_or_else(|| format!("Deployment.body.custodians[{idx}] is not an object"))?;
            for k in obj.keys() {
                if !matches!(k.as_str(), "identity" | "key") {
                    return Err(format!(
                        "unexpected property in Deployment.body.custodians[{idx}]: {k}"
                    ));
                }
            }
            let identity = obj
                .get("identity")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("Deployment.body.custodians[{idx}] missing identity"))?
                .to_string();
            if !actual_cust_ids.insert(identity.clone()) {
                return Err(format!(
                    "duplicate identity in Deployment.body.custodians: {identity}"
                ));
            }
            let key = extract_optional_str(obj, "key", &format!("custodians[{idx}].key"))?;
            if let Some(ref k) = key {
                if !actual_cust_keys.insert(k.clone()) {
                    return Err(format!("duplicate key in Deployment.body.custodians: {k}"));
                }
            }
            actual_custs.push(CustodianEntry { identity, key });
        }
        actual_custs.sort_by(|a, b| a.identity.cmp(&b.identity));
        let mut expected_custs_sorted = expected_custodians.to_vec();
        expected_custs_sorted.sort_by(|a, b| a.identity.cmp(&b.identity));
        if actual_custs != expected_custs_sorted {
            return Err(
                "Deployment.body.custodians does not match requested custodians".to_string(),
            );
        }
    }

    let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &payload_bytes);
    let inspection = PreparedClaimInspection {
        deployment: deployment.to_string(),
        start_stream: expected_start_stream,
        chain_started_ref: prepared.chain_started.record_ref.clone(),
        draft_deployment_ref,
        bootstrap_key_id: bootstrap_keyid,
        claimed_by_key_id: expected_claimed_by_keyid,
        publication_ref: cs_publication_ref.to_string(),
        publisher_key_id: cs_publisher.to_string(),
        publisher_trusted,
        definition_count: cs_defs.len(),
    };
    Ok((inspection, pae))
}

pub fn verify_and_countersign_prepared_claim(
    claimed_by_signing_key: &SigningKey,
    req: &PrepareClaimRequest,
    prepared: &PreparedClaimResponse,
    trusted_publishers: &[String],
    allow_untrusted_publisher: bool,
) -> Result<VerifiedPreparedClaim, String> {
    let pub_bytes = claimed_by_signing_key.verifying_key().to_bytes();
    let pub_entry = PublicKeyEntry {
        keyid: ed25519_key_id(&pub_bytes),
        algorithm: "ed25519".to_string(),
        bytes: BASE64_STANDARD.encode(pub_bytes),
    };
    let (inspection, pae) = verify_prepared_claim_for_public_signer(
        &pub_entry,
        req,
        prepared,
        trusted_publishers,
        allow_untrusted_publisher,
    )?;
    let sig = claimed_by_signing_key.sign(&pae);
    let finalize_request = FinalizeClaimRequest {
        code: req.code.clone(),
        payload: prepared.payload.clone(),
        ticket: prepared.ticket.clone(),
        root_signature: DsseSignature {
            keyid: inspection.claimed_by_key_id.clone(),
            sig: BASE64_STANDARD.encode(sig.to_bytes()),
        },
    };
    Ok(VerifiedPreparedClaim {
        finalize_request,
        inspection,
    })
}

/// Attaches and cryptographically verifies an external detached signature (supporting `Ed25519`,
/// `ES256`, and `ES384`, including PKCS#11 / PIV / OpenSSL ASN.1 DER `ECDSA-Sig-Value` with automatic
/// `s > floor(n / 2)` -> `n - s` low-`S` normalization) onto a verified `PreparedClaimResponse`.
pub fn attach_external_claim_signature(
    claiming_root_pubkey: &PublicKeyEntry,
    req: &PrepareClaimRequest,
    prepared: &PreparedClaimResponse,
    trusted_publishers: &[String],
    allow_untrusted_publisher: bool,
    signature_input: &[u8],
    is_base64_flag: bool,
) -> Result<VerifiedPreparedClaim, String> {
    let (verified, _) = attach_external_claim_signature_with_meta(
        claiming_root_pubkey,
        req,
        prepared,
        trusted_publishers,
        allow_untrusted_publisher,
        signature_input,
        is_base64_flag,
    )?;
    Ok(verified)
}

/// Like [`attach_external_claim_signature`], also returning whether an ASN.1 DER or high-`S`
/// ECDSA signature was normalized to canonical low-`S` `r || s`.
pub fn attach_external_claim_signature_with_meta(
    claiming_root_pubkey: &PublicKeyEntry,
    req: &PrepareClaimRequest,
    prepared: &PreparedClaimResponse,
    trusted_publishers: &[String],
    allow_untrusted_publisher: bool,
    signature_input: &[u8],
    is_base64_flag: bool,
) -> Result<(VerifiedPreparedClaim, bool), String> {
    let (alg, pub_bytes, claimed_by_keyid) = parse_and_verify_v2_pubkey(
        &claiming_root_pubkey.algorithm,
        &claiming_root_pubkey.bytes,
        Some(&claiming_root_pubkey.keyid),
        "claiming_root_pubkey",
    )?;
    let (inspection, pae) = verify_prepared_claim_for_public_signer(
        claiming_root_pubkey,
        req,
        prepared,
        trusted_publishers,
        allow_untrusted_publisher,
    )?;

    let (canonical_sig, was_normalized) = if is_base64_flag {
        let sig_str = std::str::from_utf8(signature_input)
            .map_err(|_| "--signature-b64 is not valid UTF-8".to_string())?;
        let clean: String = sig_str.chars().filter(|c| !c.is_whitespace()).collect();
        let raw_sig = BASE64_STANDARD
            .decode(&clean)
            .map_err(|e| format!("invalid --signature-b64 base64: {e}"))?;
        crate::crypto_keys::normalize_signature_bytes(alg, &raw_sig, Some((&pub_bytes, &pae)))?
    } else {
        crate::crypto_keys::parse_external_signature_bytes(
            alg,
            signature_input,
            Some((&pub_bytes, &pae)),
            "--signature-file",
        )?
    };

    crate::crypto_keys::verify_signature(alg, &pub_bytes, &pae, &canonical_sig)?;

    let finalize_request = FinalizeClaimRequest {
        code: req.code.clone(),
        payload: prepared.payload.clone(),
        ticket: prepared.ticket.clone(),
        root_signature: DsseSignature {
            keyid: claimed_by_keyid,
            sig: BASE64_STANDARD.encode(&canonical_sig),
        },
    };
    Ok((
        VerifiedPreparedClaim {
            finalize_request,
            inspection,
        },
        was_normalized,
    ))
}

/// Verifies the `FinalizedClaimResponse` returned by `POST /v1/deployment/claim/finalize`:
/// - `deploymentRecord.envelope.payload == req.payload`
/// - `deploymentRecord.ref == finalized.chain == evidence_ref(payload_bytes)`
/// - `deploymentRecord` carries exactly `[bootstrap_signature, req.root_signature]`, both cryptographically valid
/// - `gatewayKey` is a valid Provenance v2 public key distinct from `bootstrapKey`.
pub fn verify_finalized_claim(
    req: &FinalizeClaimRequest,
    expected_bootstrap_key: &PublicKeyEntry,
    expected_chain_started_ref: &str,
    finalized: &FinalizedClaimResponse,
) -> Result<(), String> {
    let (bootstrap_alg, bootstrap_pub_bytes, bootstrap_keyid) = parse_and_verify_v2_pubkey(
        &expected_bootstrap_key.algorithm,
        &expected_bootstrap_key.bytes,
        Some(&expected_bootstrap_key.keyid),
        "expected_bootstrap_key",
    )?;

    if finalized.deployment_record.envelope.payload_type != PROVENANCE_V2_PAYLOAD_TYPE {
        return Err(format!(
            "unexpected finalized deploymentRecord payloadType: {}",
            finalized.deployment_record.envelope.payload_type
        ));
    }
    if finalized.deployment_record.envelope.payload != req.payload {
        return Err("gateway altered Deployment payload in finalize response".to_string());
    }
    let payload_bytes = decode_strict_base64(&req.payload)
        .map_err(|e| format!("invalid finalize payload base64: {e}"))?;
    let expected_ref = evidence_ref(&payload_bytes);
    if finalized.deployment_record.record_ref != expected_ref {
        return Err(format!(
            "finalized deploymentRecord.ref ({}) != computed ref ({expected_ref})",
            finalized.deployment_record.record_ref
        ));
    }
    if finalized.chain != expected_ref {
        return Err(format!(
            "finalized chain ({}) != deploymentRecord.ref ({expected_ref})",
            finalized.chain
        ));
    }
    if finalized.chain_started.record_ref != expected_chain_started_ref {
        return Err(format!(
            "finalized chainStarted.ref ({}) != prepared chainStarted.ref ({expected_chain_started_ref})",
            finalized.chain_started.record_ref
        ));
    }

    let sigs = &finalized.deployment_record.envelope.signatures;
    if sigs.len() != 2 {
        return Err(format!(
            "finalized Deployment must carry exactly 2 signatures, got {}",
            sigs.len()
        ));
    }
    if sigs[0].keyid != bootstrap_keyid {
        return Err(format!(
            "finalized Deployment signatures[0].keyid ({}) != bootstrapKey ({bootstrap_keyid})",
            sigs[0].keyid
        ));
    }
    verify_dsse_v2_sig(
        bootstrap_alg,
        &bootstrap_pub_bytes,
        &payload_bytes,
        &sigs[0].sig,
        "finalized Deployment bootstrap signature (signatures[0])",
    )?;
    if sigs[1] != req.root_signature {
        return Err(
            "finalized Deployment signatures[1] does not match submitted rootSignature".to_string(),
        );
    }

    let (_, _, gw_keyid) = parse_and_verify_v2_pubkey(
        &finalized.gateway_key.algorithm,
        &finalized.gateway_key.bytes,
        Some(&finalized.gateway_key.keyid),
        "finalized.gatewayKey",
    )?;
    if gw_keyid == bootstrap_keyid {
        return Err(
            "finalized gatewayKey must be distinct from single-use bootstrapKey".to_string(),
        );
    }
    if !finalized.stream_prefix.starts_with("urn:r5e:stream:")
        || !finalized.stream_prefix.ends_with(':')
    {
        return Err(format!(
            "unexpected finalized streamPrefix: {}",
            finalized.stream_prefix
        ));
    }

    Ok(())
}

/// Builds a root-signed gateway `Endorsement` on stream
/// `urn:r5e:stream:<deployment>:authority:root:<root_hex>` and packages the exact
/// `SubmitGrantsRequest` for `POST /v1/deployment/grants` (carrying ONLY `[root_profile_blob]`
/// in `blobs` and `[root_public_key]` in `keys`).
pub fn build_root_gateway_grant(
    root_signing_key: &SigningKey,
    params: &GatewayGrantParams,
) -> Result<BuiltGatewayGrant, String> {
    let root_pub_bytes = root_signing_key.verifying_key().to_bytes();
    let root_key_id = ed25519_key_id(&root_pub_bytes);
    let root_pub_b64 = BASE64_STANDARD.encode(root_pub_bytes);
    let root_hex = crate::crypto_keys::key_id_sha256_hex(&root_key_id)?;

    if !is_valid_key_id(&params.gateway_key_id) {
        return Err(format!("invalid gatewayKeyId: {}", params.gateway_key_id));
    }
    if params.gateway_key_id == root_key_id {
        return Err("gatewayKeyId must be distinct from rootKeyId".to_string());
    }
    if params.seq == 0 {
        return Err("grant seq must be >= 1".to_string());
    }
    if params.seq == 1 && params.previous.is_some() {
        return Err("grant seq 1 must have previous = null".to_string());
    }
    if params.seq > 1 && params.previous.is_none() {
        return Err("grant seq > 1 requires previous evidence:sha256:... reference".to_string());
    }
    if let Some(ref prev) = params.previous {
        if !is_valid_evidence_ref(prev) {
            return Err(format!("invalid grant previous reference: {prev}"));
        }
    }
    if params.kinds.is_empty() {
        return Err("gateway grant kinds must be non-empty".to_string());
    }
    for k in &params.kinds {
        if !is_valid_kind_path(k) {
            return Err(format!("invalid kind path in gateway grant: {k}"));
        }
    }
    if params.actor_prefixes.is_empty() {
        return Err("gateway grant actorPrefixes must be non-empty".to_string());
    }
    if !params.actor.starts_with("urn:r5e:") {
        return Err(format!(
            "grant actor ({}) must start with 'urn:r5e:' to match root profile authority binding",
            params.actor
        ));
    }
    if params.ttl_seconds == 0 {
        return Err("grant ttl_seconds must be > 0".to_string());
    }

    let mut normalized_prefix = params.stream_prefix.clone();
    if !normalized_prefix.ends_with(':') {
        normalized_prefix.push(':');
    }
    if !normalized_prefix.starts_with("urn:r5e:stream:") {
        return Err(format!(
            "grant stream_prefix ({normalized_prefix}) must start with 'urn:r5e:stream:'"
        ));
    }

    let root_stream = format!("{normalized_prefix}authority:root:{root_hex}");
    let schemas = base_v2_schema_map();
    let endorsement_schema = schemas["provenance.r5e.io/v2/Endorsement"]
        .as_str()
        .expect("Endorsement in base_v2_schema_map")
        .to_string();

    let policy_ref = bytes_ref(b"permit(principal, action, resource);");
    let root_profile_doc = json!({
        "format": "r5e.capture-profile/v2",
        "schemas": Value::Object(schemas),
        "authority": {
            "bindings": [
                {
                    "streamPrefix": &root_stream,
                    "actorPrefixes": ["urn:r5e:"],
                    "issuerKeys": [&root_key_id],
                    "sealerKeys": [&params.gateway_key_id],
                }
            ],
            "checkpointKeys": [],
        },
        "durability": {
            "failureDomain": "offline-operator-root",
            "onFailure": "refuse",
            "requiredPayloads": "submitted",
        },
        "policyRequiredKinds": [],
        "deploymentPolicyRef": &policy_ref,
    });
    let root_profile_bytes = encode_canonical_json(&root_profile_doc)?;
    let root_profile_ref = bytes_ref(&root_profile_bytes);

    let now = params.captured_at.unwrap_or_else(chrono::Utc::now);
    let captured_at = now.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let not_after = (now + chrono::Duration::seconds(params.ttl_seconds as i64))
        .to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let not_after_utc = chrono::DateTime::parse_from_rfc3339(&not_after)
        .expect("serialized not_after RFC3339")
        .with_timezone(&chrono::Utc);
    let not_before = if let Some(ref nb) = params.not_before_override {
        if nb.ends_with("-00:00") {
            return Err(format!(
                "invalid grant notBefore ({nb}): unknown -00:00 offset is outside Provenance v2 Timestamp profile"
            ));
        }
        let parsed_nb = chrono::DateTime::parse_from_rfc3339(nb)
            .map_err(|e| format!("invalid grant notBefore RFC3339 timestamp ({nb}): {e}"))?
            .with_timezone(&chrono::Utc);
        if parsed_nb > not_after_utc {
            return Err(format!(
                "grant notBefore ({nb}) must be <= notAfter ({not_after})"
            ));
        }
        nb.clone()
    } else {
        (now - chrono::Duration::seconds(60)).to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
    };

    let prev_val = match &params.previous {
        Some(p) => Value::String(p.clone()),
        None => Value::Null,
    };

    let mut unique_kinds = Vec::with_capacity(params.kinds.len());
    for k in &params.kinds {
        if !unique_kinds.contains(k) {
            unique_kinds.push(k.clone());
        }
    }
    let mut unique_actor_prefixes = Vec::with_capacity(params.actor_prefixes.len());
    for ap in &params.actor_prefixes {
        if !unique_actor_prefixes.contains(ap) {
            unique_actor_prefixes.push(ap.clone());
        }
    }

    let endorsement = sign_v2_record_multi(
        &[root_signing_key],
        json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": &endorsement_schema,
            "profileRef": &root_profile_ref,
            "stream": &root_stream,
            "seq": params.seq,
            "previous": prev_val,
            "actor": &params.actor,
            "capturedAt": &captured_at,
            "body": {
                "subject": &params.gateway_key_id,
                "kinds": &unique_kinds,
                "streamPrefixes": [&normalized_prefix],
                "actorPrefixes": &unique_actor_prefixes,
                "mayEndorse": params.may_endorse,
                "notBefore": &not_before,
                "notAfter": &not_after,
            }
        })
        .as_object()
        .expect("Endorsement envelope object")
        .clone(),
    )?;

    let request = SubmitGrantsRequest {
        records: vec![endorsement.clone()],
        keys: vec![PublicKeyEntry {
            keyid: root_key_id.clone(),
            algorithm: "ed25519".to_string(),
            bytes: root_pub_b64,
        }],
        blobs: vec![BlobEntry {
            blob_ref: root_profile_ref.clone(),
            media_type: Some("application/json".to_string()),
            base64: BASE64_STANDARD.encode(&root_profile_bytes),
        }],
    };

    Ok(BuiltGatewayGrant {
        root_key_id,
        root_stream,
        root_profile_ref,
        endorsement,
        request,
    })
}

/// Builds a signed `Revocation` (`provenance.r5e.io/v2/Revocation`) sitting alone at `seq: 1`
/// (`previous: null`) on a unique stream `urn:r5e:stream:<deployment>:authority:revocation:<token>`,
/// under a self-describing operator capture profile whose `streamPrefix` is that exact revocation
/// stream URI and `issuerKeys` is `[revoker_keyid]`, and packages `SubmitRevocationsRequest` for
/// `POST /v1/deployment/revocations`.
pub fn build_grant_revocation(
    signer_key: &SigningKey,
    params: &GrantRevocationParams,
) -> Result<BuiltGrantRevocation, String> {
    let revoker_pub_bytes = signer_key.verifying_key().to_bytes();
    let revoker_key_id = ed25519_key_id(&revoker_pub_bytes);
    let revoker_pub_b64 = BASE64_STANDARD.encode(revoker_pub_bytes);

    if !is_valid_evidence_ref(&params.target) {
        return Err(format!(
            "invalid revocation target ({}): expected evidence:sha256:<64-lower-hex>",
            params.target
        ));
    }
    if let Some(ref reason) = params.reason {
        if reason.trim().is_empty() {
            return Err("revocation reason must be non-empty when provided".to_string());
        }
    }
    if !params.actor.starts_with("urn:r5e:") {
        return Err(format!(
            "revocation actor ({}) must start with 'urn:r5e:' to match capture profile authority binding",
            params.actor
        ));
    }

    let mut normalized_prefix = params.stream_prefix.clone();
    if !normalized_prefix.ends_with(':') {
        normalized_prefix.push(':');
    }
    let Some(after_scheme) = normalized_prefix.strip_prefix("urn:r5e:stream:") else {
        return Err(format!(
            "revocation stream_prefix ({normalized_prefix}) must start with 'urn:r5e:stream:'"
        ));
    };
    let dep_segment = after_scheme.trim_end_matches(':');
    if dep_segment.is_empty()
        || dep_segment.contains(':')
        || !is_valid_slug_token(dep_segment, true)
    {
        return Err(format!(
            "revocation stream_prefix ({normalized_prefix}) must have format 'urn:r5e:stream:<deployment>:'"
        ));
    }

    let token = if let Some(ref explicit_tok) = params.revocation_token {
        if explicit_tok.is_empty()
            || !explicit_tok
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(format!(
                "invalid revocation_token {explicit_tok:?}: must be non-empty ASCII alphanumeric, '-' or '_'"
            ));
        }
        explicit_tok.clone()
    } else {
        let rand_bytes = generate_os_random_bytes::<16>()?;
        crate::policy_gate::hex_lower(&rand_bytes)
    };

    let revocation_stream = format!("{normalized_prefix}authority:revocation:{token}");
    let schemas = base_v2_schema_map();
    let policy_ref = bytes_ref(b"permit(principal, action, resource);");
    let profile_doc = json!({
        "format": "r5e.capture-profile/v2",
        "schemas": Value::Object(schemas),
        "authority": {
            "bindings": [
                {
                    "streamPrefix": &revocation_stream,
                    "actorPrefixes": ["urn:r5e:"],
                    "issuerKeys": [&revoker_key_id],
                    "sealerKeys": [],
                }
            ],
            "checkpointKeys": [],
        },
        "durability": {
            "failureDomain": "offline-operator-root",
            "onFailure": "refuse",
            "requiredPayloads": "submitted",
        },
        "policyRequiredKinds": [],
        "deploymentPolicyRef": &policy_ref,
    });
    let profile_bytes = encode_canonical_json(&profile_doc)?;
    let profile_ref = bytes_ref(&profile_bytes);

    let now = params.captured_at.unwrap_or_else(chrono::Utc::now);
    let captured_at = now.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);

    let mut body = Map::new();
    body.insert("target".to_string(), Value::String(params.target.clone()));
    if let Some(ref reason) = params.reason {
        body.insert("reason".to_string(), Value::String(reason.clone()));
    }
    if let Some(ref details) = params.details {
        let flat = crate::attestation::normalize_a9_details(details)?;
        body.insert("details".to_string(), Value::Object(flat));
    }

    let revocation = sign_v2_record_multi(
        &[signer_key],
        json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Revocation",
            "schemaRef": REVOCATION_SCHEMA_REF,
            "profileRef": &profile_ref,
            "stream": &revocation_stream,
            "seq": 1,
            "previous": null,
            "actor": &params.actor,
            "capturedAt": &captured_at,
            "body": Value::Object(body),
        })
        .as_object()
        .expect("Revocation envelope object")
        .clone(),
    )?;

    let request = SubmitRevocationsRequest {
        records: vec![revocation.clone()],
        keys: vec![PublicKeyEntry {
            keyid: revoker_key_id.clone(),
            algorithm: "ed25519".to_string(),
            bytes: revoker_pub_b64,
        }],
        blobs: vec![BlobEntry {
            blob_ref: profile_ref.clone(),
            media_type: Some("application/json".to_string()),
            base64: BASE64_STANDARD.encode(&profile_bytes),
        }],
    };

    let req_bytes = encode_canonical_json(
        &serde_json::to_value(&request).map_err(|e| format!("serialize revocation set: {e}"))?,
    )?;
    if req_bytes.len() > MAX_REVOCATION_BODY_BYTES {
        return Err(format!(
            "revocation payload is {} bytes (maximum allowed is {MAX_REVOCATION_BODY_BYTES})",
            req_bytes.len()
        ));
    }

    Ok(BuiltGrantRevocation {
        revoker_key_id,
        revocation_stream,
        profile_ref,
        revocation,
        request,
    })
}

/// Builds a batch of `1..=16` `Revocation` records (`seq: 1`, `previous: null`, each on its own
/// unique `urn:r5e:stream:<deployment>:authority:revocation:<token>` stream and exact-`streamPrefix`
/// capture profile) packaged into a single `SubmitRevocationsRequest` with deduplicated `keys` and
/// `blobs`.
pub fn build_grant_revocations_batch(
    signer_key: &SigningKey,
    targets: &[String],
    stream_prefix: impl Into<String>,
    reason: Option<String>,
    actor: impl Into<String>,
    captured_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<BuiltGrantRevocationBatch, String> {
    let mut unique_targets: Vec<String> = Vec::with_capacity(targets.len());
    for t in targets {
        if !unique_targets.iter().any(|existing| existing == t) {
            unique_targets.push(t.clone());
        }
    }
    if unique_targets.is_empty() {
        return Err("revocation batch requires at least 1 target grant reference".to_string());
    }
    if unique_targets.len() > MAX_REVOCATION_RECORDS {
        return Err(format!(
            "revocation batch targets {} grants (maximum per POST /v1/deployment/revocations request is {MAX_REVOCATION_RECORDS})",
            unique_targets.len()
        ));
    }

    let prefix_str = stream_prefix.into();
    let actor_str = actor.into();
    let effective_now = Some(captured_at.unwrap_or_else(chrono::Utc::now));

    let mut items = Vec::with_capacity(unique_targets.len());
    let mut records = Vec::with_capacity(unique_targets.len());
    let mut keys: Vec<PublicKeyEntry> = Vec::new();
    let mut blobs: Vec<BlobEntry> = Vec::new();
    let mut seen_streams = BTreeSet::new();

    for target in unique_targets {
        let mut params = GrantRevocationParams::new(target, prefix_str.clone());
        params.reason = reason.clone();
        params.actor = actor_str.clone();
        params.captured_at = effective_now;

        let built = build_grant_revocation(signer_key, &params)?;
        if !seen_streams.insert(built.revocation_stream.clone()) {
            return Err(format!(
                "duplicate revocation stream generated in batch: {}",
                built.revocation_stream
            ));
        }
        records.push(built.revocation.clone());
        for k in &built.request.keys {
            if !keys.iter().any(|existing| existing.keyid == k.keyid) {
                keys.push(k.clone());
            }
        }
        for b in &built.request.blobs {
            if !blobs.iter().any(|existing| existing.blob_ref == b.blob_ref) {
                blobs.push(b.clone());
            }
        }
        items.push(built);
    }

    let revoker_key_id = items[0].revoker_key_id.clone();
    let request = SubmitRevocationsRequest {
        records,
        keys,
        blobs,
    };

    let req_bytes = encode_canonical_json(
        &serde_json::to_value(&request).map_err(|e| format!("serialize revocation batch: {e}"))?,
    )?;
    if req_bytes.len() > MAX_REVOCATION_BODY_BYTES {
        return Err(format!(
            "revocation batch payload is {} bytes (maximum allowed is {MAX_REVOCATION_BODY_BYTES})",
            req_bytes.len()
        ));
    }

    Ok(BuiltGrantRevocationBatch {
        revoker_key_id,
        items,
        request,
    })
}

pub(crate) fn parse_and_verify_v2_pubkey(
    algorithm: &str,
    b64_bytes: &str,
    expected_keyid: Option<&str>,
    label: &str,
) -> Result<(crate::crypto_keys::SignatureAlgorithm, Vec<u8>, String), String> {
    let alg = crate::crypto_keys::SignatureAlgorithm::parse(algorithm)
        .map_err(|e| format!("{label}: {e}"))?;
    let raw = decode_strict_base64(b64_bytes)
        .map_err(|e| format!("{label}: invalid strict base64 public key: {e}"))?;
    crate::crypto_keys::validate_public_key_bytes(alg, &raw, label)?;
    let derived_keyid =
        crate::crypto_keys::compute_key_id(alg, &raw).map_err(|e| format!("{label}: {e}"))?;
    if let Some(exp) = expected_keyid {
        if derived_keyid != exp {
            return Err(format!(
                "{label}: derived keyid ({derived_keyid}) does not match declared keyid ({exp})"
            ));
        }
    }
    Ok((alg, raw, derived_keyid))
}

pub(crate) fn verify_dsse_v2_sig(
    alg: crate::crypto_keys::SignatureAlgorithm,
    pub_bytes: &[u8],
    payload_bytes: &[u8],
    sig_b64: &str,
    label: &str,
) -> Result<(), String> {
    let sig_raw =
        decode_strict_base64(sig_b64).map_err(|e| format!("{label}: invalid sig base64: {e}"))?;
    let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, payload_bytes);
    crate::crypto_keys::verify_signature(alg, pub_bytes, &pae, &sig_raw)
        .map_err(|e| format!("{label}: {e}"))
}

fn kind_covered_by_domain(kind_path: &str, domain: &str) -> bool {
    let Some((group, _)) = kind_path.split_once('/') else {
        return false;
    };
    let dom = domain.trim().to_ascii_lowercase();
    if dom.is_empty() {
        return false;
    }
    group == dom
        || (group.len() > dom.len()
            && group.ends_with(&dom)
            && group.as_bytes()[group.len() - dom.len() - 1] == b'.')
}

fn publisher_covers_all_kinds<'a, I>(
    trusted_entries: &[String],
    publisher_keyid: &str,
    kinds: I,
) -> bool
where
    I: IntoIterator<Item = &'a String>,
{
    let mut wildcard = false;
    let mut allowed_domains: Vec<&str> = Vec::new();
    for raw in trusted_entries {
        let trimmed = raw.trim();
        if let Some((kid, doms)) = trimmed.split_once('=') {
            if kid == publisher_keyid {
                for d in doms.split(',') {
                    let dt = d.trim();
                    if !dt.is_empty() {
                        allowed_domains.push(dt);
                    }
                }
            }
        } else if trimmed == publisher_keyid {
            wildcard = true;
        }
    }
    if wildcard {
        return true;
    }
    if allowed_domains.is_empty() {
        return false;
    }
    for k in kinds {
        if !allowed_domains
            .iter()
            .any(|dom| kind_covered_by_domain(k, dom))
        {
            return false;
        }
    }
    true
}

fn parse_definitions_map(items: &[Value], label: &str) -> Result<BTreeMap<String, String>, String> {
    if items.is_empty() {
        return Err(format!("{label} must be non-empty"));
    }
    let mut map = BTreeMap::new();
    for (idx, item) in items.iter().enumerate() {
        let obj = item
            .as_object()
            .ok_or_else(|| format!("{label}[{idx}] must be an object"))?;
        if obj.len() != 2 {
            return Err(format!(
                "{label}[{idx}] must contain only kind and definition"
            ));
        }
        let kind = obj
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{label}[{idx}] missing string kind"))?;
        let def = obj
            .get("definition")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{label}[{idx}] missing string definition"))?;
        if !is_valid_kind_path(kind) {
            return Err(format!("{label}[{idx}] invalid kind path: {kind}"));
        }
        if !is_valid_bytes_ref(def) {
            return Err(format!(
                "{label}[{idx}] invalid definition bytes ref: {def}"
            ));
        }
        if map.insert(kind.to_string(), def.to_string()).is_some() {
            return Err(format!("{label} contains duplicate kind entry: {kind}"));
        }
    }
    Ok(map)
}

pub(crate) fn profile_binds_record(
    profile_val: &Value,
    stream: &str,
    actor: &str,
    issuer: &str,
) -> bool {
    let Some(bindings) = profile_val
        .get("authority")
        .and_then(|a| a.get("bindings"))
        .and_then(Value::as_array)
    else {
        return false;
    };
    bindings.iter().any(|b| {
        let Some(sp) = b.get("streamPrefix").and_then(Value::as_str) else {
            return false;
        };
        if sp.is_empty() || !stream.starts_with(sp) {
            return false;
        }
        let actor_ok = match b.get("actorPrefixes") {
            None => true,
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(Value::as_str)
                .any(|ap| !ap.is_empty() && actor.starts_with(ap)),
            _ => false,
        };
        if !actor_ok {
            return false;
        }
        let Some(iks) = b.get("issuerKeys").and_then(Value::as_array) else {
            return false;
        };
        iks.iter().filter_map(Value::as_str).any(|ik| ik == issuer)
    })
}

fn extract_optional_str(
    obj: &Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<Option<String>, String> {
    match obj.get(key) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(format!(
            "Deployment.body.{label} must be a string when present"
        )),
    }
}

pub(crate) fn extract_recorded_refs(val: &Value) -> Vec<String> {
    let Some(obj) = val.as_object() else {
        return Vec::new();
    };
    for field in ["recorded", "refs", "records", "grants"] {
        if let Some(arr) = obj.get(field).and_then(Value::as_array) {
            let mut out = Vec::new();
            for item in arr {
                if let Some(s) = item.as_str() {
                    out.push(s.to_string());
                } else if let Some(r) = item.get("ref").and_then(Value::as_str) {
                    out.push(r.to_string());
                }
            }
            if !out.is_empty() || arr.is_empty() {
                return out;
            }
        }
    }
    Vec::new()
}

fn is_lower_hex_64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn is_valid_evidence_ref(s: &str) -> bool {
    s.strip_prefix("evidence:sha256:")
        .is_some_and(is_lower_hex_64)
}

pub(crate) fn is_valid_bytes_ref(s: &str) -> bool {
    s.strip_prefix("bytes:sha256:").is_some_and(is_lower_hex_64)
}

pub(crate) fn is_valid_key_id(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("key:") else {
        return false;
    };
    let Some((alg, hex)) = rest.split_once(":sha256:") else {
        return false;
    };
    !alg.is_empty()
        && alg
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && is_lower_hex_64(hex)
}

pub(crate) fn is_valid_slug_token(s: &str, allow_leading_digit: bool) -> bool {
    let mut bytes = s.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    let first_ok = first.is_ascii_lowercase() || (allow_leading_digit && first.is_ascii_digit());
    first_ok && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub(crate) fn is_valid_uri_identity(s: &str) -> bool {
    let Some((scheme, rest)) = s.split_once(':') else {
        return false;
    };
    let mut sb = scheme.bytes();
    let Some(first) = sb.next() else {
        return false;
    };
    first.is_ascii_alphabetic()
        && sb.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-'))
        && !rest.is_empty()
        && !rest.chars().any(char::is_whitespace)
}

pub(crate) fn is_valid_kind_path(s: &str) -> bool {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 3 {
        return false;
    }
    let (pkg, ver, name) = (parts[0], parts[1], parts[2]);
    !pkg.is_empty()
        && pkg
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && ver.strip_prefix('v').is_some_and(|v| {
            !v.is_empty()
                && v.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
        && !name.is_empty()
        && name.bytes().all(|b| b.is_ascii_alphanumeric())
}

pub(crate) fn request_http11(
    cfg: &ClaimClientConfig,
    method: &str,
    path: &str,
    json_body: Option<&[u8]>,
) -> Result<(u16, Vec<u8>), ClaimError> {
    send_http11_request(
        &cfg.gateway_base_url,
        cfg.timeout,
        method,
        path,
        None,
        json_body,
    )
    .map_err(ClaimError::Transport)
}

// ---------------------------------------------------------------------------
// Detached External-Signer / Hardware Ceremonies
// ---------------------------------------------------------------------------

pub const PREPARED_CLAIM_FORMAT: &str = "r5e.prepared-claim/v2";
pub const PREPARED_ENDORSEMENT_FORMAT: &str = "r5e.prepared-endorsement/v2";
pub const PREPARED_PRINCIPAL_FORMAT: &str = "r5e.prepared-principal/v2";
pub const PREPARED_REVOCATION_FORMAT: &str = "r5e.prepared-revocation/v2";

/// Zero-secret prepared deployment claim artifact written by `prepare-claim` (`--out-prepared`)
/// and consumed by `finalize-claim` (`--prepared`).
///
/// The one-time claim `code` is NEVER stored in this file; `finalize-claim` reads it at finalize
/// time from `--claim-code-file` or `R5E_CLAIM_CODE`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreparedClaimCeremony {
    pub format: String,
    #[serde(rename = "gatewayUrl")]
    pub gateway_url: String,
    #[serde(rename = "claimingRootKey")]
    pub claiming_root_pubkey: PublicKeyEntry,
    #[serde(rename = "claimedBy")]
    pub claimed_by: String,
    pub roots: Vec<PrepareClaimRootEntry>,
    pub threshold: usize,
    #[serde(
        default,
        skip_serializing_if = "option_slice_is_none_or_empty",
        rename = "recoveryKeys"
    )]
    pub recovery_keys: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "option_slice_is_none_or_empty")]
    pub custodians: Option<Vec<CustodianEntry>>,
    #[serde(default, rename = "trustedPublishers")]
    pub trusted_publishers: Vec<String>,
    #[serde(default, rename = "allowUntrustedPublisher")]
    pub allow_untrusted_publisher: bool,
    pub prepared: PreparedClaimResponse,
    pub inspection: PreparedClaimInspection,
    #[serde(rename = "paeSha256")]
    pub pae_sha256: String,
}

/// Calls `POST /v1/deployment/claim/prepare`, verifies every offline cryptographic and structural
/// invariant against `claiming_root_pubkey` (`ed25519 | es256 | es384`), enforces the PIV hardware
/// `Ed25519` PAE ceiling (`<= 3000` bytes unless `allow_large_ed25519_pae`), and returns
/// `(PreparedClaimCeremony, dsse_pae_bytes)`.
pub fn prepare_detached_claim_ceremony(
    cfg: &ClaimClientConfig,
    claiming_root_pubkey: &PublicKeyEntry,
    req: &PrepareClaimRequest,
    trusted_publishers: &[String],
    allow_untrusted_publisher: bool,
    allow_large_ed25519_pae: bool,
) -> Result<(PreparedClaimCeremony, Vec<u8>), ClaimError> {
    let (alg, _, _) = parse_and_verify_v2_pubkey(
        &claiming_root_pubkey.algorithm,
        &claiming_root_pubkey.bytes,
        Some(&claiming_root_pubkey.keyid),
        "claiming_root_pubkey",
    )
    .map_err(ClaimError::Validation)?;

    let prepared = prepare_deployment_claim(cfg, req)?;
    let (inspection, pae) = verify_prepared_claim_for_public_signer(
        claiming_root_pubkey,
        req,
        &prepared,
        trusted_publishers,
        allow_untrusted_publisher,
    )
    .map_err(ClaimError::Validation)?;

    if !allow_large_ed25519_pae {
        crate::crypto_keys::check_piv_ed25519_pae_limit(alg, pae.len())
            .map_err(ClaimError::Validation)?;
    }

    let pae_sha256 = {
        use sha2::{Digest, Sha256};
        crate::policy_gate::hex_lower(&Sha256::digest(&pae))
    };

    Ok((
        PreparedClaimCeremony {
            format: PREPARED_CLAIM_FORMAT.to_string(),
            gateway_url: cfg.gateway_base_url.clone(),
            claiming_root_pubkey: claiming_root_pubkey.clone(),
            claimed_by: req.claimed_by.clone(),
            roots: req.roots.clone(),
            threshold: req.threshold,
            recovery_keys: req.recovery_keys.clone(),
            custodians: req.custodians.clone(),
            trusted_publishers: trusted_publishers.to_vec(),
            allow_untrusted_publisher,
            prepared,
            inspection,
            pae_sha256,
        },
        pae,
    ))
}

/// Normalizes and cryptographically verifies an external detached root signature (`ed25519`,
/// `es256`, or `es384` — supporting both raw `r || s` and ASN.1 DER `ECDSA-Sig-Value` with
/// automatic `s > floor(n / 2)` -> `n - s` normalization) over the DSSE PAE BEFORE submitting
/// `POST /v1/deployment/claim/finalize`, then verifies the gateway's `FinalizedClaimResponse`.
pub fn finalize_detached_claim_ceremony(
    cfg: &ClaimClientConfig,
    ceremony: &PreparedClaimCeremony,
    claim_code: &str,
    signature_input: &[u8],
    is_base64_flag: bool,
) -> Result<(FinalizedClaimResponse, bool), ClaimError> {
    if ceremony.format != PREPARED_CLAIM_FORMAT {
        return Err(ClaimError::Validation(format!(
            "unsupported prepared claim format {:?} (expected {PREPARED_CLAIM_FORMAT:?})",
            ceremony.format
        )));
    }
    if claim_code.trim().is_empty() {
        return Err(ClaimError::Validation(
            "claim code must be non-empty".to_string(),
        ));
    }

    let payload_bytes = decode_strict_base64(&ceremony.prepared.payload)
        .map_err(|e| ClaimError::Validation(format!("invalid prepared payload base64: {e}")))?;
    let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &payload_bytes);
    let computed_pae_sha256 = {
        use sha2::{Digest, Sha256};
        crate::policy_gate::hex_lower(&Sha256::digest(&pae))
    };
    if computed_pae_sha256 != ceremony.pae_sha256 {
        return Err(ClaimError::Validation(format!(
            "prepared claim paeSha256 mismatch: expected {}, computed {computed_pae_sha256}",
            ceremony.pae_sha256
        )));
    }

    let req = PrepareClaimRequest {
        code: claim_code.trim().to_string(),
        claimed_by: ceremony.claimed_by.clone(),
        roots: ceremony.roots.clone(),
        threshold: ceremony.threshold,
        recovery_keys: ceremony.recovery_keys.clone(),
        custodians: ceremony.custodians.clone(),
    };

    let (verified, was_normalized) = attach_external_claim_signature_with_meta(
        &ceremony.claiming_root_pubkey,
        &req,
        &ceremony.prepared,
        &ceremony.trusted_publishers,
        ceremony.allow_untrusted_publisher,
        signature_input,
        is_base64_flag,
    )
    .map_err(ClaimError::Validation)?;

    let finalized = finalize_and_verify_deployment_claim(
        cfg,
        &verified.finalize_request,
        &ceremony.prepared.bootstrap_key,
        &ceremony.inspection.chain_started_ref,
    )?;

    Ok((finalized, was_normalized))
}

fn normalize_deployment_stream_prefix(raw: &str) -> Result<(String, String), String> {
    let trimmed = raw.trim();
    if let Some(after) = trimmed.strip_prefix("urn:r5e:stream:") {
        let dep = after.trim_end_matches(':');
        if dep.is_empty() || dep.contains(':') || !is_valid_slug_token(dep, true) {
            return Err(format!(
                "invalid stream prefix {raw:?}: expected 'urn:r5e:stream:<deployment>:'"
            ));
        }
        Ok((dep.to_string(), format!("urn:r5e:stream:{dep}:")))
    } else {
        if trimmed.is_empty() || trimmed.contains(':') || !is_valid_slug_token(trimmed, true) {
            return Err(format!(
                "invalid deployment slug {raw:?}: expected lowercase slug matching ^[a-z0-9][a-z0-9-]*$"
            ));
        }
        Ok((trimmed.to_string(), format!("urn:r5e:stream:{trimmed}:")))
    }
}

fn parse_and_normalize_detached_sig(
    alg: crate::crypto_keys::SignatureAlgorithm,
    pub_bytes: &[u8],
    pae: &[u8],
    signature_input: &[u8],
    is_base64_flag: bool,
) -> Result<(Vec<u8>, bool), String> {
    let (canonical_sig, was_normalized) = if is_base64_flag {
        let sig_str = std::str::from_utf8(signature_input)
            .map_err(|_| "--signature-b64 is not valid UTF-8".to_string())?;
        let clean: String = sig_str.chars().filter(|c| !c.is_whitespace()).collect();
        let raw_sig = BASE64_STANDARD
            .decode(&clean)
            .map_err(|e| format!("invalid --signature-b64 base64: {e}"))?;
        crate::crypto_keys::normalize_signature_bytes(alg, &raw_sig, Some((pub_bytes, pae)))?
    } else {
        crate::crypto_keys::parse_external_signature_bytes(
            alg,
            signature_input,
            Some((pub_bytes, pae)),
            "--signature-file",
        )?
    };
    crate::crypto_keys::verify_signature(alg, pub_bytes, pae, &canonical_sig)?;
    Ok((canonical_sig, was_normalized))
}

/// Parameters for preparing an unsigned `provenance.r5e.io/v2/Endorsement` record (`prepare-endorsement`)
/// for external/hardware signing (PIV, `openssl`, PKCS#11, HSM).
#[derive(Debug, Clone)]
pub struct DetachedEndorsementParams {
    pub issuer_pubkey: PublicKeyEntry,
    pub subject_key_id: String,
    /// Deployment slug (`"acme-prod"`) or stream prefix (`"urn:r5e:stream:acme-prod:"`).
    pub stream_prefix: String,
    /// Optional sub-stream token (`None` -> `authority:root:<hex>`; `Some(tok)` -> `authority:root:<hex>:grant:<tok>`).
    pub grant_substream_token: Option<String>,
    pub seq: u64,
    pub previous: Option<String>,
    pub actor: String,
    pub kinds: Vec<String>,
    /// Granted `streamPrefixes` (defaults to `Some(vec!["urn:r5e:stream:<deployment>:"])`).
    pub stream_prefixes: Option<Vec<String>>,
    /// Granted `actorPrefixes` (`None` omits `actorPrefixes`, e.g. for `:retention` releaser grants).
    pub actor_prefixes: Option<Vec<String>>,
    pub acts_for: Option<String>,
    pub parent: Option<String>,
    pub role: Option<String>,
    pub may_endorse: bool,
    pub captured_at: Option<chrono::DateTime<chrono::Utc>>,
    pub not_before_override: Option<String>,
    pub ttl_seconds: u64,
    pub sealer_keys: Vec<String>,
    pub details: Option<Map<String, Value>>,
    pub allow_large_ed25519_pae: bool,
}

impl DetachedEndorsementParams {
    pub fn new_gateway_grant(
        issuer_pubkey: PublicKeyEntry,
        gateway_key_id: impl Into<String>,
        stream_prefix: impl Into<String>,
    ) -> Self {
        let gw_id = gateway_key_id.into();
        Self {
            issuer_pubkey,
            subject_key_id: gw_id.clone(),
            stream_prefix: stream_prefix.into(),
            grant_substream_token: None,
            seq: 1,
            previous: None,
            actor: "urn:r5e:operator:root".to_string(),
            kinds: default_gateway_grant_kinds(),
            stream_prefixes: None,
            actor_prefixes: Some(vec!["urn:r5e:".to_string()]),
            acts_for: None,
            parent: None,
            role: None,
            may_endorse: true,
            captured_at: None,
            not_before_override: None,
            ttl_seconds: 86_400 * 30,
            sealer_keys: vec![gw_id],
            details: None,
            allow_large_ed25519_pae: false,
        }
    }
}

/// Unsigned `Endorsement` artifact written by `prepare-endorsement` and consumed by `finalize-endorsement`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreparedEndorsement {
    pub format: String,
    #[serde(rename = "recordRef")]
    pub record_ref: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    #[serde(rename = "payloadBase64")]
    pub payload_b64: String,
    #[serde(rename = "paeSha256")]
    pub pae_sha256: String,
    #[serde(rename = "issuerKey")]
    pub issuer_pubkey: PublicKeyEntry,
    #[serde(rename = "subjectKeyId")]
    pub subject_key_id: String,
    pub stream: String,
    #[serde(rename = "profileRef")]
    pub profile_ref: String,
    #[serde(rename = "profileBlob")]
    pub profile_blob: BlobEntry,
}

/// Verified & finalized `Endorsement` returned by [`finalize_detached_endorsement`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedEndorsement {
    pub endorsement: SignedEndpointRecord,
    pub grant_request: SubmitGrantsRequest,
    pub issuer_key_id: String,
    pub subject_key_id: String,
    pub stream: String,
    pub profile_ref: String,
    pub signature_was_normalized: bool,
}

/// Prepares an unsigned `provenance.r5e.io/v2/Endorsement` record and returns `(PreparedEndorsement, dsse_pae_bytes)`.
pub fn prepare_detached_endorsement(
    params: &DetachedEndorsementParams,
) -> Result<(PreparedEndorsement, Vec<u8>), String> {
    let (alg, _, issuer_key_id) = parse_and_verify_v2_pubkey(
        &params.issuer_pubkey.algorithm,
        &params.issuer_pubkey.bytes,
        Some(&params.issuer_pubkey.keyid),
        "issuer_pubkey",
    )?;
    let issuer_hex = crate::crypto_keys::key_id_sha256_hex(&issuer_key_id)?;

    if !is_valid_key_id(&params.subject_key_id) {
        return Err(format!("invalid subject key ID: {}", params.subject_key_id));
    }
    if params.subject_key_id == issuer_key_id {
        return Err("Endorsement subject must be distinct from issuer key ID".to_string());
    }
    if params.seq == 0 {
        return Err("Endorsement seq must be >= 1".to_string());
    }
    if params.seq == 1 && params.previous.is_some() {
        return Err("Endorsement seq 1 must have previous = null".to_string());
    }
    if params.seq > 1 && params.previous.is_none() {
        return Err(
            "Endorsement seq > 1 requires previous evidence:sha256:... reference".to_string(),
        );
    }
    if let Some(ref prev) = params.previous {
        if !is_valid_evidence_ref(prev) {
            return Err(format!("invalid Endorsement previous reference: {prev}"));
        }
    }
    if params.kinds.is_empty() {
        return Err("Endorsement kinds must be non-empty".to_string());
    }
    let mut unique_kinds = Vec::with_capacity(params.kinds.len());
    for raw_k in &params.kinds {
        let k = if !raw_k.contains('/') && !raw_k.trim().is_empty() {
            format!("provenance.r5e.io/v2/{}", raw_k.trim())
        } else {
            raw_k.trim().to_string()
        };
        if !is_valid_kind_path(&k) {
            return Err(format!("invalid kind path in Endorsement: {raw_k:?}"));
        }
        if !unique_kinds.contains(&k) {
            unique_kinds.push(k);
        }
    }
    if !params.actor.starts_with("urn:r5e:") {
        return Err(format!(
            "Endorsement actor ({}) must start with 'urn:r5e:'",
            params.actor
        ));
    }
    if params.ttl_seconds == 0 {
        return Err("Endorsement ttl_seconds must be > 0".to_string());
    }

    let (_, normalized_prefix) = normalize_deployment_stream_prefix(&params.stream_prefix)?;
    let stream = match &params.grant_substream_token {
        Some(tok) => {
            if tok.is_empty()
                || !tok
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(format!(
                    "invalid grant substream token {tok:?}: must be non-empty ASCII alphanumeric, '-' or '_'"
                ));
            }
            format!("{normalized_prefix}authority:root:{issuer_hex}:grant:{tok}")
        }
        None => format!("{normalized_prefix}authority:root:{issuer_hex}"),
    };

    let unique_stream_prefixes = match &params.stream_prefixes {
        Some(sps) => {
            if sps.is_empty() {
                return Err("Endorsement streamPrefixes cannot be empty when provided".to_string());
            }
            let mut u = Vec::with_capacity(sps.len());
            for sp in sps {
                if sp.trim().is_empty() {
                    return Err("Endorsement streamPrefixes entries must be non-empty".to_string());
                }
                if !u.contains(sp) {
                    u.push(sp.clone());
                }
            }
            u
        }
        None => vec![normalized_prefix.clone()],
    };

    let unique_actor_prefixes = match &params.actor_prefixes {
        Some(aps) => {
            if aps.is_empty() {
                return Err("Endorsement actorPrefixes cannot be empty when provided".to_string());
            }
            let mut u = Vec::with_capacity(aps.len());
            for ap in aps {
                if ap.trim().is_empty() {
                    return Err("Endorsement actorPrefixes entries must be non-empty".to_string());
                }
                if !u.contains(ap) {
                    u.push(ap.clone());
                }
            }
            Some(u)
        }
        None => None,
    };

    if let Some(ref af) = params.acts_for {
        if !is_valid_uri_identity(af) {
            return Err(format!("invalid Endorsement actsFor URI: {af}"));
        }
    }
    if let Some(ref par) = params.parent {
        if !is_valid_evidence_ref(par) {
            return Err(format!("invalid Endorsement parent evidence ref: {par}"));
        }
    }
    if let Some(ref r) = params.role {
        if r.trim().is_empty() {
            return Err("Endorsement role cannot be empty when provided".to_string());
        }
    }
    let mut unique_sealer_keys = Vec::with_capacity(params.sealer_keys.len());
    for sk in &params.sealer_keys {
        if !is_valid_key_id(sk) {
            return Err(format!("invalid sealerKey ID: {sk}"));
        }
        if !unique_sealer_keys.contains(sk) {
            unique_sealer_keys.push(sk.clone());
        }
    }

    let schemas = base_v2_schema_map();
    let endorsement_schema = schemas["provenance.r5e.io/v2/Endorsement"]
        .as_str()
        .expect("Endorsement in base_v2_schema_map")
        .to_string();

    let policy_ref = bytes_ref(b"permit(principal, action, resource);");
    let profile_doc = json!({
        "format": "r5e.capture-profile/v2",
        "schemas": Value::Object(schemas),
        "authority": {
            "bindings": [
                {
                    "streamPrefix": &stream,
                    "actorPrefixes": ["urn:r5e:"],
                    "issuerKeys": [&issuer_key_id],
                    "sealerKeys": &unique_sealer_keys,
                }
            ],
            "checkpointKeys": [],
        },
        "durability": {
            "failureDomain": "offline-operator-root",
            "onFailure": "refuse",
            "requiredPayloads": "submitted",
        },
        "policyRequiredKinds": [],
        "deploymentPolicyRef": &policy_ref,
    });
    let profile_bytes = encode_canonical_json(&profile_doc)?;
    let profile_ref = bytes_ref(&profile_bytes);

    let now = params.captured_at.unwrap_or_else(chrono::Utc::now);
    let captured_at = now.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let not_after = (now + chrono::Duration::seconds(params.ttl_seconds as i64))
        .to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let not_after_utc = chrono::DateTime::parse_from_rfc3339(&not_after)
        .expect("serialized not_after RFC3339")
        .with_timezone(&chrono::Utc);
    let not_before = if let Some(ref nb) = params.not_before_override {
        if nb.ends_with("-00:00") {
            return Err(format!(
                "invalid Endorsement notBefore ({nb}): unknown -00:00 offset is outside Provenance v2 Timestamp profile"
            ));
        }
        let parsed_nb = chrono::DateTime::parse_from_rfc3339(nb)
            .map_err(|e| format!("invalid Endorsement notBefore RFC3339 timestamp ({nb}): {e}"))?
            .with_timezone(&chrono::Utc);
        if parsed_nb > not_after_utc {
            return Err(format!(
                "Endorsement notBefore ({nb}) must be <= notAfter ({not_after})"
            ));
        }
        nb.clone()
    } else {
        (now - chrono::Duration::seconds(60)).to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
    };

    let mut body = Map::new();
    body.insert(
        "subject".to_string(),
        Value::String(params.subject_key_id.clone()),
    );
    body.insert("kinds".to_string(), json!(&unique_kinds));
    body.insert("streamPrefixes".to_string(), json!(&unique_stream_prefixes));
    if let Some(ref aps) = unique_actor_prefixes {
        body.insert("actorPrefixes".to_string(), json!(aps));
    }
    if let Some(ref af) = params.acts_for {
        body.insert("actsFor".to_string(), Value::String(af.clone()));
    }
    if let Some(ref par) = params.parent {
        body.insert("parent".to_string(), Value::String(par.clone()));
    }
    if let Some(ref r) = params.role {
        body.insert("role".to_string(), Value::String(r.clone()));
    }
    body.insert("mayEndorse".to_string(), Value::Bool(params.may_endorse));
    body.insert("notBefore".to_string(), Value::String(not_before));
    body.insert("notAfter".to_string(), Value::String(not_after));
    if let Some(ref det) = params.details {
        let flat = crate::attestation::normalize_a9_details(det)?;
        if !flat.is_empty() {
            body.insert("details".to_string(), Value::Object(flat));
        }
    }

    let prev_val = match &params.previous {
        Some(p) => Value::String(p.clone()),
        None => Value::Null,
    };

    let envelope_doc = json!({
        "apiVersion": "provenance.r5e.io/v2",
        "kind": "Endorsement",
        "schemaRef": &endorsement_schema,
        "profileRef": &profile_ref,
        "issuer": &issuer_key_id,
        "stream": &stream,
        "seq": params.seq,
        "previous": prev_val,
        "actor": &params.actor,
        "capturedAt": &captured_at,
        "body": Value::Object(body),
    });
    let payload_bytes = encode_canonical_json(&envelope_doc)?;
    let record_ref = evidence_ref(&payload_bytes);
    let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &payload_bytes);

    if !params.allow_large_ed25519_pae {
        crate::crypto_keys::check_piv_ed25519_pae_limit(alg, pae.len())?;
    }

    let pae_sha256 = {
        use sha2::{Digest, Sha256};
        crate::policy_gate::hex_lower(&Sha256::digest(&pae))
    };

    let profile_blob = BlobEntry {
        blob_ref: profile_ref.clone(),
        media_type: Some("application/json".to_string()),
        base64: BASE64_STANDARD.encode(&profile_bytes),
    };

    Ok((
        PreparedEndorsement {
            format: PREPARED_ENDORSEMENT_FORMAT.to_string(),
            record_ref,
            payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
            payload_b64: BASE64_STANDARD.encode(&payload_bytes),
            pae_sha256,
            issuer_pubkey: params.issuer_pubkey.clone(),
            subject_key_id: params.subject_key_id.clone(),
            stream,
            profile_ref,
            profile_blob,
        },
        pae,
    ))
}

/// Attaches and cryptographically verifies an external detached signature (`ed25519`, `es256`, or
/// `es384`, auto-normalizing ASN.1 DER `ECDSA-Sig-Value` and `s > floor(n / 2)` -> `n - s`) onto a
/// [`PreparedEndorsement`] and returns [`FinalizedEndorsement`].
pub fn finalize_detached_endorsement(
    prepared: &PreparedEndorsement,
    signature_input: &[u8],
    is_base64_flag: bool,
) -> Result<FinalizedEndorsement, String> {
    if prepared.format != PREPARED_ENDORSEMENT_FORMAT {
        return Err(format!(
            "unsupported prepared endorsement format {:?} (expected {PREPARED_ENDORSEMENT_FORMAT:?})",
            prepared.format
        ));
    }
    if prepared.payload_type != PROVENANCE_V2_PAYLOAD_TYPE {
        return Err(format!(
            "unexpected prepared endorsement payloadType: {}",
            prepared.payload_type
        ));
    }
    let (alg, pub_bytes, issuer_key_id) = parse_and_verify_v2_pubkey(
        &prepared.issuer_pubkey.algorithm,
        &prepared.issuer_pubkey.bytes,
        Some(&prepared.issuer_pubkey.keyid),
        "prepared.issuerKey",
    )?;
    let payload_bytes = decode_strict_base64(&prepared.payload_b64)
        .map_err(|e| format!("invalid prepared endorsement payloadBase64: {e}"))?;
    let parsed_val: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("prepared endorsement payload is not valid JSON: {e}"))?;
    if encode_canonical_json(&parsed_val)? != payload_bytes {
        return Err("prepared endorsement payload is not canonical JSON".to_string());
    }
    let computed_ref = evidence_ref(&payload_bytes);
    if computed_ref != prepared.record_ref {
        return Err(format!(
            "prepared endorsement recordRef mismatch: declared {}, computed {computed_ref}",
            prepared.record_ref
        ));
    }
    if parsed_val.get("kind").and_then(Value::as_str) != Some("Endorsement")
        || parsed_val.get("issuer").and_then(Value::as_str) != Some(issuer_key_id.as_str())
    {
        return Err("prepared endorsement payload kind/issuer mismatch".to_string());
    }

    let profile_bytes = decode_strict_base64(&prepared.profile_blob.base64)
        .map_err(|e| format!("invalid prepared endorsement profileBlob base64: {e}"))?;
    if bytes_ref(&profile_bytes) != prepared.profile_ref
        || prepared.profile_blob.blob_ref != prepared.profile_ref
    {
        return Err("prepared endorsement profileBlob digest mismatch".to_string());
    }

    let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &payload_bytes);
    let computed_pae_sha256 = {
        use sha2::{Digest, Sha256};
        crate::policy_gate::hex_lower(&Sha256::digest(&pae))
    };
    if computed_pae_sha256 != prepared.pae_sha256 {
        return Err(format!(
            "prepared endorsement paeSha256 mismatch: declared {}, computed {computed_pae_sha256}",
            prepared.pae_sha256
        ));
    }

    let (canonical_sig, was_normalized) =
        parse_and_normalize_detached_sig(alg, &pub_bytes, &pae, signature_input, is_base64_flag)?;

    let endorsement = SignedEndpointRecord {
        record_ref: computed_ref,
        envelope: crate::attestation::DsseEnvelope {
            payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
            payload: prepared.payload_b64.clone(),
            signatures: vec![DsseSignature {
                keyid: issuer_key_id.clone(),
                sig: BASE64_STANDARD.encode(&canonical_sig),
            }],
        },
    };

    let grant_request = SubmitGrantsRequest {
        records: vec![endorsement.clone()],
        keys: vec![PublicKeyEntry {
            keyid: issuer_key_id.clone(),
            algorithm: alg.as_str().to_string(),
            bytes: BASE64_STANDARD.encode(&pub_bytes),
        }],
        blobs: vec![prepared.profile_blob.clone()],
    };

    Ok(FinalizedEndorsement {
        endorsement,
        grant_request,
        issuer_key_id,
        subject_key_id: prepared.subject_key_id.clone(),
        stream: prepared.stream.clone(),
        profile_ref: prepared.profile_ref.clone(),
        signature_was_normalized: was_normalized,
    })
}

/// Parameters for preparing an unsigned `provenance.r5e.io/v2/Principal` record (`prepare-principal`).
#[derive(Debug, Clone)]
pub struct DetachedPrincipalParams {
    pub principal_pubkey: PublicKeyEntry,
    pub stream_prefix: String,
    pub holder: String,
    pub custody: Option<String>,
    pub identity: Option<String>,
    pub actor: String,
    pub captured_at: Option<chrono::DateTime<chrono::Utc>>,
    pub sealer_keys: Vec<String>,
    pub details: Option<Map<String, Value>>,
    pub allow_large_ed25519_pae: bool,
}

/// Unsigned `Principal` artifact written by `prepare-principal` and consumed by `finalize-principal`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreparedPrincipal {
    pub format: String,
    #[serde(rename = "recordRef")]
    pub record_ref: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    #[serde(rename = "payloadBase64")]
    pub payload_b64: String,
    #[serde(rename = "paeSha256")]
    pub pae_sha256: String,
    #[serde(rename = "principalKey")]
    pub principal_pubkey: PublicKeyEntry,
    pub stream: String,
    #[serde(rename = "profileRef")]
    pub profile_ref: String,
    #[serde(rename = "profileBlob")]
    pub profile_blob: BlobEntry,
}

/// Verified & finalized `Principal` returned by [`finalize_detached_principal`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedPrincipal {
    pub principal: SignedEndpointRecord,
    pub grant_request: SubmitGrantsRequest,
    pub key_id: String,
    pub stream: String,
    pub profile_ref: String,
    pub signature_was_normalized: bool,
}

/// Prepares an unsigned `provenance.r5e.io/v2/Principal` record at `seq = 1, previous = null` on
/// `urn:r5e:stream:<deployment>:authority:principal:<key_sha256_hex>` (matching `Grants.record/4`).
pub fn prepare_detached_principal(
    params: &DetachedPrincipalParams,
) -> Result<(PreparedPrincipal, Vec<u8>), String> {
    let (alg, pub_bytes, key_id) = parse_and_verify_v2_pubkey(
        &params.principal_pubkey.algorithm,
        &params.principal_pubkey.bytes,
        Some(&params.principal_pubkey.keyid),
        "principal_pubkey",
    )?;
    let key_hex = crate::crypto_keys::key_id_sha256_hex(&key_id)?;

    if !is_valid_slug_token(&params.holder, false) {
        return Err(format!(
            "invalid Principal holder {:?}: must match ^[a-z][a-z0-9-]*$",
            params.holder
        ));
    }
    if let Some(ref c) = params.custody {
        if !is_valid_slug_token(c, false) {
            return Err(format!(
                "invalid Principal custody {:?}: must match ^[a-z][a-z0-9-]*$",
                c
            ));
        }
    }
    if let Some(ref id) = params.identity {
        if !is_valid_uri_identity(id) {
            return Err(format!("invalid Principal identity URI: {id}"));
        }
    }
    if !params.actor.starts_with("urn:r5e:") {
        return Err(format!(
            "Principal actor ({}) must start with 'urn:r5e:'",
            params.actor
        ));
    }
    let mut unique_sealer_keys = Vec::with_capacity(params.sealer_keys.len());
    for sk in &params.sealer_keys {
        if !is_valid_key_id(sk) {
            return Err(format!("invalid sealerKey ID: {sk}"));
        }
        if !unique_sealer_keys.contains(sk) {
            unique_sealer_keys.push(sk.clone());
        }
    }

    let (_, normalized_prefix) = normalize_deployment_stream_prefix(&params.stream_prefix)?;
    let stream = format!("{normalized_prefix}authority:principal:{key_hex}");

    let schemas = base_v2_schema_map();
    let principal_schema = schemas["provenance.r5e.io/v2/Principal"]
        .as_str()
        .expect("Principal in base_v2_schema_map")
        .to_string();

    let policy_ref = bytes_ref(b"permit(principal, action, resource);");
    let profile_doc = json!({
        "format": "r5e.capture-profile/v2",
        "schemas": Value::Object(schemas),
        "authority": {
            "bindings": [
                {
                    "streamPrefix": &stream,
                    "actorPrefixes": ["urn:r5e:"],
                    "issuerKeys": [&key_id],
                    "sealerKeys": &unique_sealer_keys,
                }
            ],
            "checkpointKeys": [],
        },
        "durability": {
            "failureDomain": "offline-operator-principal",
            "onFailure": "refuse",
            "requiredPayloads": "submitted",
        },
        "policyRequiredKinds": [],
        "deploymentPolicyRef": &policy_ref,
    });
    let profile_bytes = encode_canonical_json(&profile_doc)?;
    let profile_ref = bytes_ref(&profile_bytes);

    let now = params.captured_at.unwrap_or_else(chrono::Utc::now);
    let captured_at = now.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);

    let mut body = Map::new();
    body.insert("key".to_string(), Value::String(key_id.clone()));
    body.insert(
        "publicKey".to_string(),
        json!({
            "algorithm": alg.as_str(),
            "bytes": BASE64_STANDARD.encode(&pub_bytes),
        }),
    );
    body.insert("holder".to_string(), Value::String(params.holder.clone()));
    if let Some(ref c) = params.custody {
        body.insert("custody".to_string(), Value::String(c.clone()));
    }
    if let Some(ref id) = params.identity {
        body.insert("identity".to_string(), Value::String(id.clone()));
    }
    if let Some(ref det) = params.details {
        let flat = crate::attestation::normalize_a9_details(det)?;
        if !flat.is_empty() {
            body.insert("details".to_string(), Value::Object(flat));
        }
    }

    let envelope_doc = json!({
        "apiVersion": "provenance.r5e.io/v2",
        "kind": "Principal",
        "schemaRef": &principal_schema,
        "profileRef": &profile_ref,
        "issuer": &key_id,
        "stream": &stream,
        "seq": 1,
        "previous": null,
        "actor": &params.actor,
        "capturedAt": &captured_at,
        "body": Value::Object(body),
    });
    let payload_bytes = encode_canonical_json(&envelope_doc)?;
    let record_ref = evidence_ref(&payload_bytes);
    let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &payload_bytes);

    if !params.allow_large_ed25519_pae {
        crate::crypto_keys::check_piv_ed25519_pae_limit(alg, pae.len())?;
    }

    let pae_sha256 = {
        use sha2::{Digest, Sha256};
        crate::policy_gate::hex_lower(&Sha256::digest(&pae))
    };

    let profile_blob = BlobEntry {
        blob_ref: profile_ref.clone(),
        media_type: Some("application/json".to_string()),
        base64: BASE64_STANDARD.encode(&profile_bytes),
    };

    Ok((
        PreparedPrincipal {
            format: PREPARED_PRINCIPAL_FORMAT.to_string(),
            record_ref,
            payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
            payload_b64: BASE64_STANDARD.encode(&payload_bytes),
            pae_sha256,
            principal_pubkey: PublicKeyEntry {
                keyid: key_id,
                algorithm: alg.as_str().to_string(),
                bytes: BASE64_STANDARD.encode(&pub_bytes),
            },
            stream,
            profile_ref,
            profile_blob,
        },
        pae,
    ))
}

/// Attaches and verifies an external detached signature (`ed25519 | es256 | es384`, auto-normalizing
/// ASN.1 DER + high-`S`) onto a [`PreparedPrincipal`].
pub fn finalize_detached_principal(
    prepared: &PreparedPrincipal,
    signature_input: &[u8],
    is_base64_flag: bool,
) -> Result<FinalizedPrincipal, String> {
    if prepared.format != PREPARED_PRINCIPAL_FORMAT {
        return Err(format!(
            "unsupported prepared principal format {:?} (expected {PREPARED_PRINCIPAL_FORMAT:?})",
            prepared.format
        ));
    }
    if prepared.payload_type != PROVENANCE_V2_PAYLOAD_TYPE {
        return Err(format!(
            "unexpected prepared principal payloadType: {}",
            prepared.payload_type
        ));
    }
    let (alg, pub_bytes, key_id) = parse_and_verify_v2_pubkey(
        &prepared.principal_pubkey.algorithm,
        &prepared.principal_pubkey.bytes,
        Some(&prepared.principal_pubkey.keyid),
        "prepared.principalKey",
    )?;
    let payload_bytes = decode_strict_base64(&prepared.payload_b64)
        .map_err(|e| format!("invalid prepared principal payloadBase64: {e}"))?;
    let parsed_val: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("prepared principal payload is not valid JSON: {e}"))?;
    if encode_canonical_json(&parsed_val)? != payload_bytes {
        return Err("prepared principal payload is not canonical JSON".to_string());
    }
    let computed_ref = evidence_ref(&payload_bytes);
    if computed_ref != prepared.record_ref {
        return Err(format!(
            "prepared principal recordRef mismatch: declared {}, computed {computed_ref}",
            prepared.record_ref
        ));
    }
    if parsed_val.get("kind").and_then(Value::as_str) != Some("Principal")
        || parsed_val.get("issuer").and_then(Value::as_str) != Some(key_id.as_str())
    {
        return Err("prepared principal payload kind/issuer mismatch".to_string());
    }

    let profile_bytes = decode_strict_base64(&prepared.profile_blob.base64)
        .map_err(|e| format!("invalid prepared principal profileBlob base64: {e}"))?;
    if bytes_ref(&profile_bytes) != prepared.profile_ref
        || prepared.profile_blob.blob_ref != prepared.profile_ref
    {
        return Err("prepared principal profileBlob digest mismatch".to_string());
    }

    let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &payload_bytes);
    let computed_pae_sha256 = {
        use sha2::{Digest, Sha256};
        crate::policy_gate::hex_lower(&Sha256::digest(&pae))
    };
    if computed_pae_sha256 != prepared.pae_sha256 {
        return Err(format!(
            "prepared principal paeSha256 mismatch: declared {}, computed {computed_pae_sha256}",
            prepared.pae_sha256
        ));
    }

    let (canonical_sig, was_normalized) =
        parse_and_normalize_detached_sig(alg, &pub_bytes, &pae, signature_input, is_base64_flag)?;

    let principal = SignedEndpointRecord {
        record_ref: computed_ref,
        envelope: crate::attestation::DsseEnvelope {
            payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
            payload: prepared.payload_b64.clone(),
            signatures: vec![DsseSignature {
                keyid: key_id.clone(),
                sig: BASE64_STANDARD.encode(&canonical_sig),
            }],
        },
    };

    let grant_request = SubmitGrantsRequest {
        records: vec![principal.clone()],
        keys: vec![PublicKeyEntry {
            keyid: key_id.clone(),
            algorithm: alg.as_str().to_string(),
            bytes: BASE64_STANDARD.encode(&pub_bytes),
        }],
        blobs: vec![prepared.profile_blob.clone()],
    };

    Ok(FinalizedPrincipal {
        principal,
        grant_request,
        key_id,
        stream: prepared.stream.clone(),
        profile_ref: prepared.profile_ref.clone(),
        signature_was_normalized: was_normalized,
    })
}

/// Parameters for preparing an unsigned `provenance.r5e.io/v2/Revocation` record for detached signing.
#[derive(Debug, Clone)]
pub struct DetachedRevocationParams {
    pub revoker_pubkey: PublicKeyEntry,
    pub target: String,
    pub stream_prefix: String,
    pub reason: Option<String>,
    pub details: Option<Map<String, Value>>,
    pub actor: String,
    pub revocation_token: Option<String>,
    pub captured_at: Option<chrono::DateTime<chrono::Utc>>,
    pub allow_large_ed25519_pae: bool,
}

/// Unsigned `Revocation` artifact for detached external/hardware signing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreparedRevocation {
    pub format: String,
    #[serde(rename = "recordRef")]
    pub record_ref: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    #[serde(rename = "payloadBase64")]
    pub payload_b64: String,
    #[serde(rename = "paeSha256")]
    pub pae_sha256: String,
    #[serde(rename = "revokerKey")]
    pub revoker_pubkey: PublicKeyEntry,
    pub target: String,
    pub stream: String,
    #[serde(rename = "profileRef")]
    pub profile_ref: String,
    #[serde(rename = "profileBlob")]
    pub profile_blob: BlobEntry,
}

/// Verified & finalized `Revocation` returned by [`finalize_detached_revocation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedRevocation {
    pub revocation: SignedEndpointRecord,
    pub request: SubmitRevocationsRequest,
    pub revoker_key_id: String,
    pub stream: String,
    pub profile_ref: String,
    pub signature_was_normalized: bool,
}

/// Prepares an unsigned `provenance.r5e.io/v2/Revocation` record (`seq: 1, previous: null` on
/// `urn:r5e:stream:<deployment>:authority:revocation:<token>`) and returns `(PreparedRevocation, pae_bytes)`.
pub fn prepare_detached_revocation(
    params: &DetachedRevocationParams,
) -> Result<(PreparedRevocation, Vec<u8>), String> {
    let (alg, pub_bytes, revoker_key_id) = parse_and_verify_v2_pubkey(
        &params.revoker_pubkey.algorithm,
        &params.revoker_pubkey.bytes,
        Some(&params.revoker_pubkey.keyid),
        "revoker_pubkey",
    )?;
    if !is_valid_evidence_ref(&params.target) {
        return Err(format!(
            "invalid revocation target ({}): expected evidence:sha256:<64-lower-hex>",
            params.target
        ));
    }
    if let Some(ref reason) = params.reason {
        if reason.trim().is_empty() {
            return Err("revocation reason must be non-empty when provided".to_string());
        }
    }
    if !params.actor.starts_with("urn:r5e:") {
        return Err(format!(
            "revocation actor ({}) must start with 'urn:r5e:'",
            params.actor
        ));
    }
    let (_, normalized_prefix) = normalize_deployment_stream_prefix(&params.stream_prefix)?;
    let token = if let Some(ref explicit_tok) = params.revocation_token {
        if explicit_tok.is_empty()
            || !explicit_tok
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(format!(
                "invalid revocation_token {explicit_tok:?}: must be non-empty ASCII alphanumeric, '-' or '_'"
            ));
        }
        explicit_tok.clone()
    } else {
        let rand_bytes = generate_os_random_bytes::<16>()?;
        crate::policy_gate::hex_lower(&rand_bytes)
    };

    let revocation_stream = format!("{normalized_prefix}authority:revocation:{token}");
    let schemas = base_v2_schema_map();
    let policy_ref = bytes_ref(b"permit(principal, action, resource);");
    let profile_doc = json!({
        "format": "r5e.capture-profile/v2",
        "schemas": Value::Object(schemas),
        "authority": {
            "bindings": [
                {
                    "streamPrefix": &revocation_stream,
                    "actorPrefixes": ["urn:r5e:"],
                    "issuerKeys": [&revoker_key_id],
                    "sealerKeys": [],
                }
            ],
            "checkpointKeys": [],
        },
        "durability": {
            "failureDomain": "offline-operator-root",
            "onFailure": "refuse",
            "requiredPayloads": "submitted",
        },
        "policyRequiredKinds": [],
        "deploymentPolicyRef": &policy_ref,
    });
    let profile_bytes = encode_canonical_json(&profile_doc)?;
    let profile_ref = bytes_ref(&profile_bytes);

    let now = params.captured_at.unwrap_or_else(chrono::Utc::now);
    let captured_at = now.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);

    let mut body = Map::new();
    body.insert("target".to_string(), Value::String(params.target.clone()));
    if let Some(ref reason) = params.reason {
        body.insert("reason".to_string(), Value::String(reason.clone()));
    }
    if let Some(ref details) = params.details {
        let flat = crate::attestation::normalize_a9_details(details)?;
        if !flat.is_empty() {
            body.insert("details".to_string(), Value::Object(flat));
        }
    }

    let envelope_doc = json!({
        "apiVersion": "provenance.r5e.io/v2",
        "kind": "Revocation",
        "schemaRef": REVOCATION_SCHEMA_REF,
        "profileRef": &profile_ref,
        "issuer": &revoker_key_id,
        "stream": &revocation_stream,
        "seq": 1,
        "previous": null,
        "actor": &params.actor,
        "capturedAt": &captured_at,
        "body": Value::Object(body),
    });
    let payload_bytes = encode_canonical_json(&envelope_doc)?;
    let record_ref = evidence_ref(&payload_bytes);
    let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &payload_bytes);

    if !params.allow_large_ed25519_pae {
        crate::crypto_keys::check_piv_ed25519_pae_limit(alg, pae.len())?;
    }

    let pae_sha256 = {
        use sha2::{Digest, Sha256};
        crate::policy_gate::hex_lower(&Sha256::digest(&pae))
    };

    let profile_blob = BlobEntry {
        blob_ref: profile_ref.clone(),
        media_type: Some("application/json".to_string()),
        base64: BASE64_STANDARD.encode(&profile_bytes),
    };

    Ok((
        PreparedRevocation {
            format: PREPARED_REVOCATION_FORMAT.to_string(),
            record_ref,
            payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
            payload_b64: BASE64_STANDARD.encode(&payload_bytes),
            pae_sha256,
            revoker_pubkey: PublicKeyEntry {
                keyid: revoker_key_id,
                algorithm: alg.as_str().to_string(),
                bytes: BASE64_STANDARD.encode(&pub_bytes),
            },
            target: params.target.clone(),
            stream: revocation_stream,
            profile_ref,
            profile_blob,
        },
        pae,
    ))
}

/// Attaches and verifies an external detached signature (`ed25519 | es256 | es384`, auto-normalizing
/// ASN.1 DER + high-`S`) onto a [`PreparedRevocation`].
pub fn finalize_detached_revocation(
    prepared: &PreparedRevocation,
    signature_input: &[u8],
    is_base64_flag: bool,
) -> Result<FinalizedRevocation, String> {
    if prepared.format != PREPARED_REVOCATION_FORMAT {
        return Err(format!(
            "unsupported prepared revocation format {:?} (expected {PREPARED_REVOCATION_FORMAT:?})",
            prepared.format
        ));
    }
    if prepared.payload_type != PROVENANCE_V2_PAYLOAD_TYPE {
        return Err(format!(
            "unexpected prepared revocation payloadType: {}",
            prepared.payload_type
        ));
    }
    let (alg, pub_bytes, revoker_key_id) = parse_and_verify_v2_pubkey(
        &prepared.revoker_pubkey.algorithm,
        &prepared.revoker_pubkey.bytes,
        Some(&prepared.revoker_pubkey.keyid),
        "prepared.revokerKey",
    )?;
    let payload_bytes = decode_strict_base64(&prepared.payload_b64)
        .map_err(|e| format!("invalid prepared revocation payloadBase64: {e}"))?;
    let parsed_val: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("prepared revocation payload is not valid JSON: {e}"))?;
    if encode_canonical_json(&parsed_val)? != payload_bytes {
        return Err("prepared revocation payload is not canonical JSON".to_string());
    }
    let computed_ref = evidence_ref(&payload_bytes);
    if computed_ref != prepared.record_ref {
        return Err(format!(
            "prepared revocation recordRef mismatch: declared {}, computed {computed_ref}",
            prepared.record_ref
        ));
    }
    if parsed_val.get("kind").and_then(Value::as_str) != Some("Revocation")
        || parsed_val.get("issuer").and_then(Value::as_str) != Some(revoker_key_id.as_str())
    {
        return Err("prepared revocation payload kind/issuer mismatch".to_string());
    }
    let profile_bytes = decode_strict_base64(&prepared.profile_blob.base64)
        .map_err(|e| format!("invalid prepared revocation profileBlob base64: {e}"))?;
    if bytes_ref(&profile_bytes) != prepared.profile_ref
        || prepared.profile_blob.blob_ref != prepared.profile_ref
    {
        return Err("prepared revocation profileBlob digest mismatch".to_string());
    }

    let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &payload_bytes);
    let computed_pae_sha256 = {
        use sha2::{Digest, Sha256};
        crate::policy_gate::hex_lower(&Sha256::digest(&pae))
    };
    if computed_pae_sha256 != prepared.pae_sha256 {
        return Err(format!(
            "prepared revocation paeSha256 mismatch: declared {}, computed {computed_pae_sha256}",
            prepared.pae_sha256
        ));
    }

    let (canonical_sig, was_normalized) =
        parse_and_normalize_detached_sig(alg, &pub_bytes, &pae, signature_input, is_base64_flag)?;

    let revocation = SignedEndpointRecord {
        record_ref: computed_ref,
        envelope: crate::attestation::DsseEnvelope {
            payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
            payload: prepared.payload_b64.clone(),
            signatures: vec![DsseSignature {
                keyid: revoker_key_id.clone(),
                sig: BASE64_STANDARD.encode(&canonical_sig),
            }],
        },
    };

    let request = SubmitRevocationsRequest {
        records: vec![revocation.clone()],
        keys: vec![PublicKeyEntry {
            keyid: revoker_key_id.clone(),
            algorithm: alg.as_str().to_string(),
            bytes: BASE64_STANDARD.encode(&pub_bytes),
        }],
        blobs: vec![prepared.profile_blob.clone()],
    };

    Ok(FinalizedRevocation {
        revocation,
        request,
        revoker_key_id,
        stream: prepared.stream.clone(),
        profile_ref: prepared.profile_ref.clone(),
        signature_was_normalized: was_normalized,
    })
}

/// Merges multiple [`SubmitGrantsRequest`] sets (such as `[Endorsement, Principal]` or delegated
/// `[Endorsement, Endorsement]`) into one deduplicated `SubmitGrantsRequest` (`<= 16` records,
/// `<= 256 KiB`).
pub fn merge_submit_grants_requests(
    sets: &[SubmitGrantsRequest],
) -> Result<SubmitGrantsRequest, String> {
    let mut records: Vec<SignedEndpointRecord> = Vec::new();
    let mut keys: Vec<PublicKeyEntry> = Vec::new();
    let mut blobs: Vec<BlobEntry> = Vec::new();

    for set in sets {
        for rec in &set.records {
            if let Some(existing) = records.iter().find(|r| r.record_ref == rec.record_ref) {
                if existing != rec {
                    return Err(format!(
                        "conflicting envelope for record ref {}",
                        rec.record_ref
                    ));
                }
            } else {
                records.push(rec.clone());
            }
        }
        for k in &set.keys {
            if let Some(existing) = keys.iter().find(|ek| ek.keyid == k.keyid) {
                if existing != k {
                    return Err(format!("conflicting public key entry for {}", k.keyid));
                }
            } else {
                keys.push(k.clone());
            }
        }
        for b in &set.blobs {
            if let Some(existing) = blobs.iter().find(|eb| eb.blob_ref == b.blob_ref) {
                if existing.base64 != b.base64 {
                    return Err(format!("conflicting blob bytes for {}", b.blob_ref));
                }
            } else {
                blobs.push(b.clone());
            }
        }
    }

    if records.is_empty() {
        return Err("merged SubmitGrantsRequest must contain at least 1 record".to_string());
    }
    if records.len() > MAX_REVOCATION_RECORDS {
        return Err(format!(
            "merged SubmitGrantsRequest has {} records (max {MAX_REVOCATION_RECORDS})",
            records.len()
        ));
    }
    let merged = SubmitGrantsRequest {
        records,
        keys,
        blobs,
    };
    let merged_bytes = encode_canonical_json(
        &serde_json::to_value(&merged).map_err(|e| format!("serialize merged grants: {e}"))?,
    )?;
    if merged_bytes.len() > MAX_REVOCATION_BODY_BYTES {
        return Err(format!(
            "merged SubmitGrantsRequest is {} bytes (max {MAX_REVOCATION_BODY_BYTES})",
            merged_bytes.len()
        ));
    }
    Ok(merged)
}
