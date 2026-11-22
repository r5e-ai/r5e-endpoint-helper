//! Two-signer Retention Hold Release Ceremony (`A7-content-retention-and-disposition.md` §3.2):
//!
//! 1. **Offline / Status-Clamped Counsel Grant (`grant-releaser`)**:
//!    Builds a canonical `{records, keys, blobs}` grant set (`SubmitGrantsRequest`) signed by a
//!    current deployment root granting a counsel/releaser key `Endorsement` over
//!    `provenance.r5e.io/v2/RetentionHoldRelease` on `urn:r5e:stream:<deployment>:retention`
//!    (`mayEndorse: false`, `actorPrefixes` and `actsFor` omitted by default so the gateway's
//!    `:retention` envelope `actor` is covered cleanly).
//!    Sits at `seq: 1, previous: null` on a collision-free sub-stream
//!    `urn:r5e:stream:<deployment>:authority:root:<last_hex>:grant:<16hex_token>` with an exact
//!    matching capture-profile `streamPrefix`, satisfying `authority:root:<last_hex>` prefix
//!    admission without colliding with the root's gateway grant at `seq: 1`.
//!
//! 2. **Bearer-Authenticated Two-Step Hold-Release Ceremony (`release-hold`)**:
//!    - `POST /v1/evidence/retention/holds/release/prepare`
//!    - Offline pre-signing verification of `payloadType`, canonical JSON, `apiVersion`,
//!      `kind == "RetentionHoldRelease"`, distinct recorder `issuer`, and exact `body.{hold, reason, releasedBy}`
//!      match before counsel signs anything.
//!    - DSSEv1 PAE Ed25519 co-signing (`Signer 2`) and `POST /v1/evidence/retention/holds/release/finalize`
//!      carrying optional `authority` (`{records, keys, blobs}`).

use crate::attestation::{
    base_v2_schema_map, bytes_ref, decode_strict_base64, dsse_pae, ed25519_key_id,
    encode_canonical_json, evidence_ref, generate_os_random_bytes, sign_v2_record_multi, BlobEntry,
    DsseSignature, PublicKeyEntry, SignedEndpointRecord, SubjectPublicKey,
    PROVENANCE_V2_PAYLOAD_TYPE,
};
use crate::claim_http::{
    ceil_to_micros, is_valid_bytes_ref, is_valid_evidence_ref, is_valid_key_id, is_valid_kind_path,
    is_valid_slug_token, is_valid_uri_identity, SubmitGrantsRequest,
};
use crate::http_transport::send_http11_request;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::fmt;
use std::time::Duration;

pub const RETENTION_HOLD_RELEASE_KIND: &str = "provenance.r5e.io/v2/RetentionHoldRelease";
pub const PREPARE_HOLD_RELEASE_PATH: &str = "/v1/evidence/retention/holds/release/prepare";
pub const FINALIZE_HOLD_RELEASE_PATH: &str = "/v1/evidence/retention/holds/release/finalize";

/// Normalizes a kind argument: bare `"RetentionHoldRelease"` expands to
/// `"provenance.r5e.io/v2/RetentionHoldRelease"`, while full `<pkg>/v<N>/<Kind>` paths pass through.
pub fn normalize_releaser_kind(raw: &str) -> String {
    let trimmed = raw.trim();
    if !trimmed.is_empty() && !trimmed.contains('/') {
        format!("provenance.r5e.io/v2/{trimmed}")
    } else {
        trimmed.to_string()
    }
}

/// Extracts and validates `<deployment>` from either a bare deployment slug (`"meridian-prod"`)
/// or a stream prefix (`"urn:r5e:stream:meridian-prod"` / `"urn:r5e:stream:meridian-prod:"`).
pub fn extract_deployment_slug(deployment_or_prefix: &str) -> Result<String, String> {
    let trimmed = deployment_or_prefix.trim();
    let candidate = if let Some(after_scheme) = trimmed.strip_prefix("urn:r5e:stream:") {
        after_scheme.trim_end_matches(':')
    } else {
        trimmed
    };
    if candidate.is_empty() || candidate.contains(':') || !is_valid_slug_token(candidate, true) {
        return Err(format!(
            "invalid deployment or stream prefix {deployment_or_prefix:?}: expected lowercase deployment slug or 'urn:r5e:stream:<deployment>:'"
        ));
    }
    Ok(candidate.to_string())
}

/// Parameters for building a root `Endorsement` granting a counsel / hold-releaser key standing
/// on `urn:r5e:stream:<deployment>:retention`.
#[derive(Debug, Clone)]
pub struct ReleaserGrantParams {
    /// Subject `key:ed25519:sha256:...` identifier of the counsel / releaser key.
    pub releaser_key_id: String,
    /// Deployment slug (`"acme-prod"`) or stream prefix (`"urn:r5e:stream:acme-prod:"`).
    pub deployment: String,
    /// Granted kind paths (defaults to `["provenance.r5e.io/v2/RetentionHoldRelease"]`).
    pub kinds: Vec<String>,
    /// Optional `Endorsement.body.actorPrefixes`. Omitted by default (`None`) because
    /// `RetentionHoldRelease.actor` on `:retention` is the gateway's actor (`A7` §3.2) and
    /// `Endorsement.json` marks `actorPrefixes` `nonEmpty` when present.
    pub actor_prefixes: Option<Vec<String>>,
    /// Optional `Endorsement.body.actsFor` URI. Omitted by default (`None`).
    pub acts_for: Option<String>,
    /// Envelope `actor` of the root's `Endorsement` (must start with `"urn:r5e:"`).
    pub actor: String,
    /// Optional token suffix for `urn:r5e:stream:<deployment>:authority:root:<root_hex>:grant:<token>`.
    /// When `None`, 8 OS-random bytes formatted as 16 lowercase hex chars are generated.
    pub grant_token: Option<String>,
    /// Stream sequence number (default `1`).
    pub seq: u64,
    /// Required when `seq > 1`; must be `None` when `seq == 1`.
    pub previous: Option<String>,
    /// Optional explicit `capturedAt` instant; defaults to `Utc::now()`.
    pub captured_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Optional explicit RFC 3339 `Endorsement.body.notBefore` override.
    pub not_before_override: Option<String>,
    /// Optional `GET /v1/deployment` start-head floor: clamps both `capturedAt` and default
    /// `notBefore` to `>= ceil_to_micros(floor)` with `SecondsFormat::Micros`.
    pub start_head_floor: Option<chrono::DateTime<chrono::Utc>>,
    /// Validity window in seconds (`notAfter = effective_captured_at + ttl_seconds`, default 30d).
    pub ttl_seconds: u64,
}

impl ReleaserGrantParams {
    pub fn new(releaser_key_id: impl Into<String>, deployment: impl Into<String>) -> Self {
        Self {
            releaser_key_id: releaser_key_id.into(),
            deployment: deployment.into(),
            kinds: vec![RETENTION_HOLD_RELEASE_KIND.to_string()],
            actor_prefixes: None,
            acts_for: None,
            actor: "urn:r5e:operator:root".to_string(),
            grant_token: None,
            seq: 1,
            previous: None,
            captured_at: None,
            not_before_override: None,
            start_head_floor: None,
            ttl_seconds: 86_400 * 30,
        }
    }
}

/// Output of `build_releaser_grant`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltReleaserGrant {
    pub root_key_id: String,
    pub releaser_key_id: String,
    pub deployment: String,
    pub grant_stream: String,
    pub retention_stream: String,
    pub profile_ref: String,
    pub captured_at: String,
    pub not_before: String,
    pub not_after: String,
    pub endorsement: SignedEndpointRecord,
    pub request: SubmitGrantsRequest,
}

/// Builds a canonical `{records, keys, blobs}` grant set (`SubmitGrantsRequest`) signed by
/// `root_signing_key` granting `params.releaser_key_id` standing on
/// `urn:r5e:stream:<deployment>:retention` (`mayEndorse: false`).
pub fn build_releaser_grant(
    root_signing_key: &SigningKey,
    params: &ReleaserGrantParams,
) -> Result<BuiltReleaserGrant, String> {
    let root_pub_bytes = root_signing_key.verifying_key().to_bytes();
    let root_key_id = ed25519_key_id(&root_pub_bytes);
    let root_pub_b64 = BASE64_STANDARD.encode(root_pub_bytes);
    let root_hex = crate::crypto_keys::key_id_sha256_hex(&root_key_id)?;

    if !is_valid_key_id(&params.releaser_key_id) {
        return Err(format!(
            "invalid releaser key ID ({}): expected key:<alg>:sha256:<64-lower-hex>",
            params.releaser_key_id
        ));
    }
    if params.releaser_key_id == root_key_id {
        return Err("releaser key ID must be distinct from root signing key ID".to_string());
    }

    let deployment = extract_deployment_slug(&params.deployment)?;

    if params.seq == 0 {
        return Err("releaser grant seq must be >= 1".to_string());
    }
    if params.seq == 1 && params.previous.is_some() {
        return Err("releaser grant seq 1 must have previous = null".to_string());
    }
    if params.seq > 1 && params.previous.is_none() {
        return Err(
            "releaser grant seq > 1 requires --previous evidence:sha256:... reference".to_string(),
        );
    }
    if let Some(ref prev) = params.previous {
        if !is_valid_evidence_ref(prev) {
            return Err(format!("invalid releaser grant previous reference: {prev}"));
        }
    }

    if params.kinds.is_empty() {
        return Err("releaser grant kinds must be non-empty".to_string());
    }
    let mut normalized_kinds = Vec::with_capacity(params.kinds.len());
    for raw_k in &params.kinds {
        let k = normalize_releaser_kind(raw_k);
        if !is_valid_kind_path(&k) {
            return Err(format!("invalid kind path in releaser grant: {raw_k:?}"));
        }
        if !normalized_kinds.iter().any(|existing| existing == &k) {
            normalized_kinds.push(k);
        }
    }

    if let Some(ref aps) = params.actor_prefixes {
        for ap in aps {
            if ap.trim().is_empty() {
                return Err(
                    "releaser grant actorPrefixes entries must be non-empty strings".to_string(),
                );
            }
        }
    }
    if let Some(ref acts_for) = params.acts_for {
        if !is_valid_uri_identity(acts_for) {
            return Err(format!(
                "invalid releaser grant actsFor URI ({acts_for}): expected RFC 3986 <scheme>:<non-empty>"
            ));
        }
    }
    if !params.actor.starts_with("urn:r5e:") {
        return Err(format!(
            "releaser grant actor ({}) must start with 'urn:r5e:' to match capture profile authority binding",
            params.actor
        ));
    }
    if params.ttl_seconds == 0 {
        return Err("releaser grant ttl_seconds must be > 0".to_string());
    }

    let token = if let Some(ref explicit_tok) = params.grant_token {
        if explicit_tok.is_empty()
            || !explicit_tok
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(format!(
                "invalid grant_token {explicit_tok:?}: must be non-empty ASCII alphanumeric, '-' or '_'"
            ));
        }
        explicit_tok.clone()
    } else {
        let rand_bytes = generate_os_random_bytes::<8>()?;
        crate::policy_gate::hex_lower(&rand_bytes)
    };

    let grant_stream =
        format!("urn:r5e:stream:{deployment}:authority:root:{root_hex}:grant:{token}");
    let retention_stream = format!("urn:r5e:stream:{deployment}:retention");

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
                    "streamPrefix": &grant_stream,
                    "actorPrefixes": ["urn:r5e:"],
                    "issuerKeys": [&root_key_id],
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

    let floor_micros = params.start_head_floor.map(ceil_to_micros);
    let base_now = params.captured_at.unwrap_or_else(chrono::Utc::now);
    let effective_now = match floor_micros {
        Some(fl) => std::cmp::max(base_now, fl),
        None => base_now,
    };

    let captured_at = effective_now.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let not_after = (effective_now + chrono::Duration::seconds(params.ttl_seconds as i64))
        .to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let not_after_utc = chrono::DateTime::parse_from_rfc3339(&not_after)
        .expect("serialized not_after RFC3339")
        .with_timezone(&chrono::Utc);

    let not_before = if let Some(ref nb) = params.not_before_override {
        if nb.ends_with("-00:00") {
            return Err(format!(
                "invalid releaser grant notBefore ({nb}): unknown -00:00 offset is outside Provenance v2 Timestamp profile"
            ));
        }
        let parsed_nb = chrono::DateTime::parse_from_rfc3339(nb)
            .map_err(|e| format!("invalid releaser grant notBefore RFC3339 timestamp ({nb}): {e}"))?
            .with_timezone(&chrono::Utc);
        if parsed_nb > not_after_utc {
            return Err(format!(
                "releaser grant notBefore ({nb}) must be <= notAfter ({not_after})"
            ));
        }
        nb.clone()
    } else {
        let default_nb_dt = match floor_micros {
            Some(fl) => std::cmp::max(effective_now - chrono::Duration::seconds(60), fl),
            None => effective_now - chrono::Duration::seconds(60),
        };
        default_nb_dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
    };

    let mut body = Map::new();
    body.insert(
        "subject".to_string(),
        Value::String(params.releaser_key_id.clone()),
    );
    body.insert("kinds".to_string(), json!(&normalized_kinds));
    body.insert("streamPrefixes".to_string(), json!([&retention_stream]));
    if let Some(ref aps) = params.actor_prefixes {
        if !aps.is_empty() {
            body.insert("actorPrefixes".to_string(), json!(aps));
        }
    }
    if let Some(ref acts_for) = params.acts_for {
        body.insert("actsFor".to_string(), Value::String(acts_for.clone()));
    }
    body.insert("mayEndorse".to_string(), Value::Bool(false));
    body.insert("notBefore".to_string(), Value::String(not_before.clone()));
    body.insert("notAfter".to_string(), Value::String(not_after.clone()));

    let prev_val = match &params.previous {
        Some(p) => Value::String(p.clone()),
        None => Value::Null,
    };

    let endorsement = sign_v2_record_multi(
        &[root_signing_key],
        json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": &endorsement_schema,
            "profileRef": &profile_ref,
            "stream": &grant_stream,
            "seq": params.seq,
            "previous": prev_val,
            "actor": &params.actor,
            "capturedAt": &captured_at,
            "body": Value::Object(body),
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
            blob_ref: profile_ref.clone(),
            media_type: Some("application/json".to_string()),
            base64: BASE64_STANDARD.encode(&profile_bytes),
        }],
    };

    Ok(BuiltReleaserGrant {
        root_key_id,
        releaser_key_id: params.releaser_key_id.clone(),
        deployment,
        grant_stream,
        retention_stream,
        profile_ref,
        captured_at,
        not_before,
        not_after,
        endorsement,
        request,
    })
}

/// Bearer-authenticated HTTP client configuration for `release-hold`.
///
/// Custom `Debug` implementation redacts `bearer_token` so bearer credentials never appear in logs.
#[derive(Clone)]
pub struct HoldReleaseClientConfig {
    pub gateway_base_url: String,
    pub bearer_token: String,
    pub timeout: Duration,
}

impl HoldReleaseClientConfig {
    pub fn new(gateway_base_url: impl Into<String>, bearer_token: impl Into<String>) -> Self {
        Self {
            gateway_base_url: gateway_base_url.into(),
            bearer_token: bearer_token.into(),
            timeout: Duration::from_secs(15),
        }
    }
}

impl fmt::Debug for HoldReleaseClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HoldReleaseClientConfig")
            .field("gateway_base_url", &self.gateway_base_url)
            .field("bearer_token", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoldReleaseError {
    /// `400` (`malformed_request`)
    BadRequest {
        error_code: Option<String>,
        body: String,
    },
    /// `401` (`unauthorized` / missing or invalid bearer token)
    Unauthorized {
        error_code: Option<String>,
        body: String,
    },
    /// `403` (`forbidden` / insufficient scope)
    Forbidden {
        error_code: Option<String>,
        body: String,
    },
    /// `404` (`not_found`)
    NotFound {
        error_code: Option<String>,
        body: String,
    },
    /// `409` (`retention_stream_moved`, `not_claimed`, etc.)
    Conflict {
        error_code: Option<String>,
        body: String,
    },
    /// `413` (`too_large`)
    PayloadTooLarge {
        error_code: Option<String>,
        body: String,
    },
    /// `422` (`releaser_has_no_standing`, `hold_already_released`, `no_such_hold`,
    /// `ticket_expired`, `ticket_does_not_match`, `bad_signature`, etc.)
    Unprocessable {
        error_code: Option<String>,
        body: String,
    },
    /// Other unexpected HTTP status (`500`, `503`, etc.)
    HttpStatus {
        status: u16,
        error_code: Option<String>,
        body: String,
    },
    /// Local pre-signing or post-finalization cryptographic / payload verification refusal
    Validation(String),
    /// Socket, HTTP framing, or JSON parse failure
    Transport(String),
}

impl HoldReleaseError {
    pub fn error_code(&self) -> Option<&str> {
        match self {
            Self::BadRequest { error_code, .. }
            | Self::Unauthorized { error_code, .. }
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
            Self::Unauthorized { .. } => Some(401),
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

impl fmt::Display for HoldReleaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadRequest { error_code, body } => {
                write!(f, "bad hold-release request (400 {:?}): {body}", error_code)
            }
            Self::Unauthorized { error_code, body } => {
                write!(
                    f,
                    "hold-release unauthorized (401 {:?}): {body}",
                    error_code
                )
            }
            Self::Forbidden { error_code, body } => {
                write!(f, "hold-release forbidden (403 {:?}): {body}", error_code)
            }
            Self::NotFound { error_code, body } => {
                write!(f, "hold-release not found (404 {:?}): {body}", error_code)
            }
            Self::Conflict { error_code, body } => {
                write!(f, "hold-release conflict (409 {:?}): {body}", error_code)
            }
            Self::PayloadTooLarge { error_code, body } => {
                write!(
                    f,
                    "hold-release payload too large (413 {:?}): {body}",
                    error_code
                )
            }
            Self::Unprocessable { error_code, body } => {
                write!(f, "hold-release refused (422 {:?}): {body}", error_code)
            }
            Self::HttpStatus {
                status,
                error_code,
                body,
            } => write!(f, "hold-release HTTP {status} ({:?}): {body}", error_code),
            Self::Validation(msg) => write!(f, "hold-release validation refused: {msg}"),
            Self::Transport(msg) => write!(f, "hold-release transport error: {msg}"),
        }
    }
}

impl std::error::Error for HoldReleaseError {}

pub fn classify_hold_release_error(status: u16, body_bytes: &[u8]) -> HoldReleaseError {
    let body = String::from_utf8_lossy(body_bytes).into_owned();
    let error_code = serde_json::from_slice::<Value>(body_bytes)
        .ok()
        .and_then(|v| {
            v.get("error")
                .or_else(|| v.get("code"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        });
    match status {
        400 => HoldReleaseError::BadRequest { error_code, body },
        401 => HoldReleaseError::Unauthorized { error_code, body },
        403 => HoldReleaseError::Forbidden { error_code, body },
        404 => HoldReleaseError::NotFound { error_code, body },
        409 => HoldReleaseError::Conflict { error_code, body },
        413 => HoldReleaseError::PayloadTooLarge { error_code, body },
        422 => HoldReleaseError::Unprocessable { error_code, body },
        other => HoldReleaseError::HttpStatus {
            status: other,
            error_code,
            body,
        },
    }
}

/// Request body for `POST /v1/evidence/retention/holds/release/prepare`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrepareHoldReleaseRequest {
    pub hold: String,
    pub reason: String,
    #[serde(rename = "releasedBy")]
    pub released_by: SubjectPublicKey,
}

/// Response `200` from `POST /v1/evidence/retention/holds/release/prepare`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreparedHoldReleaseResponse {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub payload: String,
    pub ticket: String,
}

/// Request body for `POST /v1/evidence/retention/holds/release/finalize`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalizeHoldReleaseRequest {
    pub payload: String,
    pub ticket: String,
    pub signature: DsseSignature,
    #[serde(rename = "releasedBy")]
    pub released_by: SubjectPublicKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<SubmitGrantsRequest>,
}

/// Response `201` (or `200`) from `POST /v1/evidence/retention/holds/release/finalize`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalizedHoldReleaseResponse {
    pub release: String,
    pub seq: u64,
    pub hold: String,
}

/// Structured offline inspection of a gateway-prepared `RetentionHoldRelease` draft verified
/// prior to signing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreparedHoldReleaseInspection {
    #[serde(rename = "expectedReleaseRef")]
    pub expected_release_ref: String,
    #[serde(rename = "recorderIssuer")]
    pub recorder_issuer: String,
    pub stream: String,
    pub seq: u64,
    #[serde(rename = "capturedAt")]
    pub captured_at: String,
    pub hold: String,
    pub reason: String,
    #[serde(rename = "releasedBy")]
    pub released_by: String,
}

/// Result of offline pre-signing verification and DSSEv1 PAE co-signing of a prepared hold release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPreparedHoldRelease {
    pub finalize_request: FinalizeHoldReleaseRequest,
    pub inspection: PreparedHoldReleaseInspection,
}

/// Complete outcome of `execute_release_hold_ceremony`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldReleaseCeremonyOutcome {
    pub inspection: PreparedHoldReleaseInspection,
    pub finalized: FinalizedHoldReleaseResponse,
}

/// Verifies a gateway-prepared `RetentionHoldRelease` draft locally BEFORE signing with counsel's
/// Ed25519 private key (`Signer 2`):
/// 1. Validates local request fields (`hold` evidence ref, non-empty `reason`, matching `releasedBy` key).
/// 2. Checks `ticket` is non-empty and `payloadType == "application/vnd.r5e.provenance-evidence+json;v=2"`.
/// 3. Strict-base64 decodes `payload`, parses JSON, and checks canonical JSON (`VERIFY-V2` §2.1).
/// 4. Checks `apiVersion == "provenance.r5e.io/v2"` and `kind == "RetentionHoldRelease"`.
/// 5. Checks `issuer` is a valid key ID distinct from `releaser_keyid` (`RetentionHoldRelease` 2-party invariant).
/// 6. Checks `body.hold == req.hold`, `body.reason == req.reason`, and `body.releasedBy == releaser_keyid`.
/// 7. Signs `dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &payload_bytes)` with `releaser_signing_key`.
pub fn verify_and_countersign_prepared_hold_release(
    releaser_signing_key: &SigningKey,
    req: &PrepareHoldReleaseRequest,
    prepared: &PreparedHoldReleaseResponse,
    authority: Option<SubmitGrantsRequest>,
) -> Result<VerifiedPreparedHoldRelease, String> {
    if !is_valid_evidence_ref(&req.hold) {
        return Err(format!(
            "invalid hold reference ({}): expected evidence:sha256:<64-lower-hex>",
            req.hold
        ));
    }
    if req.reason.trim().is_empty() {
        return Err("hold-release reason must be non-empty".to_string());
    }

    let releaser_pub_bytes = releaser_signing_key.verifying_key().to_bytes();
    let releaser_keyid = ed25519_key_id(&releaser_pub_bytes);
    let releaser_pub_b64 = BASE64_STANDARD.encode(releaser_pub_bytes);

    if req.released_by.algorithm != "ed25519" || req.released_by.bytes != releaser_pub_b64 {
        return Err(
            "prepare request releasedBy public key does not match local releaser signing key"
                .to_string(),
        );
    }

    if let Some(ref auth) = authority {
        if auth.records.is_empty() {
            return Err("carried authority grant set must contain at least 1 record".to_string());
        }
        let auth_val =
            serde_json::to_value(auth).map_err(|e| format!("invalid authority JSON: {e}"))?;
        encode_canonical_json(&auth_val)
            .map_err(|e| format!("carried authority grant set fails canonical JSON check: {e}"))?;
    }

    if prepared.ticket.trim().is_empty() {
        return Err("prepared hold-release response is missing a non-empty ticket".to_string());
    }
    if prepared.payload_type != PROVENANCE_V2_PAYLOAD_TYPE {
        return Err(format!(
            "refusing to co-sign unexpected payloadType {:?} (expected {PROVENANCE_V2_PAYLOAD_TYPE:?})",
            prepared.payload_type
        ));
    }

    let payload_bytes = decode_strict_base64(&prepared.payload)
        .map_err(|e| format!("invalid prepared payload base64: {e}"))?;
    let payload_val: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("prepared payload is not valid JSON: {e}"))?;
    let canonical_bytes = encode_canonical_json(&payload_val)
        .map_err(|e| format!("prepared payload fails canonical JSON rules: {e}"))?;
    if canonical_bytes != payload_bytes {
        return Err("prepared payload is not canonical JSON (VERIFY-V2 §2.1)".to_string());
    }

    let api_version = payload_val
        .get("apiVersion")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let kind = payload_val
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if api_version != "provenance.r5e.io/v2" || kind != "RetentionHoldRelease" {
        return Err(format!(
            "refusing to co-sign non-RetentionHoldRelease record ({api_version}/{kind})"
        ));
    }

    let schema_ref = payload_val
        .get("schemaRef")
        .and_then(Value::as_str)
        .ok_or_else(|| "prepared RetentionHoldRelease missing string schemaRef".to_string())?;
    if !is_valid_bytes_ref(schema_ref) {
        return Err(format!(
            "prepared RetentionHoldRelease has invalid schemaRef: {schema_ref}"
        ));
    }

    let issuer = payload_val
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or_else(|| "prepared RetentionHoldRelease missing string issuer".to_string())?;
    if !is_valid_key_id(issuer) {
        return Err(format!(
            "prepared RetentionHoldRelease has invalid issuer key ID: {issuer}"
        ));
    }
    if issuer == releaser_keyid {
        return Err(format!(
            "prepared RetentionHoldRelease issuer ({issuer}) equals releaser key ({releaser_keyid}); recorder and releaser must be distinct keys"
        ));
    }

    let stream = payload_val
        .get("stream")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "prepared RetentionHoldRelease missing non-empty stream".to_string())?
        .to_string();
    let seq = payload_val
        .get("seq")
        .and_then(Value::as_u64)
        .filter(|&n| n >= 1)
        .ok_or_else(|| "prepared RetentionHoldRelease missing seq >= 1".to_string())?;
    let captured_at = payload_val
        .get("capturedAt")
        .and_then(Value::as_str)
        .ok_or_else(|| "prepared RetentionHoldRelease missing string capturedAt".to_string())?
        .to_string();
    chrono::DateTime::parse_from_rfc3339(&captured_at)
        .map_err(|e| format!("prepared RetentionHoldRelease has invalid capturedAt: {e}"))?;

    let body = payload_val
        .get("body")
        .and_then(Value::as_object)
        .ok_or_else(|| "prepared RetentionHoldRelease missing body object".to_string())?;
    for k in body.keys() {
        if !matches!(k.as_str(), "hold" | "releasedBy" | "reason" | "details") {
            return Err(format!(
                "unexpected property in RetentionHoldRelease.body: {k}"
            ));
        }
    }

    let draft_hold = body
        .get("hold")
        .and_then(Value::as_str)
        .ok_or_else(|| "prepared RetentionHoldRelease.body missing string hold".to_string())?;
    if draft_hold != req.hold {
        return Err(format!(
            "refusing to co-sign mismatched body.hold: requested {}, gateway prepared {draft_hold}",
            req.hold
        ));
    }

    let draft_reason = body
        .get("reason")
        .and_then(Value::as_str)
        .ok_or_else(|| "prepared RetentionHoldRelease.body missing string reason".to_string())?;
    if draft_reason != req.reason {
        return Err(format!(
            "refusing to co-sign mismatched body.reason: requested {:?}, gateway prepared {:?}",
            req.reason, draft_reason
        ));
    }

    let draft_released_by = body
        .get("releasedBy")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            "prepared RetentionHoldRelease.body missing string releasedBy".to_string()
        })?;
    if draft_released_by != releaser_keyid {
        return Err(format!(
            "refusing to co-sign mismatched body.releasedBy: expected {releaser_keyid}, gateway prepared {draft_released_by}"
        ));
    }

    let expected_release_ref = evidence_ref(&payload_bytes);
    let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &payload_bytes);
    let sig = releaser_signing_key.sign(&pae);

    let finalize_request = FinalizeHoldReleaseRequest {
        payload: prepared.payload.clone(),
        ticket: prepared.ticket.clone(),
        signature: DsseSignature {
            keyid: releaser_keyid.clone(),
            sig: BASE64_STANDARD.encode(sig.to_bytes()),
        },
        released_by: SubjectPublicKey {
            algorithm: "ed25519".to_string(),
            bytes: releaser_pub_b64,
        },
        authority,
    };

    Ok(VerifiedPreparedHoldRelease {
        finalize_request,
        inspection: PreparedHoldReleaseInspection {
            expected_release_ref,
            recorder_issuer: issuer.to_string(),
            stream,
            seq,
            captured_at,
            hold: draft_hold.to_string(),
            reason: draft_reason.to_string(),
            released_by: releaser_keyid,
        },
    })
}

/// `POST /v1/evidence/retention/holds/release/prepare`
pub fn prepare_hold_release(
    cfg: &HoldReleaseClientConfig,
    req: &PrepareHoldReleaseRequest,
) -> Result<PreparedHoldReleaseResponse, HoldReleaseError> {
    let req_val = serde_json::to_value(req)
        .map_err(|e| HoldReleaseError::Transport(format!("serialize prepare request: {e}")))?;
    let body = encode_canonical_json(&req_val).map_err(HoldReleaseError::Validation)?;
    let (status, resp_bytes) = post_json_bearer_http11(cfg, PREPARE_HOLD_RELEASE_PATH, &body)?;
    if status != 200 {
        return Err(classify_hold_release_error(status, &resp_bytes));
    }
    serde_json::from_slice(&resp_bytes).map_err(|e| {
        HoldReleaseError::Transport(format!("parse prepare hold-release 200 JSON: {e}"))
    })
}

/// `POST /v1/evidence/retention/holds/release/finalize`
pub fn finalize_hold_release(
    cfg: &HoldReleaseClientConfig,
    req: &FinalizeHoldReleaseRequest,
) -> Result<FinalizedHoldReleaseResponse, HoldReleaseError> {
    let req_val = serde_json::to_value(req)
        .map_err(|e| HoldReleaseError::Transport(format!("serialize finalize request: {e}")))?;
    let body = encode_canonical_json(&req_val).map_err(HoldReleaseError::Validation)?;
    let (status, resp_bytes) = post_json_bearer_http11(cfg, FINALIZE_HOLD_RELEASE_PATH, &body)?;
    if status != 201 && status != 200 {
        return Err(classify_hold_release_error(status, &resp_bytes));
    }
    serde_json::from_slice(&resp_bytes).map_err(|e| {
        HoldReleaseError::Transport(format!("parse finalize hold-release {status} JSON: {e}"))
    })
}

/// Executes the complete 2-step `release-hold` ceremony (`prepare` -> offline verification &
/// DSSE PAE signing -> `finalize` + post-finalize receipt check).
pub fn execute_release_hold_ceremony(
    cfg: &HoldReleaseClientConfig,
    releaser_signing_key: &SigningKey,
    hold: impl Into<String>,
    reason: impl Into<String>,
    authority: Option<SubmitGrantsRequest>,
) -> Result<HoldReleaseCeremonyOutcome, HoldReleaseError> {
    let hold_str = hold.into();
    let reason_str = reason.into();
    if !is_valid_evidence_ref(&hold_str) {
        return Err(HoldReleaseError::Validation(format!(
            "invalid --hold reference ({hold_str}): expected evidence:sha256:<64-lower-hex>"
        )));
    }
    if reason_str.trim().is_empty() {
        return Err(HoldReleaseError::Validation(
            "--reason must be non-empty".to_string(),
        ));
    }
    if cfg.bearer_token.trim().is_empty() {
        return Err(HoldReleaseError::Validation(
            "bearer token must be non-empty".to_string(),
        ));
    }

    let releaser_pub_b64 = BASE64_STANDARD.encode(releaser_signing_key.verifying_key().to_bytes());
    let prepare_req = PrepareHoldReleaseRequest {
        hold: hold_str.clone(),
        reason: reason_str,
        released_by: SubjectPublicKey {
            algorithm: "ed25519".to_string(),
            bytes: releaser_pub_b64,
        },
    };

    let prepared = prepare_hold_release(cfg, &prepare_req)?;
    let verified = verify_and_countersign_prepared_hold_release(
        releaser_signing_key,
        &prepare_req,
        &prepared,
        authority,
    )
    .map_err(HoldReleaseError::Validation)?;

    let finalized = finalize_hold_release(cfg, &verified.finalize_request)?;
    if !is_valid_evidence_ref(&finalized.release) {
        return Err(HoldReleaseError::Validation(format!(
            "finalize response returned invalid release evidence ref: {}",
            finalized.release
        )));
    }
    if finalized.release != verified.inspection.expected_release_ref {
        return Err(HoldReleaseError::Validation(format!(
            "finalize response release ref ({}) does not match signed payload digest ({})",
            finalized.release, verified.inspection.expected_release_ref
        )));
    }
    if finalized.hold != hold_str {
        return Err(HoldReleaseError::Validation(format!(
            "finalize response hold ({}) does not match requested hold ({hold_str})",
            finalized.hold
        )));
    }
    if finalized.seq == 0 {
        return Err(HoldReleaseError::Validation(
            "finalize response seq must be >= 1".to_string(),
        ));
    }

    Ok(HoldReleaseCeremonyOutcome {
        inspection: verified.inspection,
        finalized,
    })
}

fn post_json_bearer_http11(
    cfg: &HoldReleaseClientConfig,
    path: &str,
    json_body: &[u8],
) -> Result<(u16, Vec<u8>), HoldReleaseError> {
    if cfg.bearer_token.contains('\r') || cfg.bearer_token.contains('\n') {
        return Err(HoldReleaseError::Validation(
            "bearer token contains illegal CR/LF characters".to_string(),
        ));
    }
    send_http11_request(
        &cfg.gateway_base_url,
        cfg.timeout,
        "POST",
        path,
        Some(&cfg.bearer_token),
        Some(json_body),
    )
    .map_err(HoldReleaseError::Transport)
}
