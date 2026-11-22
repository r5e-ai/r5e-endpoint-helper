//! Offline Root Workload Badge Ceremony (`mint-workload-badge`, `cosign-workload-badge`,
//! `submit-grant`) for `A5` / `A8` Workload Record Admission & Deployment Grants:
//!
//! - Mints a standard Provenance v2 authority chain `[E_0, ..., Badge]` (never a bespoke kind)
//!   packaged as a pure `SubmitGrantsRequest { records, keys, blobs }` ready for
//!   `POST /v1/deployment/grants`.
//! - Supports 1-root ceremonies (either with an explicit `--delegator-key-file` or a zeroized
//!   ephemeral ceremony delegator key so `E_0` is never a self-endorsement per `A5` §4.7) and
//!   sequential multi-root chains (`R_1 -> ... -> R_m -> W`, up to 15 roots + 1 `Badge` = 16 links).
//! - Supports both 1-step local signing (`--workload-key-file` / `--generate-workload-key-out`)
//!   and 2-step air-gapped co-signing (`--workload-public-key --out-prepared-badge` followed by
//!   `cosign-workload-badge` on the workload host, verifying all bounds and signatures before
//!   attaching Signature #2).
//! - Enforces tight `Endorsement` bounds (`E.kinds == Badge.kinds`, `E.streamPrefixes ==
//!   Badge.streamPrefixes == ["urn:r5e:stream:<dep>:endpoint:offline-<24hex>:"]`, `E.actsFor ==
//!   Badge.actsFor == <principal>`, `E.actorPrefixes == Badge.actorPrefixes == [<workload>, ...]`,
//!   `notAfter > notBefore`, window `<= 43_200` seconds, and `notBefore <= capturedAt <= notAfter`).

use crate::attestation::{
    base_v2_schema_map, bytes_ref, decode_strict_base64, dsse_pae, ed25519_key_id,
    encode_canonical_json, evidence_ref, generate_os_random_bytes, generate_os_random_seed_32,
    sign_v2_record_multi, BlobEntry, DsseEnvelope, DsseSignature, EnrolledEndpointSession,
    EnrolledSessionOptions, FinalizeBadgeRequest, FinalizedBadgeResponse, PublicKeyEntry,
    SignedEndpointRecord, PROVENANCE_V2_PAYLOAD_TYPE,
};
use crate::claim_http::{
    ceil_to_micros, default_workload_badge_kinds, is_valid_key_id, is_valid_kind_path,
    is_valid_slug_token, is_valid_uri_identity, SubmitGrantsRequest,
};
use crate::crypto_keys::{
    compute_key_id, normalize_signature_bytes, parse_external_signature_bytes,
    validate_public_key_bytes, verify_signature, SignatureAlgorithm,
};
use crate::evidence_http::{
    is_admissible_workload_kind, normalize_workload_kind, EnrolledStateFile,
};
use crate::hold_release::extract_deployment_slug;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::sync::atomic::{compiler_fence, Ordering};

pub const MAX_OFFLINE_BADGE_WINDOW_SECONDS: u64 = 43_200;
pub const DEFAULT_OFFLINE_BADGE_TTL_SECONDS: u64 = 3_600;
pub const PREPARED_OFFLINE_BADGE_FORMAT: &str = "r5e.offline-prepared-badge/v1";
pub const DEFAULT_OFFLINE_CEDAR_POLICY: &str = "permit(principal, action, resource);\n";

pub const EPHEMERAL_DELEGATOR_REVOCATION_NOTE: &str = "1-root ceremony used a zeroized ephemeral delegator key for Endorsement -> Badge (A5 §4.7 forbids self-endorsement); any ancestor root key (or the workload subject key) can revoke E_0 or the Badge via POST /v1/deployment/revocations.";

fn zeroize_seed(seed: &mut [u8; 32]) {
    for b in seed.iter_mut() {
        // SAFETY: `b` is a valid mutable byte in `seed`.
        unsafe {
            std::ptr::write_volatile(b, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

fn hex_lower(bytes: &[u8]) -> String {
    crate::policy_gate::hex_lower(bytes)
}

/// Returns `true` iff `kind_or_path` is an admissible operational workload kind for an offline
/// workload `Badge` (`A8` §2.2 + `R7`: categorically excludes structural/authority/seal/retention
/// kinds AND gateway-proxied `ModelCall` / `ModelResponse`).
pub fn is_admissible_offline_badge_kind(kind_or_path: &str) -> bool {
    let normalized = normalize_workload_kind(kind_or_path);
    if !is_valid_kind_path(&normalized) || !is_admissible_workload_kind(&normalized) {
        return false;
    }
    !matches!(
        normalized.as_str(),
        "provenance.r5e.io/v2/ModelCall" | "provenance.r5e.io/v2/ModelResponse"
    )
}

fn parse_strict_v2_rfc3339(ts: &str, label: &str) -> Result<chrono::DateTime<chrono::Utc>, String> {
    let trimmed = ts.trim();
    if trimmed.ends_with("-00:00") {
        return Err(format!(
            "invalid {label} ({trimmed}): unknown -00:00 offset is outside Provenance v2 Timestamp profile"
        ));
    }
    chrono::DateTime::parse_from_rfc3339(trimmed)
        .map_err(|e| format!("invalid {label} RFC3339 timestamp ({trimmed}): {e}"))
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

fn validate_24_lower_hex(token: &str) -> Result<(), String> {
    if token.len() != 24
        || !token
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(format!(
            "invalid offline badge token {token:?}: expected exactly 24 lowercase hex characters ([0-9a-f]{{24}})"
        ));
    }
    Ok(())
}

/// Parameters for [`prepare_offline_workload_badge`] and [`mint_offline_workload_badge`].
#[derive(Debug, Clone)]
pub struct OfflineWorkloadBadgeParams {
    /// Deployment slug (`"acme-prod"`) or stream prefix (`"urn:r5e:stream:acme-prod:"`).
    pub deployment: String,
    /// Required principal URI (`actsFor` on every `Endorsement` and `Badge`).
    pub principal: String,
    /// Required workload URI (`Badge.body.workload` and first entry in `actorPrefixes`).
    pub workload: String,
    /// Optional additional `actorPrefixes` URIs beyond `workload`.
    pub extra_actor_prefixes: Vec<String>,
    /// Badge holder slug (`^[a-z][a-z0-9-]*$`, default `"endpoint-helper"`).
    pub holder: String,
    /// Optional human-readable purpose stored in local `EnrolledStateFile` (never emitted on `Badge.body`, which has `additionalProperties: false`).
    pub purpose: Option<String>,
    /// Permitted operational workload kinds (empty -> `default_workload_badge_kinds()`).
    pub kinds: Vec<String>,
    /// Must be `false`: leaf workload `Badge` credentials cannot endorse further keys (`A5` §4.3).
    pub may_endorse: bool,
    /// Envelope `actor` on offline authority records (default `"urn:r5e:operator:root"`).
    pub operator_actor: String,
    /// Optional deterministic 24-hex badge token (`offline-<24hex>`); generated from 12 OS-random bytes when `None`.
    pub badge_token_hex: Option<String>,
    /// Optional explicit `capturedAt` instant; defaults to `Utc::now()`.
    pub captured_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Optional `GET /v1/deployment` start-head floor clamping `capturedAt >= ceil_to_micros(floor)`.
    pub start_head_floor: Option<chrono::DateTime<chrono::Utc>>,
    /// Optional explicit RFC 3339 `notBefore` timestamp (refused if `> capturedAt`).
    pub not_before: Option<String>,
    /// Optional explicit RFC 3339 `notAfter` (`--expires-at`) timestamp.
    pub expires_at: Option<String>,
    /// Validity window in seconds when `expires_at` is `None` (default `3600`, max `43_200`).
    pub ttl_seconds: Option<u64>,
    /// Optional gateway key ID for authority `CaptureProfile.sealerKeys` (empty `[]` when `None`).
    pub gateway_key_id: Option<String>,
}

impl OfflineWorkloadBadgeParams {
    pub fn new(
        deployment: impl Into<String>,
        principal: impl Into<String>,
        workload: impl Into<String>,
    ) -> Self {
        Self {
            deployment: deployment.into(),
            principal: principal.into(),
            workload: workload.into(),
            extra_actor_prefixes: Vec::new(),
            holder: "endpoint-helper".to_string(),
            purpose: None,
            kinds: Vec::new(),
            may_endorse: false,
            operator_actor: "urn:r5e:operator:root".to_string(),
            badge_token_hex: None,
            captured_at: None,
            start_head_floor: None,
            not_before: None,
            expires_at: None,
            ttl_seconds: None,
            gateway_key_id: None,
        }
    }
}

fn default_ed25519_alg() -> String {
    "ed25519".to_string()
}

/// Zero-secret air-gapped draft emitted by `mint-workload-badge --workload-public-key ... --out-prepared-badge`
/// and consumed by `cosign-workload-badge`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedOfflineWorkloadBadge {
    pub format: String,
    pub deployment: String,
    pub badge_token_hex: String,
    pub stream_prefix: String,
    pub badge_stream: String,
    pub workload_key_id: String,
    #[serde(default = "default_ed25519_alg")]
    pub workload_algorithm: String,
    pub workload_public_key_b64: String,
    pub badge_issuer_key_id: String,
    pub ephemeral_delegator: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegator_key_id: Option<String>,
    pub holder: String,
    pub principal: String,
    pub workload: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    pub actor_prefixes: Vec<String>,
    pub kinds: Vec<String>,
    pub captured_at: String,
    pub not_before: String,
    pub not_after: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub badge_payload_b64: String,
    pub issuer_signature: DsseSignature,
    pub badge_profile_ref: String,
    pub authority_chain: Vec<SignedEndpointRecord>,
    pub keys: Vec<PublicKeyEntry>,
    pub blobs: Vec<BlobEntry>,
}

impl PreparedOfflineWorkloadBadge {
    /// Returns the exact raw DSSE PAE bytes that Signer #2 (`workload_key_id`) signs externally
    /// (PIV, `openssl dgst -sign`, PKCS#11, HSM).
    pub fn badge_pae_bytes(&self) -> Result<Vec<u8>, String> {
        if self.payload_type != PROVENANCE_V2_PAYLOAD_TYPE {
            return Err(format!(
                "unexpected payloadType {:?} in prepared offline badge",
                self.payload_type
            ));
        }
        let payload_bytes = decode_strict_base64(&self.badge_payload_b64)?;
        Ok(dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &payload_bytes))
    }
}

/// Completed offline workload badge + endorsement chain ready for `POST /v1/deployment/grants`
/// and optional `0600` `EnrolledStateFile` creation.
#[derive(Debug, Clone)]
pub struct MintedOfflineWorkloadBadge {
    pub deployment: String,
    pub badge_token_hex: String,
    pub stream_prefix: String,
    pub badge_stream: String,
    pub badge_ref: String,
    pub workload_key_id: String,
    pub badge_issuer_key_id: String,
    pub root_key_ids: Vec<String>,
    pub ephemeral_delegator: bool,
    pub delegator_key_id: Option<String>,
    pub holder: String,
    pub principal: String,
    pub workload: String,
    pub purpose: Option<String>,
    pub actor_prefixes: Vec<String>,
    pub kinds: Vec<String>,
    pub captured_at: String,
    pub not_before: String,
    pub not_after: String,
    pub authority_chain: Vec<SignedEndpointRecord>,
    pub badge: SignedEndpointRecord,
    pub grant_request: SubmitGrantsRequest,
}

impl MintedOfflineWorkloadBadge {
    /// Builds a self-contained `EnrolledStateFile` (`r5e.endpoint-enrolled-state/v1`) from this
    /// offline-minted badge, workload signing key, Cedar policy bytes, and session options
    /// (including deployment `retention` parity).
    pub fn build_enrolled_state_file(
        &self,
        gateway_url: impl Into<String>,
        workload_signing_key: SigningKey,
        cedar_policy_bytes: &[u8],
        options: &EnrolledSessionOptions,
    ) -> Result<EnrolledStateFile, String> {
        let actual_id = ed25519_key_id(&workload_signing_key.verifying_key().to_bytes());
        if actual_id != self.workload_key_id {
            return Err(format!(
                "workload signing key ({actual_id}) does not match badge subject ({})",
                self.workload_key_id
            ));
        }
        if self.badge.envelope.signatures.len() != 2 {
            return Err("minted Badge must carry 2 DSSE signatures".to_string());
        }
        let finalize_req = FinalizeBadgeRequest {
            ticket: format!("offline-ceremony-{}", self.badge_token_hex),
            payload: self.badge.envelope.payload.clone(),
            subject_signature: self.badge.envelope.signatures[1].clone(),
        };
        let finalized = FinalizedBadgeResponse {
            badge: self.badge.clone(),
            stream_prefix: self.stream_prefix.clone(),
            authority_chain: self.authority_chain.clone(),
            publications: Vec::new(),
            keys: self.grant_request.keys.clone(),
            blobs: self.grant_request.blobs.clone(),
        };
        let session = EnrolledEndpointSession::from_finalized_with_options(
            workload_signing_key,
            &finalize_req,
            &finalized,
            cedar_policy_bytes,
            &self.actor_prefixes,
            options,
        )?;
        Ok(EnrolledStateFile::from_enrolled_session(
            gateway_url,
            self.holder.clone(),
            self.purpose.clone(),
            &session,
        ))
    }
}

fn build_authority_profile_blob(
    stream_uri: &str,
    issuer_key_id: &str,
    gateway_key_id: Option<&str>,
) -> Result<(String, BlobEntry), String> {
    let schemas = base_v2_schema_map();
    let policy_ref = bytes_ref(b"permit(principal, action, resource);");
    let sealer_keys: Vec<&str> = gateway_key_id.into_iter().collect();
    let doc = json!({
        "format": "r5e.capture-profile/v2",
        "schemas": Value::Object(schemas),
        "authority": {
            "bindings": [
                {
                    "streamPrefix": stream_uri,
                    "actorPrefixes": ["urn:r5e:"],
                    "issuerKeys": [issuer_key_id],
                    "sealerKeys": sealer_keys,
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
    let bytes = encode_canonical_json(&doc)?;
    let pref = bytes_ref(&bytes);
    let entry = BlobEntry {
        blob_ref: pref.clone(),
        media_type: Some("application/json".to_string()),
        base64: BASE64_STANDARD.encode(&bytes),
    };
    Ok((pref, entry))
}

/// Builds and signs `[E_0, ...]` plus Signer #1's signature on the `Badge` draft using only the
/// workload's 32-byte Ed25519 public key (`workload_public_key_bytes`), returning a zero-secret
/// [`PreparedOfflineWorkloadBadge`] suitable for air-gapped co-signing.
pub fn prepare_offline_workload_badge(
    root_keys: &[SigningKey],
    explicit_delegator_key: Option<&SigningKey>,
    workload_public_key_bytes: &[u8; 32],
    params: &OfflineWorkloadBadgeParams,
) -> Result<PreparedOfflineWorkloadBadge, String> {
    prepare_offline_workload_badge_with_alg(
        root_keys,
        explicit_delegator_key,
        SignatureAlgorithm::Ed25519,
        workload_public_key_bytes,
        params,
    )
}

/// Builds and signs `[E_0, ...]` plus Signer #1's signature on the `Badge` draft using any
/// Provenance v2 public key (`Ed25519`, `ES256`, or `ES384`), returning a zero-secret
/// [`PreparedOfflineWorkloadBadge`] suitable for PIV / OpenSSL / air-gapped co-signing.
pub fn prepare_offline_workload_badge_with_alg(
    root_keys: &[SigningKey],
    explicit_delegator_key: Option<&SigningKey>,
    workload_alg: SignatureAlgorithm,
    workload_public_key_bytes: &[u8],
    params: &OfflineWorkloadBadgeParams,
) -> Result<PreparedOfflineWorkloadBadge, String> {
    if root_keys.is_empty() {
        return Err("at least one --root-key-file is required".to_string());
    }
    if root_keys.len() > 15 {
        return Err(format!(
            "offline authority chain has {} root keys (+ 1 Badge > 16 max links in A5 §4.7)",
            root_keys.len()
        ));
    }
    if params.may_endorse {
        return Err(
            "offline workload Badge cannot set --may-endorse=true; workload badges are leaf credentials (A5 §4.3)"
                .to_string(),
        );
    }

    let deployment = extract_deployment_slug(&params.deployment)?;
    let principal = params.principal.trim();
    if !is_valid_uri_identity(principal) {
        return Err(format!(
            "invalid --principal URI {:?}: expected scheme URI such as 'urn:r5e:principal:...' or 'spiffe://...'",
            params.principal
        ));
    }
    let workload = params.workload.trim();
    if !is_valid_uri_identity(workload) {
        return Err(format!(
            "invalid --workload URI {:?}: expected scheme URI such as 'urn:r5e:workload:...' or 'spiffe://...'",
            params.workload
        ));
    }

    let holder = params.holder.trim();
    if holder.is_empty() || !is_valid_slug_token(holder, false) {
        return Err(format!(
            "invalid --holder {holder:?}: expected lowercase slug matching ^[a-z][a-z0-9-]*$"
        ));
    }
    if let Some(ref p) = params.purpose {
        if p.trim().is_empty() {
            return Err("--purpose must be non-empty when provided".to_string());
        }
    }
    if !params.operator_actor.starts_with("urn:r5e:") {
        return Err(format!(
            "operator actor ({}) must start with 'urn:r5e:'",
            params.operator_actor
        ));
    }
    if let Some(ref gw_id) = params.gateway_key_id {
        if !is_valid_key_id(gw_id) {
            return Err(format!("invalid --gateway-key-id: {gw_id}"));
        }
    }

    // Validate workload public key admissibility upfront (`VERIFY-V2` §2.3).
    validate_public_key_bytes(
        workload_alg,
        workload_public_key_bytes,
        "workload_public_key",
    )?;
    let workload_key_id = compute_key_id(workload_alg, workload_public_key_bytes)?;
    let workload_pub_b64 = BASE64_STANDARD.encode(workload_public_key_bytes);

    // Build actorPrefixes = [workload, ...extra] (K1: workload actor URI MUST be covered!).
    let mut actor_prefixes = vec![workload.to_string()];
    for extra in &params.extra_actor_prefixes {
        let trimmed = extra.trim();
        if !is_valid_uri_identity(trimmed) {
            return Err(format!("invalid --actor-prefix URI {extra:?}"));
        }
        if !actor_prefixes.iter().any(|existing| existing == trimmed) {
            actor_prefixes.push(trimmed.to_string());
        }
    }

    // Validate and normalize kinds (R7: admissible workload operational kinds ONLY).
    let raw_kinds = if params.kinds.is_empty() {
        default_workload_badge_kinds()
    } else {
        params.kinds.clone()
    };
    let mut kinds = Vec::with_capacity(raw_kinds.len());
    for raw_k in &raw_kinds {
        let norm = normalize_workload_kind(raw_k);
        if !is_admissible_offline_badge_kind(&norm) {
            return Err(format!(
                "kind {norm:?} is not admissible on an offline workload Badge (authority, structural, seal, retention, and gateway ModelCall/ModelResponse kinds are forbidden)"
            ));
        }
        if !kinds.iter().any(|existing| existing == &norm) {
            kinds.push(norm);
        }
    }
    if kinds.is_empty() {
        return Err("offline workload Badge kinds must be non-empty".to_string());
    }

    // Validate badge token (`offline-<24hex>`).
    let badge_token_hex = match &params.badge_token_hex {
        Some(tok) => {
            validate_24_lower_hex(tok)?;
            tok.clone()
        }
        None => hex_lower(&generate_os_random_bytes::<12>()?),
    };
    let endpoint_stream_prefix =
        format!("urn:r5e:stream:{deployment}:endpoint:offline-{badge_token_hex}:");
    let badge_stream =
        format!("urn:r5e:stream:{deployment}:authority:badge:offline-{badge_token_hex}");

    // Validate timestamps & <= 43_200s authority window (K2 + R7 + A5 §§4.5–4.6).
    let base_now = params.captured_at.unwrap_or_else(chrono::Utc::now);
    let floored_now = match params.start_head_floor {
        Some(fl) => std::cmp::max(base_now, ceil_to_micros(fl)),
        None => base_now,
    };
    let effective_captured_at = ceil_to_micros(floored_now);
    let captured_at_str =
        effective_captured_at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);

    let not_before_dt = match &params.not_before {
        Some(nb_raw) => {
            let parsed = parse_strict_v2_rfc3339(nb_raw, "--not-before")?;
            if parsed > effective_captured_at {
                return Err(format!(
                    "--not-before ({}) cannot be after capturedAt ({captured_at_str}); A5 §4.6 requires child link capturedAt to lie within parent [notBefore, notAfter]",
                    nb_raw.trim()
                ));
            }
            parsed
        }
        None => effective_captured_at,
    };
    let not_before_str = not_before_dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);

    let not_after_dt = match &params.expires_at {
        Some(exp_raw) => parse_strict_v2_rfc3339(exp_raw, "--expires-at")?,
        None => {
            let ttl = params
                .ttl_seconds
                .unwrap_or(DEFAULT_OFFLINE_BADGE_TTL_SECONDS);
            if ttl == 0 {
                return Err("--ttl-seconds must be >= 1".to_string());
            }
            not_before_dt + chrono::Duration::seconds(ttl as i64)
        }
    };
    if not_after_dt <= not_before_dt {
        return Err(format!(
            "expiresAt / notAfter ({}) must be strictly after notBefore ({not_before_str})",
            not_after_dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
        ));
    }
    if effective_captured_at > not_after_dt {
        return Err(format!(
            "expiresAt / notAfter ({}) cannot be earlier than capturedAt ({captured_at_str})",
            not_after_dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
        ));
    }
    let window_span = not_after_dt.signed_duration_since(not_before_dt);
    if window_span > chrono::Duration::seconds(MAX_OFFLINE_BADGE_WINDOW_SECONDS as i64) {
        return Err(format!(
            "authority window ({}s) exceeds maximum {} seconds (12h) allowed for offline workload badges and endorsements",
            window_span.num_seconds(),
            MAX_OFFLINE_BADGE_WINDOW_SECONDS
        ));
    }
    let not_after_str = not_after_dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);

    // Check pairwise distinctness across root keys and workload key (A5 §4.7).
    let mut root_ids = Vec::with_capacity(root_keys.len());
    for rk in root_keys {
        let kid = ed25519_key_id(&rk.verifying_key().to_bytes());
        if kid == workload_key_id {
            return Err(format!(
                "root key ({kid}) must be distinct from workload key (A5 §4.7 forbids self-endorsement)"
            ));
        }
        if root_ids.iter().any(|existing| existing == &kid) {
            return Err(format!(
                "duplicate --root-key-file key ({kid}); A5 §4.7 forbids cycles or repeated keys in an authority chain"
            ));
        }
        root_ids.push(kid);
    }

    // Build sequence of link issuers: `[R_1, ..., badge_issuer]`.
    let mut ephemeral_seed: Option<[u8; 32]> = None;
    let ephemeral_signing_key: Option<SigningKey>;
    let ephemeral_delegator: bool;
    let delegator_key_id: Option<String>;

    let chain_signers: Vec<&SigningKey> = if root_keys.len() == 1 {
        if let Some(dk) = explicit_delegator_key {
            let dk_id = ed25519_key_id(&dk.verifying_key().to_bytes());
            if dk_id == root_ids[0] {
                return Err(
                    "--delegator-key-file must be distinct from --root-key-file (A5 §4.7 forbids self-endorsement)"
                        .to_string(),
                );
            }
            if dk_id == workload_key_id {
                return Err(
                    "--delegator-key-file must be distinct from workload key (A5 §4.7 forbids self-issued Badge)"
                        .to_string(),
                );
            }
            ephemeral_delegator = false;
            delegator_key_id = Some(dk_id);
            vec![&root_keys[0], dk]
        } else {
            let mut seed = generate_os_random_seed_32()?;
            let dk = SigningKey::from_bytes(&seed);
            let dk_id = ed25519_key_id(&dk.verifying_key().to_bytes());
            if dk_id == root_ids[0] || dk_id == workload_key_id {
                zeroize_seed(&mut seed);
                return Err(
                    "generated delegator key collided with root or workload key".to_string()
                );
            }
            ephemeral_seed = Some(seed);
            ephemeral_signing_key = Some(dk);
            ephemeral_delegator = true;
            delegator_key_id = Some(dk_id);
            vec![
                &root_keys[0],
                ephemeral_signing_key
                    .as_ref()
                    .expect("ephemeral signing key"),
            ]
        }
    } else {
        if explicit_delegator_key.is_some() {
            return Err(
                "--delegator-key-file is only supported when a single --root-key-file is passed; with multiple --root-key-file flags, roots chain R_1 -> ... -> R_m -> workload"
                    .to_string(),
            );
        }
        ephemeral_delegator = false;
        delegator_key_id = None;
        root_keys.iter().collect()
    };

    let schemas = base_v2_schema_map();
    let endorsement_schema = schemas["provenance.r5e.io/v2/Endorsement"]
        .as_str()
        .expect("Endorsement schema in base_v2_schema_map")
        .to_string();
    let badge_schema = schemas["provenance.r5e.io/v2/Badge"]
        .as_str()
        .expect("Badge schema in base_v2_schema_map")
        .to_string();

    let mut key_map: BTreeMap<String, PublicKeyEntry> = BTreeMap::new();
    let mut key_order: Vec<String> = Vec::new();
    let record_signer_key = |pub_bytes: &[u8; 32],
                             map: &mut BTreeMap<String, PublicKeyEntry>,
                             order: &mut Vec<String>| {
        let kid = ed25519_key_id(pub_bytes);
        if !map.contains_key(&kid) {
            order.push(kid.clone());
            map.insert(
                kid.clone(),
                PublicKeyEntry {
                    keyid: kid,
                    algorithm: "ed25519".to_string(),
                    bytes: BASE64_STANDARD.encode(pub_bytes),
                },
            );
        }
    };

    let mut blob_map: BTreeMap<String, BlobEntry> = BTreeMap::new();
    let mut blob_order: Vec<String> = Vec::new();
    let record_blob =
        |entry: BlobEntry, map: &mut BTreeMap<String, BlobEntry>, order: &mut Vec<String>| {
            if !map.contains_key(&entry.blob_ref) {
                order.push(entry.blob_ref.clone());
                map.insert(entry.blob_ref.clone(), entry);
            }
        };

    // Build Endorsements E_0 .. E_{k-2} where k == chain_signers.len() >= 2.
    let mut authority_chain: Vec<SignedEndpointRecord> =
        Vec::with_capacity(chain_signers.len() - 1);
    for idx in 0..(chain_signers.len() - 1) {
        let issuer_sk = chain_signers[idx];
        let issuer_pub = issuer_sk.verifying_key().to_bytes();
        let issuer_id = ed25519_key_id(&issuer_pub);
        record_signer_key(&issuer_pub, &mut key_map, &mut key_order);

        let subject_pub = chain_signers[idx + 1].verifying_key().to_bytes();
        let subject_id = ed25519_key_id(&subject_pub);

        let grant_tok = hex_lower(&generate_os_random_bytes::<8>()?);
        let e_stream = if idx == 0 {
            let root_hex = issuer_id
                .strip_prefix("key:ed25519:sha256:")
                .ok_or_else(|| format!("unexpected root key id format: {issuer_id}"))?;
            format!("urn:r5e:stream:{deployment}:authority:root:{root_hex}:grant:{grant_tok}")
        } else {
            format!("urn:r5e:stream:{deployment}:authority:delegation:{grant_tok}")
        };

        let (e_prof_ref, e_prof_blob) =
            build_authority_profile_blob(&e_stream, &issuer_id, params.gateway_key_id.as_deref())?;
        record_blob(e_prof_blob, &mut blob_map, &mut blob_order);

        let mut e_body = Map::new();
        if idx > 0 {
            e_body.insert(
                "parent".to_string(),
                Value::String(authority_chain[idx - 1].record_ref.clone()),
            );
        }
        e_body.insert("subject".to_string(), Value::String(subject_id));
        e_body.insert("mayEndorse".to_string(), Value::Bool(true));
        e_body.insert(
            "kinds".to_string(),
            Value::Array(kinds.iter().cloned().map(Value::String).collect()),
        );
        e_body.insert(
            "streamPrefixes".to_string(),
            Value::Array(vec![Value::String(endpoint_stream_prefix.clone())]),
        );
        e_body.insert(
            "actorPrefixes".to_string(),
            Value::Array(actor_prefixes.iter().cloned().map(Value::String).collect()),
        );
        e_body.insert("actsFor".to_string(), Value::String(principal.to_string()));
        e_body.insert(
            "notBefore".to_string(),
            Value::String(not_before_str.clone()),
        );
        e_body.insert("notAfter".to_string(), Value::String(not_after_str.clone()));

        let e_env = json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": &endorsement_schema,
            "profileRef": &e_prof_ref,
            "issuer": &issuer_id,
            "stream": &e_stream,
            "seq": 1,
            "previous": null,
            "actor": &params.operator_actor,
            "capturedAt": &captured_at_str,
            "body": Value::Object(e_body),
        });
        let signed_e = sign_v2_record_multi(
            &[issuer_sk],
            e_env
                .as_object()
                .expect("Endorsement envelope JSON object")
                .clone(),
        )?;
        authority_chain.push(signed_e);
    }

    // Signer #1 on Badge is the last entry of `chain_signers`.
    let badge_issuer_sk = *chain_signers.last().expect("non-empty chain_signers");
    let badge_issuer_pub = badge_issuer_sk.verifying_key().to_bytes();
    let badge_issuer_id = ed25519_key_id(&badge_issuer_pub);
    record_signer_key(&badge_issuer_pub, &mut key_map, &mut key_order);
    if !key_map.contains_key(&workload_key_id) {
        key_order.push(workload_key_id.clone());
        key_map.insert(
            workload_key_id.clone(),
            PublicKeyEntry {
                keyid: workload_key_id.clone(),
                algorithm: workload_alg.as_str().to_string(),
                bytes: workload_pub_b64.clone(),
            },
        );
    }

    let (badge_prof_ref, badge_prof_blob) = build_authority_profile_blob(
        &badge_stream,
        &badge_issuer_id,
        params.gateway_key_id.as_deref(),
    )?;
    record_blob(badge_prof_blob, &mut blob_map, &mut blob_order);

    let last_endorsement_ref = authority_chain
        .last()
        .expect("at least one Endorsement in chain")
        .record_ref
        .clone();

    let mut badge_body = Map::new();
    badge_body.insert("parent".to_string(), Value::String(last_endorsement_ref));
    badge_body.insert(
        "subject".to_string(),
        Value::String(workload_key_id.clone()),
    );
    badge_body.insert(
        "subjectKey".to_string(),
        json!({
            "algorithm": workload_alg.as_str(),
            "bytes": &workload_pub_b64,
        }),
    );
    badge_body.insert("holder".to_string(), Value::String(holder.to_string()));
    badge_body.insert("workload".to_string(), Value::String(workload.to_string()));
    badge_body.insert("actsFor".to_string(), Value::String(principal.to_string()));
    badge_body.insert(
        "kinds".to_string(),
        Value::Array(kinds.iter().cloned().map(Value::String).collect()),
    );
    badge_body.insert(
        "streamPrefixes".to_string(),
        Value::Array(vec![Value::String(endpoint_stream_prefix.clone())]),
    );
    badge_body.insert(
        "actorPrefixes".to_string(),
        Value::Array(actor_prefixes.iter().cloned().map(Value::String).collect()),
    );
    badge_body.insert(
        "notBefore".to_string(),
        Value::String(not_before_str.clone()),
    );
    badge_body.insert("notAfter".to_string(), Value::String(not_after_str.clone()));

    let badge_env = json!({
        "apiVersion": "provenance.r5e.io/v2",
        "kind": "Badge",
        "schemaRef": &badge_schema,
        "profileRef": &badge_prof_ref,
        "issuer": &badge_issuer_id,
        "stream": &badge_stream,
        "seq": 1,
        "previous": null,
        "actor": &params.operator_actor,
        "capturedAt": &captured_at_str,
        "body": Value::Object(badge_body),
    });
    let badge_payload_bytes = encode_canonical_json(&badge_env)?;
    let badge_pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &badge_payload_bytes);
    let issuer_sig = badge_issuer_sk.sign(&badge_pae);

    if let Some(mut seed) = ephemeral_seed {
        zeroize_seed(&mut seed);
    }

    let keys: Vec<PublicKeyEntry> = key_order
        .into_iter()
        .filter_map(|k| key_map.remove(&k))
        .collect();
    let blobs: Vec<BlobEntry> = blob_order
        .into_iter()
        .filter_map(|b| blob_map.remove(&b))
        .collect();

    Ok(PreparedOfflineWorkloadBadge {
        format: PREPARED_OFFLINE_BADGE_FORMAT.to_string(),
        deployment,
        badge_token_hex,
        stream_prefix: endpoint_stream_prefix,
        badge_stream,
        workload_key_id,
        workload_algorithm: workload_alg.as_str().to_string(),
        workload_public_key_b64: workload_pub_b64,
        badge_issuer_key_id: badge_issuer_id,
        ephemeral_delegator,
        delegator_key_id,
        holder: holder.to_string(),
        principal: principal.to_string(),
        workload: workload.to_string(),
        purpose: params.purpose.as_ref().map(|s| s.trim().to_string()),
        actor_prefixes,
        kinds,
        captured_at: captured_at_str,
        not_before: not_before_str,
        not_after: not_after_str,
        payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
        badge_payload_b64: BASE64_STANDARD.encode(&badge_payload_bytes),
        issuer_signature: DsseSignature {
            keyid: badge_issuer_sk_id_from_pub(&badge_issuer_pub),
            sig: BASE64_STANDARD.encode(issuer_sig.to_bytes()),
        },
        badge_profile_ref: badge_prof_ref,
        authority_chain,
        keys,
        blobs,
    })
}

fn badge_issuer_sk_id_from_pub(pub_bytes: &[u8; 32]) -> String {
    ed25519_key_id(pub_bytes)
}

fn resolve_verifying_key_map(
    keys: &[PublicKeyEntry],
) -> Result<BTreeMap<String, (SignatureAlgorithm, Vec<u8>)>, String> {
    let mut out = BTreeMap::new();
    for entry in keys {
        let alg = SignatureAlgorithm::parse(&entry.algorithm)
            .map_err(|e| format!("key {}: {e}", entry.keyid))?;
        let raw = decode_strict_base64(&entry.bytes)
            .map_err(|e| format!("invalid strict base64 on key {}: {e}", entry.keyid))?;
        validate_public_key_bytes(alg, &raw, &entry.keyid)?;
        let computed = compute_key_id(alg, &raw)?;
        if computed != entry.keyid {
            return Err(format!(
                "key id mismatch: declared {}, computed {computed}",
                entry.keyid
            ));
        }
        out.insert(entry.keyid.clone(), (alg, raw));
    }
    Ok(out)
}

fn verify_dsse_signature(
    vk_map: &BTreeMap<String, (SignatureAlgorithm, Vec<u8>)>,
    dsse_sig: &DsseSignature,
    pae: &[u8],
) -> Result<(), String> {
    let (alg, pub_bytes) = vk_map
        .get(&dsse_sig.keyid)
        .ok_or_else(|| format!("missing PublicKeyEntry for signer {}", dsse_sig.keyid))?;
    let sig_bytes = decode_strict_base64(&dsse_sig.sig).map_err(|e| {
        format!(
            "invalid strict base64 signature from {}: {e}",
            dsse_sig.keyid
        )
    })?;
    verify_signature(*alg, pub_bytes, pae, &sig_bytes)
        .map_err(|e| format!("signature verification failed for {}: {e}", dsse_sig.keyid))
}

/// Verifies every structural bound, timestamp constraint, profile digest, and signature on a
/// [`PreparedOfflineWorkloadBadge`] BEFORE attaching an external Signer #2 signature (supporting
/// `Ed25519`, `ES256`, and `ES384`, including PIV / OpenSSL ASN.1 DER `ECDSA-Sig-Value`
/// with automatic `s > floor(n / 2)` -> `n - s` low-`S` normalization), returning
/// `(MintedOfflineWorkloadBadge, signature_was_normalized)`.
pub fn cosign_prepared_offline_workload_badge_with_external_signature(
    prepared: &PreparedOfflineWorkloadBadge,
    signature_input: &[u8],
    is_base64_flag: bool,
) -> Result<(MintedOfflineWorkloadBadge, bool), String> {
    if prepared.format != PREPARED_OFFLINE_BADGE_FORMAT {
        return Err(format!(
            "unsupported prepared badge format {:?} (expected {PREPARED_OFFLINE_BADGE_FORMAT})",
            prepared.format
        ));
    }
    if prepared.payload_type != PROVENANCE_V2_PAYLOAD_TYPE {
        return Err(format!(
            "unexpected payloadType {:?} in prepared offline badge",
            prepared.payload_type
        ));
    }
    let deployment = extract_deployment_slug(&prepared.deployment)?;
    validate_24_lower_hex(&prepared.badge_token_hex)?;

    let expected_stream_prefix = format!(
        "urn:r5e:stream:{deployment}:endpoint:offline-{}:",
        prepared.badge_token_hex
    );
    let expected_badge_stream = format!(
        "urn:r5e:stream:{deployment}:authority:badge:offline-{}",
        prepared.badge_token_hex
    );
    if prepared.stream_prefix != expected_stream_prefix {
        return Err(format!(
            "prepared badge stream_prefix {:?} does not match expected {expected_stream_prefix:?}",
            prepared.stream_prefix
        ));
    }
    if prepared.badge_stream != expected_badge_stream {
        return Err(format!(
            "prepared badge_stream {:?} does not match expected {expected_badge_stream:?}",
            prepared.badge_stream
        ));
    }

    let workload_alg = SignatureAlgorithm::parse(&prepared.workload_algorithm)?;
    let workload_pub_bytes = decode_strict_base64(&prepared.workload_public_key_b64)
        .map_err(|e| format!("invalid workload_public_key_b64: {e}"))?;
    validate_public_key_bytes(
        workload_alg,
        &workload_pub_bytes,
        "prepared.workload_public_key",
    )?;
    let expected_workload_id = compute_key_id(workload_alg, &workload_pub_bytes)?;
    let expected_workload_b64 = &prepared.workload_public_key_b64;
    if prepared.workload_key_id != expected_workload_id {
        return Err(format!(
            "derived workload key id ({expected_workload_id}) does not match prepared badge workload_key_id ({})",
            prepared.workload_key_id
        ));
    }

    let vk_map = resolve_verifying_key_map(&prepared.keys)?;

    // Verify every blob hash in `prepared.blobs`.
    let mut blob_refs = BTreeMap::new();
    for b in &prepared.blobs {
        let raw = decode_strict_base64(&b.base64)
            .map_err(|e| format!("invalid base64 on blob {}: {e}", b.blob_ref))?;
        let computed = bytes_ref(&raw);
        if computed != b.blob_ref {
            return Err(format!(
                "blob digest mismatch: declared {}, computed {computed}",
                b.blob_ref
            ));
        }
        blob_refs.insert(b.blob_ref.clone(), raw);
    }

    if prepared.authority_chain.is_empty() || prepared.authority_chain.len() > 15 {
        return Err(format!(
            "prepared badge authority_chain must have 1..=15 Endorsement links, got {}",
            prepared.authority_chain.len()
        ));
    }

    // Parse & verify Badge payload before signing.
    let badge_payload_bytes = decode_strict_base64(&prepared.badge_payload_b64)?;
    let badge_val: Value = serde_json::from_slice(&badge_payload_bytes)
        .map_err(|e| format!("prepared badge payload is not valid JSON: {e}"))?;
    if encode_canonical_json(&badge_val)? != badge_payload_bytes {
        return Err("prepared badge payload is not canonical JSON (VERIFY-V2 §2.1)".to_string());
    }
    if badge_val.get("apiVersion").and_then(Value::as_str) != Some("provenance.r5e.io/v2")
        || badge_val.get("kind").and_then(Value::as_str) != Some("Badge")
    {
        return Err("refusing to co-sign non-Badge record".to_string());
    }
    if badge_val.get("stream").and_then(Value::as_str) != Some(expected_badge_stream.as_str())
        || badge_val.get("seq").and_then(Value::as_u64) != Some(1)
        || badge_val.get("previous") != Some(&Value::Null)
    {
        return Err("prepared Badge envelope stream/seq/previous invalid".to_string());
    }
    let badge_prof_ref = badge_val
        .get("profileRef")
        .and_then(Value::as_str)
        .ok_or_else(|| "prepared Badge missing profileRef".to_string())?;
    if !blob_refs.contains_key(badge_prof_ref) {
        return Err(format!(
            "prepared Badge profileRef {badge_prof_ref} missing from blobs"
        ));
    }

    let badge_issuer = badge_val
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or_else(|| "prepared Badge missing issuer".to_string())?;
    if badge_issuer != prepared.badge_issuer_key_id || badge_issuer == expected_workload_id {
        return Err("prepared Badge issuer invalid or equals workload key".to_string());
    }
    if prepared.issuer_signature.keyid != badge_issuer {
        return Err(
            "prepared Badge issuer_signature keyid does not match Badge.issuer".to_string(),
        );
    }
    let badge_pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &badge_payload_bytes);
    verify_dsse_signature(&vk_map, &prepared.issuer_signature, &badge_pae)?;

    let b_captured_str = badge_val
        .get("capturedAt")
        .and_then(Value::as_str)
        .ok_or_else(|| "prepared Badge missing capturedAt".to_string())?;
    let b_captured = parse_strict_v2_rfc3339(b_captured_str, "Badge.capturedAt")?;

    let b_body = badge_val
        .get("body")
        .and_then(Value::as_object)
        .ok_or_else(|| "prepared Badge missing body".to_string())?;
    if b_body.get("mayEndorse").is_some() {
        return Err("prepared Badge body must not contain mayEndorse".to_string());
    }
    const ALLOWED_BADGE_BODY_KEYS: &[&str] = &[
        "actorPrefixes",
        "actsFor",
        "details",
        "holder",
        "kinds",
        "notAfter",
        "notBefore",
        "parent",
        "streamPrefixes",
        "subject",
        "subjectKey",
        "workload",
    ];
    for key in b_body.keys() {
        if !ALLOWED_BADGE_BODY_KEYS.contains(&key.as_str()) {
            return Err(format!(
                "prepared Badge body contains forbidden/unknown property {key:?} (provenance.r5e.io/v2/Badge.json sets additionalProperties: false)"
            ));
        }
    }
    if b_body.get("subject").and_then(Value::as_str) != Some(expected_workload_id.as_str()) {
        return Err("prepared Badge body.subject does not match workload key".to_string());
    }
    let sk_obj = b_body
        .get("subjectKey")
        .and_then(Value::as_object)
        .ok_or_else(|| "prepared Badge missing body.subjectKey".to_string())?;
    if sk_obj.get("algorithm").and_then(Value::as_str) != Some(workload_alg.as_str())
        || sk_obj.get("bytes").and_then(Value::as_str) != Some(expected_workload_b64.as_str())
    {
        return Err(
            "prepared Badge body.subjectKey does not match workload public key".to_string(),
        );
    }

    let b_nb_str = b_body
        .get("notBefore")
        .and_then(Value::as_str)
        .ok_or_else(|| "prepared Badge missing body.notBefore".to_string())?;
    let b_na_str = b_body
        .get("notAfter")
        .and_then(Value::as_str)
        .ok_or_else(|| "prepared Badge missing body.notAfter".to_string())?;
    let b_nb = parse_strict_v2_rfc3339(b_nb_str, "Badge.body.notBefore")?;
    let b_na = parse_strict_v2_rfc3339(b_na_str, "Badge.body.notAfter")?;
    if b_na <= b_nb
        || b_captured < b_nb
        || b_captured > b_na
        || (b_na - b_nb) > chrono::Duration::seconds(MAX_OFFLINE_BADGE_WINDOW_SECONDS as i64)
    {
        return Err("prepared Badge time window violates A5/A8 bounds".to_string());
    }

    let b_kinds: Vec<String> = b_body
        .get("kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| "prepared Badge missing body.kinds".to_string())?
        .iter()
        .map(|v| {
            v.as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| "non-string in Badge.body.kinds".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if b_kinds.is_empty() || !b_kinds.iter().all(|k| is_admissible_offline_badge_kind(k)) {
        return Err("prepared Badge contains empty or forbidden kinds".to_string());
    }

    let b_streams: Vec<String> = b_body
        .get("streamPrefixes")
        .and_then(Value::as_array)
        .ok_or_else(|| "prepared Badge missing body.streamPrefixes".to_string())?
        .iter()
        .filter_map(|v| v.as_str().map(ToOwned::to_owned))
        .collect();
    if b_streams != vec![expected_stream_prefix.clone()] {
        return Err("prepared Badge streamPrefixes mismatch".to_string());
    }

    let b_acts_for = b_body
        .get("actsFor")
        .and_then(Value::as_str)
        .ok_or_else(|| "prepared Badge missing body.actsFor".to_string())?;
    let b_workload = b_body
        .get("workload")
        .and_then(Value::as_str)
        .ok_or_else(|| "prepared Badge missing body.workload".to_string())?;
    if !is_valid_uri_identity(b_acts_for) || !is_valid_uri_identity(b_workload) {
        return Err("prepared Badge actsFor/workload must be valid URIs".to_string());
    }
    let b_actor_prefixes: Vec<String> = b_body
        .get("actorPrefixes")
        .and_then(Value::as_array)
        .ok_or_else(|| "prepared Badge missing body.actorPrefixes".to_string())?
        .iter()
        .filter_map(|v| v.as_str().map(ToOwned::to_owned))
        .collect();
    if !b_actor_prefixes.iter().any(|p| b_workload.starts_with(p)) {
        return Err("prepared Badge actorPrefixes does not cover Badge.body.workload".to_string());
    }

    // Verify every Endorsement link in `authority_chain` and tight bounds (`R7` + `A5` §4).
    let mut root_key_ids = Vec::new();
    for (idx, link) in prepared.authority_chain.iter().enumerate() {
        if link.envelope.payload_type != PROVENANCE_V2_PAYLOAD_TYPE
            || link.envelope.signatures.len() != 1
        {
            return Err(format!("Endorsement[{idx}] invalid DSSE envelope"));
        }
        let l_bytes = decode_strict_base64(&link.envelope.payload)?;
        if evidence_ref(&l_bytes) != link.record_ref {
            return Err(format!("Endorsement[{idx}] record_ref mismatch"));
        }
        let l_val: Value = serde_json::from_slice(&l_bytes)
            .map_err(|e| format!("Endorsement[{idx}] JSON error: {e}"))?;
        if encode_canonical_json(&l_val)? != l_bytes {
            return Err(format!("Endorsement[{idx}] payload is not canonical JSON"));
        }
        if l_val.get("apiVersion").and_then(Value::as_str) != Some("provenance.r5e.io/v2")
            || l_val.get("kind").and_then(Value::as_str) != Some("Endorsement")
        {
            return Err(format!("Endorsement[{idx}] is not a v2 Endorsement"));
        }
        let l_prof_ref = l_val
            .get("profileRef")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !blob_refs.contains_key(l_prof_ref) {
            return Err(format!("Endorsement[{idx}] profileRef missing from blobs"));
        }
        let l_issuer = l_val
            .get("issuer")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if link.envelope.signatures[0].keyid != l_issuer {
            return Err(format!("Endorsement[{idx}] signer does not match issuer"));
        }
        let l_pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &l_bytes);
        verify_dsse_signature(&vk_map, &link.envelope.signatures[0], &l_pae)?;
        root_key_ids.push(l_issuer.to_string());

        let l_body = l_val
            .get("body")
            .and_then(Value::as_object)
            .ok_or_else(|| format!("Endorsement[{idx}] missing body"))?;
        let l_subject = l_body
            .get("subject")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if l_subject.is_empty() || l_subject == l_issuer {
            return Err(format!(
                "Endorsement[{idx}] is a self-endorsement or missing subject (A5 §4.7)"
            ));
        }
        if l_body.get("mayEndorse").and_then(Value::as_bool) != Some(true) {
            return Err(format!("Endorsement[{idx}] must have mayEndorse == true"));
        }
        if idx == 0 {
            if l_body.get("parent").is_some() {
                return Err("top Endorsement[0] must be parentless".to_string());
            }
        } else {
            let expected_parent = &prepared.authority_chain[idx - 1].record_ref;
            if l_body.get("parent").and_then(Value::as_str) != Some(expected_parent.as_str()) {
                return Err(format!("Endorsement[{idx}] parent mismatch"));
            }
            let prev_bytes =
                decode_strict_base64(&prepared.authority_chain[idx - 1].envelope.payload)?;
            let prev_val: Value = serde_json::from_slice(&prev_bytes).map_err(|e| e.to_string())?;
            let prev_subject = prev_val["body"]["subject"].as_str().unwrap_or_default();
            if l_issuer != prev_subject {
                return Err(format!(
                    "Endorsement[{idx}] issuer ({l_issuer}) != previous link subject ({prev_subject})"
                ));
            }
        }

        // Verify R7 tight bounds on every Endorsement:
        let l_kinds: Vec<String> = l_body
            .get("kinds")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let l_streams: Vec<String> = l_body
            .get("streamPrefixes")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let l_actors: Vec<String> = l_body
            .get("actorPrefixes")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        if l_kinds != b_kinds
            || l_streams != b_streams
            || l_actors != b_actor_prefixes
            || l_body.get("actsFor").and_then(Value::as_str) != Some(b_acts_for)
        {
            return Err(format!(
                "Endorsement[{idx}] bounds (kinds/streamPrefixes/actorPrefixes/actsFor) are wider than or mismatched with Badge"
            ));
        }
        let l_nb = parse_strict_v2_rfc3339(
            l_body
                .get("notBefore")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            "Endorsement.notBefore",
        )?;
        let l_na = parse_strict_v2_rfc3339(
            l_body
                .get("notAfter")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            "Endorsement.notAfter",
        )?;
        if l_na <= l_nb
            || (l_na - l_nb) > chrono::Duration::seconds(MAX_OFFLINE_BADGE_WINDOW_SECONDS as i64)
            || b_nb < l_nb
            || b_na > l_na
            || b_captured < l_nb
            || b_captured > l_na
        {
            return Err(format!("Endorsement[{idx}] window violates A5/A8 bounds"));
        }
    }

    // Verify last Endorsement links directly into Badge:
    let last_e = prepared.authority_chain.last().expect("non-empty chain");
    if b_body.get("parent").and_then(Value::as_str) != Some(last_e.record_ref.as_str()) {
        return Err("Badge.body.parent does not match last Endorsement ref".to_string());
    }
    let last_e_bytes = decode_strict_base64(&last_e.envelope.payload)?;
    let last_e_val: Value = serde_json::from_slice(&last_e_bytes).map_err(|e| e.to_string())?;
    if last_e_val["body"]["subject"].as_str() != Some(badge_issuer) {
        return Err("Badge.issuer does not match last Endorsement subject".to_string());
    }

    // Normalize & cryptographically verify Signer #2 signature over `badge_pae` BEFORE emitting:
    let (canonical_sig, was_normalized) = if is_base64_flag {
        let sig_str = std::str::from_utf8(signature_input)
            .map_err(|_| "--signature-b64 is not valid UTF-8".to_string())?;
        let clean: String = sig_str.chars().filter(|c| !c.is_whitespace()).collect();
        let raw_sig = BASE64_STANDARD
            .decode(&clean)
            .map_err(|e| format!("invalid --signature-b64 base64: {e}"))?;
        normalize_signature_bytes(
            workload_alg,
            &raw_sig,
            Some((&workload_pub_bytes, &badge_pae)),
        )?
    } else {
        parse_external_signature_bytes(
            workload_alg,
            signature_input,
            Some((&workload_pub_bytes, &badge_pae)),
            "--signature-file",
        )?
    };
    verify_signature(
        workload_alg,
        &workload_pub_bytes,
        &badge_pae,
        &canonical_sig,
    )?;

    let badge_ref = evidence_ref(&badge_payload_bytes);
    let badge = SignedEndpointRecord {
        record_ref: badge_ref.clone(),
        envelope: DsseEnvelope {
            payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
            payload: prepared.badge_payload_b64.clone(),
            signatures: vec![
                prepared.issuer_signature.clone(),
                DsseSignature {
                    keyid: expected_workload_id.clone(),
                    sig: BASE64_STANDARD.encode(&canonical_sig),
                },
            ],
        },
    };

    let mut records = prepared.authority_chain.clone();
    records.push(badge.clone());

    if prepared.ephemeral_delegator && !root_key_ids.is_empty() {
        // Only the operator root(s) are actual deployment roots; the ephemeral delegator was the last link issuer.
        root_key_ids.truncate(1);
    }

    let grant_request = SubmitGrantsRequest {
        records,
        keys: prepared.keys.clone(),
        blobs: prepared.blobs.clone(),
    };

    Ok((
        MintedOfflineWorkloadBadge {
            deployment,
            badge_token_hex: prepared.badge_token_hex.clone(),
            stream_prefix: expected_stream_prefix,
            badge_stream: expected_badge_stream,
            badge_ref,
            workload_key_id: expected_workload_id,
            badge_issuer_key_id: badge_issuer.to_string(),
            root_key_ids,
            ephemeral_delegator: prepared.ephemeral_delegator,
            delegator_key_id: prepared.delegator_key_id.clone(),
            holder: prepared.holder.clone(),
            principal: b_acts_for.to_string(),
            workload: b_workload.to_string(),
            purpose: prepared.purpose.clone(),
            actor_prefixes: b_actor_prefixes,
            kinds: b_kinds,
            captured_at: b_captured_str.to_string(),
            not_before: b_nb_str.to_string(),
            not_after: b_na_str.to_string(),
            authority_chain: prepared.authority_chain.clone(),
            badge,
            grant_request,
        },
        was_normalized,
    ))
}

/// Verifies every structural bound, timestamp constraint, profile digest, and signature on
/// a [`PreparedOfflineWorkloadBadge`] BEFORE attaching Signer #2 (`workload_signing_key`),
/// returning a completed [`MintedOfflineWorkloadBadge`].
pub fn cosign_prepared_offline_workload_badge(
    prepared: &PreparedOfflineWorkloadBadge,
    workload_signing_key: &SigningKey,
) -> Result<MintedOfflineWorkloadBadge, String> {
    let workload_pub_bytes = workload_signing_key.verifying_key().to_bytes();
    let expected_workload_id = ed25519_key_id(&workload_pub_bytes);
    if prepared.workload_key_id != expected_workload_id {
        return Err(format!(
            "workload signing key ({expected_workload_id}) does not match prepared badge workload_key_id ({})",
            prepared.workload_key_id
        ));
    }
    let badge_pae = prepared.badge_pae_bytes()?;
    let subject_sig = workload_signing_key.sign(&badge_pae);
    let (minted, _) = cosign_prepared_offline_workload_badge_with_external_signature(
        prepared,
        &subject_sig.to_bytes(),
        false,
    )?;
    Ok(minted)
}

/// 1-step offline ceremony when the workload `SigningKey` is available during minting:
/// runs [`prepare_offline_workload_badge`] + [`cosign_prepared_offline_workload_badge`].
pub fn mint_offline_workload_badge(
    root_keys: &[SigningKey],
    explicit_delegator_key: Option<&SigningKey>,
    workload_signing_key: &SigningKey,
    params: &OfflineWorkloadBadgeParams,
) -> Result<MintedOfflineWorkloadBadge, String> {
    let pub_bytes = workload_signing_key.verifying_key().to_bytes();
    let prepared =
        prepare_offline_workload_badge(root_keys, explicit_delegator_key, &pub_bytes, params)?;
    cosign_prepared_offline_workload_badge(&prepared, workload_signing_key)
}
