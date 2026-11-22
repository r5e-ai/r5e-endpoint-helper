//! Operator Root Rotation Ceremony (`A6-slice2-roots-changed.md`):
//! - Offline proposal authoring (`propose_root_change` -> `provenance.r5e.io/v2/RootsChanged`)
//! - Offline 2-signer custodian co-signing (`approve_root_change` -> `provenance.r5e.io/v2/RootChangeApproval`)
//! - Gateway submission (`POST /v1/deployment/roots`) + immediate gateway sealer/working-key
//!   re-endorsement (`POST /v1/deployment/grants`) per `A6-slice2-roots-changed.md` §§4.4 & 5.4.

use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

use crate::attestation::{
    base_v2_schema_map, bytes_ref, decode_strict_base64, dsse_pae, ed25519_key_id,
    encode_canonical_json, evidence_ref, generate_os_random_bytes, sign_v2_record_multi, BlobEntry,
    DsseEnvelope, DsseSignature, PublicKeyEntry, SignedEndpointRecord, PROVENANCE_V2_PAYLOAD_TYPE,
    ROOTS_CHANGED_SCHEMA_REF, ROOT_CHANGE_APPROVAL_SCHEMA_REF,
};
use crate::claim_http::{
    build_root_gateway_grant, ceil_to_micros, classify_claim_error, default_gateway_grant_kinds,
    extract_recorded_refs, get_deployment_status, is_valid_bytes_ref, is_valid_evidence_ref,
    is_valid_key_id, is_valid_slug_token, is_valid_uri_identity, parse_and_verify_v2_pubkey,
    profile_binds_record, record_captured_at_utc, request_http11, submit_deployment_grants,
    verify_dsse_v2_sig, BuiltGatewayGrant, ClaimClientConfig, ClaimError, CustodianEntry,
    DeploymentStatusResponse, GatewayGrantParams, PrepareClaimRootEntry, SubmitGrantsRequest,
    SubmitGrantsResponse,
};

pub const DEPLOYMENT_ROOTS_PATH: &str = "/v1/deployment/roots";

/// Normative operator warning (`A6-slice2-roots-changed.md` §5.5) emitted whenever a deployment is
/// claimed with neither `recoveryKeys` nor `custodians`.
pub const IRREVERSIBLE_CLAIM_WARNING: &str = "WARNING: Neither --recovery-key nor --custodian was provided. A deployment claimed with no recovery keys and no named custodians can NEVER replace its root keys on this chain.";

/// Authorisation mode for `provenance.r5e.io/v2/RootsChanged` (`A6-slice2-roots-changed.md` §1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RootChangeAuthorization {
    Quorum,
    Recovery,
}

impl RootChangeAuthorization {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quorum => "quorum",
            Self::Recovery => "recovery",
        }
    }
}

/// Parameters for authoring a proposed `RootsChanged` record (`propose-root-change`).
#[derive(Debug, Clone)]
pub struct ProposeRootChangeParams {
    pub deployment: String,
    pub chain: String,
    pub replaces: String,
    pub seq: u64,
    pub authorization: RootChangeAuthorization,
    pub roots: Vec<PrepareClaimRootEntry>,
    pub threshold: usize,
    pub recovery_keys: Vec<String>,
    pub custodians: Vec<CustodianEntry>,
    pub reason: Option<String>,
    pub actor: String,
    pub captured_at: Option<DateTime<Utc>>,
    pub roots_changed_schema_ref: Option<String>,
    pub approval_schema_ref: Option<String>,
    pub custom_definition_blobs: Vec<BlobEntry>,
}

impl ProposeRootChangeParams {
    pub fn new(
        deployment: impl Into<String>,
        chain: impl Into<String>,
        replaces: impl Into<String>,
        seq: u64,
        authorization: RootChangeAuthorization,
        roots: Vec<PrepareClaimRootEntry>,
        threshold: usize,
    ) -> Self {
        Self {
            deployment: deployment.into(),
            chain: chain.into(),
            replaces: replaces.into(),
            seq,
            authorization,
            roots,
            threshold,
            recovery_keys: Vec::new(),
            custodians: Vec::new(),
            reason: None,
            actor: "urn:r5e:operator:root".to_string(),
            captured_at: None,
            roots_changed_schema_ref: None,
            approval_schema_ref: None,
            custom_definition_blobs: Vec::new(),
        }
    }
}

/// Offline root-rotation ceremony artifact written by `propose-root-change`, enriched by one or
/// more `approve-root-change` invocations, and submitted by `apply-root-change`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RootChangeProposalFile {
    pub deployment: String,
    pub chain: String,
    pub seq: u64,
    pub change: SignedEndpointRecord,
    pub approvals: Vec<SignedEndpointRecord>,
    pub keys: Vec<PublicKeyEntry>,
    pub blobs: Vec<BlobEntry>,
}

/// Parameters for co-signing a `RootChangeApproval` record (`approve-root-change`).
#[derive(Debug, Clone)]
pub struct ApproveRootChangeParams {
    pub custodian: String,
    pub reason: Option<String>,
    pub actor: String,
    pub captured_at: Option<DateTime<Utc>>,
    pub approval_schema_ref: Option<String>,
    pub custom_definition_blobs: Vec<BlobEntry>,
}

impl ApproveRootChangeParams {
    pub fn new(custodian: impl Into<String>) -> Self {
        Self {
            custodian: custodian.into(),
            reason: None,
            actor: "urn:r5e:operator:custodian".to_string(),
            captured_at: None,
            approval_schema_ref: None,
            custom_definition_blobs: Vec::new(),
        }
    }
}

/// Wire body for `POST /v1/deployment/roots` (`A6-slice2-roots-changed.md` §5.4).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubmitRootChangeRequest {
    pub change: SignedEndpointRecord,
    pub approvals: Vec<SignedEndpointRecord>,
    pub keys: Vec<PublicKeyEntry>,
    pub blobs: Vec<BlobEntry>,
}

/// Parsed response from `POST /v1/deployment/roots`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitRootChangeResponse {
    pub status: u16,
    pub recorded_refs: Vec<String>,
    pub raw: Value,
}

/// Complete outcome of `apply_root_change` (`POST /v1/deployment/roots` + optional `POST /v1/deployment/grants`).
#[derive(Debug, Clone)]
pub struct AppliedRootChangeOutcome {
    pub roots_response: SubmitRootChangeResponse,
    pub gateway_grant: Option<(BuiltGatewayGrant, SubmitGrantsResponse)>,
}

fn build_operator_capture_profile_blob(
    stream_prefix: &str,
    issuer_key_id: &str,
    roots_changed_schema_override: Option<&str>,
    approval_schema_override: Option<&str>,
) -> Result<BlobEntry, String> {
    let mut schemas = base_v2_schema_map();
    if let Some(rc_ref) = roots_changed_schema_override {
        if !is_valid_bytes_ref(rc_ref) {
            return Err(format!("invalid --roots-changed-schema-ref: {rc_ref}"));
        }
        schemas.insert(
            "provenance.r5e.io/v2/RootsChanged".to_string(),
            Value::String(rc_ref.to_string()),
        );
    }
    if let Some(ap_ref) = approval_schema_override {
        if !is_valid_bytes_ref(ap_ref) {
            return Err(format!("invalid --approval-schema-ref: {ap_ref}"));
        }
        schemas.insert(
            "provenance.r5e.io/v2/RootChangeApproval".to_string(),
            Value::String(ap_ref.to_string()),
        );
    }

    let policy_ref = bytes_ref(b"permit(principal, action, resource);");
    let profile_doc = json!({
        "format": "r5e.capture-profile/v2",
        "schemas": Value::Object(schemas),
        "authority": {
            "bindings": [
                {
                    "streamPrefix": stream_prefix,
                    "actorPrefixes": ["urn:r5e:"],
                    "issuerKeys": [issuer_key_id],
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
    Ok(BlobEntry {
        blob_ref: profile_ref,
        media_type: Some("application/json".to_string()),
        base64: BASE64_STANDARD.encode(&profile_bytes),
    })
}

fn insert_unique_key(keys: &mut Vec<PublicKeyEntry>, entry: PublicKeyEntry) -> Result<(), String> {
    if let Some(existing) = keys.iter().find(|k| k.keyid == entry.keyid) {
        if existing != &entry {
            return Err(format!(
                "conflicting public key bytes for keyid {}",
                entry.keyid
            ));
        }
        return Ok(());
    }
    keys.push(entry);
    Ok(())
}

fn insert_unique_blob(blobs: &mut Vec<BlobEntry>, entry: BlobEntry) -> Result<(), String> {
    if let Some(existing) = blobs.iter().find(|b| b.blob_ref == entry.blob_ref) {
        if existing.base64 != entry.base64 {
            return Err(format!("conflicting blob bytes for ref {}", entry.blob_ref));
        }
        return Ok(());
    }
    blobs.push(entry);
    Ok(())
}

/// Validates local terms (`A6-slice2-roots-changed.md` §§3.2 & 3.4), builds a self-describing
/// `r5e.capture-profile/v2` blob, and DSSE-signs `provenance.r5e.io/v2/RootsChanged` on
/// `urn:r5e:stream:<deployment>:start` at `params.seq`.
pub fn propose_root_change(
    signer_key: &SigningKey,
    params: &ProposeRootChangeParams,
) -> Result<RootChangeProposalFile, String> {
    if !is_valid_slug_token(&params.deployment, true) {
        return Err(format!(
            "invalid deployment slug {:?}: must match ^[a-z0-9][a-z0-9-]*$",
            params.deployment
        ));
    }
    if !is_valid_evidence_ref(&params.chain) {
        return Err(format!("invalid --chain evidence ref: {}", params.chain));
    }
    if !is_valid_evidence_ref(&params.replaces) {
        return Err(format!(
            "invalid --replaces evidence ref: {}",
            params.replaces
        ));
    }
    if params.seq < 3 {
        return Err(format!(
            "wrong_start_position: RootsChanged seq must be >= 3, got {}",
            params.seq
        ));
    }
    if !params.actor.starts_with("urn:r5e:") {
        return Err(format!(
            "actor ({}) must start with 'urn:r5e:' to match capture profile authority binding",
            params.actor
        ));
    }
    if params.roots.is_empty() {
        return Err("invalid_deployment_terms: roots must be non-empty".to_string());
    }
    if params.threshold == 0 || params.threshold > params.roots.len() {
        return Err(format!(
            "invalid_deployment_terms: threshold {} must satisfy 1 <= threshold <= roots.len() ({})",
            params.threshold,
            params.roots.len()
        ));
    }
    if let Some(ref r) = params.reason {
        if r.trim().is_empty() {
            return Err("reason cannot be empty when provided".to_string());
        }
    }

    let signer_pub_bytes = signer_key.verifying_key().to_bytes();
    let signer_key_id = ed25519_key_id(&signer_pub_bytes);
    let signer_pub_b64 = BASE64_STANDARD.encode(signer_pub_bytes);

    let mut seen_root_keys = BTreeSet::new();
    let mut roots_json = Vec::with_capacity(params.roots.len());
    for (idx, r) in params.roots.iter().enumerate() {
        let (_, _, derived_key_id) = parse_and_verify_v2_pubkey(
            &r.public_key.algorithm,
            &r.public_key.bytes,
            None,
            &format!("roots[{idx}].publicKey"),
        )?;
        if !seen_root_keys.insert(derived_key_id.clone()) {
            return Err(format!(
                "invalid_deployment_terms: duplicate root key {derived_key_id}"
            ));
        }
        let mut entry = Map::new();
        entry.insert("key".to_string(), Value::String(derived_key_id));
        entry.insert("publicKey".to_string(), json!(&r.public_key));
        if let Some(ref h) = r.holder {
            if !is_valid_slug_token(h, false) {
                return Err(format!("invalid roots[{idx}].holder: {h}"));
            }
            if h == "agent" {
                return Err(format!(
                    "invalid_deployment_terms: roots[{idx}].holder cannot be \"agent\""
                ));
            }
            entry.insert("holder".to_string(), Value::String(h.clone()));
        }
        if let Some(ref c) = r.custody {
            if !is_valid_slug_token(c, false) {
                return Err(format!("invalid roots[{idx}].custody: {c}"));
            }
            entry.insert("custody".to_string(), Value::String(c.clone()));
        }
        if let Some(ref id) = r.identity {
            if !is_valid_uri_identity(id) {
                return Err(format!("invalid roots[{idx}].identity URI: {id}"));
            }
            entry.insert("identity".to_string(), Value::String(id.clone()));
        }
        roots_json.push(Value::Object(entry));
    }

    let mut seen_recovery_keys = BTreeSet::new();
    for rk in &params.recovery_keys {
        if !is_valid_key_id(rk) {
            return Err(format!("invalid recoveryKey format: {rk}"));
        }
        if !seen_recovery_keys.insert(rk.clone()) {
            return Err(format!(
                "invalid_deployment_terms: duplicate recoveryKey {rk}"
            ));
        }
        if seen_root_keys.contains(rk) {
            return Err(format!(
                "invalid_deployment_terms: recovery key {rk} overlaps new roots"
            ));
        }
        if params.authorization == RootChangeAuthorization::Recovery && rk == &signer_key_id {
            return Err(format!(
                "spent_recovery_key_retained: recovery signer {signer_key_id} has revealed its public key and cannot be retained in recoveryKeys"
            ));
        }
    }

    let mut seen_custodian_ids = BTreeSet::new();
    let mut seen_custodian_keys = BTreeSet::new();
    for c in &params.custodians {
        if !is_valid_uri_identity(&c.identity) {
            return Err(format!("invalid custodian identity URI: {}", c.identity));
        }
        if !seen_custodian_ids.insert(c.identity.clone()) {
            return Err(format!(
                "invalid_deployment_terms: duplicate custodian identity {}",
                c.identity
            ));
        }
        if let Some(ref k) = c.key {
            if !is_valid_key_id(k) {
                return Err(format!("invalid custodian key format: {k}"));
            }
            if !seen_custodian_keys.insert(k.clone()) {
                return Err(format!(
                    "invalid_deployment_terms: duplicate custodian key {k}"
                ));
            }
            if seen_root_keys.contains(k) || seen_recovery_keys.contains(k) {
                return Err(format!(
                    "invalid_deployment_terms: custodian personal key {k} cannot appear in roots or recoveryKeys"
                ));
            }
        }
    }

    let start_stream = format!("urn:r5e:stream:{}:start", params.deployment);
    let effective_rc_schema = params
        .roots_changed_schema_ref
        .as_deref()
        .unwrap_or(ROOTS_CHANGED_SCHEMA_REF);
    let profile_blob = build_operator_capture_profile_blob(
        &start_stream,
        &signer_key_id,
        params.roots_changed_schema_ref.as_deref(),
        params.approval_schema_ref.as_deref(),
    )?;

    let mut body = Map::new();
    body.insert("chain".to_string(), Value::String(params.chain.clone()));
    body.insert(
        "replaces".to_string(),
        Value::String(params.replaces.clone()),
    );
    body.insert(
        "authorization".to_string(),
        Value::String(params.authorization.as_str().to_string()),
    );
    body.insert("signer".to_string(), Value::String(signer_key_id.clone()));
    body.insert(
        "signerKey".to_string(),
        json!({
            "algorithm": "ed25519",
            "bytes": &signer_pub_b64,
        }),
    );
    body.insert("roots".to_string(), Value::Array(roots_json));
    body.insert(
        "threshold".to_string(),
        Value::Number(params.threshold.into()),
    );
    if !params.recovery_keys.is_empty() {
        body.insert("recoveryKeys".to_string(), json!(&params.recovery_keys));
    }
    if !params.custodians.is_empty() {
        body.insert("custodians".to_string(), json!(&params.custodians));
    }
    if let Some(ref reason) = params.reason {
        body.insert("reason".to_string(), Value::String(reason.clone()));
    }

    let now = params.captured_at.unwrap_or_else(Utc::now);
    let captured_at = now.to_rfc3339_opts(SecondsFormat::Micros, true);

    let change_record = sign_v2_record_multi(
        &[signer_key],
        json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootsChanged",
            "schemaRef": effective_rc_schema,
            "profileRef": &profile_blob.blob_ref,
            "stream": &start_stream,
            "seq": params.seq,
            "previous": &params.replaces,
            "actor": &params.actor,
            "capturedAt": &captured_at,
            "body": Value::Object(body),
        })
        .as_object()
        .expect("RootsChanged envelope object")
        .clone(),
    )?;

    let mut blobs = Vec::new();
    insert_unique_blob(&mut blobs, profile_blob)?;
    for b in &params.custom_definition_blobs {
        insert_unique_blob(&mut blobs, b.clone())?;
    }

    let keys = vec![PublicKeyEntry {
        keyid: signer_key_id,
        algorithm: "ed25519".to_string(),
        bytes: signer_pub_b64,
    }];

    Ok(RootChangeProposalFile {
        deployment: params.deployment.clone(),
        chain: params.chain.clone(),
        seq: params.seq,
        change: change_record,
        approvals: Vec::new(),
        keys,
        blobs,
    })
}

/// Co-signs a 2-signature `provenance.r5e.io/v2/RootChangeApproval` (`signatures: [root, custodianKey]`)
/// on a fresh off-start stream `urn:r5e:stream:<deployment>:authority:approval:<random12b64url>`
/// (`seq = 1`, `previous = null`), verifies the target `RootsChanged` proposal first, and appends
/// the approval, public keys, and capture profile blob (deduped) into `proposal`.
pub fn approve_root_change(
    proposal: &mut RootChangeProposalFile,
    root_signing_key: &SigningKey,
    custodian_signing_key: &SigningKey,
    params: &ApproveRootChangeParams,
) -> Result<SignedEndpointRecord, String> {
    let change_val = verify_roots_changed_record_in_proposal(proposal)?;
    let change_auth = change_val
        .get("body")
        .and_then(|b| b.get("authorization"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if change_auth != "quorum" {
        return Err(format!(
            "approval_not_for_quorum_change: proposal authorization is {change_auth:?} (RootChangeApproval only applies to \"quorum\" proposals)"
        ));
    }

    if !is_valid_uri_identity(&params.custodian) {
        return Err(format!(
            "invalid custodian identity URI: {}",
            params.custodian
        ));
    }
    if !params.actor.starts_with("urn:r5e:") {
        return Err(format!(
            "actor ({}) must start with 'urn:r5e:' to match capture profile authority binding",
            params.actor
        ));
    }
    if let Some(ref r) = params.reason {
        if r.trim().is_empty() {
            return Err("reason cannot be empty when provided".to_string());
        }
    }

    let root_pub_bytes = root_signing_key.verifying_key().to_bytes();
    let root_key_id = ed25519_key_id(&root_pub_bytes);
    let root_pub_b64 = BASE64_STANDARD.encode(root_pub_bytes);

    let cust_pub_bytes = custodian_signing_key.verifying_key().to_bytes();
    let cust_key_id = ed25519_key_id(&cust_pub_bytes);
    let cust_pub_b64 = BASE64_STANDARD.encode(cust_pub_bytes);

    if root_key_id == cust_key_id {
        return Err(format!(
            "approver_not_in_quorum: custodian personal signing key ({cust_key_id}) must be distinct from approving root key"
        ));
    }

    // Check existing approvals in `proposal` to prevent conflicting `(root, custodian, custodianKey)`
    // entries that would disqualify votes under `A6-slice2-roots-changed.md` §3.4:
    for existing in &proposal.approvals {
        let existing_bytes = decode_strict_base64(&existing.envelope.payload)
            .map_err(|e| format!("invalid existing approval payload base64: {e}"))?;
        let existing_val: Value = serde_json::from_slice(&existing_bytes)
            .map_err(|e| format!("invalid existing approval payload JSON: {e}"))?;
        let ex_body = existing_val
            .get("body")
            .and_then(Value::as_object)
            .ok_or_else(|| "existing approval missing body".to_string())?;
        let ex_root = ex_body
            .get("root")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let ex_cust = ex_body
            .get("custodian")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let ex_ckey = ex_body
            .get("custodianKey")
            .and_then(Value::as_str)
            .unwrap_or_default();

        if ex_root == root_key_id && ex_cust == params.custodian && ex_ckey == cust_key_id {
            return Err(format!(
                "duplicate approval: root {root_key_id} and custodian {} already approved this proposal",
                params.custodian
            ));
        }
        if ex_root == root_key_id {
            return Err(format!(
                "conflicting approval under root {root_key_id}: already paired with ({ex_cust}, {ex_ckey}); a second pair would disqualify this root's quorum vote (§3.4)"
            ));
        }
        if ex_cust == params.custodian {
            return Err(format!(
                "conflicting approval for custodian {}: already paired with root {ex_root}; approving under two distinct roots disqualifies both (§3.4)",
                params.custodian
            ));
        }
        if ex_ckey == cust_key_id {
            return Err(format!(
                "conflicting approval for custodianKey {cust_key_id}: already paired with root {ex_root}; approving under two distinct roots disqualifies both (§3.4)"
            ));
        }
    }

    let rand_12 = generate_os_random_bytes::<12>()?;
    let rand_token = URL_SAFE_NO_PAD.encode(rand_12);
    let approval_stream = format!(
        "urn:r5e:stream:{}:authority:approval:{rand_token}",
        proposal.deployment
    );

    let effective_ap_schema = params
        .approval_schema_ref
        .as_deref()
        .unwrap_or(ROOT_CHANGE_APPROVAL_SCHEMA_REF);
    let profile_blob = build_operator_capture_profile_blob(
        &approval_stream,
        &root_key_id,
        None,
        params.approval_schema_ref.as_deref(),
    )?;

    let mut body = Map::new();
    body.insert(
        "change".to_string(),
        Value::String(proposal.change.record_ref.clone()),
    );
    body.insert("root".to_string(), Value::String(root_key_id.clone()));
    body.insert(
        "custodian".to_string(),
        Value::String(params.custodian.clone()),
    );
    body.insert(
        "custodianKey".to_string(),
        Value::String(cust_key_id.clone()),
    );
    body.insert(
        "custodianPublicKey".to_string(),
        json!({
            "algorithm": "ed25519",
            "bytes": &cust_pub_b64,
        }),
    );
    if let Some(ref reason) = params.reason {
        body.insert("reason".to_string(), Value::String(reason.clone()));
    }

    let now = params.captured_at.unwrap_or_else(Utc::now);
    let captured_at = now.to_rfc3339_opts(SecondsFormat::Micros, true);

    let approval = sign_v2_record_multi(
        &[root_signing_key, custodian_signing_key],
        json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootChangeApproval",
            "schemaRef": effective_ap_schema,
            "profileRef": &profile_blob.blob_ref,
            "stream": &approval_stream,
            "seq": 1,
            "previous": null,
            "actor": &params.actor,
            "capturedAt": &captured_at,
            "body": Value::Object(body),
        })
        .as_object()
        .expect("RootChangeApproval envelope object")
        .clone(),
    )?;

    proposal.approvals.push(approval.clone());
    insert_unique_key(
        &mut proposal.keys,
        PublicKeyEntry {
            keyid: root_key_id,
            algorithm: "ed25519".to_string(),
            bytes: root_pub_b64,
        },
    )?;
    insert_unique_key(
        &mut proposal.keys,
        PublicKeyEntry {
            keyid: cust_key_id,
            algorithm: "ed25519".to_string(),
            bytes: cust_pub_b64,
        },
    )?;
    insert_unique_blob(&mut proposal.blobs, profile_blob)?;
    for b in &params.custom_definition_blobs {
        insert_unique_blob(&mut proposal.blobs, b.clone())?;
    }

    Ok(approval)
}

fn verify_roots_changed_record_in_proposal(
    proposal: &RootChangeProposalFile,
) -> Result<Value, String> {
    if !is_valid_slug_token(&proposal.deployment, true) {
        return Err(format!(
            "invalid proposal deployment slug: {:?}",
            proposal.deployment
        ));
    }
    if !is_valid_evidence_ref(&proposal.chain) {
        return Err(format!("invalid proposal chain ref: {}", proposal.chain));
    }
    if proposal.seq < 3 {
        return Err(format!(
            "invalid proposal seq {}: must be >= 3",
            proposal.seq
        ));
    }
    if proposal.change.envelope.payload_type != PROVENANCE_V2_PAYLOAD_TYPE {
        return Err(format!(
            "unexpected proposal.change payloadType: {}",
            proposal.change.envelope.payload_type
        ));
    }
    let payload_bytes = decode_strict_base64(&proposal.change.envelope.payload)
        .map_err(|e| format!("invalid proposal.change payload base64: {e}"))?;
    let computed_ref = evidence_ref(&payload_bytes);
    if computed_ref != proposal.change.record_ref {
        return Err(format!(
            "proposal.change.ref ({}) != computed digest ({computed_ref})",
            proposal.change.record_ref
        ));
    }
    let parsed: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("invalid proposal.change JSON: {e}"))?;
    if encode_canonical_json(&parsed)? != payload_bytes {
        return Err("proposal.change payload is not canonical JSON (VERIFY-V2 §2.1)".to_string());
    }
    if parsed.get("apiVersion").and_then(Value::as_str) != Some("provenance.r5e.io/v2")
        || parsed.get("kind").and_then(Value::as_str) != Some("RootsChanged")
    {
        return Err(
            "proposal.change is not a provenance.r5e.io/v2 RootsChanged record".to_string(),
        );
    }
    let expected_stream = format!("urn:r5e:stream:{}:start", proposal.deployment);
    if parsed.get("stream").and_then(Value::as_str) != Some(expected_stream.as_str()) {
        return Err(format!(
            "proposal.change stream ({:?}) != expected {expected_stream}",
            parsed.get("stream")
        ));
    }
    if parsed.get("seq").and_then(Value::as_u64) != Some(proposal.seq) {
        return Err(format!(
            "proposal.change seq ({:?}) != proposal.seq ({})",
            parsed.get("seq"),
            proposal.seq
        ));
    }
    if proposal.change.envelope.signatures.len() != 1 {
        return Err(format!(
            "proposal.change must carry 1 signature, got {}",
            proposal.change.envelope.signatures.len()
        ));
    }
    let signer_id = parsed
        .get("body")
        .and_then(|b| b.get("signer"))
        .and_then(Value::as_str)
        .ok_or_else(|| "proposal.change missing body.signer".to_string())?;
    if parsed.get("issuer").and_then(Value::as_str) != Some(signer_id)
        || proposal.change.envelope.signatures[0].keyid != signer_id
    {
        return Err("proposal.change signer / issuer / signature[0].keyid mismatch".to_string());
    }
    let signer_key_obj = parsed
        .get("body")
        .and_then(|b| b.get("signerKey"))
        .and_then(Value::as_object)
        .ok_or_else(|| "proposal.change missing body.signerKey".to_string())?;
    let (signer_alg, signer_pub_bytes, _) = parse_and_verify_v2_pubkey(
        signer_key_obj
            .get("algorithm")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        signer_key_obj
            .get("bytes")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        Some(signer_id),
        "proposal.change.body.signerKey",
    )?;
    verify_dsse_v2_sig(
        signer_alg,
        &signer_pub_bytes,
        &payload_bytes,
        &proposal.change.envelope.signatures[0].sig,
        "proposal.change signature",
    )?;
    if parsed
        .get("body")
        .and_then(|b| b.get("chain"))
        .and_then(Value::as_str)
        != Some(proposal.chain.as_str())
    {
        return Err("proposal.change.body.chain != proposal.chain".to_string());
    }
    Ok(parsed)
}

/// Offline integrity check over a `RootChangeProposalFile` before submitting it to
/// `POST /v1/deployment/roots`.
pub fn verify_proposal_locally(proposal: &RootChangeProposalFile) -> Result<(), String> {
    let mut keys_by_id = BTreeMap::new();
    for k in &proposal.keys {
        let (alg, pub_bytes, _) = parse_and_verify_v2_pubkey(
            &k.algorithm,
            &k.bytes,
            Some(&k.keyid),
            &format!("proposal.keys[{}]", k.keyid),
        )?;
        if keys_by_id
            .insert(k.keyid.clone(), (alg, pub_bytes))
            .is_some()
        {
            return Err(format!("duplicate keyid in proposal.keys: {}", k.keyid));
        }
    }

    let mut blobs_by_ref = BTreeMap::new();
    for b in &proposal.blobs {
        let raw = decode_strict_base64(&b.base64)
            .map_err(|e| format!("invalid base64 in proposal.blobs[{}]: {e}", b.blob_ref))?;
        let computed = bytes_ref(&raw);
        if computed != b.blob_ref {
            return Err(format!(
                "proposal.blobs digest mismatch: declared {}, computed {computed}",
                b.blob_ref
            ));
        }
        blobs_by_ref.insert(b.blob_ref.clone(), raw);
    }

    let change_val = verify_roots_changed_record_in_proposal(proposal)?;
    let change_profile_ref = change_val
        .get("profileRef")
        .and_then(Value::as_str)
        .ok_or_else(|| "proposal.change missing profileRef".to_string())?;
    let change_prof_bytes = blobs_by_ref.get(change_profile_ref).ok_or_else(|| {
        format!("proposal.blobs missing profileRef {change_profile_ref} cited by proposal.change")
    })?;
    let change_prof_val: Value = serde_json::from_slice(change_prof_bytes)
        .map_err(|e| format!("invalid JSON in change profile blob: {e}"))?;
    let change_stream = change_val
        .get("stream")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let change_actor = change_val
        .get("actor")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let change_issuer = change_val
        .get("issuer")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !keys_by_id.contains_key(change_issuer) {
        return Err(format!(
            "proposal.keys missing signer key {change_issuer} for proposal.change"
        ));
    }
    if !profile_binds_record(&change_prof_val, change_stream, change_actor, change_issuer) {
        return Err(
            "proposal.change capture profile does not bind (stream, actor, issuer)".to_string(),
        );
    }

    let mut seen_approval_streams = BTreeSet::new();
    for (idx, ap) in proposal.approvals.iter().enumerate() {
        if ap.envelope.payload_type != PROVENANCE_V2_PAYLOAD_TYPE {
            return Err(format!(
                "proposal.approvals[{idx}] unexpected payloadType: {}",
                ap.envelope.payload_type
            ));
        }
        let ap_bytes = decode_strict_base64(&ap.envelope.payload)
            .map_err(|e| format!("proposal.approvals[{idx}] invalid payload base64: {e}"))?;
        if evidence_ref(&ap_bytes) != ap.record_ref {
            return Err(format!("proposal.approvals[{idx}] ref digest mismatch"));
        }
        let ap_val: Value = serde_json::from_slice(&ap_bytes)
            .map_err(|e| format!("proposal.approvals[{idx}] invalid JSON: {e}"))?;
        if encode_canonical_json(&ap_val)? != ap_bytes {
            return Err(format!(
                "proposal.approvals[{idx}] payload is not canonical JSON"
            ));
        }
        if ap_val.get("kind").and_then(Value::as_str) != Some("RootChangeApproval") {
            return Err(format!(
                "proposal.approvals[{idx}] is not RootChangeApproval"
            ));
        }
        let ap_stream = ap_val
            .get("stream")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("proposal.approvals[{idx}] missing stream"))?;
        if ap_stream == change_stream || !seen_approval_streams.insert(ap_stream.to_string()) {
            return Err(format!(
                "approval_not_alone_on_stream: proposal.approvals[{idx}] stream {ap_stream} collides"
            ));
        }
        if ap_val.get("seq").and_then(Value::as_u64) != Some(1)
            || ap_val.get("previous") != Some(&Value::Null)
        {
            return Err(format!(
                "approval_not_alone_on_stream: proposal.approvals[{idx}] must sit at seq 1 with previous null"
            ));
        }
        let ap_body = ap_val
            .get("body")
            .and_then(Value::as_object)
            .ok_or_else(|| format!("proposal.approvals[{idx}] missing body"))?;
        if ap_body.get("change").and_then(Value::as_str)
            != Some(proposal.change.record_ref.as_str())
        {
            return Err(format!(
                "proposal.approvals[{idx}].body.change does not match proposal.change.ref"
            ));
        }
        if ap.envelope.signatures.len() != 2 {
            return Err(format!(
                "proposal.approvals[{idx}] must carry 2 signatures, got {}",
                ap.envelope.signatures.len()
            ));
        }
        let root_id = ap_body
            .get("root")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let cust_key_id = ap_body
            .get("custodianKey")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if ap.envelope.signatures[0].keyid != root_id
            || ap.envelope.signatures[1].keyid != cust_key_id
        {
            return Err(format!(
                "proposal.approvals[{idx}] signature keyids do not match [root, custodianKey]"
            ));
        }
        let (root_alg, root_pub_bytes) = keys_by_id.get(root_id).ok_or_else(|| {
            format!("proposal.keys missing approving root key {root_id} for approvals[{idx}]")
        })?;
        let (cust_alg, cust_pub_bytes) = keys_by_id.get(cust_key_id).ok_or_else(|| {
            format!("proposal.keys missing custodianKey {cust_key_id} for approvals[{idx}]")
        })?;
        verify_dsse_v2_sig(
            *root_alg,
            root_pub_bytes,
            &ap_bytes,
            &ap.envelope.signatures[0].sig,
            &format!("approvals[{idx}] root signature"),
        )?;
        verify_dsse_v2_sig(
            *cust_alg,
            cust_pub_bytes,
            &ap_bytes,
            &ap.envelope.signatures[1].sig,
            &format!("approvals[{idx}] custodian signature"),
        )?;

        let ap_prof_ref = ap_val
            .get("profileRef")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("proposal.approvals[{idx}] missing profileRef"))?;
        let ap_prof_bytes = blobs_by_ref.get(ap_prof_ref).ok_or_else(|| {
            format!("proposal.blobs missing profileRef {ap_prof_ref} for approvals[{idx}]")
        })?;
        let ap_prof_val: Value = serde_json::from_slice(ap_prof_bytes)
            .map_err(|e| format!("invalid JSON in approvals[{idx}] profile blob: {e}"))?;
        let ap_actor = ap_val
            .get("actor")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !profile_binds_record(&ap_prof_val, ap_stream, ap_actor, root_id) {
            return Err(format!(
                "proposal.approvals[{idx}] capture profile does not bind (stream, actor, issuer)"
            ));
        }
    }

    Ok(())
}

/// Submits a `{change, approvals, keys, blobs}` root-replacement bundle (`POST /v1/deployment/roots`).
pub fn submit_deployment_roots(
    cfg: &ClaimClientConfig,
    req: &SubmitRootChangeRequest,
) -> Result<SubmitRootChangeResponse, ClaimError> {
    let body = serde_json::to_vec(req)
        .map_err(|e| ClaimError::Transport(format!("serialize root change request: {e}")))?;
    let (status, resp_bytes) = request_http11(cfg, "POST", DEPLOYMENT_ROOTS_PATH, Some(&body))?;
    if status != 201 && status != 200 {
        return Err(classify_claim_error(status, &resp_bytes));
    }
    let raw: Value = if resp_bytes.iter().all(u8::is_ascii_whitespace) {
        json!({})
    } else {
        serde_json::from_slice(&resp_bytes).map_err(|e| {
            ClaimError::Transport(format!("invalid JSON from /v1/deployment/roots: {e}"))
        })?
    };
    let recorded_refs = extract_recorded_refs(&raw);
    Ok(SubmitRootChangeResponse {
        status,
        recorded_refs,
        raw,
    })
}

fn derive_chain_start_not_before(status: &DeploymentStatusResponse) -> Option<String> {
    let earliest = [
        status.chain_started.as_ref(),
        status.deployment_record.as_ref(),
    ]
    .into_iter()
    .flatten()
    .filter_map(record_captured_at_utc)
    .min()?;
    Some((earliest - chrono::Duration::seconds(60)).to_rfc3339_opts(SecondsFormat::Micros, true))
}

/// Applies a verified `RootChangeProposalFile` via `POST /v1/deployment/roots` and, when
/// `grant_gateway_with` is supplied (`A6-slice2-roots-changed.md` §4.4 recommended operational default),
/// immediately mints and submits a fresh gateway `Endorsement` (covering `EpochSeal` + working kinds)
/// to `POST /v1/deployment/grants` so pre-rotation seals stay qualifying and `Sealer` continues uninterrupted.
#[allow(clippy::too_many_arguments)]
pub fn apply_root_change(
    cfg: &ClaimClientConfig,
    proposal: &RootChangeProposalFile,
    grant_gateway_with: Option<&SigningKey>,
    gateway_key_id_override: Option<String>,
    grant_not_before: Option<String>,
    grant_ttl_seconds: u64,
    grant_seq: u64,
    grant_previous: Option<String>,
    grant_actor: &str,
    grant_kinds: Option<Vec<String>>,
) -> Result<AppliedRootChangeOutcome, ClaimError> {
    verify_proposal_locally(proposal).map_err(ClaimError::Validation)?;

    let submit_req = SubmitRootChangeRequest {
        change: proposal.change.clone(),
        approvals: proposal.approvals.clone(),
        keys: proposal.keys.clone(),
        blobs: proposal.blobs.clone(),
    };
    let roots_response = submit_deployment_roots(cfg, &submit_req)?;

    let gateway_grant = if let Some(grant_root_key) = grant_gateway_with {
        let known_gw_key_id = gateway_key_id_override.or_else(|| {
            roots_response
                .raw
                .get("gatewayKey")
                .and_then(|gk| gk.get("keyid"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        });

        let fetched_status = if known_gw_key_id.is_none() {
            Some(get_deployment_status(cfg)?)
        } else if grant_not_before.is_none() {
            // Best-effort status lookup to anchor `notBefore` at chain start (`capturedAt - 60s`);
            // gracefully fall back to `None` if `--gateway-key-id` was passed against a minimal host.
            get_deployment_status(cfg).ok()
        } else {
            None
        };

        let resolved_gw_key_id = match known_gw_key_id.or_else(|| {
            fetched_status
                .as_ref()
                .and_then(|s| s.gateway_key.as_ref().map(|gk| gk.keyid.clone()))
        }) {
            Some(id) => id,
            None => {
                return Err(ClaimError::Validation(
                    "gatewayKey was not provided via --gateway-key-id and was not returned by GET /v1/deployment"
                        .to_string(),
                ));
            }
        };

        let effective_not_before = grant_not_before.or_else(|| {
            fetched_status
                .as_ref()
                .and_then(derive_chain_start_not_before)
        });

        let stream_prefix = format!("urn:r5e:stream:{}:", proposal.deployment);
        let mut grant_params = GatewayGrantParams::new(resolved_gw_key_id, stream_prefix);
        if let Some(admitted_floor) = [
            record_captured_at_utc(&proposal.change),
            fetched_status
                .as_ref()
                .and_then(|s| s.deployment_record.as_ref())
                .and_then(record_captured_at_utc),
        ]
        .into_iter()
        .flatten()
        .max()
        {
            grant_params.captured_at =
                Some(std::cmp::max(Utc::now(), ceil_to_micros(admitted_floor)));
        }
        grant_params.seq = grant_seq;
        grant_params.previous = grant_previous;
        grant_params.actor = grant_actor.to_string();
        grant_params.not_before_override = effective_not_before;
        grant_params.ttl_seconds = grant_ttl_seconds;
        grant_params.kinds = grant_kinds.unwrap_or_else(default_gateway_grant_kinds);

        let built = build_root_gateway_grant(grant_root_key, &grant_params)
            .map_err(ClaimError::Validation)?;
        let grant_resp = submit_deployment_grants(cfg, &built.request)?;
        Some((built, grant_resp))
    } else {
        None
    };

    Ok(AppliedRootChangeOutcome {
        roots_response,
        gateway_grant,
    })
}

// ---------------------------------------------------------------------------
// Detached External-Signer / Hardware Root Rotation
// ---------------------------------------------------------------------------

pub const PREPARED_ROOT_CHANGE_FORMAT: &str = "r5e.prepared-root-change/v2";
pub const PREPARED_ROOT_APPROVAL_FORMAT: &str = "r5e.prepared-root-approval/v2";

/// Unsigned `RootsChanged` ceremony artifact written by `prepare-root-change` and finalized by
/// `finalize-root-change`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreparedRootChange {
    pub format: String,
    pub deployment: String,
    pub chain: String,
    pub seq: u64,
    #[serde(rename = "recordRef")]
    pub record_ref: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    #[serde(rename = "payloadBase64")]
    pub payload_b64: String,
    #[serde(rename = "paeSha256")]
    pub pae_sha256: String,
    #[serde(rename = "signerKey")]
    pub signer_pubkey: PublicKeyEntry,
    pub blobs: Vec<BlobEntry>,
}

/// Unsigned 2-signer `RootChangeApproval` ceremony artifact written by `prepare-root-approval`
/// and finalized by `finalize-root-approval` (`signatures: [root, custodianKey]`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreparedRootApproval {
    pub format: String,
    #[serde(rename = "changeRef")]
    pub change_ref: String,
    #[serde(rename = "recordRef")]
    pub record_ref: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    #[serde(rename = "payloadBase64")]
    pub payload_b64: String,
    #[serde(rename = "paeSha256")]
    pub pae_sha256: String,
    #[serde(rename = "rootKey")]
    pub root_pubkey: PublicKeyEntry,
    pub custodian: String,
    #[serde(rename = "custodianKey")]
    pub custodian_pubkey: PublicKeyEntry,
    pub blobs: Vec<BlobEntry>,
}

fn parse_external_sig_for_pubkey(
    pubkey: &PublicKeyEntry,
    pae: &[u8],
    sig_input: &[u8],
    is_b64_flag: bool,
    label: &str,
) -> Result<(Vec<u8>, bool), String> {
    let (alg, pub_bytes, _) =
        parse_and_verify_v2_pubkey(&pubkey.algorithm, &pubkey.bytes, Some(&pubkey.keyid), label)?;
    let (canonical_sig, was_normalized) = if is_b64_flag {
        let sig_str = std::str::from_utf8(sig_input)
            .map_err(|_| format!("{label}: base64 signature is not valid UTF-8"))?;
        let clean: String = sig_str.chars().filter(|c| !c.is_whitespace()).collect();
        let raw_sig = BASE64_STANDARD
            .decode(&clean)
            .map_err(|e| format!("{label}: invalid base64 signature: {e}"))?;
        crate::crypto_keys::normalize_signature_bytes(alg, &raw_sig, Some((&pub_bytes, pae)))?
    } else {
        crate::crypto_keys::parse_external_signature_bytes(
            alg,
            sig_input,
            Some((&pub_bytes, pae)),
            label,
        )?
    };
    crate::crypto_keys::verify_signature(alg, &pub_bytes, pae, &canonical_sig)?;
    Ok((canonical_sig, was_normalized))
}

/// Builds and validates an unsigned `provenance.r5e.io/v2/RootsChanged` record for an external /
/// hardware signer (`ed25519 | es256 | es384`), returning `(PreparedRootChange, dsse_pae_bytes)`.
pub fn prepare_detached_root_change(
    signer_pubkey: &PublicKeyEntry,
    params: &ProposeRootChangeParams,
    allow_large_ed25519_pae: bool,
) -> Result<(PreparedRootChange, Vec<u8>), String> {
    let (signer_alg, signer_pub_bytes, signer_key_id) = parse_and_verify_v2_pubkey(
        &signer_pubkey.algorithm,
        &signer_pubkey.bytes,
        Some(&signer_pubkey.keyid),
        "signer_pubkey",
    )?;
    let signer_pub_b64 = BASE64_STANDARD.encode(&signer_pub_bytes);

    if !is_valid_slug_token(&params.deployment, true) {
        return Err(format!(
            "invalid deployment slug {:?}: must match ^[a-z0-9][a-z0-9-]*$",
            params.deployment
        ));
    }
    if !is_valid_evidence_ref(&params.chain) {
        return Err(format!("invalid --chain evidence ref: {}", params.chain));
    }
    if !is_valid_evidence_ref(&params.replaces) {
        return Err(format!(
            "invalid --replaces evidence ref: {}",
            params.replaces
        ));
    }
    if params.seq < 3 {
        return Err(format!(
            "wrong_start_position: RootsChanged seq must be >= 3, got {}",
            params.seq
        ));
    }
    if !params.actor.starts_with("urn:r5e:") {
        return Err(format!(
            "actor ({}) must start with 'urn:r5e:' to match capture profile authority binding",
            params.actor
        ));
    }
    if params.roots.is_empty() {
        return Err("invalid_deployment_terms: roots must be non-empty".to_string());
    }
    if params.threshold == 0 || params.threshold > params.roots.len() {
        return Err(format!(
            "invalid_deployment_terms: threshold {} must satisfy 1 <= threshold <= roots.len() ({})",
            params.threshold,
            params.roots.len()
        ));
    }
    if let Some(ref r) = params.reason {
        if r.trim().is_empty() {
            return Err("reason cannot be empty when provided".to_string());
        }
    }

    let mut seen_root_keys = BTreeSet::new();
    let mut roots_json = Vec::with_capacity(params.roots.len());
    for (idx, r) in params.roots.iter().enumerate() {
        let (_, _, derived_key_id) = parse_and_verify_v2_pubkey(
            &r.public_key.algorithm,
            &r.public_key.bytes,
            None,
            &format!("roots[{idx}].publicKey"),
        )?;
        if !seen_root_keys.insert(derived_key_id.clone()) {
            return Err(format!(
                "invalid_deployment_terms: duplicate root key {derived_key_id}"
            ));
        }
        let mut entry = Map::new();
        entry.insert("key".to_string(), Value::String(derived_key_id));
        entry.insert("publicKey".to_string(), json!(&r.public_key));
        if let Some(ref h) = r.holder {
            if !is_valid_slug_token(h, false) {
                return Err(format!("invalid roots[{idx}].holder: {h}"));
            }
            if h == "agent" {
                return Err(format!(
                    "invalid_deployment_terms: roots[{idx}].holder cannot be \"agent\""
                ));
            }
            entry.insert("holder".to_string(), Value::String(h.clone()));
        }
        if let Some(ref c) = r.custody {
            if !is_valid_slug_token(c, false) {
                return Err(format!("invalid roots[{idx}].custody: {c}"));
            }
            entry.insert("custody".to_string(), Value::String(c.clone()));
        }
        if let Some(ref id) = r.identity {
            if !is_valid_uri_identity(id) {
                return Err(format!("invalid roots[{idx}].identity URI: {id}"));
            }
            entry.insert("identity".to_string(), Value::String(id.clone()));
        }
        roots_json.push(Value::Object(entry));
    }

    let mut seen_recovery_keys = BTreeSet::new();
    for rk in &params.recovery_keys {
        if !is_valid_key_id(rk) {
            return Err(format!("invalid recoveryKey format: {rk}"));
        }
        if !seen_recovery_keys.insert(rk.clone()) {
            return Err(format!(
                "invalid_deployment_terms: duplicate recoveryKey {rk}"
            ));
        }
        if seen_root_keys.contains(rk) {
            return Err(format!(
                "invalid_deployment_terms: recovery key {rk} overlaps new roots"
            ));
        }
        if params.authorization == RootChangeAuthorization::Recovery && rk == &signer_key_id {
            return Err(format!(
                "spent_recovery_key_retained: recovery signer {signer_key_id} has revealed its public key and cannot be retained in recoveryKeys"
            ));
        }
    }

    let mut seen_custodian_ids = BTreeSet::new();
    let mut seen_custodian_keys = BTreeSet::new();
    for c in &params.custodians {
        if !is_valid_uri_identity(&c.identity) {
            return Err(format!("invalid custodian identity URI: {}", c.identity));
        }
        if !seen_custodian_ids.insert(c.identity.clone()) {
            return Err(format!(
                "invalid_deployment_terms: duplicate custodian identity {}",
                c.identity
            ));
        }
        if let Some(ref k) = c.key {
            if !is_valid_key_id(k) {
                return Err(format!("invalid custodian key format: {k}"));
            }
            if !seen_custodian_keys.insert(k.clone()) {
                return Err(format!(
                    "invalid_deployment_terms: duplicate custodian key {k}"
                ));
            }
            if seen_root_keys.contains(k) || seen_recovery_keys.contains(k) {
                return Err(format!(
                    "invalid_deployment_terms: custodian personal key {k} cannot appear in roots or recoveryKeys"
                ));
            }
        }
    }

    let start_stream = format!("urn:r5e:stream:{}:start", params.deployment);
    let effective_rc_schema = params
        .roots_changed_schema_ref
        .as_deref()
        .unwrap_or(ROOTS_CHANGED_SCHEMA_REF);
    let profile_blob = build_operator_capture_profile_blob(
        &start_stream,
        &signer_key_id,
        params.roots_changed_schema_ref.as_deref(),
        params.approval_schema_ref.as_deref(),
    )?;

    let mut body = Map::new();
    body.insert("chain".to_string(), Value::String(params.chain.clone()));
    body.insert(
        "replaces".to_string(),
        Value::String(params.replaces.clone()),
    );
    body.insert(
        "authorization".to_string(),
        Value::String(params.authorization.as_str().to_string()),
    );
    body.insert("signer".to_string(), Value::String(signer_key_id.clone()));
    body.insert(
        "signerKey".to_string(),
        json!({
            "algorithm": signer_alg.as_str(),
            "bytes": &signer_pub_b64,
        }),
    );
    body.insert("roots".to_string(), Value::Array(roots_json));
    body.insert(
        "threshold".to_string(),
        Value::Number(params.threshold.into()),
    );
    if !params.recovery_keys.is_empty() {
        body.insert("recoveryKeys".to_string(), json!(&params.recovery_keys));
    }
    if !params.custodians.is_empty() {
        body.insert("custodians".to_string(), json!(&params.custodians));
    }
    if let Some(ref reason) = params.reason {
        body.insert("reason".to_string(), Value::String(reason.clone()));
    }

    let now = params.captured_at.unwrap_or_else(Utc::now);
    let captured_at = now.to_rfc3339_opts(SecondsFormat::Micros, true);

    let envelope_doc = json!({
        "apiVersion": "provenance.r5e.io/v2",
        "kind": "RootsChanged",
        "schemaRef": effective_rc_schema,
        "profileRef": &profile_blob.blob_ref,
        "issuer": &signer_key_id,
        "stream": &start_stream,
        "seq": params.seq,
        "previous": &params.replaces,
        "actor": &params.actor,
        "capturedAt": &captured_at,
        "body": Value::Object(body),
    });
    let payload_bytes = encode_canonical_json(&envelope_doc)?;
    let record_ref = evidence_ref(&payload_bytes);
    let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &payload_bytes);

    if !allow_large_ed25519_pae {
        crate::crypto_keys::check_piv_ed25519_pae_limit(signer_alg, pae.len())?;
    }

    let pae_sha256 = {
        use sha2::{Digest, Sha256};
        crate::policy_gate::hex_lower(&Sha256::digest(&pae))
    };

    let mut blobs = Vec::new();
    insert_unique_blob(&mut blobs, profile_blob)?;
    for b in &params.custom_definition_blobs {
        insert_unique_blob(&mut blobs, b.clone())?;
    }

    Ok((
        PreparedRootChange {
            format: PREPARED_ROOT_CHANGE_FORMAT.to_string(),
            deployment: params.deployment.clone(),
            chain: params.chain.clone(),
            seq: params.seq,
            record_ref,
            payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
            payload_b64: BASE64_STANDARD.encode(&payload_bytes),
            pae_sha256,
            signer_pubkey: PublicKeyEntry {
                keyid: signer_key_id,
                algorithm: signer_alg.as_str().to_string(),
                bytes: signer_pub_b64,
            },
            blobs,
        },
        pae,
    ))
}

/// Attaches and verifies an external detached signature (`ed25519 | es256 | es384`, auto-normalizing
/// ASN.1 DER + high-`S`) onto a [`PreparedRootChange`] and produces a [`RootChangeProposalFile`].
pub fn finalize_detached_root_change(
    prepared: &PreparedRootChange,
    signature_input: &[u8],
    is_base64_flag: bool,
) -> Result<(RootChangeProposalFile, bool), String> {
    if prepared.format != PREPARED_ROOT_CHANGE_FORMAT {
        return Err(format!(
            "unsupported prepared root change format {:?} (expected {PREPARED_ROOT_CHANGE_FORMAT:?})",
            prepared.format
        ));
    }
    let payload_bytes = decode_strict_base64(&prepared.payload_b64)
        .map_err(|e| format!("invalid prepared root change payloadBase64: {e}"))?;
    let computed_ref = evidence_ref(&payload_bytes);
    if computed_ref != prepared.record_ref {
        return Err(format!(
            "prepared root change recordRef mismatch: declared {}, computed {computed_ref}",
            prepared.record_ref
        ));
    }
    let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &payload_bytes);
    let computed_pae_sha256 = {
        use sha2::{Digest, Sha256};
        crate::policy_gate::hex_lower(&Sha256::digest(&pae))
    };
    if computed_pae_sha256 != prepared.pae_sha256 {
        return Err(format!(
            "prepared root change paeSha256 mismatch: declared {}, computed {computed_pae_sha256}",
            prepared.pae_sha256
        ));
    }

    let (canonical_sig, was_normalized) = parse_external_sig_for_pubkey(
        &prepared.signer_pubkey,
        &pae,
        signature_input,
        is_base64_flag,
        "RootsChanged signer signature",
    )?;

    let change_record = SignedEndpointRecord {
        record_ref: computed_ref,
        envelope: DsseEnvelope {
            payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
            payload: prepared.payload_b64.clone(),
            signatures: vec![DsseSignature {
                keyid: prepared.signer_pubkey.keyid.clone(),
                sig: BASE64_STANDARD.encode(&canonical_sig),
            }],
        },
    };

    let proposal = RootChangeProposalFile {
        deployment: prepared.deployment.clone(),
        chain: prepared.chain.clone(),
        seq: prepared.seq,
        change: change_record,
        approvals: Vec::new(),
        keys: vec![prepared.signer_pubkey.clone()],
        blobs: prepared.blobs.clone(),
    };
    verify_proposal_locally(&proposal)?;
    Ok((proposal, was_normalized))
}

/// Builds an unsigned 2-signer `provenance.r5e.io/v2/RootChangeApproval` (`signatures: [root, custodianKey]`)
/// for external/hardware signing (`ed25519 | es256 | es384`), returning `(PreparedRootApproval, dsse_pae_bytes)`.
pub fn prepare_detached_root_approval(
    proposal: &RootChangeProposalFile,
    root_pubkey: &PublicKeyEntry,
    custodian_pubkey: &PublicKeyEntry,
    params: &ApproveRootChangeParams,
    allow_large_ed25519_pae: bool,
) -> Result<(PreparedRootApproval, Vec<u8>), String> {
    let change_val = verify_roots_changed_record_in_proposal(proposal)?;
    let change_auth = change_val
        .get("body")
        .and_then(|b| b.get("authorization"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if change_auth != "quorum" {
        return Err(format!(
            "approval_not_for_quorum_change: proposal authorization is {change_auth:?}"
        ));
    }
    if !is_valid_uri_identity(&params.custodian) {
        return Err(format!(
            "invalid custodian identity URI: {}",
            params.custodian
        ));
    }
    if !params.actor.starts_with("urn:r5e:") {
        return Err(format!(
            "actor ({}) must start with 'urn:r5e:'",
            params.actor
        ));
    }
    if let Some(ref r) = params.reason {
        if r.trim().is_empty() {
            return Err("reason cannot be empty when provided".to_string());
        }
    }

    let (root_alg, root_pub_bytes, root_key_id) = parse_and_verify_v2_pubkey(
        &root_pubkey.algorithm,
        &root_pubkey.bytes,
        Some(&root_pubkey.keyid),
        "root_pubkey",
    )?;
    let (cust_alg, cust_pub_bytes, cust_key_id) = parse_and_verify_v2_pubkey(
        &custodian_pubkey.algorithm,
        &custodian_pubkey.bytes,
        Some(&custodian_pubkey.keyid),
        "custodian_pubkey",
    )?;
    if root_key_id == cust_key_id {
        return Err(format!(
            "approver_not_in_quorum: custodian personal signing key ({cust_key_id}) must be distinct from approving root key"
        ));
    }

    for existing in &proposal.approvals {
        let existing_bytes = decode_strict_base64(&existing.envelope.payload)
            .map_err(|e| format!("invalid existing approval payload base64: {e}"))?;
        let existing_val: Value = serde_json::from_slice(&existing_bytes)
            .map_err(|e| format!("invalid existing approval payload JSON: {e}"))?;
        let ex_body = existing_val
            .get("body")
            .and_then(Value::as_object)
            .ok_or_else(|| "existing approval missing body".to_string())?;
        let ex_root = ex_body
            .get("root")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let ex_cust = ex_body
            .get("custodian")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let ex_ckey = ex_body
            .get("custodianKey")
            .and_then(Value::as_str)
            .unwrap_or_default();

        if ex_root == root_key_id && ex_cust == params.custodian && ex_ckey == cust_key_id {
            return Err(format!(
                "duplicate approval: root {root_key_id} and custodian {} already approved this proposal",
                params.custodian
            ));
        }
        if ex_root == root_key_id {
            return Err(format!(
                "conflicting approval under root {root_key_id}: already paired with ({ex_cust}, {ex_ckey})"
            ));
        }
        if ex_cust == params.custodian {
            return Err(format!(
                "conflicting approval for custodian {}: already paired with root {ex_root}",
                params.custodian
            ));
        }
        if ex_ckey == cust_key_id {
            return Err(format!(
                "conflicting approval for custodianKey {cust_key_id}: already paired with root {ex_root}"
            ));
        }
    }

    let rand_12 = generate_os_random_bytes::<12>()?;
    let rand_token = URL_SAFE_NO_PAD.encode(rand_12);
    let approval_stream = format!(
        "urn:r5e:stream:{}:authority:approval:{rand_token}",
        proposal.deployment
    );

    let effective_ap_schema = params
        .approval_schema_ref
        .as_deref()
        .unwrap_or(ROOT_CHANGE_APPROVAL_SCHEMA_REF);
    let profile_blob = build_operator_capture_profile_blob(
        &approval_stream,
        &root_key_id,
        None,
        params.approval_schema_ref.as_deref(),
    )?;

    let cust_pub_b64 = BASE64_STANDARD.encode(&cust_pub_bytes);
    let mut body = Map::new();
    body.insert(
        "change".to_string(),
        Value::String(proposal.change.record_ref.clone()),
    );
    body.insert("root".to_string(), Value::String(root_key_id.clone()));
    body.insert(
        "custodian".to_string(),
        Value::String(params.custodian.clone()),
    );
    body.insert(
        "custodianKey".to_string(),
        Value::String(cust_key_id.clone()),
    );
    body.insert(
        "custodianPublicKey".to_string(),
        json!({
            "algorithm": cust_alg.as_str(),
            "bytes": &cust_pub_b64,
        }),
    );
    if let Some(ref reason) = params.reason {
        body.insert("reason".to_string(), Value::String(reason.clone()));
    }

    let now = params.captured_at.unwrap_or_else(Utc::now);
    let captured_at = now.to_rfc3339_opts(SecondsFormat::Micros, true);

    let envelope_doc = json!({
        "apiVersion": "provenance.r5e.io/v2",
        "kind": "RootChangeApproval",
        "schemaRef": effective_ap_schema,
        "profileRef": &profile_blob.blob_ref,
        "issuer": &root_key_id,
        "stream": &approval_stream,
        "seq": 1,
        "previous": null,
        "actor": &params.actor,
        "capturedAt": &captured_at,
        "body": Value::Object(body),
    });
    let payload_bytes = encode_canonical_json(&envelope_doc)?;
    let record_ref = evidence_ref(&payload_bytes);
    let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &payload_bytes);

    if !allow_large_ed25519_pae {
        crate::crypto_keys::check_piv_ed25519_pae_limit(root_alg, pae.len())?;
        crate::crypto_keys::check_piv_ed25519_pae_limit(cust_alg, pae.len())?;
    }

    let pae_sha256 = {
        use sha2::{Digest, Sha256};
        crate::policy_gate::hex_lower(&Sha256::digest(&pae))
    };

    let mut blobs = Vec::new();
    insert_unique_blob(&mut blobs, profile_blob)?;
    for b in &params.custom_definition_blobs {
        insert_unique_blob(&mut blobs, b.clone())?;
    }

    Ok((
        PreparedRootApproval {
            format: PREPARED_ROOT_APPROVAL_FORMAT.to_string(),
            change_ref: proposal.change.record_ref.clone(),
            record_ref,
            payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
            payload_b64: BASE64_STANDARD.encode(&payload_bytes),
            pae_sha256,
            root_pubkey: PublicKeyEntry {
                keyid: root_key_id,
                algorithm: root_alg.as_str().to_string(),
                bytes: BASE64_STANDARD.encode(&root_pub_bytes),
            },
            custodian: params.custodian.clone(),
            custodian_pubkey: PublicKeyEntry {
                keyid: cust_key_id,
                algorithm: cust_alg.as_str().to_string(),
                bytes: cust_pub_b64,
            },
            blobs,
        },
        pae,
    ))
}

/// Attaches and verifies both `[root, custodianKey]` signatures (`ed25519 | es256 | es384`,
/// auto-normalizing ASN.1 DER + high-`S` on both signers) onto a [`PreparedRootApproval`] and
/// appends the approval to `proposal`.
pub fn finalize_detached_root_approval(
    proposal: &mut RootChangeProposalFile,
    prepared: &PreparedRootApproval,
    root_sig_input: &[u8],
    root_is_b64: bool,
    custodian_sig_input: &[u8],
    custodian_is_b64: bool,
) -> Result<(SignedEndpointRecord, bool, bool), String> {
    if prepared.format != PREPARED_ROOT_APPROVAL_FORMAT {
        return Err(format!(
            "unsupported prepared root approval format {:?} (expected {PREPARED_ROOT_APPROVAL_FORMAT:?})",
            prepared.format
        ));
    }
    if prepared.change_ref != proposal.change.record_ref {
        return Err(format!(
            "prepared root approval changeRef ({}) does not match proposal.change.ref ({})",
            prepared.change_ref, proposal.change.record_ref
        ));
    }
    let payload_bytes = decode_strict_base64(&prepared.payload_b64)
        .map_err(|e| format!("invalid prepared root approval payloadBase64: {e}"))?;
    let computed_ref = evidence_ref(&payload_bytes);
    if computed_ref != prepared.record_ref {
        return Err(format!(
            "prepared root approval recordRef mismatch: declared {}, computed {computed_ref}",
            prepared.record_ref
        ));
    }
    let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &payload_bytes);
    let computed_pae_sha256 = {
        use sha2::{Digest, Sha256};
        crate::policy_gate::hex_lower(&Sha256::digest(&pae))
    };
    if computed_pae_sha256 != prepared.pae_sha256 {
        return Err(format!(
            "prepared root approval paeSha256 mismatch: declared {}, computed {computed_pae_sha256}",
            prepared.pae_sha256
        ));
    }

    let (root_sig, root_norm) = parse_external_sig_for_pubkey(
        &prepared.root_pubkey,
        &pae,
        root_sig_input,
        root_is_b64,
        "RootChangeApproval root signature (Signer 1)",
    )?;
    let (cust_sig, cust_norm) = parse_external_sig_for_pubkey(
        &prepared.custodian_pubkey,
        &pae,
        custodian_sig_input,
        custodian_is_b64,
        "RootChangeApproval custodian signature (Signer 2)",
    )?;

    let approval = SignedEndpointRecord {
        record_ref: computed_ref,
        envelope: DsseEnvelope {
            payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
            payload: prepared.payload_b64.clone(),
            signatures: vec![
                DsseSignature {
                    keyid: prepared.root_pubkey.keyid.clone(),
                    sig: BASE64_STANDARD.encode(&root_sig),
                },
                DsseSignature {
                    keyid: prepared.custodian_pubkey.keyid.clone(),
                    sig: BASE64_STANDARD.encode(&cust_sig),
                },
            ],
        },
    };

    proposal.approvals.push(approval.clone());
    insert_unique_key(&mut proposal.keys, prepared.root_pubkey.clone())?;
    insert_unique_key(&mut proposal.keys, prepared.custodian_pubkey.clone())?;
    for b in &prepared.blobs {
        insert_unique_blob(&mut proposal.blobs, b.clone())?;
    }
    verify_proposal_locally(proposal)?;
    Ok((approval, root_norm, cust_norm))
}

/// Applies a verified [`RootChangeProposalFile`] (`POST /v1/deployment/roots`) and optionally
/// submits a pre-signed detached gateway `SubmitGrantsRequest` (`POST /v1/deployment/grants`,
/// e.g. produced by `finalize-endorsement` from an external `es256` hardware root).
pub fn apply_root_change_with_grant_request(
    cfg: &ClaimClientConfig,
    proposal: &RootChangeProposalFile,
    detached_grant: Option<&SubmitGrantsRequest>,
) -> Result<(SubmitRootChangeResponse, Option<SubmitGrantsResponse>), ClaimError> {
    verify_proposal_locally(proposal).map_err(ClaimError::Validation)?;
    let submit_req = SubmitRootChangeRequest {
        change: proposal.change.clone(),
        approvals: proposal.approvals.clone(),
        keys: proposal.keys.clone(),
        blobs: proposal.blobs.clone(),
    };
    let roots_resp = submit_deployment_roots(cfg, &submit_req)?;
    let grant_resp = match detached_grant {
        Some(grant_req) => Some(submit_deployment_grants(cfg, grant_req)?),
        None => None,
    };
    Ok((roots_resp, grant_resp))
}
