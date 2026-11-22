//! Detached external-signer `DefinitionPublished` preparation and finalization
//! (`BLOCK-0.md`, `A9-closures-before-block-0.md` §§4–6, `VERIFY-V2.md` §§2.3–2.4,
//! and `Mix.Tasks.Recurse.Provenance.Publish`).
//!
//! Produces a `CarriedPublicationSet` JSON file (`{"blobs": [...], "keys": [...], "records": [...]}`)
//! compatible byte-for-byte with `R5E_EVIDENCE_PUBLICATIONS_FILE` in `recurse_gateway` while
//! keeping the publisher private key strictly outside the process (PIV, `openssl`,
//! PKCS#11, HSM).

use crate::attestation::{
    base_v2_schema_map, bytes_ref, decode_strict_base64, dsse_pae, encode_canonical_json,
    evidence_ref, normalize_a9_details, validate_a9_details, BlobEntry, DsseEnvelope,
    DsseSignature, PublicKeyEntry, SignedEndpointRecord, DEFINITION_PUBLISHED_SCHEMA_REF,
    PROVENANCE_V2_PAYLOAD_TYPE,
};
use crate::claim_http::CarriedPublicationSet;
use crate::crypto_keys::{
    compute_key_id, normalize_signature_bytes, parse_external_signature_bytes,
    parse_public_key_material, validate_public_key_bytes, verify_signature, SignatureAlgorithm,
};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const PREPARED_PUBLICATION_FORMAT: &str = "r5e.prepared-publication/v1";

/// One expanded `r5e.kind-definition/v1` document loaded from disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedDefinitionDocument {
    pub kind_path: String,
    pub definition_ref: String,
    pub canonical_bytes: Vec<u8>,
}

/// Parameters for [`prepare_publication`].
#[derive(Debug, Clone)]
pub struct PreparePublicationParams {
    pub definitions_dir: std::path::PathBuf,
    pub publisher_public_key_raw: Vec<u8>,
    pub algorithm: Option<SignatureAlgorithm>,
    pub publisher_name: String,
    pub package: Option<String>,
    pub proposal: Option<String>,
    pub previous: Option<String>,
    pub envelope_seq: Option<u64>,
    pub manifest_ref: Option<String>,
    pub stream: Option<String>,
    pub actor: Option<String>,
    pub captured_at: String,
    pub details: Option<Map<String, Value>>,
}

/// Self-contained unsigned publication state written by `prepare-publication` (`--out-prepared`)
/// and consumed by `finalize-publication` (`--prepared`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreparedPublication {
    pub format: String,
    #[serde(rename = "recordRef")]
    pub record_ref: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    #[serde(rename = "payloadBase64")]
    pub payload_b64: String,
    #[serde(rename = "paeSha256")]
    pub pae_sha256: String,
    #[serde(rename = "publisherKey")]
    pub publisher_public_key: PublicKeyEntry,
    #[serde(rename = "profileRef")]
    pub profile_ref: String,
    pub blobs: Vec<BlobEntry>,
}

/// Result returned by [`finalize_publication`] after cryptographic verification.
#[derive(Debug, Clone)]
pub struct FinalizePublicationResult {
    pub publication_set: CarriedPublicationSet,
    pub record_ref: String,
    pub publisher_key_id: String,
    pub algorithm: SignatureAlgorithm,
    pub definition_count: usize,
    pub signature_was_normalized: bool,
}

/// Checks `evidence:sha256:<64 lowercase hex>`.
pub fn is_valid_evidence_ref(s: &str) -> bool {
    let Some(hex) = s.strip_prefix("evidence:sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Checks `bytes:sha256:<64 lowercase hex>`.
pub fn is_valid_bytes_ref(s: &str) -> bool {
    let Some(hex) = s.strip_prefix("bytes:sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Validates `DefinitionPublished.body.proposal` per `A9-closures-before-block-0.md` §§5–6:
/// - Same-chain evidence ref: `evidence:sha256:<64 lowercase hex>`
/// - Cross-chain evidence ref: `chain:evidence:sha256:<64 lowercase hex>/evidence:sha256:<64 lowercase hex>`
///   (labels such as `chain:r5e-dev/...` are strictly rejected).
pub fn is_valid_proposal_ref(s: &str) -> bool {
    if is_valid_evidence_ref(s) {
        return true;
    }
    let Some(rest) = s.strip_prefix("chain:") else {
        return false;
    };
    let Some((chain_name, target_ref)) = rest.split_once('/') else {
        return false;
    };
    is_valid_evidence_ref(chain_name) && is_valid_evidence_ref(target_ref)
}

/// Checks Provenance v2 kind path grammar `^[a-z0-9.-]+/v[0-9a-z]+/[A-Za-z0-9]+$`.
pub fn is_valid_kind_path(s: &str) -> bool {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 3 {
        return false;
    }
    let (group, version, kind) = (parts[0], parts[1], parts[2]);
    if group.is_empty()
        || !group
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-'))
    {
        return false;
    }
    let Some(ver_tail) = version.strip_prefix('v') else {
        return false;
    };
    if ver_tail.is_empty()
        || !ver_tail
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'z'))
    {
        return false;
    }
    !kind.is_empty() && kind.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Checks Provenance v2 strict RFC 3339 timestamp (`VERIFY-V2.md` §2.2, rejecting `-00:00` / `-00:00`).
pub fn validate_provenance_rfc3339(ts: &str, label: &str) -> Result<(), String> {
    if ts.ends_with("-00:00") {
        return Err(format!(
            "{label}: RFC 3339 unknown local offset -00:00 is forbidden in Provenance v2"
        ));
    }
    if !ts.contains('T') {
        return Err(format!(
            "{label}: timestamp must use uppercase 'T' separator"
        ));
    }
    if ts.ends_with('z') {
        return Err(format!("{label}: UTC designator must be uppercase 'Z'"));
    }
    chrono::DateTime::parse_from_rfc3339(ts)
        .map_err(|e| format!("{label}: invalid RFC 3339 timestamp {ts:?}: {e}"))?;
    Ok(())
}

fn validate_identity_uri(uri: &str, label: &str) -> Result<(), String> {
    let trimmed = uri.trim();
    if trimmed.is_empty() || trimmed != uri || uri.chars().any(char::is_whitespace) {
        return Err(format!("{label}: URI must be non-empty without whitespace"));
    }
    let Some((scheme, rest)) = uri.split_once(':') else {
        return Err(format!("{label}: URI {uri:?} missing scheme ':'"));
    };
    if scheme.is_empty()
        || !scheme.as_bytes()[0].is_ascii_alphabetic()
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
        || rest.is_empty()
    {
        return Err(format!("{label}: invalid URI {uri:?}"));
    }
    Ok(())
}

fn collect_json_files_recursive(
    dir: &Path,
    out: &mut Vec<std::path::PathBuf>,
) -> Result<(), String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot read definitions directory {}: {e}", dir.display()))?;
    let mut paths: Vec<std::path::PathBuf> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("error reading entry in {}: {e}", dir.display()))?;
        paths.push(entry.path());
    }
    paths.sort();
    for p in paths {
        if p.is_dir() {
            collect_json_files_recursive(&p, out)?;
        } else if p.extension().and_then(|e| e.to_str()) == Some("json") {
            out.push(p);
        }
    }
    Ok(())
}

fn parse_and_validate_definition_bytes(
    raw_bytes: &[u8],
    source_path: &Path,
    expected_kind: Option<&str>,
    expected_ref: Option<&str>,
) -> Result<LoadedDefinitionDocument, String> {
    let doc: Value = serde_json::from_slice(raw_bytes).map_err(|e| {
        format!(
            "definition file {} is not valid JSON: {e}",
            source_path.display()
        )
    })?;
    let fmt = doc
        .get("format")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if fmt != "r5e.kind-definition/v1" {
        return Err(format!(
            "definition file {} has format {fmt:?}, expected \"r5e.kind-definition/v1\"",
            source_path.display()
        ));
    }
    let kind_path = doc.get("kind").and_then(Value::as_str).ok_or_else(|| {
        format!(
            "definition file {} missing string \"kind\"",
            source_path.display()
        )
    })?;
    if !is_valid_kind_path(kind_path) {
        return Err(format!(
            "definition file {} has invalid kind path {kind_path:?}",
            source_path.display()
        ));
    }
    if let Some(exp_k) = expected_kind {
        if kind_path != exp_k {
            return Err(format!(
                "definition file {} declares kind {kind_path:?}, expected {exp_k:?}",
                source_path.display()
            ));
        }
    }
    let canonical = encode_canonical_json(&doc).map_err(|e| {
        format!(
            "definition file {} cannot encode as canonical JSON: {e}",
            source_path.display()
        )
    })?;
    if raw_bytes != canonical.as_slice() {
        // Also check if trailing newline was the only difference; never silently mutate hashed bytes
        // if index.json pinned an exact digest, so check `expected_ref` against `canonical`.
        if let Some(exp_r) = expected_ref {
            let raw_r = bytes_ref(raw_bytes);
            let can_r = bytes_ref(&canonical);
            if raw_r != exp_r && can_r != exp_r {
                return Err(format!(
                    "definition file {} digest mismatch: expected {exp_r}, got {can_r}",
                    source_path.display()
                ));
            }
            if raw_r == exp_r && raw_r != can_r {
                return Err(format!(
                    "definition file {} is not canonical JSON (VERIFY-V2 §2.1)",
                    source_path.display()
                ));
            }
        }
    }
    let def_ref = bytes_ref(&canonical);
    if let Some(exp_r) = expected_ref {
        if def_ref != exp_r {
            return Err(format!(
                "definition file {} digest ({def_ref}) does not match index.json ({exp_r})",
                source_path.display()
            ));
        }
    }
    Ok(LoadedDefinitionDocument {
        kind_path: kind_path.to_string(),
        definition_ref: def_ref,
        canonical_bytes: canonical,
    })
}

/// Loads expanded `r5e.kind-definition/v1` documents from `dir`:
/// - When `dir/index.json` exists, loads the exact `{kind_path: bytes_ref}` map from `index.json`
///   and verifies each `<dir>/<kind_path>.json` document matches both `kind` and `bytes_ref`.
/// - Otherwise recursively scans `.json` files in `dir` whose `"format"` is `"r5e.kind-definition/v1"`
///   (ignoring package manifests like `"r5e.definition-package/v1"`).
pub fn load_definitions_from_dir(dir: &Path) -> Result<Vec<LoadedDefinitionDocument>, String> {
    if !dir.is_dir() {
        return Err(format!(
            "definitions directory {} does not exist or is not a directory",
            dir.display()
        ));
    }

    let index_path = dir.join("index.json");
    if index_path.is_file() {
        let index_bytes = std::fs::read(&index_path)
            .map_err(|e| format!("cannot read {}: {e}", index_path.display()))?;
        let index_map: BTreeMap<String, String> = serde_json::from_slice(&index_bytes)
            .map_err(|e| format!("invalid JSON in {}: {e}", index_path.display()))?;
        if index_map.is_empty() {
            return Err(format!(
                "{} contains zero definitions",
                index_path.display()
            ));
        }
        let mut out = Vec::with_capacity(index_map.len());
        for (kind_path, expected_ref) in &index_map {
            if !is_valid_kind_path(kind_path) {
                return Err(format!(
                    "{}: invalid kind path {kind_path:?}",
                    index_path.display()
                ));
            }
            if !is_valid_bytes_ref(expected_ref) {
                return Err(format!(
                    "{}: invalid bytes ref for {kind_path}: {expected_ref:?}",
                    index_path.display()
                ));
            }
            let file_path = dir.join(format!("{kind_path}.json"));
            let raw = std::fs::read(&file_path).map_err(|e| {
                format!(
                    "cannot read definition {} referenced by {}: {e}",
                    file_path.display(),
                    index_path.display()
                )
            })?;
            let doc = parse_and_validate_definition_bytes(
                &raw,
                &file_path,
                Some(kind_path),
                Some(expected_ref),
            )?;
            out.push(doc);
        }
        return Ok(out);
    }

    let mut json_files = Vec::new();
    collect_json_files_recursive(dir, &mut json_files)?;
    let mut by_kind: BTreeMap<String, LoadedDefinitionDocument> = BTreeMap::new();
    for path in json_files {
        let raw =
            std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let Ok(probe) = serde_json::from_slice::<Value>(&raw) else {
            continue;
        };
        if probe.get("format").and_then(Value::as_str) != Some("r5e.kind-definition/v1") {
            continue;
        }
        let doc = parse_and_validate_definition_bytes(&raw, &path, None, None)?;
        if by_kind.contains_key(&doc.kind_path) {
            return Err(format!(
                "duplicate kind definition for {:?} in {}",
                doc.kind_path,
                dir.display()
            ));
        }
        by_kind.insert(doc.kind_path.clone(), doc);
    }
    if by_kind.is_empty() {
        return Err(format!(
            "no r5e.kind-definition/v1 JSON documents found in {}",
            dir.display()
        ));
    }
    Ok(by_kind.into_values().collect())
}

fn compute_publication_digest_16(docs: &[LoadedDefinitionDocument]) -> String {
    let mut lines: Vec<String> = docs
        .iter()
        .map(|d| format!("{} {}", d.kind_path, d.definition_ref))
        .collect();
    lines.sort();
    let joined = lines.join("\n");
    let full_hex = crate::policy_gate::hex_lower(&Sha256::digest(joined.as_bytes()));
    full_hex[..16].to_string()
}

/// Builds an unsigned `DefinitionPublished` record, its publisher `CaptureProfile` blob, all
/// definition document blobs, and the exact raw DSSE PAE bytes to sign externally on hardware
/// (PIV, `openssl dgst -sign`, PKCS#11, HSM).
pub fn prepare_publication(
    params: &PreparePublicationParams,
) -> Result<(PreparedPublication, Vec<u8>), String> {
    let (alg, pub_bytes, publisher_key_id) = parse_public_key_material(
        params.algorithm,
        &params.publisher_public_key_raw,
        "--publisher-public-key",
    )?;

    let publisher_name = params.publisher_name.trim();
    if publisher_name.is_empty()
        || publisher_name
            .bytes()
            .any(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')))
    {
        return Err(format!(
            "invalid publisher name {publisher_name:?}: expected non-empty ASCII [A-Za-z0-9_.-]+"
        ));
    }

    validate_provenance_rfc3339(&params.captured_at, "--captured-at")?;

    let docs = load_definitions_from_dir(&params.definitions_dir)?;
    let default_stream_prefix = format!("urn:r5e:stream:publisher:{publisher_name}:");
    let digest_16 = compute_publication_digest_16(&docs);
    let stream = match &params.stream {
        Some(s) => {
            validate_identity_uri(s, "--stream")?;
            s.clone()
        }
        None => format!("{default_stream_prefix}api:{digest_16}"),
    };
    let stream_prefix = if stream.starts_with(&default_stream_prefix) {
        default_stream_prefix
    } else {
        stream.clone()
    };

    let actor = match &params.actor {
        Some(a) => {
            validate_identity_uri(a, "--actor")?;
            a.clone()
        }
        None => format!("urn:r5e:publisher:{publisher_name}"),
    };
    let actor_prefixes = if actor.starts_with("urn:r5e:publisher:") {
        vec!["urn:r5e:publisher:".to_string()]
    } else {
        vec![actor.clone()]
    };

    if let Some(ref pkg) = params.package {
        if pkg.trim().is_empty() {
            return Err("--package must not be empty when supplied".to_string());
        }
    }
    if let Some(ref prop) = params.proposal {
        if !is_valid_proposal_ref(prop) {
            return Err(format!(
                "invalid --proposal {prop:?}: expected evidence:sha256:<64 lowercase hex> or chain:evidence:sha256:<64 lowercase hex>/evidence:sha256:<64 lowercase hex> (A9 §§5–6)"
            ));
        }
    }
    if let Some(ref prev) = params.previous {
        if !is_valid_evidence_ref(prev) {
            return Err(format!(
                "invalid --previous {prev:?}: expected evidence:sha256:<64 lowercase hex>"
            ));
        }
    }
    if let Some(ref mref) = params.manifest_ref {
        if !is_valid_bytes_ref(mref) {
            return Err(format!(
                "invalid --manifest-ref {mref:?}: expected bytes:sha256:<64 lowercase hex>"
            ));
        }
    }

    let seq = params.envelope_seq.unwrap_or(1);
    if seq == 0 {
        return Err("--seq must be >= 1".to_string());
    }
    let envelope_previous = if seq > 1 {
        let prev = params.previous.as_ref().ok_or_else(|| {
            "--previous <evidence:sha256:...> is required when --seq > 1".to_string()
        })?;
        Value::String(prev.clone())
    } else {
        Value::Null
    };

    let normalized_details = match &params.details {
        Some(d) => {
            let norm = normalize_a9_details(d)?;
            validate_a9_details(&norm, "DefinitionPublished.body.details")?;
            Some(norm)
        }
        None => None,
    };

    // Build publisher CaptureProfile matching `Recurse.Provenance.Publication.issue`:
    let mut profile_schemas = base_v2_schema_map();
    // `Recurse.Provenance.Definitions.schema_refs()` maps `provenance.r5e.io/v2/*` in the profile,
    // and any custom published definitions are also added so `DefinitionPublished` & extension kinds resolve:
    for doc in &docs {
        profile_schemas.insert(
            doc.kind_path.clone(),
            Value::String(doc.definition_ref.clone()),
        );
    }
    profile_schemas.insert(
        "provenance.r5e.io/v2/DefinitionPublished".to_string(),
        Value::String(DEFINITION_PUBLISHED_SCHEMA_REF.to_string()),
    );

    let deployment_policy_ref = bytes_ref(format!("r5e.publisher/{publisher_name}").as_bytes());
    let profile_doc = serde_json::json!({
        "format": "r5e.capture-profile/v2",
        "schemas": Value::Object(profile_schemas),
        "authority": {
            "bindings": [
                {
                    "streamPrefix": stream_prefix,
                    "actorPrefixes": actor_prefixes,
                    "issuerKeys": [publisher_key_id],
                    "sealerKeys": [],
                }
            ],
            "checkpointKeys": [],
        },
        "durability": {
            "failureDomain": "published once and carried",
            "requiredPayloads": "submitted",
            "onFailure": "refuse",
        },
        "policyRequiredKinds": [],
        "deploymentPolicyRef": deployment_policy_ref,
    });
    let profile_bytes = encode_canonical_json(&profile_doc)?;
    let profile_ref = bytes_ref(&profile_bytes);

    let definitions_json: Vec<Value> = docs
        .iter()
        .map(|d| {
            serde_json::json!({
                "kind": d.kind_path,
                "definition": d.definition_ref,
            })
        })
        .collect();

    let mut body = Map::new();
    body.insert("definitions".to_string(), Value::Array(definitions_json));
    if let Some(ref pkg) = params.package {
        body.insert("package".to_string(), Value::String(pkg.clone()));
    }
    if let Some(ref mref) = params.manifest_ref {
        body.insert("manifestRef".to_string(), Value::String(mref.clone()));
    }
    if let Some(ref prev) = params.previous {
        body.insert("previous".to_string(), Value::String(prev.clone()));
    }
    if let Some(ref prop) = params.proposal {
        body.insert("proposal".to_string(), Value::String(prop.clone()));
    }
    if let Some(det) = normalized_details {
        if !det.is_empty() {
            body.insert("details".to_string(), Value::Object(det));
        }
    }

    let mut envelope_payload = Map::new();
    envelope_payload.insert(
        "apiVersion".to_string(),
        Value::String("provenance.r5e.io/v2".to_string()),
    );
    envelope_payload.insert(
        "kind".to_string(),
        Value::String("DefinitionPublished".to_string()),
    );
    envelope_payload.insert(
        "schemaRef".to_string(),
        Value::String(DEFINITION_PUBLISHED_SCHEMA_REF.to_string()),
    );
    envelope_payload.insert("profileRef".to_string(), Value::String(profile_ref.clone()));
    envelope_payload.insert(
        "issuer".to_string(),
        Value::String(publisher_key_id.clone()),
    );
    envelope_payload.insert("stream".to_string(), Value::String(stream));
    envelope_payload.insert("seq".to_string(), Value::Number(seq.into()));
    envelope_payload.insert("previous".to_string(), envelope_previous);
    envelope_payload.insert("actor".to_string(), Value::String(actor));
    envelope_payload.insert(
        "capturedAt".to_string(),
        Value::String(params.captured_at.clone()),
    );
    envelope_payload.insert("body".to_string(), Value::Object(body));

    let payload_bytes = encode_canonical_json(&Value::Object(envelope_payload))?;
    let record_ref = evidence_ref(&payload_bytes);
    let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &payload_bytes);
    let pae_sha256 = crate::policy_gate::hex_lower(&Sha256::digest(&pae));

    let mut blobs = Vec::with_capacity(1 + docs.len());
    let mut seen_refs = BTreeSet::new();
    seen_refs.insert(profile_ref.clone());
    blobs.push(BlobEntry {
        blob_ref: profile_ref.clone(),
        media_type: None,
        base64: BASE64_STANDARD.encode(&profile_bytes),
    });
    for d in &docs {
        if seen_refs.insert(d.definition_ref.clone()) {
            blobs.push(BlobEntry {
                blob_ref: d.definition_ref.clone(),
                media_type: None,
                base64: BASE64_STANDARD.encode(&d.canonical_bytes),
            });
        }
    }

    let prepared = PreparedPublication {
        format: PREPARED_PUBLICATION_FORMAT.to_string(),
        record_ref,
        payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
        payload_b64: BASE64_STANDARD.encode(&payload_bytes),
        pae_sha256,
        publisher_public_key: PublicKeyEntry {
            keyid: publisher_key_id,
            algorithm: alg.as_str().to_string(),
            bytes: BASE64_STANDARD.encode(&pub_bytes),
        },
        profile_ref,
        blobs,
    };

    Ok((prepared, pae))
}

/// Like [`prepare_publication`], additionally enforcing the PIV hardware `Ed25519` 3,000-byte
/// PAE ceiling when `piv_hardware` is `true`.
pub fn prepare_publication_with_piv_guard(
    params: &PreparePublicationParams,
    piv_hardware: bool,
) -> Result<(PreparedPublication, Vec<u8>), String> {
    let (prepared, pae) = prepare_publication(params)?;
    let alg = SignatureAlgorithm::parse(&prepared.publisher_public_key.algorithm)?;
    if piv_hardware {
        crate::crypto_keys::check_piv_ed25519_pae_limit(alg, pae.len())?;
    }
    Ok((prepared, pae))
}

/// Verifies all blobs, definition hashes, publisher key admissibility, and external signature
/// (auto-normalizing ASN.1 DER `ECDSA-Sig-Value` and `s > floor(n / 2)` for `es256` / `es384`),
/// then returns the canonical `CarriedPublicationSet` ready for `R5E_EVIDENCE_PUBLICATIONS_FILE`.
pub fn finalize_publication(
    prepared: &PreparedPublication,
    signature_input: &[u8],
    is_base64_flag: bool,
) -> Result<FinalizePublicationResult, String> {
    if prepared.format != PREPARED_PUBLICATION_FORMAT {
        return Err(format!(
            "unsupported prepared publication format {:?}, expected {:?}",
            prepared.format, PREPARED_PUBLICATION_FORMAT
        ));
    }
    if prepared.payload_type != PROVENANCE_V2_PAYLOAD_TYPE {
        return Err(format!(
            "unexpected payloadType {:?} in prepared publication",
            prepared.payload_type
        ));
    }

    let alg = SignatureAlgorithm::parse(&prepared.publisher_public_key.algorithm)?;
    let pub_bytes = decode_strict_base64(&prepared.publisher_public_key.bytes)
        .map_err(|e| format!("invalid publisherKey.bytes base64: {e}"))?;
    validate_public_key_bytes(alg, &pub_bytes, "prepared.publisherKey")?;
    let derived_key_id = compute_key_id(alg, &pub_bytes)?;
    if derived_key_id != prepared.publisher_public_key.keyid {
        return Err(format!(
            "prepared publisherKey keyid mismatch: declared {}, derived {derived_key_id}",
            prepared.publisher_public_key.keyid
        ));
    }

    let payload_bytes = decode_strict_base64(&prepared.payload_b64)
        .map_err(|e| format!("invalid payloadBase64: {e}"))?;
    let payload_val: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("prepared payload is not valid JSON: {e}"))?;
    let reencoded = encode_canonical_json(&payload_val)?;
    if reencoded != payload_bytes {
        return Err("prepared payload is not canonical JSON (VERIFY-V2 §2.1)".to_string());
    }
    let actual_record_ref = evidence_ref(&payload_bytes);
    if actual_record_ref != prepared.record_ref {
        return Err(format!(
            "prepared recordRef mismatch: declared {}, computed {actual_record_ref}",
            prepared.record_ref
        ));
    }

    if payload_val.get("apiVersion").and_then(Value::as_str) != Some("provenance.r5e.io/v2")
        || payload_val.get("kind").and_then(Value::as_str) != Some("DefinitionPublished")
    {
        return Err("prepared payload is not provenance.r5e.io/v2/DefinitionPublished".to_string());
    }
    if payload_val.get("issuer").and_then(Value::as_str) != Some(derived_key_id.as_str()) {
        return Err("prepared DefinitionPublished issuer does not match publisherKey".to_string());
    }
    if payload_val.get("profileRef").and_then(Value::as_str) != Some(prepared.profile_ref.as_str())
    {
        return Err(
            "prepared DefinitionPublished profileRef does not match prepared.profileRef"
                .to_string(),
        );
    }

    // Verify every blob's strict base64 and SHA-256 content address:
    let mut blob_bytes_by_ref: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for blob in &prepared.blobs {
        if !is_valid_bytes_ref(&blob.blob_ref) {
            return Err(format!("invalid blob ref {:?}", blob.blob_ref));
        }
        let decoded = decode_strict_base64(&blob.base64)
            .map_err(|e| format!("invalid base64 on blob {}: {e}", blob.blob_ref))?;
        let computed = bytes_ref(&decoded);
        if computed != blob.blob_ref {
            return Err(format!(
                "blob digest mismatch: declared {}, computed {computed}",
                blob.blob_ref
            ));
        }
        if blob_bytes_by_ref
            .insert(blob.blob_ref.clone(), decoded)
            .is_some()
        {
            return Err(format!(
                "duplicate blob ref {} in prepared publication",
                blob.blob_ref
            ));
        }
    }

    let profile_raw = blob_bytes_by_ref
        .get(&prepared.profile_ref)
        .ok_or_else(|| {
            format!(
                "prepared blobs missing publisher CaptureProfile {}",
                prepared.profile_ref
            )
        })?;
    let profile_json: Value = serde_json::from_slice(profile_raw)
        .map_err(|e| format!("publisher CaptureProfile blob is not valid JSON: {e}"))?;
    if encode_canonical_json(&profile_json)? != *profile_raw {
        return Err("publisher CaptureProfile blob is not canonical JSON".to_string());
    }

    let body_obj = payload_val
        .get("body")
        .and_then(Value::as_object)
        .ok_or_else(|| "DefinitionPublished payload missing body object".to_string())?;
    if let Some(prop) = body_obj.get("proposal").and_then(Value::as_str) {
        if !is_valid_proposal_ref(prop) {
            return Err(format!(
                "invalid DefinitionPublished.body.proposal {prop:?}"
            ));
        }
    }
    if let Some(prev) = body_obj.get("previous").and_then(Value::as_str) {
        if !is_valid_evidence_ref(prev) {
            return Err(format!(
                "invalid DefinitionPublished.body.previous {prev:?}"
            ));
        }
    }
    if let Some(det) = body_obj.get("details") {
        let det_map = det
            .as_object()
            .ok_or_else(|| "DefinitionPublished.body.details must be an object".to_string())?;
        validate_a9_details(det_map, "DefinitionPublished.body.details")?;
    }

    let defs_arr = body_obj
        .get("definitions")
        .and_then(Value::as_array)
        .ok_or_else(|| "DefinitionPublished.body.definitions must be an array".to_string())?;
    if defs_arr.is_empty() {
        return Err("DefinitionPublished.body.definitions must be non-empty".to_string());
    }
    let mut seen_kinds = BTreeSet::new();
    for entry in defs_arr {
        let obj = entry
            .as_object()
            .ok_or_else(|| "definitions entry must be an object".to_string())?;
        let kind_str = obj
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| "definitions entry missing string \"kind\"".to_string())?;
        let def_ref = obj
            .get("definition")
            .and_then(Value::as_str)
            .ok_or_else(|| "definitions entry missing string \"definition\"".to_string())?;
        if !seen_kinds.insert(kind_str.to_string()) {
            return Err(format!("duplicate kind {kind_str:?} in definitions"));
        }
        let def_bytes = blob_bytes_by_ref
            .get(def_ref)
            .ok_or_else(|| format!("missing definition blob {def_ref} for kind {kind_str}"))?;
        let def_doc: Value = serde_json::from_slice(def_bytes).map_err(|e| {
            format!("definition blob {def_ref} for {kind_str} is invalid JSON: {e}")
        })?;
        if encode_canonical_json(&def_doc)? != *def_bytes {
            return Err(format!(
                "definition blob {def_ref} for {kind_str} is not canonical JSON"
            ));
        }
        if def_doc.get("format").and_then(Value::as_str) != Some("r5e.kind-definition/v1") {
            return Err(format!(
                "definition blob {def_ref} for {kind_str} is not r5e.kind-definition/v1"
            ));
        }
        if def_doc.get("kind").and_then(Value::as_str) != Some(kind_str) {
            return Err(format!(
                "definition blob {def_ref} declares kind {:?}, expected {kind_str:?}",
                def_doc.get("kind")
            ));
        }
    }

    let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &payload_bytes);
    let actual_pae_sha256 = crate::policy_gate::hex_lower(&Sha256::digest(&pae));
    if actual_pae_sha256 != prepared.pae_sha256 {
        return Err(format!(
            "prepared paeSha256 mismatch: declared {}, computed {actual_pae_sha256}",
            prepared.pae_sha256
        ));
    }

    let (canonical_sig, was_normalized) = if is_base64_flag {
        let sig_str = std::str::from_utf8(signature_input)
            .map_err(|_| "--signature-b64 is not valid UTF-8".to_string())?;
        let clean: String = sig_str.chars().filter(|c| !c.is_whitespace()).collect();
        let raw_sig = BASE64_STANDARD
            .decode(&clean)
            .map_err(|e| format!("invalid --signature-b64 base64: {e}"))?;
        normalize_signature_bytes(alg, &raw_sig, Some((&pub_bytes, &pae)))?
    } else {
        parse_external_signature_bytes(
            alg,
            signature_input,
            Some((&pub_bytes, &pae)),
            "--signature-file",
        )?
    };

    // Cryptographically verify the normalized signature over the DSSE PAE BEFORE emitting!
    verify_signature(alg, &pub_bytes, &pae, &canonical_sig)?;

    let signed_record = SignedEndpointRecord {
        record_ref: prepared.record_ref.clone(),
        envelope: DsseEnvelope {
            payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
            payload: prepared.payload_b64.clone(),
            signatures: vec![DsseSignature {
                keyid: derived_key_id.clone(),
                sig: BASE64_STANDARD.encode(&canonical_sig),
            }],
        },
    };

    let publication_set = CarriedPublicationSet {
        records: vec![signed_record],
        keys: vec![PublicKeyEntry {
            keyid: derived_key_id.clone(),
            algorithm: alg.as_str().to_string(),
            bytes: BASE64_STANDARD.encode(&pub_bytes),
        }],
        blobs: prepared.blobs.clone(),
    };

    Ok(FinalizePublicationResult {
        publication_set,
        record_ref: prepared.record_ref.clone(),
        publisher_key_id: derived_key_id,
        algorithm: alg,
        definition_count: defs_arr.len(),
        signature_was_normalized: was_normalized,
    })
}

/// Serializes a [`CarriedPublicationSet`] into canonical JSON bytes (`Recurse.Provenance.Publication.encode/1`).
pub fn encode_carried_publication_set_canonical(
    set: &CarriedPublicationSet,
) -> Result<Vec<u8>, String> {
    let val = serde_json::to_value(set)
        .map_err(|e| format!("failed to serialize CarriedPublicationSet: {e}"))?;
    encode_canonical_json(&val)
}

/// Writes `content` atomically (via sibling `.tmp.<pid>.<rand>` + `sync_all()` + `rename`) with `mode`
/// permissions on Unix (`0o644` or `0o600`).
pub fn write_atomic_file(path: &Path, content: &[u8], mode: u32) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create parent directory {}: {e}", parent.display()))?;
        }
    }
    let rand_suffix = crate::attestation::generate_os_random_bytes::<8>()
        .map(|b| crate::policy_gate::hex_lower(&b))
        .unwrap_or_else(|_| "0000000000000000".to_string());
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("publication");
    let tmp_path = path.with_file_name(format!(
        ".{file_name}.tmp.{}.{rand_suffix}",
        std::process::id()
    ));

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp_path)
            .map_err(|e| format!("cannot create temporary file {}: {e}", tmp_path.display()))?;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(mode)).map_err(
            |e| {
                let _ = std::fs::remove_file(&tmp_path);
                format!("cannot set permissions on {}: {e}", tmp_path.display())
            },
        )?;
        if let Err(e) = f.write_all(content).and_then(|_| f.sync_all()) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(format!("cannot write {}: {e}", tmp_path.display()));
        }
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&tmp_path, content)
            .map_err(|e| format!("cannot write {}: {e}", tmp_path.display()))?;
    }

    std::fs::rename(&tmp_path, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        format!(
            "cannot atomically rename {} -> {}: {e}",
            tmp_path.display(),
            path.display()
        )
    })
}
