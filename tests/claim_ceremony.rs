use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use r5e_endpoint_helper::attestation::{
    base_v2_schema_map, bytes_ref, decode_strict_base64, dsse_pae, ed25519_key_id,
    encode_canonical_json, evidence_ref, sign_v2_record_multi, BlobEntry, DsseEnvelope,
    DsseSignature, EndpointBundleRecorder, PublicKeyEntry, SignedEndpointRecord, SubjectPublicKey,
    PROVENANCE_V2_PAYLOAD_TYPE, ROOTS_CHANGED_SCHEMA_REF, ROOT_CHANGE_APPROVAL_SCHEMA_REF,
};
use r5e_endpoint_helper::claim_http::{
    build_root_gateway_grant, classify_claim_error, default_gateway_grant_kinds,
    execute_claim_ceremony, get_deployment_status, verify_and_countersign_prepared_claim,
    verify_finalized_claim, CarriedPublicationSet, ClaimClientConfig, ClaimError, CustodianEntry,
    DeploymentClaimState, DeploymentStatusResponse, FinalizeClaimRequest, FinalizedClaimResponse,
    GatewayGrantParams, PrepareClaimRequest, PrepareClaimRootEntry, PreparedClaimResponse,
    SubmitGrantsRequest, DEPLOYMENT_GRANTS_PATH, DEPLOYMENT_STATUS_PATH, FINALIZE_CLAIM_PATH,
    PREPARE_CLAIM_PATH,
};
use r5e_endpoint_helper::root_rotation::IRREVERSIBLE_CLAIM_WARNING;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;

fn optional_definitions_dir() -> Option<PathBuf> {
    if let Some(val) = std::env::var_os("R5E_DEFINITIONS_DIR") {
        let dir = PathBuf::from(val);
        assert!(
            dir.join("index.json").is_file(),
            "R5E_DEFINITIONS_DIR={} missing index.json",
            dir.display()
        );
        return Some(dir);
    }
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../r5e-spec/definitions");
    if dir.join("index.json").is_file() {
        Some(dir)
    } else {
        None
    }
}

fn resolve_py_verifier() -> Option<(PathBuf, PathBuf)> {
    if let Some(val) = std::env::var_os("R5E_VERIFY_PY_DIR") {
        let dir = PathBuf::from(val);
        let venv_py = dir.join(".venv/bin/python");
        if venv_py.is_file() {
            return Some((dir, venv_py));
        }
        if dir.join("r5e_verify/__init__.py").is_file()
            && Command::new("python3")
                .args(["-c", "import cryptography"])
                .status()
                .is_ok_and(|s| s.success())
        {
            return Some((dir, PathBuf::from("python3")));
        }
        panic!(
            "R5E_VERIFY_PY_DIR={} is set, expected {}/.venv/bin/python or python3 with cryptography",
            dir.display(),
            dir.display()
        );
    }
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../r5e-verify-py");
    let venv_py = dir.join(".venv/bin/python");
    if venv_py.is_file() {
        Some((dir, venv_py))
    } else {
        None
    }
}

fn resolve_rs_verifier_bin() -> Option<PathBuf> {
    if let Some(val) = std::env::var_os("R5E_VERIFY_RS_BIN") {
        let bin = PathBuf::from(val);
        assert!(
            bin.is_file(),
            "R5E_VERIFY_RS_BIN={} does not exist",
            bin.display()
        );
        return Some(bin);
    }
    let bin = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../r5e-verify-rs/target/release/recurse_verify");
    if bin.is_file() {
        Some(bin)
    } else {
        None
    }
}

struct MockNodeFixtures {
    deployment: String,
    publisher_key: SigningKey,
    publisher_id: String,
    bootstrap_key: SigningKey,
    bootstrap_id: String,
    bootstrap_entry: PublicKeyEntry,
    gateway_key: SigningKey,
    gateway_id: String,
    gateway_entry: PublicKeyEntry,
    publication_set: CarriedPublicationSet,
    publication_ref: String,
    bootstrap_profile_blob: BlobEntry,
    chain_started: SignedEndpointRecord,
}

fn build_mock_node_fixtures(deployment: &str) -> MockNodeFixtures {
    let publisher_key = SigningKey::from_bytes(&[0x11; 32]);
    let bootstrap_key = SigningKey::from_bytes(&[0x22; 32]);
    let gateway_key = SigningKey::from_bytes(&[0x33; 32]);

    let pub_bytes = publisher_key.verifying_key().to_bytes();
    let boot_bytes = bootstrap_key.verifying_key().to_bytes();
    let gw_bytes = gateway_key.verifying_key().to_bytes();

    let publisher_id = ed25519_key_id(&pub_bytes);
    let bootstrap_id = ed25519_key_id(&boot_bytes);
    let gateway_id = ed25519_key_id(&gw_bytes);

    let schemas = base_v2_schema_map();
    let defs_vec: Vec<Value> = schemas
        .iter()
        .map(|(k, v)| json!({ "kind": k, "definition": v }))
        .collect();

    let policy_ref = bytes_ref(b"permit(principal, action, resource);");
    let pub_profile_bytes = encode_canonical_json(&json!({
        "format": "r5e.capture-profile/v2",
        "schemas": schemas,
        "authority": {
            "bindings": [
                {
                    "streamPrefix": "urn:r5e:stream:publisher:",
                    "actorPrefixes": ["urn:r5e:publisher:"],
                    "issuerKeys": [&publisher_id],
                    "sealerKeys": [],
                }
            ],
            "checkpointKeys": [],
        },
        "durability": {
            "failureDomain": "steward-offline",
            "onFailure": "refuse",
            "requiredPayloads": "submitted",
        },
        "policyRequiredKinds": [],
        "deploymentPolicyRef": &policy_ref,
    }))
    .unwrap();
    let pub_profile_ref = bytes_ref(&pub_profile_bytes);

    let def_published_schema = schemas["provenance.r5e.io/v2/DefinitionPublished"]
        .as_str()
        .unwrap();
    let def_published = sign_v2_record_multi(
        &[&publisher_key],
        json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "DefinitionPublished",
            "schemaRef": def_published_schema,
            "profileRef": &pub_profile_ref,
            "stream": "urn:r5e:stream:publisher:base",
            "seq": 1,
            "previous": null,
            "actor": "urn:r5e:publisher:steward",
            "capturedAt": "2026-11-12T07:00:00Z",
            "body": {
                "package": "r5e.provenance",
                "definitions": &defs_vec,
            }
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .unwrap();
    let publication_ref = def_published.record_ref.clone();

    let publication_set = CarriedPublicationSet {
        records: vec![def_published],
        keys: vec![PublicKeyEntry {
            keyid: publisher_id.clone(),
            algorithm: "ed25519".to_string(),
            bytes: BASE64_STANDARD.encode(pub_bytes),
        }],
        blobs: vec![BlobEntry {
            blob_ref: pub_profile_ref,
            media_type: Some("application/json".to_string()),
            base64: BASE64_STANDARD.encode(&pub_profile_bytes),
        }],
    };

    let start_stream = format!("urn:r5e:stream:{deployment}:start");
    let boot_profile_bytes = encode_canonical_json(&json!({
        "format": "r5e.capture-profile/v2",
        "schemas": {
            "provenance.r5e.io/v2/ChainStarted": schemas["provenance.r5e.io/v2/ChainStarted"],
            "provenance.r5e.io/v2/Deployment": schemas["provenance.r5e.io/v2/Deployment"],
        },
        "authority": {
            "bindings": [
                {
                    "streamPrefix": &start_stream,
                    "actorPrefixes": ["urn:r5e:node:"],
                    "issuerKeys": [&bootstrap_id],
                    "sealerKeys": [&gateway_id],
                }
            ],
            "checkpointKeys": [],
        },
        "durability": {
            "failureDomain": "gateway-local",
            "onFailure": "refuse",
            "requiredPayloads": "submitted",
        },
        "policyRequiredKinds": [],
        "deploymentPolicyRef": &policy_ref,
    }))
    .unwrap();
    let boot_profile_ref = bytes_ref(&boot_profile_bytes);
    let bootstrap_profile_blob = BlobEntry {
        blob_ref: boot_profile_ref.clone(),
        media_type: Some("application/json".to_string()),
        base64: BASE64_STANDARD.encode(&boot_profile_bytes),
    };

    let cs_schema = schemas["provenance.r5e.io/v2/ChainStarted"]
        .as_str()
        .unwrap();
    let chain_started = sign_v2_record_multi(
        &[&bootstrap_key],
        json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "ChainStarted",
            "schemaRef": cs_schema,
            "profileRef": &boot_profile_ref,
            "stream": &start_stream,
            "seq": 1,
            "previous": null,
            "actor": format!("urn:r5e:node:{deployment}"),
            "capturedAt": "2026-11-12T07:55:00Z",
            "body": {
                "deployment": deployment,
                "bootstrap": &bootstrap_id,
                "bootstrapKey": {
                    "algorithm": "ed25519",
                    "bytes": BASE64_STANDARD.encode(boot_bytes),
                },
                "publication": &publication_ref,
                "publisher": &publisher_id,
                "definitions": &defs_vec,
            }
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .unwrap();

    MockNodeFixtures {
        deployment: deployment.to_string(),
        publisher_key,
        publisher_id,
        bootstrap_key,
        bootstrap_id: bootstrap_id.clone(),
        bootstrap_entry: PublicKeyEntry {
            keyid: bootstrap_id,
            algorithm: "ed25519".to_string(),
            bytes: BASE64_STANDARD.encode(boot_bytes),
        },
        gateway_key,
        gateway_id: gateway_id.clone(),
        gateway_entry: PublicKeyEntry {
            keyid: gateway_id,
            algorithm: "ed25519".to_string(),
            bytes: BASE64_STANDARD.encode(gw_bytes),
        },
        publication_set,
        publication_ref,
        bootstrap_profile_blob,
        chain_started,
    }
}

fn build_prepared_claim_from_request(
    fx: &MockNodeFixtures,
    req: &PrepareClaimRequest,
    ticket: &str,
) -> PreparedClaimResponse {
    let schemas = base_v2_schema_map();
    let dep_schema = schemas["provenance.r5e.io/v2/Deployment"].as_str().unwrap();
    let roots_val: Vec<Value> = req
        .roots
        .iter()
        .map(|r| {
            let pk_bytes: [u8; 32] = decode_strict_base64(&r.public_key.bytes)
                .unwrap()
                .try_into()
                .unwrap();
            let key_id = ed25519_key_id(&pk_bytes);
            let mut m = serde_json::Map::new();
            m.insert("key".to_string(), Value::String(key_id));
            m.insert("publicKey".to_string(), json!(&r.public_key));
            if let Some(ref h) = r.holder {
                m.insert("holder".to_string(), Value::String(h.clone()));
            }
            if let Some(ref c) = r.custody {
                m.insert("custody".to_string(), Value::String(c.clone()));
            }
            if let Some(ref id) = r.identity {
                m.insert("identity".to_string(), Value::String(id.clone()));
            }
            Value::Object(m)
        })
        .collect();

    let mut body_map = serde_json::Map::new();
    body_map.insert(
        "accepts".to_string(),
        Value::String(fx.chain_started.record_ref.clone()),
    );
    body_map.insert(
        "bootstrap".to_string(),
        Value::String(fx.bootstrap_id.clone()),
    );
    body_map.insert(
        "claimedBy".to_string(),
        Value::String(req.claimed_by.clone()),
    );
    body_map.insert("roots".to_string(), Value::Array(roots_val));
    body_map.insert("threshold".to_string(), Value::Number(req.threshold.into()));
    if let Some(ref rks) = req.recovery_keys {
        if !rks.is_empty() {
            body_map.insert("recoveryKeys".to_string(), json!(rks));
        }
    }
    if let Some(ref custs) = req.custodians {
        if !custs.is_empty() {
            body_map.insert("custodians".to_string(), json!(custs));
        }
    }

    let draft_payload = encode_canonical_json(&json!({
        "apiVersion": "provenance.r5e.io/v2",
        "kind": "Deployment",
        "schemaRef": dep_schema,
        "profileRef": &fx.bootstrap_profile_blob.blob_ref,
        "issuer": &fx.bootstrap_id,
        "stream": format!("urn:r5e:stream:{}:start", fx.deployment),
        "seq": 2,
        "previous": &fx.chain_started.record_ref,
        "actor": format!("urn:r5e:node:{}", fx.deployment),
        "capturedAt": "2026-11-12T08:00:00Z",
        "body": Value::Object(body_map),
    }))
    .unwrap();

    PreparedClaimResponse {
        payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
        payload: BASE64_STANDARD.encode(&draft_payload),
        ticket: ticket.to_string(),
        expires: "2026-11-12T08:10:00Z".to_string(),
        chain_started: fx.chain_started.clone(),
        bootstrap_key: fx.bootstrap_entry.clone(),
        publication: fx.publication_set.clone(),
        bootstrap_profile: fx.bootstrap_profile_blob.clone(),
    }
}

#[test]
fn base_v2_schema_map_matches_all_28_published_definitions() {
    let schemas = base_v2_schema_map();
    assert_eq!(schemas.len(), 28, "must carry all 28 base definitions");
    assert_eq!(
        schemas["provenance.r5e.io/v2/ChainStarted"],
        "bytes:sha256:8a2095f031e761d5dd606fdea9f1d6a5e4ca4c46860c621c2d7a51f3f3c3feb5"
    );
    assert_eq!(
        schemas["provenance.r5e.io/v2/Deployment"],
        "bytes:sha256:f1f731b69ef1b43e56f7818ec19f0ba241dcb13e329810b28d5f726da4d11915"
    );
    assert_eq!(
        schemas["provenance.r5e.io/v2/RootsChanged"],
        ROOTS_CHANGED_SCHEMA_REF
    );
    assert_eq!(
        schemas["provenance.r5e.io/v2/RootChangeApproval"],
        ROOT_CHANGE_APPROVAL_SCHEMA_REF
    );
    assert_eq!(
        schemas["provenance.r5e.io/v2/RetentionHold"],
        "bytes:sha256:37d3d08f778c42f62685938e82cf2f0a3d185e574777ac1a83f6a12191c3443c"
    );
    assert_eq!(
        schemas["provenance.r5e.io/v2/RetentionHoldRelease"],
        "bytes:sha256:44e73b344f8c8b70ac5b73873c72dc9a0b35b7da6b2c841f870c3b093d145862"
    );
    assert_eq!(
        schemas["provenance.r5e.io/v2/PayloadDisposition"],
        "bytes:sha256:6c3afdfa4e5adb47188e5027ed671830a0e399e17705d97653e40cd5a637cce5"
    );

    // Also verify default_gateway_grant_kinds has all 16 kinds (including A7 §6.5 retention-stream
    // kinds + A8 §2.2 Disclosure & Verification):
    let gw_kinds = default_gateway_grant_kinds();
    assert_eq!(
        gw_kinds.len(),
        16,
        "expected 16 default gateway grant kinds: {gw_kinds:?}"
    );
    for required_kind in [
        "provenance.r5e.io/v2/Disclosure",
        "provenance.r5e.io/v2/Verification",
        "provenance.r5e.io/v2/RetentionHold",
        "provenance.r5e.io/v2/RetentionHoldRelease",
        "provenance.r5e.io/v2/PayloadDisposition",
    ] {
        assert!(
            gw_kinds.iter().any(|k| k == required_kind),
            "default_gateway_grant_kinds missing {required_kind}: {gw_kinds:?}"
        );
        assert!(
            schemas.contains_key(required_kind),
            "base_v2_schema_map missing {required_kind}"
        );
    }

    if let Some(defs_dir) = optional_definitions_dir() {
        let raw = std::fs::read_to_string(defs_dir.join("index.json")).unwrap();
        let expected: serde_json::Map<String, Value> = serde_json::from_str(&raw).unwrap();
        assert_eq!(expected.len(), 28);
        assert_eq!(
            schemas, expected,
            "base_v2_schema_map drifted from definitions/index.json"
        );
        // Verify every single one of the 28 entries matches the canonical SHA-256 of its definition JSON file:
        for (kind_path, expected_ref_val) in &schemas {
            let expected_ref = expected_ref_val.as_str().unwrap();
            let def_file = defs_dir.join(format!("{kind_path}.json"));
            let def_raw = std::fs::read(&def_file)
                .unwrap_or_else(|e| panic!("read {}: {e}", def_file.display()));
            let def_val: Value = serde_json::from_slice(&def_raw).unwrap();
            let def_canonical = encode_canonical_json(&def_val).unwrap();
            assert_eq!(
                bytes_ref(&def_canonical),
                expected_ref,
                "definition file digest drifted for {kind_path}"
            );
        }
    }
}

#[test]
fn classify_claim_error_maps_gateway_http_statuses_and_redacts_secrets_in_debug() {
    let e400 = classify_claim_error(400, br#"{"error":"malformed_request"}"#);
    assert!(matches!(e400, ClaimError::BadRequest { .. }));
    assert_eq!(e400.error_code(), Some("malformed_request"));
    assert_eq!(e400.http_status(), Some(400));

    let e403 = classify_claim_error(403, br#"{"error":"wrong_claim_code"}"#);
    assert!(matches!(e403, ClaimError::Forbidden { .. }));
    assert_eq!(e403.error_code(), Some("wrong_claim_code"));

    let e404 = classify_claim_error(404, br#"{"error":"evidence_not_recorded_here"}"#);
    assert!(matches!(e404, ClaimError::NotFound { .. }));
    assert_eq!(e404.error_code(), Some("evidence_not_recorded_here"));

    let e409 = classify_claim_error(409, br#"{"error":"already_claimed"}"#);
    assert!(matches!(e409, ClaimError::Conflict { .. }));
    assert_eq!(e409.error_code(), Some("already_claimed"));

    let e409_ns = classify_claim_error(409, br#"{"error":"not_started"}"#);
    assert_eq!(e409_ns.error_code(), Some("not_started"));

    let e422 = classify_claim_error(422, br#"{"error":"duplicate_root"}"#);
    assert!(matches!(e422, ClaimError::Unprocessable { .. }));
    assert_eq!(e422.error_code(), Some("duplicate_root"));

    // Verify Debug never leaks `code`!
    let secret = "super-secret-one-time-claim-code-991827";
    let prep_req = PrepareClaimRequest {
        code: secret.to_string(),
        claimed_by:
            "key:ed25519:sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
        roots: vec![],
        threshold: 1,
        recovery_keys: Some(vec![]),
        custodians: None,
    };
    assert!(!format!("{prep_req:?}").contains(secret));
    // Also verify empty `recovery_keys` & `custodians` are omitted when serialized:
    let prep_wire: Value = serde_json::to_value(&prep_req).unwrap();
    assert!(prep_wire.get("recoveryKeys").is_none());
    assert!(prep_wire.get("custodians").is_none());

    let fin_req = FinalizeClaimRequest {
        code: secret.to_string(),
        payload: "e30=".to_string(),
        ticket: "tkt".to_string(),
        root_signature: DsseSignature {
            keyid: "k".to_string(),
            sig: "s".to_string(),
        },
    };
    assert!(!format!("{fin_req:?}").contains(secret));
}

#[test]
fn adversarial_gateway_tampering_is_refused_before_root_key_signs() {
    let fx = build_mock_node_fixtures("acme-prod");
    let root1 = SigningKey::from_bytes(&[0x41; 32]);
    let root2 = SigningKey::from_bytes(&[0x42; 32]);
    let recovery = SigningKey::from_bytes(&[0x51; 32]);

    let root1_id = ed25519_key_id(&root1.verifying_key().to_bytes());
    let recovery_id = ed25519_key_id(&recovery.verifying_key().to_bytes());

    let req = PrepareClaimRequest {
        code: "claim-code-xyz".to_string(),
        claimed_by: root1_id.clone(),
        roots: vec![
            PrepareClaimRootEntry {
                public_key: SubjectPublicKey {
                    algorithm: "ed25519".to_string(),
                    bytes: BASE64_STANDARD.encode(root1.verifying_key().to_bytes()),
                },
                holder: Some("person".to_string()),
                custody: Some("hardware".to_string()),
                identity: Some("mailto:lena@acme.example".to_string()),
            },
            PrepareClaimRootEntry {
                public_key: SubjectPublicKey {
                    algorithm: "ed25519".to_string(),
                    bytes: BASE64_STANDARD.encode(root2.verifying_key().to_bytes()),
                },
                holder: Some("person".to_string()),
                custody: Some("hardware".to_string()),
                identity: Some("mailto:omar@acme.example".to_string()),
            },
        ],
        threshold: 2,
        recovery_keys: Some(vec![recovery_id.clone()]),
        custodians: Some(vec![CustodianEntry {
            identity: "mailto:lena@acme.example".to_string(),
            key: None,
        }]),
    };

    let honest = build_prepared_claim_from_request(&fx, &req, "ticket-1");

    // Sanity check: honest response verifies cleanly with pinned publisher:
    let ok = verify_and_countersign_prepared_claim(
        &root1,
        &req,
        &honest,
        std::slice::from_ref(&fx.publisher_id),
        false,
    )
    .expect("honest prepared claim must verify");
    assert_eq!(ok.inspection.publisher_key_id, fx.publisher_id);
    assert!(ok.inspection.publisher_trusted);
    assert_eq!(ok.inspection.definition_count, 28);

    // 1. Wrong `bootstrapKey` signature on `ChainStarted`:
    let mut bad_cs_sig = honest.clone();
    let rogue_boot = SigningKey::from_bytes(&[0x99; 32]);
    let cs_bytes = decode_strict_base64(&bad_cs_sig.chain_started.envelope.payload).unwrap();
    let bad_sig = rogue_boot.sign(&dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &cs_bytes));
    bad_cs_sig.chain_started.envelope.signatures[0].sig =
        BASE64_STANDARD.encode(bad_sig.to_bytes());
    let err = verify_and_countersign_prepared_claim(
        &root1,
        &req,
        &bad_cs_sig,
        std::slice::from_ref(&fx.publisher_id),
        false,
    )
    .expect_err("must refuse bad ChainStarted signature");
    assert!(
        err.contains("chainStarted signature"),
        "unexpected err: {err}"
    );

    // 2a. Untrusted publisher when `trusted_publishers` is set to another key:
    let other_pub_id = ed25519_key_id(
        &SigningKey::from_bytes(&[0x77; 32])
            .verifying_key()
            .to_bytes(),
    );
    let err = verify_and_countersign_prepared_claim(&root1, &req, &honest, &[other_pub_id], true)
        .expect_err("must refuse publisher mismatch when trusted_publishers is non-empty");
    assert!(
        err.contains("publisher_not_trusted"),
        "unexpected err: {err}"
    );

    // 2b. Untrusted publisher when `trusted_publishers` is empty and `allow_untrusted_publisher == false`:
    let err = verify_and_countersign_prepared_claim(&root1, &req, &honest, &[], false).expect_err(
        "must fail closed when publisher is unpinned and allow_untrusted_publisher == false",
    );
    assert!(
        err.contains("publisher_not_trusted"),
        "unexpected err: {err}"
    );

    // 2c. Opt-in `allow_untrusted_publisher == true` with empty `trusted_publishers` marks `publisher_trusted = false`:
    let untrusted_ok = verify_and_countersign_prepared_claim(&root1, &req, &honest, &[], true)
        .expect("explicit allow_untrusted_publisher should succeed");
    assert!(!untrusted_ok.inspection.publisher_trusted);

    // 3. `ChainStarted.definitions` differing from `DefinitionPublished.definitions`:
    let mut bad_defs = honest.clone();
    let mut pub_payload_val: Value = serde_json::from_slice(
        &decode_strict_base64(&bad_defs.publication.records[0].envelope.payload).unwrap(),
    )
    .unwrap();
    // Remove the last definition from DefinitionPublished and re-sign with publisher_key + update ChainStarted.publication:
    pub_payload_val["body"]["definitions"]
        .as_array_mut()
        .unwrap()
        .pop();
    let tampered_pub = sign_v2_record_multi(
        &[&fx.publisher_key],
        pub_payload_val.as_object().unwrap().clone(),
    )
    .unwrap();
    let mut cs_val: Value = serde_json::from_slice(
        &decode_strict_base64(&bad_defs.chain_started.envelope.payload).unwrap(),
    )
    .unwrap();
    cs_val["body"]["publication"] = Value::String(tampered_pub.record_ref.clone());
    let tampered_cs =
        sign_v2_record_multi(&[&fx.bootstrap_key], cs_val.as_object().unwrap().clone()).unwrap();
    bad_defs.publication.records = vec![tampered_pub];
    bad_defs.chain_started = tampered_cs.clone();
    // Update draft Deployment accepts/previous to point to `tampered_cs`:
    let mut dep_val: Value =
        serde_json::from_slice(&decode_strict_base64(&bad_defs.payload).unwrap()).unwrap();
    dep_val["previous"] = Value::String(tampered_cs.record_ref.clone());
    dep_val["body"]["accepts"] = Value::String(tampered_cs.record_ref);
    bad_defs.payload = BASE64_STANDARD.encode(encode_canonical_json(&dep_val).unwrap());
    let err = verify_and_countersign_prepared_claim(
        &root1,
        &req,
        &bad_defs,
        std::slice::from_ref(&fx.publisher_id),
        false,
    )
    .expect_err("must refuse ChainStarted definitions differing from DefinitionPublished");
    assert!(
        err.contains("definitions_differ_from_publication"),
        "unexpected err: {err}"
    );

    // 4a. Gateway injects a 3rd rogue root key in `prepared.payload`:
    let mut rogue_root_prep = honest.clone();
    let rogue_root = SigningKey::from_bytes(&[0x88; 32]);
    let rogue_root_id = ed25519_key_id(&rogue_root.verifying_key().to_bytes());
    let mut dep_val: Value =
        serde_json::from_slice(&decode_strict_base64(&rogue_root_prep.payload).unwrap()).unwrap();
    dep_val["body"]["roots"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "key": rogue_root_id,
            "publicKey": {
                "algorithm": "ed25519",
                "bytes": BASE64_STANDARD.encode(rogue_root.verifying_key().to_bytes()),
            }
        }));
    rogue_root_prep.payload = BASE64_STANDARD.encode(encode_canonical_json(&dep_val).unwrap());
    let err = verify_and_countersign_prepared_claim(
        &root1,
        &req,
        &rogue_root_prep,
        std::slice::from_ref(&fx.publisher_id),
        false,
    )
    .expect_err("must refuse added rogue root");
    assert!(
        err.contains("roots length mismatch"),
        "unexpected err: {err}"
    );

    // 4b. Gateway swaps root2 for rogue_root:
    let mut swapped_root_prep = honest.clone();
    let mut dep_val: Value =
        serde_json::from_slice(&decode_strict_base64(&swapped_root_prep.payload).unwrap()).unwrap();
    dep_val["body"]["roots"][1] = json!({
        "key": ed25519_key_id(&rogue_root.verifying_key().to_bytes()),
        "publicKey": {
            "algorithm": "ed25519",
            "bytes": BASE64_STANDARD.encode(rogue_root.verifying_key().to_bytes()),
        },
        "holder": "person",
        "custody": "hardware",
        "identity": "mailto:omar@acme.example",
    });
    swapped_root_prep.payload = BASE64_STANDARD.encode(encode_canonical_json(&dep_val).unwrap());
    let err = verify_and_countersign_prepared_claim(
        &root1,
        &req,
        &swapped_root_prep,
        std::slice::from_ref(&fx.publisher_id),
        false,
    )
    .expect_err("must refuse swapped root");
    assert!(
        err.contains("Deployment.body.roots does not match"),
        "unexpected err: {err}"
    );

    // 4c. Gateway downgrades `threshold` from 2 to 1:
    let mut bad_thresh = honest.clone();
    let mut dep_val: Value =
        serde_json::from_slice(&decode_strict_base64(&bad_thresh.payload).unwrap()).unwrap();
    dep_val["body"]["threshold"] = json!(1);
    bad_thresh.payload = BASE64_STANDARD.encode(encode_canonical_json(&dep_val).unwrap());
    let err = verify_and_countersign_prepared_claim(
        &root1,
        &req,
        &bad_thresh,
        std::slice::from_ref(&fx.publisher_id),
        false,
    )
    .expect_err("must refuse altered threshold");
    assert!(err.contains("threshold mismatch"), "unexpected err: {err}");

    // 4d. Gateway alters `recoveryKeys` or `accepts`:
    let mut bad_rk = honest.clone();
    let mut dep_val: Value =
        serde_json::from_slice(&decode_strict_base64(&bad_rk.payload).unwrap()).unwrap();
    dep_val["body"]["recoveryKeys"] =
        json!([ed25519_key_id(&rogue_root.verifying_key().to_bytes())]);
    bad_rk.payload = BASE64_STANDARD.encode(encode_canonical_json(&dep_val).unwrap());
    let err = verify_and_countersign_prepared_claim(
        &root1,
        &req,
        &bad_rk,
        std::slice::from_ref(&fx.publisher_id),
        false,
    )
    .expect_err("must refuse altered recoveryKeys");
    assert!(err.contains("recoveryKeys"), "unexpected err: {err}");

    let mut bad_accepts = honest.clone();
    let mut dep_val: Value =
        serde_json::from_slice(&decode_strict_base64(&bad_accepts.payload).unwrap()).unwrap();
    dep_val["body"]["accepts"] =
        json!("evidence:sha256:0000000000000000000000000000000000000000000000000000000000000000");
    bad_accepts.payload = BASE64_STANDARD.encode(encode_canonical_json(&dep_val).unwrap());
    let err = verify_and_countersign_prepared_claim(
        &root1,
        &req,
        &bad_accepts,
        std::slice::from_ref(&fx.publisher_id),
        false,
    )
    .expect_err("must refuse wrong accepts");
    assert!(
        err.contains("accepts_is_not_chain_started"),
        "unexpected err: {err}"
    );

    // 5. Non-canonical JSON in `prepared.payload` (pretty-printed with whitespace):
    let mut non_canon = honest.clone();
    let dep_val: Value =
        serde_json::from_slice(&decode_strict_base64(&non_canon.payload).unwrap()).unwrap();
    let pretty_bytes = serde_json::to_vec_pretty(&dep_val).unwrap();
    non_canon.payload = BASE64_STANDARD.encode(&pretty_bytes);
    let err = verify_and_countersign_prepared_claim(
        &root1,
        &req,
        &non_canon,
        std::slice::from_ref(&fx.publisher_id),
        false,
    )
    .expect_err("must refuse non-canonical JSON payload");
    assert!(err.contains("not canonical JSON"), "unexpected err: {err}");

    // 6. Post-finalize tampering checks (`verify_finalized_claim`):
    let payload_bytes = decode_strict_base64(&ok.finalize_request.payload).unwrap();
    let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &payload_bytes);
    let boot_sig = fx.bootstrap_key.sign(&pae);
    let dep_ref = evidence_ref(&payload_bytes);
    let valid_finalized = FinalizedClaimResponse {
        deployment_record: SignedEndpointRecord {
            record_ref: dep_ref.clone(),
            envelope: DsseEnvelope {
                payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
                payload: ok.finalize_request.payload.clone(),
                signatures: vec![
                    DsseSignature {
                        keyid: fx.bootstrap_id.clone(),
                        sig: BASE64_STANDARD.encode(boot_sig.to_bytes()),
                    },
                    ok.finalize_request.root_signature.clone(),
                ],
            },
        },
        chain: dep_ref,
        chain_started: fx.chain_started.clone(),
        gateway_key: fx.gateway_entry.clone(),
        stream_prefix: "urn:r5e:stream:acme-prod:".to_string(),
    };
    verify_finalized_claim(
        &ok.finalize_request,
        &fx.bootstrap_entry,
        &fx.chain_started.record_ref,
        &valid_finalized,
    )
    .expect("valid finalized claim passes");

    // 6a. Missing bootstrap signature (only 1 signature):
    let mut missing_boot = valid_finalized.clone();
    missing_boot.deployment_record.envelope.signatures.remove(0);
    let err = verify_finalized_claim(
        &ok.finalize_request,
        &fx.bootstrap_entry,
        &fx.chain_started.record_ref,
        &missing_boot,
    )
    .expect_err("must refuse missing bootstrap signature");
    assert!(err.contains("2 signatures"), "unexpected err: {err}");

    // 6b. Altered payload in finalize response:
    let mut altered_fin = valid_finalized.clone();
    altered_fin.deployment_record.envelope.payload = BASE64_STANDARD.encode(b"{}");
    let err = verify_finalized_claim(
        &ok.finalize_request,
        &fx.bootstrap_entry,
        &fx.chain_started.record_ref,
        &altered_fin,
    )
    .expect_err("must refuse altered payload");
    assert!(
        err.contains("altered Deployment payload"),
        "unexpected err: {err}"
    );

    // 6c. `gatewayKey` reusing `bootstrapKey`:
    let mut reused_boot = valid_finalized;
    reused_boot.gateway_key = fx.bootstrap_entry.clone();
    let err = verify_finalized_claim(
        &ok.finalize_request,
        &fx.bootstrap_entry,
        &fx.chain_started.record_ref,
        &reused_boot,
    )
    .expect_err("must refuse gatewayKey == bootstrapKey");
    assert!(
        err.contains("distinct from single-use bootstrapKey"),
        "unexpected err: {err}"
    );
}

#[test]
fn full_http_multi_root_claim_and_gateway_grant_ceremony_verifies_end_to_end() {
    let fx = build_mock_node_fixtures("meridian-prod");
    let root1 = SigningKey::from_bytes(&[0x61; 32]);
    let root2 = SigningKey::from_bytes(&[0x62; 32]);
    let root3 = SigningKey::from_bytes(&[0x63; 32]);
    let recovery1 = SigningKey::from_bytes(&[0x64; 32]);
    let custodian_key = SigningKey::from_bytes(&[0x65; 32]);

    let root1_id = ed25519_key_id(&root1.verifying_key().to_bytes());
    let root1_hex = root1_id
        .strip_prefix("key:ed25519:sha256:")
        .unwrap()
        .to_string();
    let recovery1_id = ed25519_key_id(&recovery1.verifying_key().to_bytes());
    let custodian_key_id = ed25519_key_id(&custodian_key.verifying_key().to_bytes());

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let fx_srv = MockNodeFixtures {
        deployment: fx.deployment.clone(),
        publisher_key: fx.publisher_key.clone(),
        publisher_id: fx.publisher_id.clone(),
        bootstrap_key: fx.bootstrap_key.clone(),
        bootstrap_id: fx.bootstrap_id.clone(),
        bootstrap_entry: fx.bootstrap_entry.clone(),
        gateway_key: fx.gateway_key.clone(),
        gateway_id: fx.gateway_id.clone(),
        gateway_entry: fx.gateway_entry.clone(),
        publication_set: fx.publication_set.clone(),
        publication_ref: fx.publication_ref.clone(),
        bootstrap_profile_blob: fx.bootstrap_profile_blob.clone(),
        chain_started: fx.chain_started.clone(),
    };
    let expected_root_stream = format!("urn:r5e:stream:meridian-prod:authority:root:{root1_hex}");

    let server_thread = std::thread::spawn(move || {
        let mut stored_deployment: Option<SignedEndpointRecord> = None;

        // Serve 5 requests:
        // 0: GET /v1/deployment (not_started check)
        // 1: GET /v1/deployment (unclaimed check, chunked)
        // 2: POST /v1/deployment/claim/prepare (chunked)
        // 3: POST /v1/deployment/claim/finalize (Content-Length)
        // 4: POST /v1/deployment/grants (strictly enforces blobs == [profile_blob]!)
        // 5: GET /v1/deployment (claimed check)
        for step in 0..6 {
            let (mut sock, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(sock.try_clone().unwrap());
            let mut req_line = String::new();
            reader.read_line(&mut req_line).unwrap();
            let mut content_len = 0usize;
            loop {
                let mut h = String::new();
                reader.read_line(&mut h).unwrap();
                let t = h.trim();
                if t.is_empty() {
                    break;
                }
                if let Some((k, v)) = t.split_once(':') {
                    if k.eq_ignore_ascii_case("content-length") {
                        content_len = v.trim().parse().unwrap();
                    }
                }
            }
            let mut body_buf = vec![0u8; content_len];
            if content_len > 0 {
                reader.read_exact(&mut body_buf).unwrap();
            }

            match step {
                0 => {
                    assert!(req_line.starts_with(&format!("GET {DEPLOYMENT_STATUS_PATH} ")));
                    let resp = serde_json::to_vec(&json!({
                        "deployment": "meridian-prod",
                        "state": "not_started",
                        "chain": null,
                    }))
                    .unwrap();
                    write_content_length(&mut sock, 200, "OK", &resp);
                }
                1 => {
                    assert!(req_line.starts_with(&format!("GET {DEPLOYMENT_STATUS_PATH} ")));
                    let resp = serde_json::to_vec(&DeploymentStatusResponse {
                        deployment: Some(fx_srv.deployment.clone()),
                        state: DeploymentClaimState::Unclaimed,
                        chain_started: Some(fx_srv.chain_started.clone()),
                        bootstrap_key: Some(fx_srv.bootstrap_entry.clone()),
                        chain: None,
                        deployment_record: None,
                        gateway_key: None,
                        stream_prefix: None,
                        grants: Vec::new(),
                    })
                    .unwrap();
                    write_chunked(&mut sock, 200, "OK", &resp);
                }
                2 => {
                    assert!(req_line.starts_with(&format!("POST {PREPARE_CLAIM_PATH} ")));
                    let raw_json: Value = serde_json::from_slice(&body_buf).unwrap();
                    // Verify `roots[i].key` is NEVER sent in prepare request!
                    for r in raw_json["roots"].as_array().unwrap() {
                        assert!(
                            r.get("key").is_none(),
                            "prepare request must NOT send roots[].key: {r}"
                        );
                    }
                    let prep_req: PrepareClaimRequest = serde_json::from_slice(&body_buf).unwrap();
                    assert_eq!(prep_req.code, "one-time-claim-code-meridian");
                    assert_eq!(prep_req.roots.len(), 3);
                    assert_eq!(prep_req.threshold, 2);

                    let prep_resp =
                        build_prepared_claim_from_request(&fx_srv, &prep_req, "stateless-tkt-77");
                    let resp = serde_json::to_vec(&prep_resp).unwrap();
                    write_chunked(&mut sock, 200, "OK", &resp);
                }
                3 => {
                    assert!(req_line.starts_with(&format!("POST {FINALIZE_CLAIM_PATH} ")));
                    let fin_req: FinalizeClaimRequest = serde_json::from_slice(&body_buf).unwrap();
                    assert_eq!(fin_req.code, "one-time-claim-code-meridian");
                    assert_eq!(fin_req.ticket, "stateless-tkt-77");

                    let payload_bytes = decode_strict_base64(&fin_req.payload).unwrap();
                    let parsed: Value = serde_json::from_slice(&payload_bytes).unwrap();
                    let claimed_by = parsed["body"]["claimedBy"].as_str().unwrap();
                    assert_eq!(claimed_by, fin_req.root_signature.keyid);

                    // Verify root signature on gateway side:
                    let claimant_b64 = parsed["body"]["roots"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|r| r["key"].as_str() == Some(claimed_by))
                        .unwrap()["publicKey"]["bytes"]
                        .as_str()
                        .unwrap();
                    let claimant_pk: [u8; 32] = decode_strict_base64(claimant_b64)
                        .unwrap()
                        .try_into()
                        .unwrap();
                    let claimant_vk = VerifyingKey::from_bytes(&claimant_pk).unwrap();
                    let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &payload_bytes);
                    let root_sig_bytes: [u8; 64] =
                        decode_strict_base64(&fin_req.root_signature.sig)
                            .unwrap()
                            .try_into()
                            .unwrap();
                    claimant_vk
                        .verify(&pae, &ed25519_dalek::Signature::from_bytes(&root_sig_bytes))
                        .expect("claimant root signature must verify");

                    let boot_sig = fx_srv.bootstrap_key.sign(&pae);
                    let dep_ref = evidence_ref(&payload_bytes);
                    let dep_rec = SignedEndpointRecord {
                        record_ref: dep_ref.clone(),
                        envelope: DsseEnvelope {
                            payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
                            payload: fin_req.payload,
                            signatures: vec![
                                DsseSignature {
                                    keyid: fx_srv.bootstrap_id.clone(),
                                    sig: BASE64_STANDARD.encode(boot_sig.to_bytes()),
                                },
                                fin_req.root_signature,
                            ],
                        },
                    };
                    stored_deployment = Some(dep_rec.clone());
                    let resp = serde_json::to_vec(&FinalizedClaimResponse {
                        deployment_record: dep_rec,
                        chain: dep_ref,
                        chain_started: fx_srv.chain_started.clone(),
                        gateway_key: fx_srv.gateway_entry.clone(),
                        stream_prefix: "urn:r5e:stream:meridian-prod:".to_string(),
                    })
                    .unwrap();
                    write_content_length(&mut sock, 201, "Created", &resp);
                }
                4 => {
                    assert!(req_line.starts_with(&format!("POST {DEPLOYMENT_GRANTS_PATH} ")));
                    let grants_req: SubmitGrantsRequest =
                        serde_json::from_slice(&body_buf).unwrap();
                    assert_eq!(grants_req.records.len(), 1);
                    assert_eq!(grants_req.keys.len(), 1);
                    // CRITICAL ("After Carbon's review"): blobs may contain ONLY cited profile blobs!
                    assert_eq!(
                        grants_req.blobs.len(),
                        1,
                        "POST /v1/deployment/grants blobs must contain ONLY [root_profile_blob], got {:?}",
                        grants_req.blobs
                    );
                    let end_bytes =
                        decode_strict_base64(&grants_req.records[0].envelope.payload).unwrap();
                    let end_val: Value = serde_json::from_slice(&end_bytes).unwrap();
                    assert_eq!(end_val["kind"], "Endorsement");
                    assert_eq!(end_val["stream"], expected_root_stream);
                    assert_eq!(end_val["seq"], 1);
                    assert_eq!(
                        end_val["profileRef"].as_str().unwrap(),
                        grants_req.blobs[0].blob_ref
                    );
                    assert_eq!(end_val["body"]["subject"], fx_srv.gateway_id);
                    assert_eq!(end_val["body"]["mayEndorse"], true);
                    assert_eq!(
                        end_val["body"]["kinds"].as_array().unwrap().len(),
                        default_gateway_grant_kinds().len()
                    );

                    let prof_bytes = decode_strict_base64(&grants_req.blobs[0].base64).unwrap();
                    let prof_val: Value = serde_json::from_slice(&prof_bytes).unwrap();
                    assert_eq!(prof_val["schemas"].as_object().unwrap().len(), 28);
                    assert_eq!(
                        prof_val["authority"]["bindings"][0]["sealerKeys"],
                        json!([&fx_srv.gateway_id])
                    );

                    let resp = serde_json::to_vec(&json!({
                        "recorded": [&grants_req.records[0].record_ref]
                    }))
                    .unwrap();
                    write_chunked(&mut sock, 201, "Created", &resp);
                }
                5 => {
                    assert!(req_line.starts_with(&format!("GET {DEPLOYMENT_STATUS_PATH} ")));
                    let dep_rec = stored_deployment.clone().unwrap();
                    let resp = serde_json::to_vec(&DeploymentStatusResponse {
                        deployment: Some(fx_srv.deployment.clone()),
                        state: DeploymentClaimState::Claimed,
                        chain_started: Some(fx_srv.chain_started.clone()),
                        bootstrap_key: None,
                        chain: Some(dep_rec.record_ref.clone()),
                        deployment_record: Some(dep_rec),
                        gateway_key: Some(fx_srv.gateway_entry.clone()),
                        stream_prefix: Some("urn:r5e:stream:meridian-prod:".to_string()),
                        grants: Vec::new(),
                    })
                    .unwrap();
                    write_content_length(&mut sock, 200, "OK", &resp);
                }
                _ => unreachable!(),
            }
        }
    });

    let cfg = ClaimClientConfig::new(format!("http://{addr}"));

    // Step 0 & 1: GET /v1/deployment (`not_started`, then `unclaimed`):
    let st0 = get_deployment_status(&cfg).unwrap();
    assert_eq!(st0.state, DeploymentClaimState::NotStarted);
    assert!(st0.chain_started.is_none());

    let st1 = get_deployment_status(&cfg).unwrap();
    assert_eq!(st1.state, DeploymentClaimState::Unclaimed);
    assert_eq!(
        st1.chain_started.as_ref().unwrap().record_ref,
        fx.chain_started.record_ref
    );

    // Step 2-4: Full 3-root (threshold 2) claim + gateway grant ceremony:
    let prepare_req = PrepareClaimRequest {
        code: "one-time-claim-code-meridian".to_string(),
        claimed_by: root1_id.clone(),
        roots: vec![
            PrepareClaimRootEntry {
                public_key: SubjectPublicKey {
                    algorithm: "ed25519".to_string(),
                    bytes: BASE64_STANDARD.encode(root1.verifying_key().to_bytes()),
                },
                holder: Some("person".to_string()),
                custody: Some("hardware".to_string()),
                identity: Some("mailto:lena@meridian.example".to_string()),
            },
            PrepareClaimRootEntry {
                public_key: SubjectPublicKey {
                    algorithm: "ed25519".to_string(),
                    bytes: BASE64_STANDARD.encode(root2.verifying_key().to_bytes()),
                },
                holder: Some("person".to_string()),
                custody: Some("hardware".to_string()),
                identity: Some("mailto:omar@meridian.example".to_string()),
            },
            PrepareClaimRootEntry {
                public_key: SubjectPublicKey {
                    algorithm: "ed25519".to_string(),
                    bytes: BASE64_STANDARD.encode(root3.verifying_key().to_bytes()),
                },
                holder: Some("organization".to_string()),
                custody: Some("hsm".to_string()),
                identity: Some("urn:meridian:vault:escrow".to_string()),
            },
        ],
        threshold: 2,
        recovery_keys: Some(vec![recovery1_id]),
        custodians: Some(vec![
            CustodianEntry {
                identity: "mailto:lena@meridian.example".to_string(),
                key: Some(custodian_key_id),
            },
            CustodianEntry {
                identity: "mailto:omar@meridian.example".to_string(),
                key: None,
            },
        ]),
    };

    let outcome = execute_claim_ceremony(
        &cfg,
        &root1,
        &prepare_req,
        std::slice::from_ref(&fx.publisher_id),
        false,
        true,
        86_400 * 30,
        "urn:r5e:operator:lena",
        None,
    )
    .expect("multi-root claim + gateway grant ceremony succeeds");

    let st2 = get_deployment_status(&cfg).unwrap();
    assert_eq!(st2.state, DeploymentClaimState::Claimed);
    assert_eq!(st2.chain.as_deref(), Some(outcome.finalized.chain.as_str()));

    server_thread.join().unwrap();

    let (built_grant, grant_resp) = outcome.gateway_grant.expect("gateway grant submitted");
    assert_eq!(grant_resp.status, 201);
    assert_eq!(
        grant_resp.recorded_refs,
        vec![built_grant.endorsement.record_ref.clone()]
    );

    // Cross-verifier check: assemble a full `r5e.provenance-export/v2` bundle anchored ONLY by
    // `--trusted-chain <outcome.finalized.chain>` (zero `--trusted-root` flags!) with a gateway
    // `SessionOpened` record beneath the root's gateway `Endorsement`, and verify against the
    // clean-room Python and Rust verifiers if present on disk!
    let mut recorder = EndpointBundleRecorder::new();
    for k in &fx.publication_set.keys {
        let kb: [u8; 32] = decode_strict_base64(&k.bytes).unwrap().try_into().unwrap();
        recorder.register_ed25519_key(&kb);
    }
    recorder.register_ed25519_key(&fx.bootstrap_key.verifying_key().to_bytes());
    recorder.register_ed25519_key(&root1.verifying_key().to_bytes());
    recorder.register_ed25519_key(&root2.verifying_key().to_bytes());
    recorder.register_ed25519_key(&root3.verifying_key().to_bytes());
    recorder.register_ed25519_key(&fx.gateway_key.verifying_key().to_bytes());

    for b in &fx.publication_set.blobs {
        let raw = decode_strict_base64(&b.base64).unwrap();
        recorder.put_blob(&raw, b.media_type.as_deref());
    }
    let boot_prof_raw = decode_strict_base64(&fx.bootstrap_profile_blob.base64).unwrap();
    recorder.put_blob(&boot_prof_raw, Some("application/json"));
    let root_prof_raw = decode_strict_base64(&built_grant.request.blobs[0].base64).unwrap();
    recorder.put_blob(&root_prof_raw, Some("application/json"));

    for r in &fx.publication_set.records {
        recorder.ingest_external_record(r).unwrap();
    }
    recorder
        .ingest_external_record(&outcome.finalized.chain_started)
        .unwrap();
    recorder
        .ingest_external_record(&outcome.finalized.deployment_record)
        .unwrap();
    recorder
        .ingest_external_record(&built_grant.endorsement)
        .unwrap();

    // Gateway emits a `SessionOpened` under its new grant!
    let schemas = base_v2_schema_map();
    let gw_profile_bytes = encode_canonical_json(&json!({
        "format": "r5e.capture-profile/v2",
        "schemas": schemas,
        "authority": {
            "bindings": [
                {
                    "streamPrefix": "urn:r5e:stream:meridian-prod:",
                    "actorPrefixes": ["urn:r5e:"],
                    "issuerKeys": [&fx.gateway_id],
                    "sealerKeys": [&fx.gateway_id],
                }
            ],
            "checkpointKeys": [],
        },
        "durability": {
            "failureDomain": "gateway-local",
            "onFailure": "refuse",
            "requiredPayloads": "submitted",
        },
        "policyRequiredKinds": [],
        "deploymentPolicyRef": bytes_ref(b"permit(principal, action, resource);"),
    }))
    .unwrap();
    let gw_profile_ref = recorder.put_blob(&gw_profile_bytes, Some("application/json"));
    let session_now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    recorder
        .append_stream_record(
            &[&fx.gateway_key],
            "urn:r5e:stream:meridian-prod:sessions:s1",
            json!({
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "SessionOpened",
                "schemaRef": schemas["provenance.r5e.io/v2/SessionOpened"],
                "profileRef": &gw_profile_ref,
                "actor": "urn:r5e:agent:codex",
                "session": "urn:r5e:session:meridian-prod:s1",
                "capturedAt": &session_now,
                "body": {
                    "session": "urn:r5e:session:meridian-prod:s1",
                }
            })
            .as_object()
            .unwrap()
            .clone(),
        )
        .unwrap();

    let bundle_bytes = recorder
        .export_v2_bundle_bytes(json!({ "session": "urn:r5e:session:meridian-prod:s1" }))
        .unwrap();
    let tmp_bundle = std::env::temp_dir().join(format!(
        "r5e-endpoint-helper-a6-claim-{}.json",
        std::process::id()
    ));
    std::fs::write(&tmp_bundle, &bundle_bytes).unwrap();

    let live_defs_dir = optional_definitions_dir();

    if let Some((py_verifier_repo, py_bin)) = resolve_py_verifier() {
        let mut cmd = Command::new(&py_bin);
        cmd.current_dir(&py_verifier_repo)
            .env("PYTHONPATH", &py_verifier_repo)
            .args([
                "-m",
                "r5e_verify",
                tmp_bundle.to_str().unwrap(),
                "--trusted-chain",
                &outcome.finalized.chain,
                "--trusted-publisher",
                &fx.publisher_id,
            ]);
        if let Some(defs) = &live_defs_dir {
            cmd.args(["--definitions-dir", defs.to_str().unwrap()]);
        }
        let out = cmd.output().unwrap();
        let stdout_str = String::from_utf8_lossy(&out.stdout);
        let stderr_str = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(0),
            "clean-room Python verifier rejected A6 claimed bundle: stdout={stdout_str} stderr={stderr_str}"
        );
        let report: Value = serde_json::from_str(&stdout_str).unwrap();
        assert_eq!(report["summary"]["failed"], 0);
        assert_eq!(report["summary"]["incomplete"], 0);
        assert_eq!(report["start"]["chain"], outcome.finalized.chain);
    }

    if let Some(rs_verifier_bin) = resolve_rs_verifier_bin() {
        let mut cmd = Command::new(&rs_verifier_bin);
        cmd.args([
            tmp_bundle.to_str().unwrap(),
            "--trusted-chain",
            &outcome.finalized.chain,
            "--trusted-publisher",
            &fx.publisher_id,
        ]);
        if let Some(defs) = &live_defs_dir {
            cmd.args(["--definitions-dir", defs.to_str().unwrap()]);
        }
        let out = cmd.output().unwrap();
        let stdout_str = String::from_utf8_lossy(&out.stdout);
        let stderr_str = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(0),
            "clean-room Rust verifier rejected A6 claimed bundle: stdout={stdout_str} stderr={stderr_str}"
        );
        let report: Value = serde_json::from_str(&stdout_str).unwrap();
        assert_eq!(report["summary"]["failed"], 0);
        assert_eq!(report["summary"]["incomplete"], 0);
        assert_eq!(report["start"]["chain"], outcome.finalized.chain);
    }

    let _ = std::fs::remove_file(&tmp_bundle);
}

#[test]
fn cli_claim_and_grant_gateway_subcommands_preserve_zero_secret_exposure() {
    let bin = env!("CARGO_BIN_EXE_r5e-endpoint-helper");

    // 1. Ensure `--claim-code` CLI flag does NOT exist (must never accept secret in argv!):
    let bad_flag = Command::new(bin)
        .args([
            "claim",
            "--gateway-url",
            "http://127.0.0.1:9",
            "--claim-code",
            "secret",
        ])
        .output()
        .unwrap();
    assert!(!bad_flag.status.success());
    let stderr_str = String::from_utf8_lossy(&bad_flag.stderr);
    assert!(stderr_str.contains("unexpected argument '--claim-code'"));

    // 2. Spin up mock gateway for step-1 `claim --skip-gateway-grant`, then standalone `grant-gateway`:
    let fx = build_mock_node_fixtures("cli-prod");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let fx_srv = MockNodeFixtures {
        deployment: fx.deployment.clone(),
        publisher_key: fx.publisher_key.clone(),
        publisher_id: fx.publisher_id.clone(),
        bootstrap_key: fx.bootstrap_key.clone(),
        bootstrap_id: fx.bootstrap_id.clone(),
        bootstrap_entry: fx.bootstrap_entry.clone(),
        gateway_key: fx.gateway_key.clone(),
        gateway_id: fx.gateway_id.clone(),
        gateway_entry: fx.gateway_entry.clone(),
        publication_set: fx.publication_set.clone(),
        publication_ref: fx.publication_ref.clone(),
        bootstrap_profile_blob: fx.bootstrap_profile_blob.clone(),
        chain_started: fx.chain_started.clone(),
    };

    let secret_code = "cli-secret-claim-code-do-not-leak-88421";
    let secret_code_srv = secret_code.to_string();

    let server_thread = std::thread::spawn(move || {
        for step in 0..3 {
            let (mut sock, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(sock.try_clone().unwrap());
            let mut req_line = String::new();
            reader.read_line(&mut req_line).unwrap();
            let mut content_len = 0usize;
            loop {
                let mut h = String::new();
                reader.read_line(&mut h).unwrap();
                let t = h.trim();
                if t.is_empty() {
                    break;
                }
                if let Some((k, v)) = t.split_once(':') {
                    if k.eq_ignore_ascii_case("content-length") {
                        content_len = v.trim().parse().unwrap();
                    }
                }
            }
            let mut body_buf = vec![0u8; content_len];
            if content_len > 0 {
                reader.read_exact(&mut body_buf).unwrap();
            }

            match step {
                0 => {
                    assert!(req_line.starts_with(&format!("POST {PREPARE_CLAIM_PATH} ")));
                    let prep_req: PrepareClaimRequest = serde_json::from_slice(&body_buf).unwrap();
                    assert_eq!(prep_req.code, secret_code_srv);
                    let prep_resp =
                        build_prepared_claim_from_request(&fx_srv, &prep_req, "cli-ticket-1");
                    let resp = serde_json::to_vec(&prep_resp).unwrap();
                    write_content_length(&mut sock, 200, "OK", &resp);
                }
                1 => {
                    assert!(req_line.starts_with(&format!("POST {FINALIZE_CLAIM_PATH} ")));
                    let fin_req: FinalizeClaimRequest = serde_json::from_slice(&body_buf).unwrap();
                    assert_eq!(fin_req.code, secret_code_srv);
                    let payload_bytes = decode_strict_base64(&fin_req.payload).unwrap();
                    let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &payload_bytes);
                    let boot_sig = fx_srv.bootstrap_key.sign(&pae);
                    let dep_ref = evidence_ref(&payload_bytes);
                    let dep_rec = SignedEndpointRecord {
                        record_ref: dep_ref.clone(),
                        envelope: DsseEnvelope {
                            payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
                            payload: fin_req.payload,
                            signatures: vec![
                                DsseSignature {
                                    keyid: fx_srv.bootstrap_id.clone(),
                                    sig: BASE64_STANDARD.encode(boot_sig.to_bytes()),
                                },
                                fin_req.root_signature,
                            ],
                        },
                    };
                    let resp = serde_json::to_vec(&FinalizedClaimResponse {
                        deployment_record: dep_rec,
                        chain: dep_ref,
                        chain_started: fx_srv.chain_started.clone(),
                        gateway_key: fx_srv.gateway_entry.clone(),
                        stream_prefix: "urn:r5e:stream:cli-prod:".to_string(),
                    })
                    .unwrap();
                    write_content_length(&mut sock, 201, "Created", &resp);
                }
                2 => {
                    assert!(req_line.starts_with(&format!("POST {DEPLOYMENT_GRANTS_PATH} ")));
                    let grants_req: SubmitGrantsRequest =
                        serde_json::from_slice(&body_buf).unwrap();
                    assert_eq!(grants_req.blobs.len(), 1);
                    let resp = serde_json::to_vec(&json!({
                        "recorded": [&grants_req.records[0].record_ref]
                    }))
                    .unwrap();
                    write_content_length(&mut sock, 201, "Created", &resp);
                }
                _ => unreachable!(),
            }
        }
    });

    let tmp_dir = std::env::temp_dir().join(format!(
        "r5e-endpoint-helper-cli-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let code_file = tmp_dir.join("claim.code");
    let seed_out = tmp_dir.join("root.seed");
    let receipt_out = tmp_dir.join("receipt.json");
    std::fs::write(&code_file, format!("{secret_code}\n")).unwrap();

    let claim_out = Command::new(bin)
        .args([
            "claim",
            "--gateway-url",
            &format!("http://{addr}"),
            "--claim-code-file",
            code_file.to_str().unwrap(),
            "--generate-root-seed-out",
            seed_out.to_str().unwrap(),
            "--holder",
            "person",
            "--custody",
            "hardware",
            "--identity",
            "mailto:lena@cli.example",
            "--trusted-publisher",
            &fx.publisher_id,
            "--allow-permanent-roots",
            "--skip-gateway-grant",
            "--out-receipt",
            receipt_out.to_str().unwrap(),
        ])
        .env_remove("R5E_ROOT_SEED_B64")
        .env_remove("R5E_CLAIM_CODE")
        .output()
        .unwrap();

    let stdout_str = String::from_utf8_lossy(&claim_out.stdout);
    let stderr_str = String::from_utf8_lossy(&claim_out.stderr);
    assert!(
        claim_out.status.success(),
        "claim CLI failed: stdout={stdout_str}, stderr={stderr_str}"
    );
    assert!(
        stderr_str.contains(IRREVERSIBLE_CLAIM_WARNING),
        "permanent-roots claim must still emit the plain-language irreversibility warning to stderr"
    );

    // Verify 0600 permissions on generated root seed and zero secret leakage in stdout/stderr/receipt:
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&seed_out).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "generated root seed file must have mode 0600");
    }
    let seed_file_text = std::fs::read_to_string(&seed_out).unwrap();
    let seed_b64_trimmed = seed_file_text.trim();
    assert!(!seed_b64_trimmed.is_empty());
    assert!(!stdout_str.contains(secret_code));
    assert!(!stderr_str.contains(secret_code));
    assert!(!stdout_str.contains(seed_b64_trimmed));
    assert!(!stderr_str.contains(seed_b64_trimmed));

    let summary: Value = serde_json::from_str(stdout_str.trim()).unwrap();
    assert_eq!(summary["ok"], true);
    assert_eq!(summary["gatewayKey"]["keyid"], fx.gateway_id);
    assert_eq!(summary["publisher"], fx.publisher_id);
    assert_eq!(summary["definitionCount"], 28);
    assert_eq!(summary["gatewayGrantSubmitted"], false);
    assert!(summary["chain"]
        .as_str()
        .unwrap()
        .starts_with("evidence:sha256:"));
    let root_key_id = summary["rootKeyId"].as_str().unwrap().to_string();

    let receipt_raw = std::fs::read_to_string(&receipt_out).unwrap();
    assert!(!receipt_raw.contains(secret_code));
    assert!(!receipt_raw.contains(seed_b64_trimmed));
    let receipt: Value = serde_json::from_str(&receipt_raw).unwrap();
    assert_eq!(receipt["chain"], summary["chain"]);
    assert_eq!(receipt["rootKeyId"], root_key_id);

    // 3. Standalone `grant-gateway` using `--root-seed-file` (`0600`):
    let grant_out = Command::new(bin)
        .args([
            "grant-gateway",
            "--gateway-url",
            &format!("http://{addr}"),
            "--root-seed-file",
            seed_out.to_str().unwrap(),
            "--gateway-key-id",
            &fx.gateway_id,
            "--deployment",
            "cli-prod",
            "--seq",
            "1",
        ])
        .env_remove("R5E_ROOT_SEED_B64")
        .output()
        .unwrap();
    let grant_stdout = String::from_utf8_lossy(&grant_out.stdout);
    let grant_stderr = String::from_utf8_lossy(&grant_out.stderr);
    assert!(
        grant_out.status.success(),
        "grant-gateway CLI failed: stdout={grant_stdout}, stderr={grant_stderr}"
    );
    assert!(!grant_stdout.contains(seed_b64_trimmed));
    assert!(!grant_stderr.contains(seed_b64_trimmed));
    let grant_summary: Value = serde_json::from_str(grant_stdout.trim()).unwrap();
    assert_eq!(grant_summary["ok"], true);
    assert_eq!(grant_summary["rootKeyId"], root_key_id);
    assert_eq!(grant_summary["gatewayKeyId"], fx.gateway_id);

    // Also test subsequent `seq = 2` validation on `build_root_gateway_grant`:
    let seed_raw: [u8; 32] = decode_strict_base64(seed_b64_trimmed)
        .unwrap()
        .try_into()
        .unwrap();
    let root_sk = SigningKey::from_bytes(&seed_raw);
    let mut seq2_params = GatewayGrantParams::new(&fx.gateway_id, "urn:r5e:stream:cli-prod:");
    seq2_params.seq = 2;
    assert!(
        build_root_gateway_grant(&root_sk, &seq2_params).is_err(),
        "seq 2 without previous must fail"
    );
    seq2_params.previous = Some(
        grant_summary["endorsementRef"]
            .as_str()
            .unwrap()
            .to_string(),
    );
    let seq2_built =
        build_root_gateway_grant(&root_sk, &seq2_params).expect("seq 2 with previous succeeds");
    assert_eq!(seq2_built.request.blobs.len(), 1);

    server_thread.join().unwrap();
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn claim_and_immediate_gateway_grant_handles_same_second_999999_micros_and_clock_skew() {
    use chrono::{DateTime, Duration, SecondsFormat, Timelike, Utc};

    // Exercise both:
    // 1. `.999999Z` within the current UTC second (the exact Live Run 6 subsecond truncation trap,
    //    at its worst possible `.999999Z` boundary), and
    // 2. `150ms` forward clock skew on the gateway (`Deployment.capturedAt` ahead of operator `Utc::now()`).
    let now_base = Utc::now();
    let case_same_sec_999999 = now_base
        .with_nanosecond(999_999_000)
        .unwrap()
        .to_rfc3339_opts(SecondsFormat::Micros, true);
    let case_skew_ahead =
        (now_base + Duration::milliseconds(150)).to_rfc3339_opts(SecondsFormat::Micros, true);

    for (idx, dep_captured_at) in [case_same_sec_999999, case_skew_ahead]
        .into_iter()
        .enumerate()
    {
        let deployment = format!("subsec-live6-{idx}");
        let fx = build_mock_node_fixtures(&deployment);
        let root_sk = SigningKey::from_bytes(&[0x91 + idx as u8; 32]);
        let root_pub = root_sk.verifying_key().to_bytes();
        let root_id = ed25519_key_id(&root_pub);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let dep_ts_srv = dep_captured_at.clone();
        let fx_srv_dep = fx.deployment.clone();
        let fx_srv_boot_key = fx.bootstrap_key.clone();
        let fx_srv_boot_id = fx.bootstrap_id.clone();
        let fx_srv_boot_entry = fx.bootstrap_entry.clone();
        let fx_srv_gw_entry = fx.gateway_entry.clone();
        let fx_srv_pub_set = fx.publication_set.clone();
        let fx_srv_boot_prof = fx.bootstrap_profile_blob.clone();
        let fx_srv_cs = fx.chain_started.clone();

        let srv = std::thread::spawn(move || {
            for step in 0..3 {
                let (mut sock, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(&mut sock);
                let mut req_line = String::new();
                reader.read_line(&mut req_line).unwrap();
                let mut content_len = 0usize;
                loop {
                    let mut h = String::new();
                    reader.read_line(&mut h).unwrap();
                    let t = h.trim_end_matches(&['\r', '\n'][..]);
                    if t.is_empty() {
                        break;
                    }
                    if let Some((k, v)) = t.split_once(':') {
                        if k.trim().eq_ignore_ascii_case("content-length") {
                            content_len = v.trim().parse().unwrap();
                        }
                    }
                }
                let mut body_buf = vec![0u8; content_len];
                if content_len > 0 {
                    reader.read_exact(&mut body_buf).unwrap();
                }

                match step {
                    0 => {
                        assert!(req_line.starts_with(&format!("POST {PREPARE_CLAIM_PATH} ")));
                        let prep_req: PrepareClaimRequest =
                            serde_json::from_slice(&body_buf).unwrap();
                        let schemas = base_v2_schema_map();
                        let dep_schema =
                            schemas["provenance.r5e.io/v2/Deployment"].as_str().unwrap();
                        let draft_payload = encode_canonical_json(&json!({
                            "apiVersion": "provenance.r5e.io/v2",
                            "kind": "Deployment",
                            "schemaRef": dep_schema,
                            "profileRef": &fx_srv_boot_prof.blob_ref,
                            "issuer": &fx_srv_boot_id,
                            "stream": format!("urn:r5e:stream:{fx_srv_dep}:start"),
                            "seq": 2,
                            "previous": &fx_srv_cs.record_ref,
                            "actor": format!("urn:r5e:node:{fx_srv_dep}"),
                            "capturedAt": &dep_ts_srv,
                            "body": {
                                "accepts": &fx_srv_cs.record_ref,
                                "bootstrap": &fx_srv_boot_id,
                                "claimedBy": &prep_req.claimed_by,
                                "roots": [{
                                    "key": &prep_req.claimed_by,
                                    "publicKey": &prep_req.roots[0].public_key,
                                    "holder": "person",
                                    "custody": "hardware",
                                }],
                                "threshold": 1,
                                "recoveryKeys": prep_req.recovery_keys.unwrap(),
                            }
                        }))
                        .unwrap();
                        let resp = serde_json::to_vec(&PreparedClaimResponse {
                            payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
                            payload: BASE64_STANDARD.encode(&draft_payload),
                            ticket: format!("subsec-tkt-{idx}"),
                            expires: "2099-01-01T00:00:00Z".to_string(),
                            chain_started: fx_srv_cs.clone(),
                            bootstrap_key: fx_srv_boot_entry.clone(),
                            publication: fx_srv_pub_set.clone(),
                            bootstrap_profile: fx_srv_boot_prof.clone(),
                        })
                        .unwrap();
                        write_content_length(&mut sock, 200, "OK", &resp);
                    }
                    1 => {
                        assert!(req_line.starts_with(&format!("POST {FINALIZE_CLAIM_PATH} ")));
                        let fin_req: FinalizeClaimRequest =
                            serde_json::from_slice(&body_buf).unwrap();
                        let pbytes = decode_strict_base64(&fin_req.payload).unwrap();
                        let boot_sig =
                            fx_srv_boot_key.sign(&dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &pbytes));
                        let dep_ref = evidence_ref(&pbytes);
                        let dep_rec = SignedEndpointRecord {
                            record_ref: dep_ref.clone(),
                            envelope: DsseEnvelope {
                                payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
                                payload: fin_req.payload,
                                signatures: vec![
                                    DsseSignature {
                                        keyid: fx_srv_boot_id.clone(),
                                        sig: BASE64_STANDARD.encode(boot_sig.to_bytes()),
                                    },
                                    fin_req.root_signature,
                                ],
                            },
                        };
                        let resp = serde_json::to_vec(&FinalizedClaimResponse {
                            deployment_record: dep_rec,
                            chain: dep_ref,
                            chain_started: fx_srv_cs.clone(),
                            gateway_key: fx_srv_gw_entry.clone(),
                            stream_prefix: format!("urn:r5e:stream:{fx_srv_dep}:"),
                        })
                        .unwrap();
                        write_content_length(&mut sock, 201, "Created", &resp);
                    }
                    2 => {
                        assert!(req_line.starts_with(&format!("POST {DEPLOYMENT_GRANTS_PATH} ")));
                        let grants_req: SubmitGrantsRequest =
                            serde_json::from_slice(&body_buf).unwrap();
                        let resp = serde_json::to_vec(&json!({
                            "recorded": [&grants_req.records[0].record_ref]
                        }))
                        .unwrap();
                        write_content_length(&mut sock, 201, "Created", &resp);
                    }
                    _ => unreachable!(),
                }
            }
        });

        let standby_rec_id = ed25519_key_id(
            &SigningKey::from_bytes(&[0xa5; 32])
                .verifying_key()
                .to_bytes(),
        );
        let prep_req = PrepareClaimRequest {
            code: "SUBSEC-CODE".to_string(),
            claimed_by: root_id,
            roots: vec![PrepareClaimRootEntry {
                public_key: SubjectPublicKey {
                    algorithm: "ed25519".to_string(),
                    bytes: BASE64_STANDARD.encode(root_pub),
                },
                holder: Some("person".to_string()),
                custody: Some("hardware".to_string()),
                identity: None,
            }],
            threshold: 1,
            recovery_keys: Some(vec![standby_rec_id]),
            custodians: None,
        };

        let cfg = ClaimClientConfig::new(format!("http://{addr}"));
        let outcome = execute_claim_ceremony(
            &cfg,
            &root_sk,
            &prep_req,
            std::slice::from_ref(&fx.publisher_id),
            false,
            true,
            86_400 * 30,
            "urn:r5e:operator:root",
            None,
        )
        .expect("claim + immediate gateway grant must succeed");
        srv.join().unwrap();

        let (built_grant, _) = outcome.gateway_grant.expect("gateway grant minted");
        let end_bytes = decode_strict_base64(&built_grant.endorsement.envelope.payload).unwrap();
        let end_val: Value = serde_json::from_slice(&end_bytes).unwrap();
        let end_ts = end_val["capturedAt"].as_str().unwrap();

        assert!(
            end_ts.contains('.') && end_ts.ends_with('Z'),
            "Endorsement.capturedAt must carry microsecond precision (.ffffffZ), got {end_ts}"
        );

        let dep_dt = DateTime::parse_from_rfc3339(&dep_captured_at)
            .unwrap()
            .with_timezone(&Utc);
        let end_dt = DateTime::parse_from_rfc3339(end_ts)
            .unwrap()
            .with_timezone(&Utc);
        assert!(
            end_dt >= dep_dt,
            "case {idx}: Endorsement.capturedAt ({end_ts}) MUST be >= Deployment.capturedAt ({dep_captured_at})"
        );
    }
}

fn write_content_length(sock: &mut std::net::TcpStream, status: u16, reason: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    sock.write_all(head.as_bytes()).unwrap();
    sock.write_all(body).unwrap();
    sock.flush().unwrap();
}

fn write_chunked(sock: &mut std::net::TcpStream, status: u16, reason: &str, body: &[u8]) {
    let mid = body.len() / 2;
    let part1 = &body[..mid];
    let part2 = &body[mid..];
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    );
    sock.write_all(head.as_bytes()).unwrap();
    if !part1.is_empty() {
        sock.write_all(format!("{:x}\r\n", part1.len()).as_bytes())
            .unwrap();
        sock.write_all(part1).unwrap();
        sock.write_all(b"\r\n").unwrap();
    }
    if !part2.is_empty() {
        sock.write_all(format!("{:x}\r\n", part2.len()).as_bytes())
            .unwrap();
        sock.write_all(part2).unwrap();
        sock.write_all(b"\r\n").unwrap();
    }
    sock.write_all(b"0\r\n\r\n").unwrap();
    sock.flush().unwrap();
}
