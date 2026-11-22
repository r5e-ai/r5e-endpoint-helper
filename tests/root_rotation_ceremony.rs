use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use r5e_endpoint_helper::attestation::{
    base_v2_schema_map, bytes_ref, decode_strict_base64, dsse_pae, ed25519_key_id,
    encode_canonical_json, encode_pkcs8_ed25519_pem, encode_spki_ed25519_pem, evidence_ref,
    sign_v2_record_multi, write_private_key_file_0600, BlobEntry, DsseEnvelope, DsseSignature,
    PublicKeyEntry, SignedEndpointRecord, SubjectPublicKey, PROVENANCE_V2_PAYLOAD_TYPE,
    ROOTS_CHANGED_SCHEMA_REF, ROOT_CHANGE_APPROVAL_SCHEMA_REF,
};
use r5e_endpoint_helper::claim_http::{
    build_root_gateway_grant, default_gateway_grant_kinds, CarriedPublicationSet,
    ClaimClientConfig, ClaimError, DeploymentClaimState, DeploymentStatusResponse,
    FinalizeClaimRequest, FinalizedClaimResponse, GatewayGrantParams, PrepareClaimRequest,
    PrepareClaimRootEntry, PreparedClaimResponse, SubmitGrantsRequest, DEPLOYMENT_GRANTS_PATH,
    DEPLOYMENT_STATUS_PATH, FINALIZE_CLAIM_PATH, PREPARE_CLAIM_PATH,
};
use r5e_endpoint_helper::root_rotation::{
    apply_root_change, propose_root_change, submit_deployment_roots, verify_proposal_locally,
    ProposeRootChangeParams, RootChangeAuthorization, RootChangeProposalFile,
    SubmitRootChangeRequest, DEPLOYMENT_ROOTS_PATH, IRREVERSIBLE_CLAIM_WARNING,
};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;

fn read_http_request(stream: &mut std::net::TcpStream) -> (String, Vec<u8>) {
    let mut reader = BufReader::new(stream);
    let mut req_line = String::new();
    reader.read_line(&mut req_line).unwrap();
    let mut content_len = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_len = v.trim().parse().unwrap();
            }
        }
    }
    let mut body = vec![0u8; content_len];
    if content_len > 0 {
        reader.read_exact(&mut body).unwrap();
    }
    (req_line, body)
}

fn write_json_response(stream: &mut std::net::TcpStream, status: u16, reason: &str, body: &[u8]) {
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    stream.flush().unwrap();
}

fn make_public_key_entry(sk: &SigningKey) -> (String, PublicKeyEntry) {
    let pub_bytes = sk.verifying_key().to_bytes();
    let kid = ed25519_key_id(&pub_bytes);
    let entry = PublicKeyEntry {
        keyid: kid.clone(),
        algorithm: "ed25519".to_string(),
        bytes: BASE64_STANDARD.encode(pub_bytes),
    };
    (kid, entry)
}

fn make_temp_dir(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("r5e-endpoint-helper-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct MockClaimGatewayFixtures {
    deployment: String,
    publisher_id: String,
    bootstrap_key: SigningKey,
    bootstrap_id: String,
    bootstrap_entry: PublicKeyEntry,
    gateway_id: String,
    gateway_entry: PublicKeyEntry,
    publication_set: CarriedPublicationSet,
    bootstrap_profile_blob: BlobEntry,
    chain_started: SignedEndpointRecord,
}

fn build_mock_claim_gateway_fixtures(deployment: &str) -> MockClaimGatewayFixtures {
    let publisher_key = SigningKey::from_bytes(&[0x11; 32]);
    let bootstrap_key = SigningKey::from_bytes(&[0x22; 32]);
    let gateway_key = SigningKey::from_bytes(&[0x33; 32]);

    let (publisher_id, publisher_entry) = make_public_key_entry(&publisher_key);
    let (bootstrap_id, bootstrap_entry) = make_public_key_entry(&bootstrap_key);
    let (gateway_id, gateway_entry) = make_public_key_entry(&gateway_key);

    let schemas = base_v2_schema_map();
    let defs_vec: Vec<Value> = schemas
        .iter()
        .map(|(k, v)| json!({ "kind": k, "definition": v }))
        .collect();
    let policy_ref = bytes_ref(b"permit(principal, action, resource);");

    let pub_profile_bytes = encode_canonical_json(&json!({
        "format": "r5e.capture-profile/v2",
        "schemas": &schemas,
        "authority": {
            "bindings": [{
                "streamPrefix": "urn:r5e:stream:publisher:",
                "actorPrefixes": ["urn:r5e:publisher:"],
                "issuerKeys": [&publisher_id],
                "sealerKeys": [],
            }],
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

    let dp_schema = schemas["provenance.r5e.io/v2/DefinitionPublished"]
        .as_str()
        .unwrap();
    let pub_record = sign_v2_record_multi(
        &[&publisher_key],
        json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "DefinitionPublished",
            "schemaRef": dp_schema,
            "profileRef": &pub_profile_ref,
            "stream": "urn:r5e:stream:publisher:base",
            "seq": 1,
            "previous": null,
            "actor": "urn:r5e:publisher:steward",
            "capturedAt": "2026-11-12T08:00:00Z",
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
    let publication_ref = pub_record.record_ref.clone();
    let publication_set = CarriedPublicationSet {
        records: vec![pub_record],
        keys: vec![publisher_entry],
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
            "provenance.r5e.io/v2/ChainStarted": &schemas["provenance.r5e.io/v2/ChainStarted"],
            "provenance.r5e.io/v2/Deployment": &schemas["provenance.r5e.io/v2/Deployment"],
        },
        "authority": {
            "bindings": [{
                "streamPrefix": &start_stream,
                "actorPrefixes": ["urn:r5e:node:"],
                "issuerKeys": [&bootstrap_id],
                "sealerKeys": [&gateway_id],
            }],
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
        base64: BASE64_STANDARD.encode(&boot_profile_bytes),
        media_type: Some("application/json".to_string()),
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
            "capturedAt": "2026-11-12T08:01:00Z",
            "body": {
                "deployment": deployment,
                "bootstrap": &bootstrap_id,
                "bootstrapKey": {
                    "algorithm": "ed25519",
                    "bytes": &bootstrap_entry.bytes,
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

    MockClaimGatewayFixtures {
        deployment: deployment.to_string(),
        publisher_id,
        bootstrap_key,
        bootstrap_id,
        bootstrap_entry,
        gateway_id,
        gateway_entry,
        publication_set,
        bootstrap_profile_blob,
        chain_started,
    }
}

fn build_prepared_claim_from_request(
    fx: &MockClaimGatewayFixtures,
    req: &PrepareClaimRequest,
    ticket: &str,
) -> PreparedClaimResponse {
    let schemas = base_v2_schema_map();
    let dep_schema = schemas["provenance.r5e.io/v2/Deployment"].as_str().unwrap();

    let roots_val: Vec<Value> = req
        .roots
        .iter()
        .map(|r| {
            let raw_pk: [u8; 32] = decode_strict_base64(&r.public_key.bytes)
                .unwrap()
                .try_into()
                .unwrap();
            let mut m = Map::new();
            m.insert("key".to_string(), Value::String(ed25519_key_id(&raw_pk)));
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

    let mut body_map = Map::new();
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
        "capturedAt": "2026-11-12T08:02:00Z",
        "body": Value::Object(body_map),
    }))
    .unwrap();

    PreparedClaimResponse {
        payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
        payload: BASE64_STANDARD.encode(&draft_payload),
        ticket: ticket.to_string(),
        expires: "2026-11-12T08:12:00Z".to_string(),
        chain_started: fx.chain_started.clone(),
        bootstrap_key: fx.bootstrap_entry.clone(),
        publication: fx.publication_set.clone(),
        bootstrap_profile: fx.bootstrap_profile_blob.clone(),
    }
}

#[test]
fn claim_irreversibility_guard_and_generate_recovery_key_ceremony() {
    let bin = env!("CARGO_BIN_EXE_r5e-endpoint-helper");
    let tmp_dir = make_temp_dir("claim-irreversibility");
    let fx = build_mock_claim_gateway_fixtures("acme-slice2");

    let secret_code = "CLM-SLICE2-SECRET-9988";
    let code_file = tmp_dir.join("claim.code");
    let root_seed_out = tmp_dir.join("root.seed");
    let recovery_pem_out = tmp_dir.join("recovery-01.pem");
    let receipt_out = tmp_dir.join("claim-receipt.json");
    std::fs::write(&code_file, format!("{secret_code}\n")).unwrap();

    // 1. Invoking `claim` with neither `--recovery-key`, `--generate-recovery-key`, `--custodian`,
    //    nor `--allow-permanent-roots` MUST exit 2 before touching network or generating keys,
    //    and MUST print the exact §5.5 plain-language irreversibility warning to stderr.
    let refused = Command::new(bin)
        .args([
            "claim",
            "--gateway-url",
            "http://127.0.0.1:9",
            "--claim-code-file",
            code_file.to_str().unwrap(),
            "--generate-root-seed-out",
            root_seed_out.to_str().unwrap(),
            "--trusted-publisher",
            &fx.publisher_id,
            "--skip-gateway-grant",
        ])
        .env_remove("R5E_ROOT_SEED_B64")
        .env_remove("R5E_CLAIM_CODE")
        .output()
        .unwrap();

    assert_eq!(refused.status.code(), Some(2));
    let refused_stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        refused_stderr.contains(IRREVERSIBLE_CLAIM_WARNING),
        "stderr must contain exact §5.5 warning, got: {refused_stderr}"
    );
    assert!(
        refused_stderr.contains("--allow-permanent-roots"),
        "stderr must guide operator toward --generate-recovery-key or --allow-permanent-roots"
    );
    assert!(
        !root_seed_out.exists(),
        "aborted claim must not leave generated root seed behind"
    );

    // 2. `claim --generate-recovery-key <path.pem>` succeeds without `--allow-permanent-roots`,
    //    creates `<path.pem>` with mode 0600, embeds its fingerprint in `Deployment.body.recoveryKeys`,
    //    and leaks zero secret bytes to stdout/stderr/receipt.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let publisher_id = fx.publisher_id.clone();
    let gateway_id = fx.gateway_id.clone();

    let server_handle = std::thread::spawn(move || {
        let mut captured_recovery_keys: Vec<String> = Vec::new();
        for step in 0..2 {
            let (mut sock, _) = listener.accept().unwrap();
            let (req_line, req_body) = read_http_request(&mut sock);
            match step {
                0 => {
                    assert!(req_line.starts_with(&format!("POST {PREPARE_CLAIM_PATH} ")));
                    let prep_req: PrepareClaimRequest = serde_json::from_slice(&req_body).unwrap();
                    captured_recovery_keys = prep_req
                        .recovery_keys
                        .clone()
                        .expect("recoveryKeys must be populated from --generate-recovery-key");
                    assert_eq!(captured_recovery_keys.len(), 1);
                    let prep_resp =
                        build_prepared_claim_from_request(&fx, &prep_req, "slice2-tkt-1");
                    let resp = serde_json::to_vec(&prep_resp).unwrap();
                    write_json_response(&mut sock, 200, "OK", &resp);
                }
                1 => {
                    assert!(req_line.starts_with(&format!("POST {FINALIZE_CLAIM_PATH} ")));
                    let fin_req: FinalizeClaimRequest = serde_json::from_slice(&req_body).unwrap();
                    let payload_bytes = decode_strict_base64(&fin_req.payload).unwrap();
                    let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &payload_bytes);
                    let boot_sig = fx.bootstrap_key.sign(&pae);
                    let dep_ref = evidence_ref(&payload_bytes);
                    let dep_rec = SignedEndpointRecord {
                        record_ref: dep_ref.clone(),
                        envelope: DsseEnvelope {
                            payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
                            payload: fin_req.payload,
                            signatures: vec![
                                DsseSignature {
                                    keyid: fx.bootstrap_id.clone(),
                                    sig: BASE64_STANDARD.encode(boot_sig.to_bytes()),
                                },
                                fin_req.root_signature,
                            ],
                        },
                    };
                    let resp = serde_json::to_vec(&FinalizedClaimResponse {
                        deployment_record: dep_rec,
                        chain: dep_ref,
                        chain_started: fx.chain_started.clone(),
                        gateway_key: fx.gateway_entry.clone(),
                        stream_prefix: format!("urn:r5e:stream:{}:", fx.deployment),
                    })
                    .unwrap();
                    write_json_response(&mut sock, 201, "Created", &resp);
                }
                _ => unreachable!(),
            }
        }
        captured_recovery_keys
    });

    let claim_out = Command::new(bin)
        .args([
            "claim",
            "--gateway-url",
            &format!("http://{addr}"),
            "--claim-code-file",
            code_file.to_str().unwrap(),
            "--generate-root-seed-out",
            root_seed_out.to_str().unwrap(),
            "--generate-recovery-key",
            recovery_pem_out.to_str().unwrap(),
            "--holder",
            "person",
            "--custody",
            "hardware",
            "--identity",
            "mailto:lena@acme.example",
            "--trusted-publisher",
            &publisher_id,
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
        "claim with --generate-recovery-key failed: stdout={stdout_str}, stderr={stderr_str}"
    );
    assert!(
        !stderr_str.contains(IRREVERSIBLE_CLAIM_WARNING),
        "claim with --generate-recovery-key must NOT emit permanent-roots warning"
    );

    let captured_rks = server_handle.join().unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let rec_mode = std::fs::metadata(&recovery_pem_out)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            rec_mode, 0o600,
            "generated recovery PEM must have mode 0600"
        );
    }

    let rec_pem_text = std::fs::read_to_string(&recovery_pem_out).unwrap();
    assert!(rec_pem_text.starts_with("-----BEGIN PRIVATE KEY-----"));
    let rec_pem_body_line = rec_pem_text.lines().nth(1).unwrap().trim();
    assert!(!stdout_str.contains(rec_pem_body_line));
    assert!(!stderr_str.contains(rec_pem_body_line));
    assert!(!stdout_str.contains(secret_code));
    assert!(!stderr_str.contains(secret_code));

    let summary: Value = serde_json::from_str(stdout_str.trim()).unwrap();
    assert_eq!(summary["ok"], true);
    assert_eq!(summary["gatewayKey"]["keyid"], gateway_id);
    assert_eq!(summary["recoveryKeys"], json!(&captured_rks));
    assert_eq!(summary["generatedRecoveryKey"]["keyId"], captured_rks[0]);
    assert_eq!(
        summary["generatedRecoveryKey"]["path"],
        recovery_pem_out.to_string_lossy().as_ref()
    );

    let receipt_raw = std::fs::read_to_string(&receipt_out).unwrap();
    assert!(!receipt_raw.contains(rec_pem_body_line));
    let receipt: Value = serde_json::from_str(&receipt_raw).unwrap();
    assert_eq!(receipt["generatedRecoveryKey"]["keyId"], captured_rks[0]);
    assert_eq!(receipt["recoveryKeys"], json!(&captured_rks));

    // 3. Re-using an existing `--generate-recovery-key` target without `--force` refuses overwrite (`exit 2`).
    let overwrite_refused = Command::new(bin)
        .args([
            "claim",
            "--gateway-url",
            "http://127.0.0.1:9",
            "--claim-code-file",
            code_file.to_str().unwrap(),
            "--root-seed-file",
            root_seed_out.to_str().unwrap(),
            "--generate-recovery-key",
            recovery_pem_out.to_str().unwrap(),
            "--trusted-publisher",
            &publisher_id,
            "--skip-gateway-grant",
        ])
        .env_remove("R5E_ROOT_SEED_B64")
        .env_remove("R5E_CLAIM_CODE")
        .output()
        .unwrap();
    assert_eq!(overwrite_refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&overwrite_refused.stderr).contains("--force"));
    assert_eq!(
        std::fs::read_to_string(&recovery_pem_out).unwrap(),
        rec_pem_text,
        "existing recovery key file must remain untouched when --force is omitted"
    );

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn two_of_three_quorum_root_rotation_ceremony_with_gateway_grant_reendorsement() {
    let bin = env!("CARGO_BIN_EXE_r5e-endpoint-helper");
    let tmp_dir = make_temp_dir("quorum-rotation");

    let deployment = "acme-prod";
    let chain_ref =
        "evidence:sha256:1111111111111111111111111111111111111111111111111111111111111111";

    // Active 2-of-3 root set (r1, r2, r3) + named custodians (lena, marco, priya):
    let r1_seed = [0x41; 32];
    let r2_seed = [0x42; 32];
    let _r3_seed = [0x43; 32]; // lost root being rotated out!
    let r4_new_seed = [0x44; 32]; // replaces lost r3!
    let ck_lena_seed = [0x51; 32];
    let ck_marco_seed = [0x52; 32];
    let ck_priya_seed = [0x53; 32];
    let gw_sk = SigningKey::from_bytes(&[0x61; 32]);

    let r1_sk = SigningKey::from_bytes(&r1_seed);
    let r2_sk = SigningKey::from_bytes(&r2_seed);
    let r4_sk = SigningKey::from_bytes(&r4_new_seed);
    let ck_lena_sk = SigningKey::from_bytes(&ck_lena_seed);
    let ck_marco_sk = SigningKey::from_bytes(&ck_marco_seed);
    let ck_priya_sk = SigningKey::from_bytes(&ck_priya_seed);

    let (r1_id, _) = make_public_key_entry(&r1_sk);
    let (r2_id, _) = make_public_key_entry(&r2_sk);
    let (r4_id, _) = make_public_key_entry(&r4_sk);
    let (ck_lena_id, _) = make_public_key_entry(&ck_lena_sk);
    let (ck_marco_id, _) = make_public_key_entry(&ck_marco_sk);
    let (ck_priya_id, _) = make_public_key_entry(&ck_priya_sk);
    let (gw_id, gw_entry) = make_public_key_entry(&gw_sk);

    // Exercise all supported key file formats:
    // - r1: PKCS#8 private key PEM (`.pem`)
    // - r2: raw base64 seed (`.seed`) + SPKI public key PEM (`.pub.pem`)
    // - r4 (replacement root): PKCS#8 private key PEM (`.pem`)
    // - custodian personal keys: PKCS#8 PEM & `.seed`
    let r1_pem_path = tmp_dir.join("r1.pem");
    let r2_seed_path = tmp_dir.join("r2.seed");
    let r2_spki_path = tmp_dir.join("r2.pub.pem");
    let r4_pem_path = tmp_dir.join("r4-new.pem");
    let ck_lena_pem = tmp_dir.join("lena-personal.pem");
    let ck_marco_seed_path = tmp_dir.join("marco-personal.seed");
    let ck_priya_pem = tmp_dir.join("priya-personal.pem");
    let next_rec_pem = tmp_dir.join("next-recovery.pem");
    let proposal_path = tmp_dir.join("proposal.json");

    write_private_key_file_0600(&r1_pem_path, &r1_seed, true).unwrap();
    write_private_key_file_0600(&r2_seed_path, &r2_seed, true).unwrap();
    std::fs::write(
        &r2_spki_path,
        encode_spki_ed25519_pem(&r2_sk.verifying_key().to_bytes()),
    )
    .unwrap();
    write_private_key_file_0600(&r4_pem_path, &r4_new_seed, true).unwrap();
    write_private_key_file_0600(&ck_lena_pem, &ck_lena_seed, true).unwrap();
    write_private_key_file_0600(&ck_marco_seed_path, &ck_marco_seed, true).unwrap();
    write_private_key_file_0600(&ck_priya_pem, &ck_priya_seed, true).unwrap();

    // 1. Step 1 (`propose-root-change`): r1 authors `RootsChanged` at `seq = 3`, rotating `{r1, r2, r3}` -> `{r1, r2, r4}`:
    let prop_out = Command::new(bin)
        .args([
            "propose-root-change",
            "--deployment",
            deployment,
            "--chain",
            chain_ref,
            "--replaces",
            chain_ref,
            "--seq",
            "3",
            "--authorization",
            "quorum",
            "--signer-key",
            r1_pem_path.to_str().unwrap(),
            "--root-key",
            &format!(
                "{};holder=person;custody=hardware;identity=mailto:lena@acme.example",
                r1_pem_path.display()
            ),
            "--root-key",
            &format!(
                "{};holder=person;custody=hardware;identity=mailto:marco@acme.example",
                r2_spki_path.display()
            ),
            "--root-key",
            &format!(
                "{};holder=person;custody=kms;identity=mailto:ops@acme.example",
                r4_pem_path.display()
            ),
            "--threshold",
            "2",
            "--generate-recovery-key",
            next_rec_pem.to_str().unwrap(),
            "--custodian",
            &format!("mailto:lena@acme.example={ck_lena_id}"),
            "--custodian",
            &format!("mailto:marco@acme.example={ck_marco_id}"),
            "--custodian",
            &format!("mailto:priya@acme.example={ck_priya_id}"),
            "--reason",
            "Scheduled Q4 HSM slot replacement for r3",
            "--out",
            proposal_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    let prop_stdout = String::from_utf8_lossy(&prop_out.stdout);
    let prop_stderr = String::from_utf8_lossy(&prop_out.stderr);
    assert!(
        prop_out.status.success(),
        "propose-root-change failed: stdout={prop_stdout}, stderr={prop_stderr}"
    );
    let prop_summary: Value = serde_json::from_str(prop_stdout.trim()).unwrap();
    assert_eq!(prop_summary["ok"], true);
    assert_eq!(prop_summary["authorization"], "quorum");
    assert_eq!(prop_summary["signer"], r1_id);
    let generated_rec_id = prop_summary["generatedRecoveryKey"]["keyId"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(generated_rec_id.starts_with("key:ed25519:sha256:"));

    // 2. First approval (`approve-root-change`): `(r1, mailto:lena@acme.example, ck_lena)`
    let app1_out = Command::new(bin)
        .args([
            "approve-root-change",
            "--proposal",
            proposal_path.to_str().unwrap(),
            "--root-key",
            r1_pem_path.to_str().unwrap(),
            "--custodian",
            "mailto:lena@acme.example",
            "--custodian-key",
            ck_lena_pem.to_str().unwrap(),
            "--reason",
            "Verified replacement root r4 fingerprint out of band",
        ])
        .output()
        .unwrap();
    assert!(
        app1_out.status.success(),
        "approve-root-change #1 failed: stderr={}",
        String::from_utf8_lossy(&app1_out.stderr)
    );
    let app1_summary: Value =
        serde_json::from_str(String::from_utf8_lossy(&app1_out.stdout).trim()).unwrap();
    assert_eq!(app1_summary["approvalCount"], 1);

    // 3. Veto-free quorum disqualification guards (`A6-slice2-roots-changed.md` §3.4):
    //    (a) Pairing `r1` with a second custodian (`priya`) would disqualify `r1`'s vote — MUST refuse locally (`exit 2`).
    let conflict_root = Command::new(bin)
        .args([
            "approve-root-change",
            "--proposal",
            proposal_path.to_str().unwrap(),
            "--root-key",
            r1_pem_path.to_str().unwrap(),
            "--custodian",
            "mailto:priya@acme.example",
            "--custodian-key",
            ck_priya_pem.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(conflict_root.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&conflict_root.stderr).contains("conflicting approval under root")
    );

    //    (b) Pairing `mailto:lena@acme.example` with a second root (`r2`) would disqualify both — MUST refuse locally (`exit 2`).
    let conflict_cust = Command::new(bin)
        .args([
            "approve-root-change",
            "--proposal",
            proposal_path.to_str().unwrap(),
            "--root-key",
            r2_seed_path.to_str().unwrap(),
            "--custodian",
            "mailto:lena@acme.example",
            "--custodian-key",
            ck_marco_seed_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(conflict_cust.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&conflict_cust.stderr)
        .contains("conflicting approval for custodian"));

    // 4. Second distinct approval (`approve-root-change`): `(r2, mailto:marco@acme.example, ck_marco)`
    let app2_out = Command::new(bin)
        .args([
            "approve-root-change",
            "--proposal",
            proposal_path.to_str().unwrap(),
            "--root-key",
            r2_seed_path.to_str().unwrap(),
            "--custodian",
            "mailto:marco@acme.example",
            "--custodian-key",
            ck_marco_seed_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        app2_out.status.success(),
        "approve-root-change #2 failed: stderr={}",
        String::from_utf8_lossy(&app2_out.stderr)
    );
    let app2_summary: Value =
        serde_json::from_str(String::from_utf8_lossy(&app2_out.stdout).trim()).unwrap();
    assert_eq!(app2_summary["approvalCount"], 2);

    // Inspect assembled `proposal.json` offline before submitting:
    let proposal_raw = std::fs::read_to_string(&proposal_path).unwrap();
    // Zero private key material in proposal.json:
    let r1_pem_line = encode_pkcs8_ed25519_pem(&r1_seed)
        .lines()
        .nth(1)
        .unwrap()
        .to_string();
    assert!(!proposal_raw.contains(&r1_pem_line));
    assert!(!proposal_raw.contains(&BASE64_STANDARD.encode(r2_seed)));
    assert!(!proposal_raw.contains(&BASE64_STANDARD.encode(r4_new_seed)));

    let proposal_obj: RootChangeProposalFile = serde_json::from_str(&proposal_raw).unwrap();
    verify_proposal_locally(&proposal_obj).expect("assembled 2-of-3 proposal must verify locally");
    assert_eq!(proposal_obj.approvals.len(), 2);
    // Base definitions live in index.json (`89a1b62`), so `blobs` contains ONLY the 3 stream-scoped capture profile blobs (:start + 2 distinct authority:approval:<id> streams):
    assert_eq!(
        proposal_obj.blobs.len(),
        3,
        "blobs should contain the 3 stream-scoped capture profiles (change on :start + 2 distinct approval streams)"
    );
    // Keys deduplicated: r1, ck_lena, r2, ck_marco = 4 public keys:
    assert_eq!(proposal_obj.keys.len(), 4);

    let rc_bytes = decode_strict_base64(&proposal_obj.change.envelope.payload).unwrap();
    let rc_val: Value = serde_json::from_slice(&rc_bytes).unwrap();
    assert_eq!(rc_val["kind"], "RootsChanged");
    assert_eq!(rc_val["schemaRef"], ROOTS_CHANGED_SCHEMA_REF);
    assert_eq!(
        rc_val["stream"],
        format!("urn:r5e:stream:{deployment}:start")
    );
    assert_eq!(rc_val["seq"], 3);
    assert_eq!(rc_val["previous"], chain_ref);
    assert_eq!(rc_val["body"]["roots"].as_array().unwrap().len(), 3);
    assert_eq!(rc_val["body"]["roots"][0]["key"], r1_id);
    assert_eq!(rc_val["body"]["roots"][1]["key"], r2_id);
    assert_eq!(rc_val["body"]["roots"][2]["key"], r4_id);
    assert_eq!(rc_val["body"]["recoveryKeys"], json!([&generated_rec_id]));

    let mut approval_streams = BTreeSet::new();
    for (idx, app) in proposal_obj.approvals.iter().enumerate() {
        assert_eq!(app.envelope.signatures.len(), 2);
        let ap_bytes = decode_strict_base64(&app.envelope.payload).unwrap();
        let ap_val: Value = serde_json::from_slice(&ap_bytes).unwrap();
        assert_eq!(ap_val["kind"], "RootChangeApproval");
        assert_eq!(ap_val["schemaRef"], ROOT_CHANGE_APPROVAL_SCHEMA_REF);
        assert_eq!(ap_val["seq"], 1);
        assert!(ap_val["previous"].is_null());
        assert_eq!(ap_val["body"]["change"], proposal_obj.change.record_ref);
        // Optional `reason` present on #0, omitted (`nonEmpty`) on #1:
        if idx == 0 {
            assert!(ap_val["body"]["reason"].is_string());
        } else {
            assert!(ap_val["body"].get("reason").is_none());
        }
        let s = ap_val["stream"].as_str().unwrap().to_string();
        assert!(s.starts_with(&format!("urn:r5e:stream:{deployment}:authority:approval:")));
        assert!(
            approval_streams.insert(s),
            "each approval must use a fresh stream"
        );
    }

    // 5. Step 3 (`apply-root-change --grant-gateway-with <r4-new.pem>`):
    //    Verifies `POST /v1/deployment/roots`, `GET /v1/deployment` (to resolve `gatewayKey`),
    //    and `POST /v1/deployment/grants` (re-endorsing `gatewayKey` under replacement root `r4`
    //    for `EpochSeal` + working kinds per §4.4).
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let expected_change_ref = proposal_obj.change.record_ref.clone();
    let gw_id_srv = gw_id.clone();
    let gw_entry_srv = gw_entry.clone();
    let r4_id_srv = r4_id.clone();

    let server_handle = std::thread::spawn(move || {
        for step in 0..3 {
            let (mut sock, _) = listener.accept().unwrap();
            let (req_line, req_body) = read_http_request(&mut sock);
            match step {
                0 => {
                    assert!(req_line.starts_with(&format!("POST {DEPLOYMENT_ROOTS_PATH} ")));
                    let roots_req: SubmitRootChangeRequest =
                        serde_json::from_slice(&req_body).unwrap();
                    assert_eq!(roots_req.change.record_ref, expected_change_ref);
                    assert_eq!(roots_req.approvals.len(), 2);
                    assert_eq!(roots_req.keys.len(), 4);
                    assert_eq!(roots_req.blobs.len(), 3);

                    // Cryptographically verify every DSSE signature in the submitted payload:
                    let key_map: std::collections::BTreeMap<String, VerifyingKey> = roots_req
                        .keys
                        .iter()
                        .map(|k| {
                            let raw = decode_strict_base64(&k.bytes).unwrap();
                            let vk = VerifyingKey::from_bytes(&raw.try_into().unwrap()).unwrap();
                            (k.keyid.clone(), vk)
                        })
                        .collect();
                    for rec in std::iter::once(&roots_req.change).chain(roots_req.approvals.iter())
                    {
                        let pbytes = decode_strict_base64(&rec.envelope.payload).unwrap();
                        assert_eq!(rec.record_ref, evidence_ref(&pbytes));
                        let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &pbytes);
                        for sig in &rec.envelope.signatures {
                            let vk = key_map.get(&sig.keyid).expect("signer key carried in keys");
                            let sig_bytes: [u8; 64] =
                                decode_strict_base64(&sig.sig).unwrap().try_into().unwrap();
                            vk.verify(&pae, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
                                .expect("valid Ed25519 DSSE signature");
                        }
                    }

                    let recorded: Vec<&str> = std::iter::once(roots_req.change.record_ref.as_str())
                        .chain(roots_req.approvals.iter().map(|a| a.record_ref.as_str()))
                        .collect();
                    let resp = serde_json::to_vec(&json!({ "recorded": recorded })).unwrap();
                    write_json_response(&mut sock, 201, "Created", &resp);
                }
                1 => {
                    assert!(req_line.starts_with(&format!("GET {DEPLOYMENT_STATUS_PATH} ")));
                    let resp = serde_json::to_vec(&DeploymentStatusResponse {
                        deployment: Some(deployment.to_string()),
                        state: DeploymentClaimState::Claimed,
                        chain_started: None,
                        bootstrap_key: None,
                        chain: Some(chain_ref.to_string()),
                        deployment_record: None,
                        gateway_key: Some(gw_entry_srv.clone()),
                        stream_prefix: Some(format!("urn:r5e:stream:{deployment}:")),
                        grants: Vec::new(),
                    })
                    .unwrap();
                    write_json_response(&mut sock, 200, "OK", &resp);
                }
                2 => {
                    assert!(req_line.starts_with(&format!("POST {DEPLOYMENT_GRANTS_PATH} ")));
                    let grants_req: SubmitGrantsRequest =
                        serde_json::from_slice(&req_body).unwrap();
                    assert_eq!(grants_req.records.len(), 1);
                    assert_eq!(grants_req.keys[0].keyid, r4_id_srv);
                    let end_bytes =
                        decode_strict_base64(&grants_req.records[0].envelope.payload).unwrap();
                    let end_val: Value = serde_json::from_slice(&end_bytes).unwrap();
                    assert_eq!(end_val["kind"], "Endorsement");
                    assert_eq!(end_val["issuer"], r4_id_srv);
                    assert_eq!(end_val["body"]["subject"], gw_id_srv);
                    let kinds: Vec<String> =
                        serde_json::from_value(end_val["body"]["kinds"].clone()).unwrap();
                    assert!(
                        kinds.contains(&"provenance.r5e.io/v2/EpochSeal".to_string()),
                        "gateway re-endorsement must cover EpochSeal per §4.4"
                    );
                    assert_eq!(kinds, default_gateway_grant_kinds());

                    let resp = serde_json::to_vec(&json!({
                        "recorded": [&grants_req.records[0].record_ref]
                    }))
                    .unwrap();
                    write_json_response(&mut sock, 201, "Created", &resp);
                }
                _ => unreachable!(),
            }
        }
    });

    let apply_out = Command::new(bin)
        .args([
            "apply-root-change",
            "--gateway-url",
            &format!("http://{addr}"),
            "--proposal",
            proposal_path.to_str().unwrap(),
            "--grant-gateway-with",
            r4_pem_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    let apply_stdout = String::from_utf8_lossy(&apply_out.stdout);
    let apply_stderr = String::from_utf8_lossy(&apply_out.stderr);
    assert!(
        apply_out.status.success(),
        "apply-root-change failed: stdout={apply_stdout}, stderr={apply_stderr}"
    );
    server_handle.join().unwrap();

    let apply_summary: Value = serde_json::from_str(apply_stdout.trim()).unwrap();
    assert_eq!(apply_summary["ok"], true);
    assert_eq!(apply_summary["rootsStatus"], 201);
    assert_eq!(apply_summary["approvalCount"], 2);
    assert_eq!(apply_summary["gatewayGrantSubmitted"], true);
    assert_eq!(apply_summary["grantRootKeyId"], r4_id);
    assert!(apply_summary["endorsementRef"]
        .as_str()
        .unwrap()
        .starts_with("evidence:sha256:"));

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn recovery_mode_root_rotation_and_local_validation_guards() {
    let bin = env!("CARGO_BIN_EXE_r5e-endpoint-helper");
    let tmp_dir = make_temp_dir("recovery-rotation");

    let deployment = "acme-dr";
    let chain_ref =
        "evidence:sha256:2222222222222222222222222222222222222222222222222222222222222222";
    let prior_rc_ref =
        "evidence:sha256:3333333333333333333333333333333333333333333333333333333333333333";

    let rec0_seed = [0x71; 32];
    let new_root_seed = [0x72; 32];
    let gw_sk = SigningKey::from_bytes(&[0x73; 32]);

    let rec0_sk = SigningKey::from_bytes(&rec0_seed);
    let new_root_sk = SigningKey::from_bytes(&new_root_seed);
    let (rec0_id, _) = make_public_key_entry(&rec0_sk);
    let (new_root_id, _) = make_public_key_entry(&new_root_sk);
    let (gw_id, _) = make_public_key_entry(&gw_sk);

    let rec0_pem = tmp_dir.join("recovery-0.pem");
    let new_root_seed_file = tmp_dir.join("new-root.seed");
    let aborted_rec_out = tmp_dir.join("should-not-exist.pem");
    let rec1_pem = tmp_dir.join("recovery-1.pem");
    let proposal_path = tmp_dir.join("recovery-proposal.json");

    write_private_key_file_0600(&rec0_pem, &rec0_seed, true).unwrap();
    write_private_key_file_0600(&new_root_seed_file, &new_root_seed, true).unwrap();

    // 1. Guard: retaining the spent recovery key (`rec0_id`) in `recoveryKeys` MUST fail locally (`exit 2`,
    //    `spent_recovery_key_retained`) and MUST NOT write `--generate-recovery-key` to disk!
    let spent_retained = Command::new(bin)
        .args([
            "propose-root-change",
            "--deployment",
            deployment,
            "--chain",
            chain_ref,
            "--replaces",
            prior_rc_ref,
            "--seq",
            "4",
            "--authorization",
            "recovery",
            "--signer-key",
            rec0_pem.to_str().unwrap(),
            "--root-key",
            &format!(
                "{};holder=person;custody=hardware",
                new_root_seed_file.display()
            ),
            "--threshold",
            "1",
            "--recovery-key",
            &rec0_id,
            "--generate-recovery-key",
            aborted_rec_out.to_str().unwrap(),
            "--out",
            proposal_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(spent_retained.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&spent_retained.stderr).contains("spent_recovery_key_retained"));
    assert!(
        !aborted_rec_out.exists(),
        "failed proposal must not create --generate-recovery-key file on disk"
    );

    // 2. Guard: `holder=agent` on a root MUST fail locally (`agent_cannot_be_root`):
    let agent_root = Command::new(bin)
        .args([
            "propose-root-change",
            "--deployment",
            deployment,
            "--chain",
            chain_ref,
            "--replaces",
            prior_rc_ref,
            "--seq",
            "4",
            "--authorization",
            "recovery",
            "--signer-key",
            rec0_pem.to_str().unwrap(),
            "--root-key",
            &format!("{};holder=agent;custody=kms", new_root_seed_file.display()),
            "--threshold",
            "1",
            "--out",
            proposal_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(agent_root.status.code(), Some(2));
    let agent_stderr = String::from_utf8_lossy(&agent_root.stderr);
    assert!(agent_stderr.contains("invalid_deployment_terms"));
    assert!(agent_stderr.contains("holder cannot be \"agent\""));

    // 3. Guard: `custodian` personal key overlapping `roots` MUST fail locally (`invalid_deployment_terms`):
    let overlap_cust = Command::new(bin)
        .args([
            "propose-root-change",
            "--deployment",
            deployment,
            "--chain",
            chain_ref,
            "--replaces",
            prior_rc_ref,
            "--seq",
            "4",
            "--authorization",
            "recovery",
            "--signer-key",
            rec0_pem.to_str().unwrap(),
            "--root-key",
            &format!(
                "{};holder=person;custody=hardware",
                new_root_seed_file.display()
            ),
            "--threshold",
            "1",
            "--custodian",
            &format!("mailto:lena@dr.example={new_root_id}"),
            "--out",
            proposal_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(overlap_cust.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&overlap_cust.stderr).contains("invalid_deployment_terms"));

    // 4. Valid `propose-root-change --authorization recovery --generate-recovery-key <rec1.pem>`:
    let valid_rec = Command::new(bin)
        .args([
            "propose-root-change",
            "--deployment",
            deployment,
            "--chain",
            chain_ref,
            "--replaces",
            prior_rc_ref,
            "--seq",
            "4",
            "--authorization",
            "recovery",
            "--signer-key",
            rec0_pem.to_str().unwrap(),
            "--root-key",
            &format!(
                "{};holder=organization;custody=kms;identity=https://dr.acme.example",
                new_root_seed_file.display()
            ),
            "--threshold",
            "1",
            "--generate-recovery-key",
            rec1_pem.to_str().unwrap(),
            "--reason",
            "Cold recovery exercise rotating spent rec0 -> rec1",
            "--out",
            proposal_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        valid_rec.status.success(),
        "valid recovery proposal failed: stderr={}",
        String::from_utf8_lossy(&valid_rec.stderr)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&rec1_pem).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    // 5. Guard: calling `approve-root-change` on a `recovery` proposal MUST fail locally (`approval_not_for_quorum_change`):
    let wrong_mode_approve = Command::new(bin)
        .args([
            "approve-root-change",
            "--proposal",
            proposal_path.to_str().unwrap(),
            "--root-key",
            new_root_seed_file.to_str().unwrap(),
            "--custodian",
            "mailto:lena@dr.example",
            "--custodian-key",
            rec1_pem.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(wrong_mode_approve.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&wrong_mode_approve.stderr)
        .contains("approval_not_for_quorum_change"));

    // 6. Apply recovery proposal with explicit `--gateway-key-id` (skips extra GET /v1/deployment)
    //    and verify gateway error classification (`409 stream_fork_refused` & `422 recovery_key_not_declared`) first:
    let err_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let err_addr = err_listener.local_addr().unwrap();
    let err_srv = std::thread::spawn(move || {
        let (mut s1, _) = err_listener.accept().unwrap();
        let _ = read_http_request(&mut s1);
        write_json_response(
            &mut s1,
            409,
            "Conflict",
            br#"{"error":"stream_fork_refused"}"#,
        );

        let (mut s2, _) = err_listener.accept().unwrap();
        let _ = read_http_request(&mut s2);
        write_json_response(
            &mut s2,
            422,
            "Unprocessable Entity",
            br#"{"error":"recovery_key_not_declared"}"#,
        );
    });

    let prop_obj: RootChangeProposalFile =
        serde_json::from_str(&std::fs::read_to_string(&proposal_path).unwrap()).unwrap();
    let submit_req = SubmitRootChangeRequest {
        change: prop_obj.change.clone(),
        approvals: prop_obj.approvals.clone(),
        keys: prop_obj.keys.clone(),
        blobs: prop_obj.blobs.clone(),
    };
    let err_cfg = ClaimClientConfig::new(format!("http://{err_addr}"));
    let e409 = submit_deployment_roots(&err_cfg, &submit_req).unwrap_err();
    assert!(matches!(e409, ClaimError::Conflict { .. }));
    assert_eq!(e409.error_code(), Some("stream_fork_refused"));

    let e422 = submit_deployment_roots(&err_cfg, &submit_req).unwrap_err();
    assert!(matches!(e422, ClaimError::Unprocessable { .. }));
    assert_eq!(e422.error_code(), Some("recovery_key_not_declared"));
    err_srv.join().unwrap();

    // Now apply against healthy gateway:
    let ok_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let ok_addr = ok_listener.local_addr().unwrap();
    let gw_id_srv = gw_id.clone();
    let ok_srv = std::thread::spawn(move || {
        let (mut s1, _) = ok_listener.accept().unwrap();
        let (line1, body1) = read_http_request(&mut s1);
        assert!(line1.starts_with(&format!("POST {DEPLOYMENT_ROOTS_PATH} ")));
        let req1: SubmitRootChangeRequest = serde_json::from_slice(&body1).unwrap();
        assert!(req1.approvals.is_empty());
        assert_eq!(req1.keys.len(), 1);
        assert_eq!(req1.blobs.len(), 1);
        let resp1 = serde_json::to_vec(&json!({ "recorded": [&req1.change.record_ref] })).unwrap();
        write_json_response(&mut s1, 201, "Created", &resp1);

        let (mut s2, _) = ok_listener.accept().unwrap();
        let (line2, body2) = read_http_request(&mut s2);
        assert!(line2.starts_with(&format!("POST {DEPLOYMENT_GRANTS_PATH} ")));
        let req2: SubmitGrantsRequest = serde_json::from_slice(&body2).unwrap();
        let end_bytes = decode_strict_base64(&req2.records[0].envelope.payload).unwrap();
        let end_val: Value = serde_json::from_slice(&end_bytes).unwrap();
        assert_eq!(end_val["body"]["subject"], gw_id_srv);
        assert_eq!(end_val["body"]["notBefore"], "2026-11-12T06:00:00Z");
        let resp2 =
            serde_json::to_vec(&json!({ "recorded": [&req2.records[0].record_ref] })).unwrap();
        write_json_response(&mut s2, 201, "Created", &resp2);
    });

    let apply_rec_out = Command::new(bin)
        .args([
            "apply-root-change",
            "--gateway-url",
            &format!("http://{ok_addr}"),
            "--proposal",
            proposal_path.to_str().unwrap(),
            "--grant-gateway-with",
            new_root_seed_file.to_str().unwrap(),
            "--gateway-key-id",
            &gw_id,
            "--grant-not-before",
            "2026-11-12T06:00:00Z",
        ])
        .output()
        .unwrap();
    assert!(
        apply_rec_out.status.success(),
        "apply-root-change (recovery) failed: stderr={}",
        String::from_utf8_lossy(&apply_rec_out.stderr)
    );
    ok_srv.join().unwrap();

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn apply_root_change_backdates_endorsement_not_before_to_cover_two_hour_old_deployment_start() {
    use chrono::{DateTime, Duration, SecondsFormat, Utc};

    let deployment = "acme-seal-continuity";
    let rec_sk = SigningKey::from_bytes(&[0x81; 32]);
    let new_root_sk = SigningKey::from_bytes(&[0x82; 32]);
    let boot_sk = SigningKey::from_bytes(&[0x83; 32]);
    let gw_sk = SigningKey::from_bytes(&[0x84; 32]);

    let (boot_id, _) = make_public_key_entry(&boot_sk);
    let (gw_id, gw_entry) = make_public_key_entry(&gw_sk);
    let new_root_pub_b64 = BASE64_STANDARD.encode(new_root_sk.verifying_key().to_bytes());

    // Simulate a `Deployment` record captured 2 hours ago (plus a pre-rotation `EpochSeal` 90m ago):
    let now = Utc::now();
    let dep_captured_dt = now - Duration::hours(2);
    let dep_captured_str = dep_captured_dt.to_rfc3339_opts(SecondsFormat::Micros, true);
    let expected_not_before = (chrono::DateTime::parse_from_rfc3339(&dep_captured_str)
        .unwrap()
        .with_timezone(&Utc)
        - Duration::seconds(60))
    .to_rfc3339_opts(SecondsFormat::Micros, true);
    let pre_rotation_seal_dt = now - Duration::minutes(90);

    let schemas = base_v2_schema_map();
    let dep_record = sign_v2_record_multi(
        &[&boot_sk],
        json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Deployment",
            "schemaRef": &schemas["provenance.r5e.io/v2/Deployment"],
            "profileRef": "bytes:sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "stream": format!("urn:r5e:stream:{deployment}:start"),
            "seq": 2,
            "previous": "evidence:sha256:4444444444444444444444444444444444444444444444444444444444444444",
            "actor": format!("urn:r5e:node:{deployment}"),
            "capturedAt": &dep_captured_str,
            "body": {
                "accepts": "evidence:sha256:4444444444444444444444444444444444444444444444444444444444444444",
                "bootstrap": &boot_id,
                "claimedBy": &boot_id,
                "roots": [],
                "threshold": 1,
            }
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .unwrap();
    let chain_ref = dep_record.record_ref.clone();

    let mut params = ProposeRootChangeParams::new(
        deployment,
        chain_ref.clone(),
        chain_ref.clone(),
        3,
        RootChangeAuthorization::Recovery,
        vec![PrepareClaimRootEntry {
            public_key: SubjectPublicKey {
                algorithm: "ed25519".to_string(),
                bytes: new_root_pub_b64,
            },
            holder: Some("person".to_string()),
            custody: Some("hardware".to_string()),
            identity: Some("mailto:ops@acme.example".to_string()),
        }],
        1,
    );
    // Simulate 250ms forward clock skew on `RootsChanged.capturedAt` to verify `apply_root_change`
    // clamps `Endorsement.capturedAt >= RootsChanged.capturedAt`:
    let skewed_change_dt = Utc::now() + Duration::milliseconds(250);
    params.captured_at = Some(skewed_change_dt);
    let proposal = propose_root_change(&rec_sk, &params).unwrap();

    // 1. Validate `GatewayGrantParams.not_before_override` bounds directly:
    let mut bad_grant = GatewayGrantParams::new(&gw_id, format!("urn:r5e:stream:{deployment}:"));
    bad_grant.not_before_override = Some("not-a-timestamp".to_string());
    assert!(build_root_gateway_grant(&new_root_sk, &bad_grant).is_err());

    bad_grant.not_before_override = Some("2026-11-12T08:00:00-00:00".to_string());
    assert!(build_root_gateway_grant(&new_root_sk, &bad_grant).is_err());

    bad_grant.captured_at = Some(now);
    bad_grant.ttl_seconds = 60;
    bad_grant.not_before_override =
        Some((now + Duration::hours(1)).to_rfc3339_opts(SecondsFormat::Micros, true));
    assert!(
        build_root_gateway_grant(&new_root_sk, &bad_grant).is_err(),
        "notBefore > notAfter must be rejected"
    );

    // 2. `apply_root_change` without explicit `grant_not_before` fetches `GET /v1/deployment`,
    //    reads `deploymentRecord` captured 2h ago, and sets `Endorsement.body.notBefore = dep.capturedAt - 60s`:
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let chain_ref_srv = chain_ref.clone();
    let dep_rec_srv = dep_record.clone();
    let gw_entry_srv = gw_entry.clone();
    let expected_nb_srv = expected_not_before.clone();

    let srv = std::thread::spawn(move || {
        for step in 0..3 {
            let (mut sock, _) = listener.accept().unwrap();
            let (line, body) = read_http_request(&mut sock);
            match step {
                0 => {
                    assert!(line.starts_with(&format!("POST {DEPLOYMENT_ROOTS_PATH} ")));
                    let r: SubmitRootChangeRequest = serde_json::from_slice(&body).unwrap();
                    let resp =
                        serde_json::to_vec(&json!({ "recorded": [&r.change.record_ref] })).unwrap();
                    write_json_response(&mut sock, 201, "Created", &resp);
                }
                1 => {
                    assert!(line.starts_with(&format!("GET {DEPLOYMENT_STATUS_PATH} ")));
                    let resp = serde_json::to_vec(&DeploymentStatusResponse {
                        deployment: Some(deployment.to_string()),
                        state: DeploymentClaimState::Claimed,
                        chain_started: None,
                        bootstrap_key: None,
                        chain: Some(chain_ref_srv.clone()),
                        deployment_record: Some(dep_rec_srv.clone()),
                        gateway_key: Some(gw_entry_srv.clone()),
                        stream_prefix: Some(format!("urn:r5e:stream:{deployment}:")),
                        grants: Vec::new(),
                    })
                    .unwrap();
                    write_json_response(&mut sock, 200, "OK", &resp);
                }
                2 => {
                    assert!(line.starts_with(&format!("POST {DEPLOYMENT_GRANTS_PATH} ")));
                    let gr: SubmitGrantsRequest = serde_json::from_slice(&body).unwrap();
                    let pbytes = decode_strict_base64(&gr.records[0].envelope.payload).unwrap();
                    let pval: Value = serde_json::from_slice(&pbytes).unwrap();
                    assert_eq!(pval["body"]["notBefore"], expected_nb_srv);
                    let resp = serde_json::to_vec(&json!({
                        "recorded": [&gr.records[0].record_ref]
                    }))
                    .unwrap();
                    write_json_response(&mut sock, 201, "Created", &resp);
                }
                _ => unreachable!(),
            }
        }
    });

    let cfg = ClaimClientConfig::new(format!("http://{addr}"));
    let outcome = apply_root_change(
        &cfg,
        &proposal,
        Some(&new_root_sk),
        None,
        None,
        86_400 * 30,
        1,
        None,
        "urn:r5e:operator:root",
        None,
    )
    .expect("apply_root_change must succeed and backdate notBefore");
    srv.join().unwrap();

    let (built_grant, _) = outcome.gateway_grant.expect("gateway grant submitted");
    let end_payload = decode_strict_base64(&built_grant.endorsement.envelope.payload).unwrap();
    let end_val: Value = serde_json::from_slice(&end_payload).unwrap();
    let end_captured_str = end_val["capturedAt"].as_str().unwrap();
    let rc_payload = decode_strict_base64(&proposal.change.envelope.payload).unwrap();
    let rc_val: Value = serde_json::from_slice(&rc_payload).unwrap();
    let rc_captured_str = rc_val["capturedAt"].as_str().unwrap();
    assert!(
        DateTime::parse_from_rfc3339(end_captured_str).unwrap()
            >= DateTime::parse_from_rfc3339(rc_captured_str).unwrap(),
        "Endorsement.capturedAt ({end_captured_str}) must be >= RootsChanged.capturedAt ({rc_captured_str})"
    );
    let nb_str = end_val["body"]["notBefore"].as_str().unwrap();
    let na_str = end_val["body"]["notAfter"].as_str().unwrap();
    assert_eq!(nb_str, expected_not_before);

    let nb_dt = DateTime::parse_from_rfc3339(nb_str)
        .unwrap()
        .with_timezone(&Utc);
    let na_dt = DateTime::parse_from_rfc3339(na_str)
        .unwrap()
        .with_timezone(&Utc);
    let dep_parsed_dt = DateTime::parse_from_rfc3339(&dep_captured_str)
        .unwrap()
        .with_timezone(&Utc);
    assert!(
        nb_dt <= dep_parsed_dt,
        "Endorsement.body.notBefore ({nb_dt}) must cover 2-hour-old deployment start ({dep_parsed_dt})"
    );
    assert!(
        nb_dt <= pre_rotation_seal_dt && pre_rotation_seal_dt <= na_dt,
        "Endorsement window [{nb_dt}, {na_dt}] must cover pre-rotation EpochSeal at {pre_rotation_seal_dt}"
    );

    // 3. Graceful fallback: when `gateway_key_id_override` is passed and mock host returns 404 on
    //    `GET /v1/deployment`, `apply_root_change` ignores the status-fetch failure and falls back to `now - 60s`:
    let fb_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let fb_addr = fb_listener.local_addr().unwrap();
    let fb_srv = std::thread::spawn(move || {
        for step in 0..3 {
            let (mut sock, _) = fb_listener.accept().unwrap();
            let (line, body) = read_http_request(&mut sock);
            match step {
                0 => {
                    assert!(line.starts_with(&format!("POST {DEPLOYMENT_ROOTS_PATH} ")));
                    let r: SubmitRootChangeRequest = serde_json::from_slice(&body).unwrap();
                    let resp =
                        serde_json::to_vec(&json!({ "recorded": [&r.change.record_ref] })).unwrap();
                    write_json_response(&mut sock, 201, "Created", &resp);
                }
                1 => {
                    assert!(line.starts_with(&format!("GET {DEPLOYMENT_STATUS_PATH} ")));
                    write_json_response(&mut sock, 404, "Not Found", br#"{"error":"not_mounted"}"#);
                }
                2 => {
                    assert!(line.starts_with(&format!("POST {DEPLOYMENT_GRANTS_PATH} ")));
                    let gr: SubmitGrantsRequest = serde_json::from_slice(&body).unwrap();
                    let resp = serde_json::to_vec(&json!({
                        "recorded": [&gr.records[0].record_ref]
                    }))
                    .unwrap();
                    write_json_response(&mut sock, 201, "Created", &resp);
                }
                _ => unreachable!(),
            }
        }
    });

    let fb_cfg = ClaimClientConfig::new(format!("http://{fb_addr}"));
    let fb_outcome = apply_root_change(
        &fb_cfg,
        &proposal,
        Some(&new_root_sk),
        Some(gw_id),
        None,
        86_400 * 30,
        1,
        None,
        "urn:r5e:operator:root",
        None,
    )
    .expect("apply_root_change must fall back gracefully when GET /v1/deployment fails under explicit gateway_key_id_override");
    fb_srv.join().unwrap();
    assert!(fb_outcome.gateway_grant.is_some());
}
