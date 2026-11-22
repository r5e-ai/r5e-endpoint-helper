use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use r5e_endpoint_helper::attestation::{
    base_v2_schema_map, bytes_ref, decode_strict_base64, dsse_pae, ed25519_key_id,
    encode_canonical_json, evidence_ref, sign_v2_record_multi, write_private_key_file_0600,
    DsseEnvelope, DsseSignature, PublicKeyEntry, SignedEndpointRecord, PROVENANCE_V2_PAYLOAD_TYPE,
    RETENTION_HOLD_RELEASE_SCHEMA_REF, RETENTION_HOLD_SCHEMA_REF,
};
use r5e_endpoint_helper::claim_http::{
    build_root_gateway_grant, ceil_to_micros, GatewayGrantParams, SubmitGrantsRequest,
};
use r5e_endpoint_helper::hold_release::{
    execute_release_hold_ceremony, HoldReleaseClientConfig, HoldReleaseError,
    FINALIZE_HOLD_RELEASE_PATH, PREPARE_HOLD_RELEASE_PATH,
};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
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
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::thread;

fn read_http_request(stream: &mut TcpStream) -> (String, String, Vec<(String, String)>, Vec<u8>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut req_line = String::new();
    reader.read_line(&mut req_line).unwrap();
    let parts: Vec<&str> = req_line.split_whitespace().collect();
    let method = parts.first().copied().unwrap_or("").to_string();
    let path = parts.get(1).copied().unwrap_or("").to_string();

    let mut headers = Vec::new();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            let key_lc = k.trim().to_ascii_lowercase();
            let val_tr = v.trim().to_string();
            if key_lc == "content-length" {
                content_length = val_tr.parse::<usize>().unwrap_or(0);
            }
            headers.push((key_lc, val_tr));
        }
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).unwrap();
    }
    (method, path, headers, body)
}

fn write_http_json_response(stream: &mut TcpStream, status: u16, reason: &str, body_val: &Value) {
    let body_bytes = serde_json::to_vec(body_val).unwrap();
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body_bytes.len()
    );
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(&body_bytes).unwrap();
    stream.flush().unwrap();
}

#[test]
fn grant_releaser_builds_collision_free_substream_and_clamps_to_deployment_start_head() {
    let bin = env!("CARGO_BIN_EXE_r5e-endpoint-helper");
    let root_seed = [0x31u8; 32];
    let releaser_seed = [0x32u8; 32];
    let bootstrap_seed = [0x33u8; 32];

    let root_sk = SigningKey::from_bytes(&root_seed);
    let releaser_sk = SigningKey::from_bytes(&releaser_seed);
    let bootstrap_sk = SigningKey::from_bytes(&bootstrap_seed);

    let root_key_id = ed25519_key_id(&root_sk.verifying_key().to_bytes());
    let root_hex = root_key_id.strip_prefix("key:ed25519:sha256:").unwrap();
    let releaser_key_id = ed25519_key_id(&releaser_sk.verifying_key().to_bytes());
    let releaser_pub_b64 = BASE64_STANDARD.encode(releaser_sk.verifying_key().to_bytes());

    // Simulate a `startHead` / `deploymentRecord` stamped +750ms ahead with sub-microsecond
    // precision (`.xxx999123Z`) so `ceil_to_micros` must round up without truncating below floor.
    let future_floor_raw = chrono::Utc::now()
        + chrono::Duration::milliseconds(750)
        + chrono::Duration::nanoseconds(123);
    let expected_clamped_floor = ceil_to_micros(future_floor_raw);
    let floor_rfc3339 = future_floor_raw.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);

    let dummy_dep_record = sign_v2_record_multi(
        &[&bootstrap_sk, &root_sk],
        json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Deployment",
            "schemaRef": base_v2_schema_map()["provenance.r5e.io/v2/Deployment"],
            "profileRef": bytes_ref(b"{}"),
            "stream": "urn:r5e:stream:meridian-prod:start",
            "seq": 2,
            "previous": format!("evidence:sha256:{}", "11".repeat(32)),
            "actor": "urn:r5e:gateway:meridian-prod",
            "capturedAt": &floor_rfc3339,
            "body": {"claimedBy": &root_key_id, "roots": [], "threshold": 1}
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .unwrap();

    let status_json = json!({
        "deployment": "meridian-prod",
        "state": "claimed",
        "chain": &dummy_dep_record.record_ref,
        "deploymentRecord": &dummy_dep_record,
        "startHead": &dummy_dep_record,
        "streamPrefix": "urn:r5e:stream:meridian-prod:",
    });

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let status_clone = status_json.clone();
    let server = thread::spawn(move || {
        // Serve 2 GET /v1/deployment calls (one with --releaser-key-file, one with --releaser-pubkey-file)
        for _ in 0..2 {
            let (mut sock, _) = listener.accept().unwrap();
            let (method, path, _, _) = read_http_request(&mut sock);
            assert_eq!(method, "GET");
            assert_eq!(path, "/v1/deployment");
            write_http_json_response(&mut sock, 200, "OK", &status_clone);
        }
    });

    let tmp_dir =
        std::env::temp_dir().join(format!("r5e-grant-releaser-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp_dir);
    fs::create_dir_all(&tmp_dir).unwrap();

    let root_seed_path = tmp_dir.join("root.seed");
    let releaser_seed_path = tmp_dir.join("counsel.seed");
    let releaser_pub_path = tmp_dir.join("counsel.pub.json");
    let grant_out_1 = tmp_dir.join("counsel-grant-1.json");
    let grant_out_2 = tmp_dir.join("counsel-grant-2.json");

    let root_seed_b64 = BASE64_STANDARD.encode(root_seed);
    let releaser_seed_b64 = BASE64_STANDARD.encode(releaser_seed);
    write_private_key_file_0600(&root_seed_path, &root_seed, true).unwrap();
    write_private_key_file_0600(&releaser_seed_path, &releaser_seed, true).unwrap();
    fs::write(
        &releaser_pub_path,
        serde_json::to_vec(&json!({
            "algorithm": "ed25519",
            "bytes": &releaser_pub_b64,
        }))
        .unwrap(),
    )
    .unwrap();

    let gw_url = format!("http://{addr}");

    // 1. Run `grant-releaser` deriving public key from `--releaser-key-file` (private seed):
    let out1 = Command::new(bin)
        .args([
            "grant-releaser",
            "--gateway-url",
            &gw_url,
            "--root-key-file",
            root_seed_path.to_str().unwrap(),
            "--releaser-key-file",
            releaser_seed_path.to_str().unwrap(),
            "--out-grant-file",
            grant_out_1.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stdout1 = String::from_utf8_lossy(&out1.stdout);
    let stderr1 = String::from_utf8_lossy(&out1.stderr);
    assert_eq!(
        out1.status.code(),
        Some(0),
        "grant-releaser #1 failed: stdout={stdout1} stderr={stderr1}"
    );
    assert!(!stdout1.contains(&root_seed_b64));
    assert!(!stderr1.contains(&root_seed_b64));
    assert!(!stdout1.contains(&releaser_seed_b64));
    assert!(!stderr1.contains(&releaser_seed_b64));

    // 2. Run `grant-releaser` from `--releaser-pubkey-file`:
    let out2 = Command::new(bin)
        .args([
            "grant-releaser",
            "--gateway-url",
            &gw_url,
            "--root-key-file",
            root_seed_path.to_str().unwrap(),
            "--releaser-pubkey-file",
            releaser_pub_path.to_str().unwrap(),
            "--out-grant-file",
            grant_out_2.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stdout2 = String::from_utf8_lossy(&out2.stdout);
    let stderr2 = String::from_utf8_lossy(&out2.stderr);
    assert_eq!(
        out2.status.code(),
        Some(0),
        "grant-releaser #2 failed: stdout={stdout2} stderr={stderr2}"
    );

    server.join().unwrap();

    let summary1: Value = serde_json::from_str(stdout1.trim()).unwrap();
    let summary2: Value = serde_json::from_str(stdout2.trim()).unwrap();
    assert_eq!(summary1["releaserKeyId"], releaser_key_id);
    assert_eq!(summary2["releaserKeyId"], releaser_key_id);
    assert_eq!(summary1["deployment"], "meridian-prod");
    // Two invocations produce distinct random `:grant:<16hex>` sub-streams so neither collides!
    assert_ne!(summary1["grantStream"], summary2["grantStream"]);

    let grant_file_bytes = fs::read(&grant_out_1).unwrap();
    let grant_file_str = String::from_utf8_lossy(&grant_file_bytes);
    assert!(!grant_file_str.contains(&releaser_seed_b64));
    assert!(!grant_file_str.contains(&root_seed_b64));

    let grant_val: Value = serde_json::from_slice(&grant_file_bytes).unwrap();
    assert_eq!(
        encode_canonical_json(&grant_val).unwrap(),
        grant_file_bytes,
        "written grant file must be canonical JSON"
    );
    let grant_set: SubmitGrantsRequest = serde_json::from_slice(&grant_file_bytes).unwrap();
    assert_eq!(grant_set.records.len(), 1);
    assert_eq!(grant_set.keys.len(), 1);
    assert_eq!(grant_set.keys[0].keyid, root_key_id);
    assert_eq!(grant_set.blobs.len(), 1);

    let endorsement = &grant_set.records[0];
    let payload_bytes = decode_strict_base64(&endorsement.envelope.payload).unwrap();
    assert_eq!(evidence_ref(&payload_bytes), endorsement.record_ref);
    let payload_val: Value = serde_json::from_slice(&payload_bytes).unwrap();

    let expected_prefix = format!("urn:r5e:stream:meridian-prod:authority:root:{root_hex}:grant:");
    let stream_str = payload_val["stream"].as_str().unwrap();
    assert!(
        stream_str.starts_with(&expected_prefix),
        "expected stream starting with {expected_prefix}, got {stream_str}"
    );
    let token_suffix = stream_str.strip_prefix(&expected_prefix).unwrap();
    assert_eq!(token_suffix.len(), 16);
    assert!(token_suffix
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));

    assert_eq!(payload_val["seq"], 1);
    assert_eq!(payload_val["previous"], Value::Null);
    assert_eq!(payload_val["issuer"], root_key_id);
    assert_eq!(payload_val["kind"], "Endorsement");

    let body = payload_val["body"].as_object().unwrap();
    assert_eq!(body["subject"], releaser_key_id);
    assert_eq!(
        body["kinds"],
        json!(["provenance.r5e.io/v2/RetentionHoldRelease"])
    );
    assert_eq!(
        body["streamPrefixes"],
        json!(["urn:r5e:stream:meridian-prod:retention"])
    );
    assert_eq!(body["mayEndorse"], false);
    assert!(
        !body.contains_key("actorPrefixes"),
        "actorPrefixes must be omitted by default so gateway :retention actor is covered"
    );
    assert!(
        !body.contains_key("actsFor"),
        "actsFor must be omitted by default unless --acts-for is passed"
    );

    // Verify microsecond formatting and clamping >= ceil_to_micros(startHead.capturedAt):
    let cap_str = payload_val["capturedAt"].as_str().unwrap();
    let nb_str = body["notBefore"].as_str().unwrap();
    assert!(
        cap_str.ends_with('Z') && cap_str.split('.').nth(1).unwrap().len() == 7,
        "expected microsecond .XXXXXXZ capturedAt, got {cap_str}"
    );
    assert!(
        nb_str.ends_with('Z') && nb_str.split('.').nth(1).unwrap().len() == 7,
        "expected microsecond .XXXXXXZ notBefore, got {nb_str}"
    );
    let cap_dt = chrono::DateTime::parse_from_rfc3339(cap_str)
        .unwrap()
        .with_timezone(&chrono::Utc);
    let nb_dt = chrono::DateTime::parse_from_rfc3339(nb_str)
        .unwrap()
        .with_timezone(&chrono::Utc);
    assert!(
        cap_dt >= expected_clamped_floor,
        "capturedAt ({cap_dt}) must be >= ceil_to_micros(startHead) ({expected_clamped_floor})"
    );
    assert!(
        nb_dt >= expected_clamped_floor,
        "notBefore ({nb_dt}) must be >= ceil_to_micros(startHead) ({expected_clamped_floor})"
    );
    assert!(nb_dt <= cap_dt);

    // Verify capture profile `streamPrefix` matches `stream_str` exactly:
    let prof_bytes = decode_strict_base64(&grant_set.blobs[0].base64).unwrap();
    let prof_val: Value = serde_json::from_slice(&prof_bytes).unwrap();
    assert_eq!(
        prof_val["authority"]["bindings"][0]["streamPrefix"],
        stream_str
    );

    let _ = fs::remove_dir_all(&tmp_dir);
}

#[test]
fn release_hold_executes_two_step_ceremony_with_bearer_auth_and_verifies_in_bundle() {
    let bin = env!("CARGO_BIN_EXE_r5e-endpoint-helper");

    let bootstrap_sk = SigningKey::from_bytes(&[0x41u8; 32]);
    let publisher_sk = SigningKey::from_bytes(&[0x42u8; 32]);
    let root_sk = SigningKey::from_bytes(&[0x43u8; 32]);
    let gw_sk = SigningKey::from_bytes(&[0x44u8; 32]);
    let releaser_seed = [0x45u8; 32];
    let releaser_sk = SigningKey::from_bytes(&releaser_seed);

    let bootstrap_id = ed25519_key_id(&bootstrap_sk.verifying_key().to_bytes());
    let publisher_id = ed25519_key_id(&publisher_sk.verifying_key().to_bytes());
    let root_id = ed25519_key_id(&root_sk.verifying_key().to_bytes());
    let gw_id = ed25519_key_id(&gw_sk.verifying_key().to_bytes());
    let releaser_id = ed25519_key_id(&releaser_sk.verifying_key().to_bytes());
    let releaser_pub_b64 = BASE64_STANDARD.encode(releaser_sk.verifying_key().to_bytes());

    let tmp_dir =
        std::env::temp_dir().join(format!("r5e-release-hold-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp_dir);
    fs::create_dir_all(&tmp_dir).unwrap();

    let root_seed_path = tmp_dir.join("root.seed");
    let releaser_seed_path = tmp_dir.join("releaser.seed");
    let grant_path = tmp_dir.join("releaser-grant.json");
    let receipt_path = tmp_dir.join("release-receipt.json");

    let root_seed_b64 = BASE64_STANDARD.encode([0x43u8; 32]);
    let releaser_seed_b64 = BASE64_STANDARD.encode(releaser_seed);
    write_private_key_file_0600(&root_seed_path, &[0x43u8; 32], true).unwrap();
    write_private_key_file_0600(&releaser_seed_path, &releaser_seed, true).unwrap();

    // 1. Ensure CLI NEVER accepts a raw `--bearer-token` value flag on argv:
    let bad_flag = Command::new(bin)
        .args([
            "release-hold",
            "--gateway-url",
            "http://127.0.0.1:9",
            "--hold",
            &format!("evidence:sha256:{}", "aa".repeat(32)),
            "--reason",
            "test",
            "--bearer-token",
            "raw-secret",
        ])
        .output()
        .unwrap();
    assert_ne!(
        bad_flag.status.code(),
        Some(0),
        "CLI must reject raw --bearer-token value flag"
    );

    // 2. Mint offline `grant-releaser` `{records, keys, blobs}` grant file:
    let grant_out = Command::new(bin)
        .args([
            "grant-releaser",
            "--deployment",
            "meridian-prod",
            "--root-key-file",
            root_seed_path.to_str().unwrap(),
            "--releaser-key-file",
            releaser_seed_path.to_str().unwrap(),
            "--not-before",
            "2026-11-12T00:00:00.000000Z",
            "--out-grant-file",
            grant_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(grant_out.status.code(), Some(0));
    assert!(!String::from_utf8_lossy(&grant_out.stdout).contains(&root_seed_b64));
    assert!(!String::from_utf8_lossy(&grant_out.stdout).contains(&releaser_seed_b64));
    let expected_grant: SubmitGrantsRequest =
        serde_json::from_slice(&fs::read(&grant_path).unwrap()).unwrap();

    // Build gateway runtime profile & initial `RetentionHold` (`seq: 1`) on `:retention`:
    let schemas = base_v2_schema_map();
    let policy_bytes = b"permit(principal, action, resource);";
    let policy_ref = bytes_ref(policy_bytes);
    let gw_profile_doc = json!({
        "format": "r5e.capture-profile/v2",
        "schemas": schemas,
        "authority": {
            "bindings": [
                {
                    "streamPrefix": "urn:r5e:stream:meridian-prod:",
                    "actorPrefixes": ["urn:r5e:"],
                    "issuerKeys": [&gw_id, &releaser_id],
                    "sealerKeys": [&gw_id],
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
    });
    let gw_profile_bytes = encode_canonical_json(&gw_profile_doc).unwrap();
    let gw_profile_ref = bytes_ref(&gw_profile_bytes);

    let target_blob_ref = bytes_ref(b"held tool output");
    let hold_record = sign_v2_record_multi(
        &[&gw_sk],
        json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RetentionHold",
            "schemaRef": RETENTION_HOLD_SCHEMA_REF,
            "profileRef": &gw_profile_ref,
            "stream": "urn:r5e:stream:meridian-prod:retention",
            "seq": 1,
            "previous": null,
            "actor": "urn:r5e:gateway:meridian-prod",
            "capturedAt": "2026-11-12T10:00:00.000000Z",
            "body": {
                "targets": [&target_blob_ref],
                "reason": "Litigation hold Matter #2026-44"
            }
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .unwrap();
    let hold_ref = hold_record.record_ref.clone();
    let release_reason = "Matter #2026-44 dismissed with prejudice";
    let secret_bearer = "r5e_bearer_live7_secret_token_991122";

    // Debug redaction check on `HoldReleaseClientConfig`:
    let dbg_cfg = HoldReleaseClientConfig::new("http://127.0.0.1:4000", secret_bearer);
    let dbg_str = format!("{dbg_cfg:?}");
    assert!(!dbg_str.contains(secret_bearer));
    assert!(dbg_str.contains("[REDACTED]"));

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let hold_ref_srv = hold_ref.clone();
    let reason_srv = release_reason.to_string();
    let releaser_id_srv = releaser_id.clone();
    let releaser_pub_b64_srv = releaser_pub_b64.clone();
    let releaser_vk = releaser_sk.verifying_key();
    let gw_id_srv = gw_id.clone();
    let gw_sk_srv = SigningKey::from_bytes(&[0x44u8; 32]);
    let gw_prof_ref_srv = gw_profile_ref.clone();
    let expected_grant_srv = expected_grant.clone();

    let server = thread::spawn(move || -> SignedEndpointRecord {
        // 1. Expect POST /v1/evidence/retention/holds/release/prepare
        let (mut sock1, _) = listener.accept().unwrap();
        let (m1, p1, h1, b1) = read_http_request(&mut sock1);
        assert_eq!(m1, "POST");
        assert_eq!(p1, PREPARE_HOLD_RELEASE_PATH);
        let auth1 = h1
            .iter()
            .find(|(k, _)| k == "authorization")
            .map(|(_, v)| v.as_str());
        assert_eq!(auth1, Some("Bearer r5e_bearer_live7_secret_token_991122"));

        let req1: Value = serde_json::from_slice(&b1).unwrap();
        assert_eq!(req1["hold"], hold_ref_srv);
        assert_eq!(req1["reason"], reason_srv);
        assert_eq!(
            req1["releasedBy"],
            json!({"algorithm": "ed25519", "bytes": &releaser_pub_b64_srv})
        );

        let draft_payload_bytes = encode_canonical_json(&json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RetentionHoldRelease",
            "schemaRef": RETENTION_HOLD_RELEASE_SCHEMA_REF,
            "profileRef": &gw_prof_ref_srv,
            "issuer": &gw_id_srv,
            "stream": "urn:r5e:stream:meridian-prod:retention",
            "seq": 2,
            "previous": &hold_ref_srv,
            "actor": "urn:r5e:gateway:meridian-prod",
            "capturedAt": "2026-11-12T10:05:00.500000Z",
            "body": {
                "hold": &hold_ref_srv,
                "releasedBy": &releaser_id_srv,
                "reason": &reason_srv,
            }
        }))
        .unwrap();
        let b64_payload = BASE64_STANDARD.encode(&draft_payload_bytes);
        write_http_json_response(
            &mut sock1,
            200,
            "OK",
            &json!({
                "payloadType": PROVENANCE_V2_PAYLOAD_TYPE,
                "payload": &b64_payload,
                "ticket": "tkt-live7-hold-rel",
            }),
        );

        // 2. Expect POST /v1/evidence/retention/holds/release/finalize
        let (mut sock2, _) = listener.accept().unwrap();
        let (m2, p2, h2, b2) = read_http_request(&mut sock2);
        assert_eq!(m2, "POST");
        assert_eq!(p2, FINALIZE_HOLD_RELEASE_PATH);
        let auth2 = h2
            .iter()
            .find(|(k, _)| k == "authorization")
            .map(|(_, v)| v.as_str());
        assert_eq!(auth2, Some("Bearer r5e_bearer_live7_secret_token_991122"));

        let req2: Value = serde_json::from_slice(&b2).unwrap();
        assert_eq!(req2["ticket"], "tkt-live7-hold-rel");
        assert_eq!(req2["payload"], b64_payload);
        assert_eq!(
            req2["releasedBy"],
            json!({"algorithm": "ed25519", "bytes": &releaser_pub_b64_srv})
        );
        let carried_auth: SubmitGrantsRequest =
            serde_json::from_value(req2["authority"].clone()).unwrap();
        assert_eq!(carried_auth, expected_grant_srv);

        assert_eq!(req2["signature"]["keyid"], releaser_id_srv);
        let sig2_raw = decode_strict_base64(req2["signature"]["sig"].as_str().unwrap()).unwrap();
        let sig2 = Signature::from_bytes(&sig2_raw.try_into().unwrap());
        let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &draft_payload_bytes);
        releaser_vk
            .verify(&pae, &sig2)
            .expect("counsel DSSEv1 signature must verify");

        let gw_sig = gw_sk_srv.sign(&pae);
        let release_ref = evidence_ref(&draft_payload_bytes);
        let completed_record = SignedEndpointRecord {
            record_ref: release_ref.clone(),
            envelope: DsseEnvelope {
                payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
                payload: b64_payload,
                signatures: vec![
                    DsseSignature {
                        keyid: gw_id_srv,
                        sig: BASE64_STANDARD.encode(gw_sig.to_bytes()),
                    },
                    DsseSignature {
                        keyid: releaser_id_srv,
                        sig: req2["signature"]["sig"].as_str().unwrap().to_string(),
                    },
                ],
            },
        };

        write_http_json_response(
            &mut sock2,
            201,
            "Created",
            &json!({
                "release": &release_ref,
                "seq": 2,
                "hold": &hold_ref_srv,
            }),
        );
        completed_record
    });

    let cli_out = Command::new(bin)
        .env("R5E_HOLD_TEST_TOKEN", secret_bearer)
        .args([
            "release-hold",
            "--gateway-url",
            &format!("http://{addr}"),
            "--hold",
            &hold_ref,
            "--reason",
            release_reason,
            "--bearer-token-env",
            "R5E_HOLD_TEST_TOKEN",
            "--releaser-key-file",
            releaser_seed_path.to_str().unwrap(),
            "--authority-file",
            grant_path.to_str().unwrap(),
            "--out-receipt-file",
            receipt_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    let stdout_str = String::from_utf8_lossy(&cli_out.stdout);
    let stderr_str = String::from_utf8_lossy(&cli_out.stderr);
    assert_eq!(
        cli_out.status.code(),
        Some(0),
        "release-hold CLI failed: stdout={stdout_str} stderr={stderr_str}"
    );
    assert!(!stdout_str.contains(secret_bearer));
    assert!(!stderr_str.contains(secret_bearer));
    assert!(!stdout_str.contains(&releaser_seed_b64));
    assert!(!stderr_str.contains(&releaser_seed_b64));

    let completed_release = server.join().unwrap();

    let summary: Value = serde_json::from_str(stdout_str.trim()).unwrap();
    assert_eq!(summary["ok"], true);
    assert_eq!(summary["release"], completed_release.record_ref);
    assert_eq!(summary["seq"], 2);
    assert_eq!(summary["hold"], hold_ref);
    assert_eq!(summary["releasedBy"], releaser_id);
    assert_eq!(summary["authorityCarried"], true);

    let receipt_raw = fs::read_to_string(&receipt_path).unwrap();
    assert!(!receipt_raw.contains(secret_bearer));
    assert!(!receipt_raw.contains(&releaser_seed_b64));

    // 3. Cross-verifier seam check: verify the emitted `grant-releaser` Endorsement + 2-signer
    //    `RetentionHoldRelease` inside a full `r5e.provenance-export/v2` bundle with both
    //    clean-room verifiers (`r5e-verify-py` and `r5e-verify-rs`) when present on disk!
    let mut gw_grant_params = GatewayGrantParams::new(&gw_id, "urn:r5e:stream:meridian-prod:");
    gw_grant_params.not_before_override = Some("2026-11-12T00:00:00.000000Z".to_string());
    let built_gw_grant = build_root_gateway_grant(&root_sk, &gw_grant_params).unwrap();

    let pub_profile_doc = json!({
        "format": "r5e.capture-profile/v2",
        "schemas": base_v2_schema_map(),
        "authority": {
            "bindings": [{
                "streamPrefix": "urn:r5e:stream:publications:",
                "actorPrefixes": ["urn:r5e:"],
                "issuerKeys": [&publisher_id],
                "sealerKeys": [],
            }],
            "checkpointKeys": [],
        },
        "durability": {"failureDomain": "steward", "onFailure": "refuse", "requiredPayloads": "submitted"},
        "policyRequiredKinds": [],
        "deploymentPolicyRef": &policy_ref,
    });
    let pub_profile_bytes = encode_canonical_json(&pub_profile_doc).unwrap();
    let pub_profile_ref = bytes_ref(&pub_profile_bytes);

    let mut defs_arr = Vec::new();
    for (k, v) in base_v2_schema_map() {
        defs_arr.push(json!({"kind": k, "definition": v}));
    }
    let def_published = sign_v2_record_multi(
        &[&publisher_sk],
        json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "DefinitionPublished",
            "schemaRef": base_v2_schema_map()["provenance.r5e.io/v2/DefinitionPublished"],
            "profileRef": &pub_profile_ref,
            "stream": "urn:r5e:stream:publications:base-v2",
            "seq": 1,
            "previous": null,
            "actor": "urn:r5e:steward:api",
            "capturedAt": "2026-11-12T00:00:00.000000Z",
            "body": {
                "package": "provenance.r5e.io/v2",
                "definitions": defs_arr,
            }
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .unwrap();

    let boot_profile_doc = json!({
        "format": "r5e.capture-profile/v2",
        "schemas": base_v2_schema_map(),
        "authority": {
            "bindings": [{
                "streamPrefix": "urn:r5e:stream:meridian-prod:start",
                "actorPrefixes": ["urn:r5e:"],
                "issuerKeys": [&bootstrap_id],
                "sealerKeys": [],
            }],
            "checkpointKeys": [],
        },
        "durability": {"failureDomain": "gateway-local", "onFailure": "refuse", "requiredPayloads": "submitted"},
        "policyRequiredKinds": [],
        "deploymentPolicyRef": &policy_ref,
    });
    let boot_profile_bytes = encode_canonical_json(&boot_profile_doc).unwrap();
    let boot_profile_ref = bytes_ref(&boot_profile_bytes);

    let chain_started = sign_v2_record_multi(
        &[&bootstrap_sk],
        json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "ChainStarted",
            "schemaRef": base_v2_schema_map()["provenance.r5e.io/v2/ChainStarted"],
            "profileRef": &boot_profile_ref,
            "stream": "urn:r5e:stream:meridian-prod:start",
            "seq": 1,
            "previous": null,
            "actor": "urn:r5e:gateway:meridian-prod",
            "capturedAt": "2026-11-12T00:00:01.000000Z",
            "body": {
                "deployment": "meridian-prod",
                "bootstrap": &bootstrap_id,
                "bootstrapKey": {
                    "algorithm": "ed25519",
                    "bytes": BASE64_STANDARD.encode(bootstrap_sk.verifying_key().to_bytes()),
                },
                "publication": &def_published.record_ref,
                "publisher": &publisher_id,
                "definitions": defs_arr,
            }
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .unwrap();

    let deployment_rec = sign_v2_record_multi(
        &[&bootstrap_sk, &root_sk],
        json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Deployment",
            "schemaRef": base_v2_schema_map()["provenance.r5e.io/v2/Deployment"],
            "profileRef": &boot_profile_ref,
            "stream": "urn:r5e:stream:meridian-prod:start",
            "seq": 2,
            "previous": &chain_started.record_ref,
            "actor": "urn:r5e:gateway:meridian-prod",
            "capturedAt": "2026-11-12T00:00:02.000000Z",
            "body": {
                "accepts": &chain_started.record_ref,
                "bootstrap": &bootstrap_id,
                "claimedBy": &root_id,
                "roots": [{
                    "key": &root_id,
                    "publicKey": {
                        "algorithm": "ed25519",
                        "bytes": BASE64_STANDARD.encode(root_sk.verifying_key().to_bytes()),
                    }
                }],
                "threshold": 1,
            }
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .unwrap();

    let releaser_grant_stream = {
        let p = decode_strict_base64(&expected_grant.records[0].envelope.payload).unwrap();
        let v: Value = serde_json::from_slice(&p).unwrap();
        v["stream"].as_str().unwrap().to_string()
    };

    let bundle_doc = json!({
        "format": "r5e.provenance-export/v2",
        "scope": {
            "query": {"stream": "urn:r5e:stream:meridian-prod:retention"},
            "at": [
                {
                    "stream": "urn:r5e:stream:publications:base-v2",
                    "seq": 1,
                    "event": &def_published.record_ref,
                },
                {
                    "stream": "urn:r5e:stream:meridian-prod:start",
                    "seq": 2,
                    "event": &deployment_rec.record_ref,
                },
                {
                    "stream": &built_gw_grant.root_stream,
                    "seq": 1,
                    "event": &built_gw_grant.endorsement.record_ref,
                },
                {
                    "stream": &releaser_grant_stream,
                    "seq": 1,
                    "event": &expected_grant.records[0].record_ref,
                },
                {
                    "stream": "urn:r5e:stream:meridian-prod:retention",
                    "seq": 2,
                    "event": &completed_release.record_ref,
                }
            ]
        },
        "records": [
            &def_published,
            &chain_started,
            &deployment_rec,
            &built_gw_grant.endorsement,
            &expected_grant.records[0],
            &hold_record,
            &completed_release,
        ],
        "keys": [
            PublicKeyEntry {
                keyid: bootstrap_id,
                algorithm: "ed25519".to_string(),
                bytes: BASE64_STANDARD.encode(bootstrap_sk.verifying_key().to_bytes()),
            },
            PublicKeyEntry {
                keyid: publisher_id.clone(),
                algorithm: "ed25519".to_string(),
                bytes: BASE64_STANDARD.encode(publisher_sk.verifying_key().to_bytes()),
            },
            PublicKeyEntry {
                keyid: root_id,
                algorithm: "ed25519".to_string(),
                bytes: BASE64_STANDARD.encode(root_sk.verifying_key().to_bytes()),
            },
            PublicKeyEntry {
                keyid: gw_id,
                algorithm: "ed25519".to_string(),
                bytes: BASE64_STANDARD.encode(gw_sk.verifying_key().to_bytes()),
            },
            PublicKeyEntry {
                keyid: releaser_id,
                algorithm: "ed25519".to_string(),
                bytes: releaser_pub_b64,
            },
        ],
        "blobs": [
            {
                "ref": &policy_ref,
                "mediaType": "text/plain",
                "base64": BASE64_STANDARD.encode(policy_bytes),
            },
            {
                "ref": &pub_profile_ref,
                "mediaType": "application/json",
                "base64": BASE64_STANDARD.encode(&pub_profile_bytes),
            },
            {
                "ref": &boot_profile_ref,
                "mediaType": "application/json",
                "base64": BASE64_STANDARD.encode(&boot_profile_bytes),
            },
            &built_gw_grant.request.blobs[0],
            &expected_grant.blobs[0],
            {
                "ref": &gw_profile_ref,
                "mediaType": "application/json",
                "base64": BASE64_STANDARD.encode(&gw_profile_bytes),
            },
            {
                "ref": &target_blob_ref,
                "mediaType": "text/plain",
                "base64": BASE64_STANDARD.encode(b"held tool output"),
            },
        ],
        "seals": [],
        "checkpoints": [],
        "proofs": [],
        "publicationProofs": [],
        "omissions": [],
    });
    let bundle_bytes = encode_canonical_json(&bundle_doc).unwrap();
    let bundle_path = tmp_dir.join("hold-release-bundle.json");
    fs::write(&bundle_path, &bundle_bytes).unwrap();

    let live_defs_dir = optional_definitions_dir();

    if let Some((py_verifier_repo, py_bin)) = resolve_py_verifier() {
        let mut cmd = Command::new(&py_bin);
        cmd.current_dir(&py_verifier_repo)
            .env("PYTHONPATH", &py_verifier_repo)
            .args([
                "-m",
                "r5e_verify",
                bundle_path.to_str().unwrap(),
                "--trusted-chain",
                &deployment_rec.record_ref,
                "--trusted-publisher",
                &publisher_id,
            ]);
        if let Some(defs) = &live_defs_dir {
            cmd.args(["--definitions-dir", defs.to_str().unwrap()]);
        }
        let out = cmd.output().unwrap();
        let out_stdout = String::from_utf8_lossy(&out.stdout);
        let out_stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(0),
            "clean-room Python verifier rejected hold-release bundle: stdout={out_stdout} stderr={out_stderr}"
        );
        let report: Value = serde_json::from_str(&out_stdout).unwrap();
        assert_eq!(report["summary"]["failed"], 0);
        assert_eq!(report["summary"]["incomplete"], 0);
    }

    if let Some(rs_verifier_bin) = resolve_rs_verifier_bin() {
        let mut cmd = Command::new(&rs_verifier_bin);
        cmd.args([
            bundle_path.to_str().unwrap(),
            "--trusted-chain",
            &deployment_rec.record_ref,
            "--trusted-publisher",
            &publisher_id,
        ]);
        if let Some(defs) = &live_defs_dir {
            cmd.args(["--definitions-dir", defs.to_str().unwrap()]);
        }
        let out = cmd.output().unwrap();
        let out_stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(
            out.status.code(),
            Some(0),
            "clean-room Rust verifier rejected hold-release bundle: {out_stdout}"
        );
        let report: Value = serde_json::from_str(&out_stdout).unwrap();
        assert_eq!(report["summary"]["failed"], 0);
        assert_eq!(report["summary"]["incomplete"], 0);
    }

    let _ = fs::remove_dir_all(&tmp_dir);
}

#[test]
fn release_hold_refuses_tampered_prepare_payload_before_signing_and_surfaces_gateway_errors() {
    let gw_sk = SigningKey::from_bytes(&[0x71u8; 32]);
    let releaser_sk = SigningKey::from_bytes(&[0x72u8; 32]);
    let other_sk = SigningKey::from_bytes(&[0x73u8; 32]);

    let gw_id = ed25519_key_id(&gw_sk.verifying_key().to_bytes());
    let releaser_id = ed25519_key_id(&releaser_sk.verifying_key().to_bytes());
    let other_id = ed25519_key_id(&other_sk.verifying_key().to_bytes());

    let requested_hold = format!("evidence:sha256:{}", "11".repeat(32));
    let other_hold = format!("evidence:sha256:{}", "22".repeat(32));
    let requested_reason = "Release hold 11 only";
    let dummy_profile_ref = format!("bytes:sha256:{}", "33".repeat(32));

    // Adversarial `prepare` cases — none may EVER trigger a `/finalize` POST!
    let tampered_drafts: Vec<(&str, Value, &str)> = vec![
        (
            "swapped body.hold",
            json!({
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "RetentionHoldRelease",
                "schemaRef": RETENTION_HOLD_RELEASE_SCHEMA_REF,
                "profileRef": &dummy_profile_ref,
                "issuer": &gw_id,
                "stream": "urn:r5e:stream:meridian:retention",
                "seq": 2,
                "previous": &requested_hold,
                "actor": "urn:r5e:gateway:meridian",
                "capturedAt": "2026-11-12T12:00:00.000000Z",
                "body": {
                    "hold": &other_hold,
                    "releasedBy": &releaser_id,
                    "reason": requested_reason,
                }
            }),
            "mismatched body.hold",
        ),
        (
            "rogue kind Endorsement",
            json!({
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "Endorsement",
                "schemaRef": RETENTION_HOLD_RELEASE_SCHEMA_REF,
                "profileRef": &dummy_profile_ref,
                "issuer": &gw_id,
                "stream": "urn:r5e:stream:meridian:retention",
                "seq": 2,
                "previous": &requested_hold,
                "actor": "urn:r5e:gateway:meridian",
                "capturedAt": "2026-11-12T12:00:00.000000Z",
                "body": {
                    "hold": &requested_hold,
                    "releasedBy": &releaser_id,
                    "reason": requested_reason,
                }
            }),
            "non-RetentionHoldRelease record",
        ),
        (
            "altered body.reason",
            json!({
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "RetentionHoldRelease",
                "schemaRef": RETENTION_HOLD_RELEASE_SCHEMA_REF,
                "profileRef": &dummy_profile_ref,
                "issuer": &gw_id,
                "stream": "urn:r5e:stream:meridian:retention",
                "seq": 2,
                "previous": &requested_hold,
                "actor": "urn:r5e:gateway:meridian",
                "capturedAt": "2026-11-12T12:00:00.000000Z",
                "body": {
                    "hold": &requested_hold,
                    "releasedBy": &releaser_id,
                    "reason": "Silently substituted reason",
                }
            }),
            "mismatched body.reason",
        ),
        (
            "mismatched body.releasedBy",
            json!({
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "RetentionHoldRelease",
                "schemaRef": RETENTION_HOLD_RELEASE_SCHEMA_REF,
                "profileRef": &dummy_profile_ref,
                "issuer": &gw_id,
                "stream": "urn:r5e:stream:meridian:retention",
                "seq": 2,
                "previous": &requested_hold,
                "actor": "urn:r5e:gateway:meridian",
                "capturedAt": "2026-11-12T12:00:00.000000Z",
                "body": {
                    "hold": &requested_hold,
                    "releasedBy": &other_id,
                    "reason": requested_reason,
                }
            }),
            "mismatched body.releasedBy",
        ),
        (
            "recorder issuer equals releaser key",
            json!({
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "RetentionHoldRelease",
                "schemaRef": RETENTION_HOLD_RELEASE_SCHEMA_REF,
                "profileRef": &dummy_profile_ref,
                "issuer": &releaser_id,
                "stream": "urn:r5e:stream:meridian:retention",
                "seq": 2,
                "previous": &requested_hold,
                "actor": "urn:r5e:gateway:meridian",
                "capturedAt": "2026-11-12T12:00:00.000000Z",
                "body": {
                    "hold": &requested_hold,
                    "releasedBy": &releaser_id,
                    "reason": requested_reason,
                }
            }),
            "recorder and releaser must be distinct keys",
        ),
    ];

    for (case_name, tampered_payload_val, expected_substr) in tampered_drafts {
        let finalize_calls = Arc::new(AtomicUsize::new(0));
        let finalize_calls_srv = Arc::clone(&finalize_calls);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let payload_bytes = encode_canonical_json(&tampered_payload_val).unwrap();
        let b64_payload = BASE64_STANDARD.encode(&payload_bytes);

        let srv = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let (_, path, _, _) = read_http_request(&mut sock);
            if path == FINALIZE_HOLD_RELEASE_PATH {
                finalize_calls_srv.fetch_add(1, Ordering::SeqCst);
            }
            assert_eq!(path, PREPARE_HOLD_RELEASE_PATH);
            write_http_json_response(
                &mut sock,
                200,
                "OK",
                &json!({
                    "payloadType": PROVENANCE_V2_PAYLOAD_TYPE,
                    "payload": b64_payload,
                    "ticket": "tkt-malicious",
                }),
            );
        });

        let cfg = HoldReleaseClientConfig::new(format!("http://{addr}"), "bearer-tok");
        let err = execute_release_hold_ceremony(
            &cfg,
            &releaser_sk,
            &requested_hold,
            requested_reason,
            None,
        )
        .expect_err(&format!("must refuse tampered prepare case: {case_name}"));

        srv.join().unwrap();
        assert_eq!(
            finalize_calls.load(Ordering::SeqCst),
            0,
            "must NEVER call /finalize when prepare payload is tampered ({case_name})"
        );
        match err {
            HoldReleaseError::Validation(msg) => assert!(
                msg.contains(expected_substr),
                "case {case_name}: expected {expected_substr:?} in {msg:?}"
            ),
            other => panic!("case {case_name}: expected Validation error, got {other:?}"),
        }
    }

    // Gateway HTTP error surfacing (`409 retention_stream_moved`, `422 releaser_has_no_standing`,
    // `422 hold_already_released`, `422 no_such_hold`, `401 unauthorized`):
    let error_cases: Vec<(u16, &str, &str)> = vec![
        (409, "Conflict", "retention_stream_moved"),
        (422, "Unprocessable Entity", "releaser_has_no_standing"),
        (422, "Unprocessable Entity", "hold_already_released"),
        (422, "Unprocessable Entity", "no_such_hold"),
        (401, "Unauthorized", "unauthorized"),
    ];

    for (status, reason_phrase, err_code) in error_cases {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let code_owned = err_code.to_string();
        let reason_owned = reason_phrase.to_string();

        let srv = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let _ = read_http_request(&mut sock);
            write_http_json_response(
                &mut sock,
                status,
                &reason_owned,
                &json!({"error": code_owned}),
            );
        });

        let cfg = HoldReleaseClientConfig::new(format!("http://{addr}"), "bearer-tok");
        let err = execute_release_hold_ceremony(
            &cfg,
            &releaser_sk,
            &requested_hold,
            requested_reason,
            None,
        )
        .expect_err("expected HTTP error");
        srv.join().unwrap();

        assert_eq!(err.http_status(), Some(status));
        assert_eq!(err.error_code(), Some(err_code));
        assert!(err.to_string().contains(err_code));
    }
}
