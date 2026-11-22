use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use chrono::{Duration, SecondsFormat, Utc};
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use r5e_endpoint_helper::attestation::{
    bytes_ref, decode_strict_base64, dsse_pae, ed25519_key_id, encode_canonical_json, evidence_ref,
    sign_v2_record_multi, write_private_key_file_0600, PROVENANCE_V2_PAYLOAD_TYPE,
    REVOCATION_SCHEMA_REF, ROOTS_CHANGED_SCHEMA_REF,
};
use r5e_endpoint_helper::claim_http::{
    build_grant_revocation, execute_revoke_grant_ceremony, execute_revoke_issuer_grants_ceremony,
    get_deployment_status, submit_deployment_revocations, ClaimClientConfig, ClaimError,
    GrantRevocationParams, SubmitRevocationsRequest, DEPLOYMENT_REVOCATIONS_PATH,
    DEPLOYMENT_STATUS_PATH, MAX_REVOCATION_RECORDS, REVOCATION_ROTATION_SAFETY_NOTE,
};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;

fn read_http_request(stream: &mut TcpStream) -> (String, String, Vec<u8>) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone tcp stream"));
    let mut req_line = String::new();
    reader.read_line(&mut req_line).expect("read request line");
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();

    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).expect("read header line");
        let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse::<usize>().unwrap_or(0);
            }
        }
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).expect("read request body");
    }
    (method, path, body)
}

fn write_http_json_response(stream: &mut TcpStream, status: u16, reason: &str, body: &Value) {
    let payload = serde_json::to_vec(body).expect("serialize mock response JSON");
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream
        .write_all(head.as_bytes())
        .expect("write status/headers");
    stream.write_all(&payload).expect("write body");
    stream.flush().expect("flush response");
}

fn verify_submitted_revocation_wire(
    raw_body: &[u8],
    expected_revoker_vk: &VerifyingKey,
    expected_target: &str,
    expected_reason: &str,
    expected_deployment: &str,
) -> (String, chrono::DateTime<Utc>) {
    let parsed_val: Value = serde_json::from_slice(raw_body).expect("valid JSON revocation body");
    assert_eq!(
        encode_canonical_json(&parsed_val).expect("canonicalize"),
        raw_body,
        "submitted revocation request must be canonical JSON"
    );

    let req: SubmitRevocationsRequest =
        serde_json::from_slice(raw_body).expect("typed SubmitRevocationsRequest");
    assert_eq!(req.records.len(), 1);
    assert_eq!(req.keys.len(), 1);
    assert_eq!(req.blobs.len(), 1);

    let expected_key_id = ed25519_key_id(&expected_revoker_vk.to_bytes());
    assert_eq!(req.keys[0].keyid, expected_key_id);
    assert_eq!(req.keys[0].algorithm, "ed25519");
    assert_eq!(
        decode_strict_base64(&req.keys[0].bytes).expect("decode key bytes"),
        expected_revoker_vk.to_bytes()
    );

    let rec = &req.records[0];
    assert_eq!(rec.envelope.payload_type, PROVENANCE_V2_PAYLOAD_TYPE);
    let payload_bytes = decode_strict_base64(&rec.envelope.payload).expect("decode payload");
    assert_eq!(evidence_ref(&payload_bytes), rec.record_ref);
    assert_eq!(rec.envelope.signatures.len(), 1);
    assert_eq!(rec.envelope.signatures[0].keyid, expected_key_id);

    let sig_raw = decode_strict_base64(&rec.envelope.signatures[0].sig).expect("decode sig");
    let sig_arr: [u8; 64] = sig_raw.try_into().expect("64-byte Ed25519 sig");
    let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &payload_bytes);
    expected_revoker_vk
        .verify(&pae, &Signature::from_bytes(&sig_arr))
        .expect("valid Ed25519 DSSE signature on Revocation");

    let env_json: Value = serde_json::from_slice(&payload_bytes).expect("Revocation JSON");
    assert_eq!(env_json["apiVersion"], "provenance.r5e.io/v2");
    assert_eq!(env_json["kind"], "Revocation");
    assert_eq!(
        env_json["schemaRef"],
        "bytes:sha256:04a0eb543161e1d7d45e08e6f838bad52002aa3345a95aa6a19963055311d524"
    );
    assert_eq!(env_json["schemaRef"], REVOCATION_SCHEMA_REF);
    assert_eq!(env_json["seq"], 1);
    assert_eq!(env_json["previous"], Value::Null);
    assert_eq!(env_json["issuer"], expected_key_id);

    let stream = env_json["stream"].as_str().expect("stream string");
    let expected_prefix = format!("urn:r5e:stream:{expected_deployment}:authority:revocation:");
    let token = stream
        .strip_prefix(&expected_prefix)
        .expect("stream must start with urn:r5e:stream:<deployment>:authority:revocation:");
    assert!(
        token.len() >= 16
            && token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "unexpected revocation stream token: {token}"
    );

    let captured_at_str = env_json["capturedAt"].as_str().expect("capturedAt string");
    assert!(
        captured_at_str.ends_with('Z') && captured_at_str.contains('.'),
        "capturedAt must use microsecond RFC 3339 (.ffffffZ): {captured_at_str}"
    );
    let frac = captured_at_str
        .split('.')
        .nth(1)
        .unwrap()
        .trim_end_matches('Z');
    assert_eq!(
        frac.len(),
        6,
        "capturedAt must carry 6 microsecond digits: {captured_at_str}"
    );
    let captured_at_dt = chrono::DateTime::parse_from_rfc3339(captured_at_str)
        .expect("parse RFC 3339 capturedAt")
        .with_timezone(&Utc);

    assert_eq!(
        env_json["body"],
        json!({
            "reason": expected_reason,
            "target": expected_target,
        })
    );

    // Verify self-describing capture profile in blobs[0] has exact streamPrefix == stream
    let profile_bytes = decode_strict_base64(&req.blobs[0].base64).expect("decode profile b64");
    assert_eq!(bytes_ref(&profile_bytes), req.blobs[0].blob_ref);
    assert_eq!(env_json["profileRef"], req.blobs[0].blob_ref);

    let profile_json: Value = serde_json::from_slice(&profile_bytes).expect("profile JSON");
    assert_eq!(profile_json["format"], "r5e.capture-profile/v2");
    assert_eq!(
        profile_json["schemas"]["provenance.r5e.io/v2/Revocation"],
        REVOCATION_SCHEMA_REF
    );
    let bindings = profile_json["authority"]["bindings"]
        .as_array()
        .expect("authority.bindings array");
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0]["streamPrefix"], stream);
    assert_eq!(bindings[0]["actorPrefixes"], json!(["urn:r5e:"]));
    assert_eq!(bindings[0]["issuerKeys"], json!([expected_key_id]));
    assert_eq!(bindings[0]["sealerKeys"], json!([]));

    (rec.record_ref.clone(), captured_at_dt)
}

#[test]
fn revoke_grant_ceremony_valid_envelope_profile_and_microsecond_clamp() {
    let root1_key = SigningKey::from_bytes(&[0x41; 32]);
    let rotated_root2_seed = [0x42; 32];
    let rotated_root2_key = SigningKey::from_bytes(&rotated_root2_seed);
    let rotated_root2_vk = rotated_root2_key.verifying_key();
    let rotated_root2_id = ed25519_key_id(&rotated_root2_vk.to_bytes());

    let deployment_admitted_at = Utc::now() - Duration::seconds(10);
    // Simulate a rotated start-head (`RootsChanged`) stamped slightly ahead in the same second
    // with sub-microsecond nanoseconds so floor rounding (`ceil_to_micros`) is exercised too.
    let rotated_head_floor = Utc::now() + Duration::milliseconds(650) + Duration::nanoseconds(321);
    let rotated_head_str = rotated_head_floor.to_rfc3339_opts(SecondsFormat::Nanos, true);

    let dep_record = sign_v2_record_multi(
        &[&root1_key],
        json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Deployment",
            "schemaRef": "bytes:sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "profileRef": "bytes:sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "stream": "urn:r5e:stream:acme-prod:start",
            "seq": 2,
            "previous": "evidence:sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "actor": "urn:r5e:operator:root",
            "capturedAt": deployment_admitted_at.to_rfc3339_opts(SecondsFormat::Micros, true),
            "body": { "deployment": "acme-prod" }
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .unwrap();

    let rotated_head_record = sign_v2_record_multi(
        &[&rotated_root2_key],
        json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootsChanged",
            "schemaRef": ROOTS_CHANGED_SCHEMA_REF,
            "profileRef": "bytes:sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "stream": "urn:r5e:stream:acme-prod:start",
            "seq": 3,
            "previous": &dep_record.record_ref,
            "actor": "urn:r5e:operator:root",
            "capturedAt": &rotated_head_str,
            "body": { "chain": &dep_record.record_ref }
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .unwrap();

    let status_json = json!({
        "deployment": "acme-prod",
        "state": "claimed",
        "chain": dep_record.record_ref,
        "deploymentRecord": dep_record,
        "startHead": rotated_head_record,
        "streamPrefix": "urn:r5e:stream:acme-prod:",
    });

    let target_grant_ref =
        "evidence:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let captured_posts: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_posts_srv = Arc::clone(&captured_posts);
    let stop = Arc::new(AtomicBool::new(false));
    let stop_srv = Arc::clone(&stop);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock gateway");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking listener");
    let addr = listener.local_addr().unwrap();

    let srv_handle = thread::spawn(move || {
        while !stop_srv.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_nonblocking(false)
                        .expect("blocking accepted stream");
                    let (method, path, body) = read_http_request(&mut stream);
                    match (method.as_str(), path.as_str()) {
                        ("GET", DEPLOYMENT_STATUS_PATH) => {
                            write_http_json_response(&mut stream, 200, "OK", &status_json);
                        }
                        ("POST", DEPLOYMENT_REVOCATIONS_PATH) => {
                            let parsed: SubmitRevocationsRequest =
                                serde_json::from_slice(&body).expect("parse revocation request");
                            let refs: Vec<String> = parsed
                                .records
                                .iter()
                                .map(|r| r.record_ref.clone())
                                .collect();
                            captured_posts_srv.lock().unwrap().push(body);
                            write_http_json_response(
                                &mut stream,
                                201,
                                "Created",
                                &json!({ "recorded": refs }),
                            );
                        }
                        other => panic!("unexpected mock request: {other:?}"),
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(e) => panic!("accept error: {e}"),
            }
        }
    });

    let gateway_url = format!("http://{addr}");
    let cfg = ClaimClientConfig::new(&gateway_url);

    // 1. Library ceremony helper (`execute_revoke_grant_ceremony`) + idempotent replay
    let (built_lib, resp_lib) = execute_revoke_grant_ceremony(
        &cfg,
        &rotated_root2_key,
        target_grant_ref,
        Some("retiring root1 gateway endorsement after rotation".to_string()),
        None,
        "urn:r5e:operator:root",
    )
    .expect("library execute_revoke_grant_ceremony succeeds");

    assert_eq!(resp_lib.status, 201);
    assert_eq!(
        resp_lib.recorded_refs,
        vec![built_lib.revocation.record_ref.clone()]
    );
    // Idempotent replay of the exact same request returns 201 with the same recorded ref
    let replay_resp = submit_deployment_revocations(&cfg, &built_lib.request)
        .expect("idempotent replay succeeds");
    assert_eq!(replay_resp.status, 201);
    assert_eq!(replay_resp.recorded_refs, resp_lib.recorded_refs);

    // 2. CLI `revoke-grant` using `--signer-key-file` alias and `--out-revocation-file`
    let tmp_dir =
        std::env::temp_dir().join(format!("r5e-revoke-ceremony-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp_dir);
    fs::create_dir_all(&tmp_dir).unwrap();
    let key_path = tmp_dir.join("root2.seed");
    let out_rev_path = tmp_dir.join("submitted-revocation.json");
    write_private_key_file_0600(&key_path, &rotated_root2_seed, true).unwrap();

    let cli_out = Command::new(env!("CARGO_BIN_EXE_r5e-endpoint-helper"))
        .args([
            "revoke-grant",
            "--gateway-url",
            &gateway_url,
            "--target",
            target_grant_ref,
            "--reason",
            "retiring old gateway grant",
            "--signer-key-file",
            key_path.to_str().unwrap(),
            "--out-revocation-file",
            out_rev_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn r5e-endpoint-helper revoke-grant");

    stop.store(true, Ordering::Relaxed);
    srv_handle.join().unwrap();

    assert!(
        cli_out.status.success(),
        "CLI revoke-grant failed: stderr={}",
        String::from_utf8_lossy(&cli_out.stderr)
    );
    let stdout_str = String::from_utf8(cli_out.stdout).unwrap();
    let stderr_str = String::from_utf8(cli_out.stderr).unwrap();
    let seed_b64 = BASE64_STANDARD.encode(rotated_root2_seed);
    assert!(
        !stdout_str.contains(&seed_b64) && !stderr_str.contains(&seed_b64),
        "private seed must never appear in stdout/stderr"
    );

    let cli_summary: Value = serde_json::from_str(stdout_str.trim()).expect("CLI JSON summary");
    assert_eq!(cli_summary["ok"], true);
    assert_eq!(cli_summary["submitted"], true);
    assert_eq!(cli_summary["status"], 201);
    assert_eq!(cli_summary["revokerKeyId"], rotated_root2_id);
    assert_eq!(cli_summary["target"], target_grant_ref);
    assert_eq!(cli_summary["seq"], 1);
    assert_eq!(cli_summary["safetyNote"], REVOCATION_ROTATION_SAFETY_NOTE);

    let posts = captured_posts.lock().unwrap();
    assert_eq!(posts.len(), 3, "lib + replay + CLI posts");

    let (lib_ref, lib_dt) = verify_submitted_revocation_wire(
        &posts[0],
        &rotated_root2_vk,
        target_grant_ref,
        "retiring root1 gateway endorsement after rotation",
        "acme-prod",
    );
    assert_eq!(lib_ref, built_lib.revocation.record_ref);
    assert!(
        lib_dt >= rotated_head_floor,
        "library Revocation.capturedAt ({lib_dt}) must be clamped >= rotated startHead ({rotated_head_floor})"
    );

    let (cli_ref, cli_dt) = verify_submitted_revocation_wire(
        &posts[2],
        &rotated_root2_vk,
        target_grant_ref,
        "retiring old gateway grant",
        "acme-prod",
    );
    assert_eq!(cli_summary["revocationRef"], cli_ref);
    assert_eq!(cli_summary["recordedRefs"], json!([cli_ref]));
    assert!(
        cli_dt >= rotated_head_floor,
        "CLI Revocation.capturedAt ({cli_dt}) must be clamped >= rotated startHead ({rotated_head_floor})"
    );

    let saved_bytes = fs::read(&out_rev_path).expect("read --out-revocation-file");
    assert_eq!(saved_bytes, posts[2]);

    let _ = fs::remove_dir_all(&tmp_dir);
}

#[test]
fn revoke_grant_dry_run_offline_and_help_safety_note() {
    let help_out = Command::new(env!("CARGO_BIN_EXE_r5e-endpoint-helper"))
        .args(["revoke-grant", "--help"])
        .output()
        .expect("revoke-grant --help");
    assert!(help_out.status.success());
    let help_text = String::from_utf8_lossy(&help_out.stdout);
    assert!(
        help_text.contains("grant-gateway") && help_text.contains("BEFORE revoking"),
        "revoke-grant --help must surface the rotation ordering safety note; got:\n{help_text}"
    );

    let tmp_dir =
        std::env::temp_dir().join(format!("r5e-revoke-dryrun-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp_dir);
    fs::create_dir_all(&tmp_dir).unwrap();
    let seed = [0x55; 32];
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();
    let key_path = tmp_dir.join("operator-root.key");
    let dry_path = tmp_dir.join("revocation-dry-run.json");
    write_private_key_file_0600(&key_path, &seed, true).unwrap();

    let target_ref =
        "evidence:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let dry_out = Command::new(env!("CARGO_BIN_EXE_r5e-endpoint-helper"))
        .args([
            "revoke-grant",
            "--deployment",
            "offline-corp",
            "--grant-ref",
            target_ref,
            "--reason",
            "compromised badge key",
            "--root-key-file",
            key_path.to_str().unwrap(),
            "--dry-run-out",
            dry_path.to_str().unwrap(),
        ])
        .output()
        .expect("offline dry-run revoke-grant");

    assert!(
        dry_out.status.success(),
        "dry-run failed: {}",
        String::from_utf8_lossy(&dry_out.stderr)
    );
    let summary: Value = serde_json::from_slice(&dry_out.stdout).expect("dry-run JSON summary");
    assert_eq!(summary["ok"], true);
    assert_eq!(summary["submitted"], false);
    assert_eq!(summary["safetyNote"], REVOCATION_ROTATION_SAFETY_NOTE);

    let dry_bytes = fs::read(&dry_path).expect("read dry-run file");
    let (rev_ref, _) = verify_submitted_revocation_wire(
        &dry_bytes,
        &vk,
        target_ref,
        "compromised badge key",
        "offline-corp",
    );
    assert_eq!(summary["revocationRef"], rev_ref);

    let _ = fs::remove_dir_all(&tmp_dir);
}

#[test]
fn revoke_grant_surfaces_422_not_entitled_409_not_claimed_413_too_large_and_local_refusals() {
    let outsider_seed = [0x77; 32];
    let outsider_key = SigningKey::from_bytes(&outsider_seed);
    let target_ref =
        "evidence:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    // Local validation refusals before any network traffic:
    let mut bad_reason_params = GrantRevocationParams::new(target_ref, "urn:r5e:stream:acme:");
    bad_reason_params.reason = Some("   ".to_string());
    let err_empty_reason = build_grant_revocation(&outsider_key, &bad_reason_params).unwrap_err();
    assert!(err_empty_reason.contains("non-empty"));

    let bad_target_params =
        GrantRevocationParams::new("not-an-evidence-ref", "urn:r5e:stream:acme:");
    let err_bad_target = build_grant_revocation(&outsider_key, &bad_target_params).unwrap_err();
    assert!(err_bad_target.contains("evidence:sha256:"));

    // Over-max records count refused locally before socket connect:
    let valid_built = build_grant_revocation(
        &outsider_key,
        &GrantRevocationParams::new(target_ref, "urn:r5e:stream:acme:"),
    )
    .unwrap();
    let mut too_many = valid_built.request.clone();
    too_many.records = vec![valid_built.revocation.clone(); MAX_REVOCATION_RECORDS + 1];
    let err_count =
        submit_deployment_revocations(&ClaimClientConfig::new("http://127.0.0.1:9"), &too_many)
            .unwrap_err();
    assert!(matches!(err_count, ClaimError::Validation(_)));

    // Mock HTTP error responses: (status, reason, error_code)
    for (http_code, reason_phrase, err_code) in [
        (422u16, "Unprocessable Entity", "not_entitled"),
        (409u16, "Conflict", "not_claimed"),
        (413u16, "Payload Too Large", "too_large"),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let code_owned = err_code.to_string();
        let phrase_owned = reason_phrase.to_string();
        let handle = thread::spawn(move || {
            // Serve up to 2 connections (`GET /v1/deployment` + `POST /v1/deployment/revocations`)
            for _ in 0..2 {
                if let Ok((mut stream, _)) = listener.accept() {
                    let (method, path, _) = read_http_request(&mut stream);
                    if method == "GET" && path == DEPLOYMENT_STATUS_PATH {
                        write_http_json_response(
                            &mut stream,
                            200,
                            "OK",
                            &json!({
                                "deployment": "acme-prod",
                                "state": if code_owned == "not_claimed" { "unclaimed" } else { "claimed" },
                                "streamPrefix": "urn:r5e:stream:acme-prod:",
                            }),
                        );
                    } else if method == "POST" && path == DEPLOYMENT_REVOCATIONS_PATH {
                        write_http_json_response(
                            &mut stream,
                            http_code,
                            &phrase_owned,
                            &json!({ "error": code_owned }),
                        );
                        break;
                    }
                }
            }
        });

        let cfg = ClaimClientConfig::new(format!("http://{addr}"));
        let err = execute_revoke_grant_ceremony(
            &cfg,
            &outsider_key,
            target_ref,
            Some("test error classification".to_string()),
            None,
            "urn:r5e:operator:root",
        )
        .expect_err("expected gateway error");
        handle.join().unwrap();

        assert_eq!(err.http_status(), Some(http_code));
        assert_eq!(err.error_code(), Some(err_code));
        match http_code {
            422 => assert!(matches!(err, ClaimError::Unprocessable { .. })),
            409 => assert!(matches!(err, ClaimError::Conflict { .. })),
            413 => assert!(matches!(err, ClaimError::PayloadTooLarge { .. })),
            _ => unreachable!(),
        }
    }

    // Also verify CLI exits non-zero and prints clean error message on 422 not_entitled & 409 not_claimed
    let tmp_dir =
        std::env::temp_dir().join(format!("r5e-revoke-err-cli-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp_dir);
    fs::create_dir_all(&tmp_dir).unwrap();
    let key_path = tmp_dir.join("outsider.seed");
    write_private_key_file_0600(&key_path, &outsider_seed, true).unwrap();

    for (http_code, reason_phrase, err_code) in [
        (422u16, "Unprocessable Entity", "not_entitled"),
        (409u16, "Conflict", "not_claimed"),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let code_owned = err_code.to_string();
        let phrase_owned = reason_phrase.to_string();
        let handle = thread::spawn(move || {
            for _ in 0..2 {
                if let Ok((mut stream, _)) = listener.accept() {
                    let (method, path, _) = read_http_request(&mut stream);
                    if method == "GET" && path == DEPLOYMENT_STATUS_PATH {
                        write_http_json_response(
                            &mut stream,
                            200,
                            "OK",
                            &json!({
                                "deployment": "acme-prod",
                                "state": if code_owned == "not_claimed" { "unclaimed" } else { "claimed" },
                                "streamPrefix": "urn:r5e:stream:acme-prod:",
                            }),
                        );
                    } else if method == "POST" && path == DEPLOYMENT_REVOCATIONS_PATH {
                        write_http_json_response(
                            &mut stream,
                            http_code,
                            &phrase_owned,
                            &json!({ "error": code_owned }),
                        );
                        break;
                    }
                }
            }
        });

        let out = Command::new(env!("CARGO_BIN_EXE_r5e-endpoint-helper"))
            .args([
                "revoke-grant",
                "--gateway-url",
                &format!("http://{addr}"),
                "--target",
                target_ref,
                "--reason",
                "unauthorized attempt",
                "--root-key-file",
                key_path.to_str().unwrap(),
            ])
            .output()
            .expect("spawn CLI revoke-grant");
        handle.join().unwrap();

        assert!(!out.status.success());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains(err_code) && stderr.contains(&http_code.to_string()),
            "expected stderr to mention {http_code} and {err_code}, got: {stderr}"
        );
    }

    let _ = fs::remove_dir_all(&tmp_dir);
}

#[test]
fn revoke_grant_by_issuer_batches_unrevoked_grants_and_fails_closed_when_none_match() {
    let retired_root1_key = SigningKey::from_bytes(&[0x61; 32]);
    let retired_root1_id = ed25519_key_id(&retired_root1_key.verifying_key().to_bytes());
    let active_root2_seed = [0x62; 32];
    let active_root2_key = SigningKey::from_bytes(&active_root2_seed);
    let active_root2_vk = active_root2_key.verifying_key();
    let active_root2_id = ed25519_key_id(&active_root2_vk.to_bytes());
    let unused_root3_key = SigningKey::from_bytes(&[0x63; 32]);
    let unused_root3_id = ed25519_key_id(&unused_root3_key.verifying_key().to_bytes());

    let unrevoked_g1 =
        "evidence:sha256:1111111111111111111111111111111111111111111111111111111111111111";
    let unrevoked_g2 =
        "evidence:sha256:2222222222222222222222222222222222222222222222222222222222222222";
    let already_revoked_g3 =
        "evidence:sha256:3333333333333333333333333333333333333333333333333333333333333333";
    let active_root2_grant =
        "evidence:sha256:4444444444444444444444444444444444444444444444444444444444444444";

    let status_with_grants = json!({
        "deployment": "acme-prod",
        "state": "claimed",
        "streamPrefix": "urn:r5e:stream:acme-prod:",
        "grants": [
            {
                "ref": unrevoked_g1,
                "issuer": &retired_root1_id,
                "notBefore": "2026-11-12T10:00:00.000000Z",
                "notAfter": "2026-12-12T10:00:00.000000Z",
                "mayEndorse": true,
                "revoked": false,
                "active": false
            },
            {
                "ref": already_revoked_g3,
                "issuer": &retired_root1_id,
                "notBefore": "2026-11-12T09:00:00.000000Z",
                "notAfter": "2026-12-12T09:00:00.000000Z",
                "mayEndorse": true,
                "revoked": true,
                "active": false
            },
            {
                "ref": unrevoked_g2,
                "issuer": &retired_root1_id,
                "notBefore": "2026-11-12T10:30:00.000000Z",
                "notAfter": "2026-12-12T10:30:00.000000Z",
                "mayEndorse": false,
                "revoked": false,
                "active": false
            },
            {
                "ref": active_root2_grant,
                "issuer": &active_root2_id,
                "notBefore": "2026-11-12T11:00:00.000000Z",
                "notAfter": "2026-12-12T11:00:00.000000Z",
                "mayEndorse": true,
                "revoked": false,
                "active": true
            }
        ]
    });

    let captured_posts: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_posts_srv = Arc::clone(&captured_posts);
    let stop = Arc::new(AtomicBool::new(false));
    let stop_srv = Arc::clone(&stop);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock gateway");
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();

    let srv_handle = thread::spawn(move || {
        while !stop_srv.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    let (method, path, body) = read_http_request(&mut stream);
                    match (method.as_str(), path.as_str()) {
                        ("GET", DEPLOYMENT_STATUS_PATH) => {
                            write_http_json_response(&mut stream, 200, "OK", &status_with_grants);
                        }
                        ("POST", DEPLOYMENT_REVOCATIONS_PATH) => {
                            let parsed: SubmitRevocationsRequest =
                                serde_json::from_slice(&body).expect("parse batch revocations");
                            let refs: Vec<String> = parsed
                                .records
                                .iter()
                                .map(|r| r.record_ref.clone())
                                .collect();
                            captured_posts_srv.lock().unwrap().push(body);
                            write_http_json_response(
                                &mut stream,
                                201,
                                "Created",
                                &json!({ "recorded": refs }),
                            );
                        }
                        other => panic!("unexpected mock request: {other:?}"),
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(e) => panic!("accept error: {e}"),
            }
        }
    });

    let gateway_url = format!("http://{addr}");
    let cfg = ClaimClientConfig::new(&gateway_url);

    // 1. Verify DeploymentStatusResponse parses `grants` cleanly:
    let st = get_deployment_status(&cfg).expect("GET /v1/deployment parses grants");
    assert_eq!(st.grants.len(), 4);
    assert_eq!(st.grants[0].grant_ref, unrevoked_g1);
    assert!(!st.grants[0].revoked);
    assert!(st.grants[1].revoked);
    assert!(st.grants[3].active);

    // 2. Verify CLI `deployment-status` includes `grants` in its canonical JSON output:
    let status_cli = Command::new(env!("CARGO_BIN_EXE_r5e-endpoint-helper"))
        .args(["deployment-status", "--gateway-url", &gateway_url])
        .output()
        .expect("CLI deployment-status");
    assert!(status_cli.status.success());
    let status_cli_val: Value = serde_json::from_slice(&status_cli.stdout).unwrap();
    assert_eq!(status_cli_val["grants"].as_array().unwrap().len(), 4);

    // 3. Verify CLI `revoke-grant --from-root-keyid <retired_root1_id>` selects ONLY the 2
    // unrevoked grants from `retired_root1` and submits them in a single batched POST:
    let tmp_dir =
        std::env::temp_dir().join(format!("r5e-revoke-issuer-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp_dir);
    fs::create_dir_all(&tmp_dir).unwrap();
    let root2_key_path = tmp_dir.join("active-root2.seed");
    write_private_key_file_0600(&root2_key_path, &active_root2_seed, true).unwrap();

    let revoke_cli = Command::new(env!("CARGO_BIN_EXE_r5e-endpoint-helper"))
        .args([
            "revoke-grant",
            "--gateway-url",
            &gateway_url,
            "--from-root-keyid",
            &retired_root1_id,
            "--reason",
            "retiring root1 gateway grants after rotation",
            "--root-key-file",
            root2_key_path.to_str().unwrap(),
        ])
        .output()
        .expect("CLI revoke-grant --from-root-keyid");
    assert!(
        revoke_cli.status.success(),
        "revoke-grant --from-root-keyid failed: {}",
        String::from_utf8_lossy(&revoke_cli.stderr)
    );
    let cli_summary: Value = serde_json::from_slice(&revoke_cli.stdout).unwrap();
    assert_eq!(cli_summary["ok"], true);
    assert_eq!(cli_summary["submitted"], true);
    assert_eq!(cli_summary["status"], 201);
    assert_eq!(cli_summary["count"], 2);
    assert_eq!(cli_summary["issuer"], retired_root1_id);
    assert_eq!(cli_summary["targets"], json!([unrevoked_g1, unrevoked_g2]));
    assert_eq!(cli_summary["recordedRefs"].as_array().unwrap().len(), 2);

    // 4. Fail closed when `--issuer` matches zero grants (no POST sent!):
    let no_match_err = execute_revoke_issuer_grants_ceremony(
        &cfg,
        &active_root2_key,
        &unused_root3_id,
        &[],
        Some("none match".to_string()),
        None,
        "urn:r5e:operator:root",
    )
    .expect_err("must fail closed when no unrevoked grants match issuer");
    assert!(matches!(no_match_err, ClaimError::Validation(_)));
    assert!(no_match_err.to_string().contains("no unrevoked grants"));

    let no_match_cli = Command::new(env!("CARGO_BIN_EXE_r5e-endpoint-helper"))
        .args([
            "revoke-grant",
            "--gateway-url",
            &gateway_url,
            "--issuer",
            &unused_root3_id,
            "--root-key-file",
            root2_key_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!no_match_cli.status.success());
    assert!(String::from_utf8_lossy(&no_match_cli.stderr).contains("no unrevoked grants"));

    stop.store(true, Ordering::Relaxed);
    srv_handle.join().unwrap();

    // Verify ONLY ONE `POST /v1/deployment/revocations` was sent, carrying 2 Revocations,
    // 1 deduplicated signer key, and 2 distinct exact-streamPrefix capture profiles!
    let posts = captured_posts.lock().unwrap();
    assert_eq!(posts.len(), 1);
    let batch_req: SubmitRevocationsRequest = serde_json::from_slice(&posts[0]).unwrap();
    assert_eq!(batch_req.records.len(), 2);
    assert_eq!(
        batch_req.keys.len(),
        1,
        "batch keys must deduplicate signer key"
    );
    assert_eq!(batch_req.keys[0].keyid, active_root2_id);
    assert_eq!(batch_req.blobs.len(), 2);

    let mut seen_streams = std::collections::BTreeSet::new();
    let mut seen_targets = Vec::new();
    for (idx, rec) in batch_req.records.iter().enumerate() {
        let pbytes = decode_strict_base64(&rec.envelope.payload).unwrap();
        let pval: Value = serde_json::from_slice(&pbytes).unwrap();
        assert_eq!(pval["kind"], "Revocation");
        assert_eq!(pval["seq"], 1);
        assert_eq!(pval["previous"], Value::Null);
        let stream = pval["stream"].as_str().unwrap().to_string();
        assert!(stream.starts_with("urn:r5e:stream:acme-prod:authority:revocation:"));
        assert!(
            seen_streams.insert(stream.clone()),
            "streams must be unique"
        );
        seen_targets.push(pval["body"]["target"].as_str().unwrap().to_string());

        let prof_bytes = decode_strict_base64(&batch_req.blobs[idx].base64).unwrap();
        let prof_val: Value = serde_json::from_slice(&prof_bytes).unwrap();
        assert_eq!(pval["profileRef"], batch_req.blobs[idx].blob_ref);
        assert_eq!(prof_val["authority"]["bindings"][0]["streamPrefix"], stream);
        assert_eq!(
            prof_val["authority"]["bindings"][0]["issuerKeys"],
            json!([&active_root2_id])
        );
    }
    assert_eq!(seen_targets, vec![unrevoked_g1, unrevoked_g2]);

    // 5. Also verify failing closed when `GET /v1/deployment` omits `grants` altogether:
    let legacy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let legacy_addr = legacy_listener.local_addr().unwrap();
    let legacy_srv = thread::spawn(move || {
        if let Ok((mut s, _)) = legacy_listener.accept() {
            let _ = read_http_request(&mut s);
            write_http_json_response(
                &mut s,
                200,
                "OK",
                &json!({
                    "deployment": "acme-prod",
                    "state": "claimed",
                    "streamPrefix": "urn:r5e:stream:acme-prod:"
                }),
            );
        }
    });
    let absent_err = execute_revoke_issuer_grants_ceremony(
        &ClaimClientConfig::new(format!("http://{legacy_addr}")),
        &active_root2_key,
        &retired_root1_id,
        &[],
        None,
        None,
        "urn:r5e:operator:root",
    )
    .expect_err("must fail closed when GET /v1/deployment lacks grants array");
    legacy_srv.join().unwrap();
    assert!(absent_err.to_string().contains("grants"));

    let _ = fs::remove_dir_all(&tmp_dir);
}
