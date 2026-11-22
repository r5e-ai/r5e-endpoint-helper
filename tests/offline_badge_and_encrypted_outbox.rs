use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use r5e_endpoint_helper::attestation::{
    bytes_ref, decode_strict_base64, dsse_pae, ed25519_key_id, evidence_ref,
    write_private_key_file_0600, PROVENANCE_V2_PAYLOAD_TYPE,
};
use r5e_endpoint_helper::claim_http::SubmitGrantsRequest;
use r5e_endpoint_helper::evidence_http::{
    AdmittedRecordReceipt, EnrolledStateFile, ShipRecordsRequest, ShipRecordsResponse,
};
use r5e_endpoint_helper::offline_badge::{
    OfflineWorkloadBadgeParams, PreparedOfflineWorkloadBadge,
};
use r5e_endpoint_helper::outbox_cipher::ENCRYPTED_OUTBOX_QUEUE_FORMAT;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_r5e-endpoint-helper")
}

fn temp_test_dir(prefix: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "r5e-eh-offline-outbox-{prefix}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("create temp test dir");
    dir
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

fn read_all_files_recursively(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
    for entry in fs::read_dir(dir).expect("read_dir") {
        let entry = entry.expect("dir entry");
        let p = entry.path();
        if p.is_dir() {
            read_all_files_recursively(&p, out);
        } else {
            out.push((p.clone(), fs::read(&p).expect("read file bytes")));
        }
    }
}

fn verify_grant_bundle_cryptographically(
    grant: &SubmitGrantsRequest,
    expected_deployment: &str,
    expected_endorsement_count: usize,
    expected_principal: &str,
    expected_workload: &str,
) -> (String, String) {
    assert_eq!(
        grant.records.len(),
        expected_endorsement_count + 1,
        "records must contain ONLY [E_0.., Badge]"
    );

    let mut vk_map: BTreeMap<String, VerifyingKey> = BTreeMap::new();
    for k in &grant.keys {
        assert_eq!(k.algorithm, "ed25519");
        let raw = decode_strict_base64(&k.bytes).expect("strict base64 key");
        let arr: [u8; 32] = raw.try_into().expect("32B pubkey");
        assert_eq!(ed25519_key_id(&arr), k.keyid);
        vk_map.insert(k.keyid.clone(), VerifyingKey::from_bytes(&arr).unwrap());
    }

    let mut blob_map: BTreeMap<String, Value> = BTreeMap::new();
    for b in &grant.blobs {
        let raw = decode_strict_base64(&b.base64).expect("strict base64 blob");
        assert_eq!(bytes_ref(&raw), b.blob_ref);
        let parsed: Value = serde_json::from_slice(&raw).expect("CaptureProfile JSON");
        assert_eq!(parsed["format"], "r5e.capture-profile/v2");
        blob_map.insert(b.blob_ref.clone(), parsed);
    }

    // R8 set purity: every blob must be cited as `profileRef` by at least one authority record,
    // and every key must sign at least one authority record!
    let mut cited_profiles = std::collections::BTreeSet::new();
    let mut active_signers = std::collections::BTreeSet::new();

    let badge_rec = grant.records.last().unwrap();
    let badge_bytes = decode_strict_base64(&badge_rec.envelope.payload).unwrap();
    assert_eq!(evidence_ref(&badge_bytes), badge_rec.record_ref);
    let badge_val: Value = serde_json::from_slice(&badge_bytes).unwrap();
    assert_eq!(badge_val["kind"], "Badge");
    assert_eq!(badge_val["seq"], 1);
    assert!(badge_val["previous"].is_null());

    let badge_stream = badge_val["stream"].as_str().unwrap();
    let badge_prefix_expected =
        format!("urn:r5e:stream:{expected_deployment}:authority:badge:offline-");
    let token_hex = badge_stream
        .strip_prefix(&badge_prefix_expected)
        .expect("Badge stream must match authority:badge:offline-<24hex>");
    assert_eq!(token_hex.len(), 24);
    assert!(token_hex
        .bytes()
        .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')));

    let expected_endpoint_prefix =
        format!("urn:r5e:stream:{expected_deployment}:endpoint:offline-{token_hex}:");
    assert_eq!(
        badge_val["body"]["streamPrefixes"],
        json!([&expected_endpoint_prefix])
    );
    assert_eq!(badge_val["body"]["actsFor"], expected_principal);
    assert_eq!(badge_val["body"]["workload"], expected_workload);
    assert_eq!(
        badge_val["body"]["actorPrefixes"][0],
        json!(expected_workload)
    );
    assert!(badge_val["body"].get("mayEndorse").is_none());

    // Verify 2 signatures on Badge:
    assert_eq!(badge_rec.envelope.signatures.len(), 2);
    let badge_pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &badge_bytes);
    for dsig in &badge_rec.envelope.signatures {
        let vk = vk_map.get(&dsig.keyid).expect("Badge signer key present");
        let sb: [u8; 64] = decode_strict_base64(&dsig.sig).unwrap().try_into().unwrap();
        vk.verify(&badge_pae, &Signature::from_bytes(&sb))
            .expect("valid Badge Ed25519 signature");
        active_signers.insert(dsig.keyid.clone());
    }
    assert_eq!(
        badge_rec.envelope.signatures[0].keyid,
        badge_val["issuer"].as_str().unwrap()
    );
    assert_eq!(
        badge_rec.envelope.signatures[1].keyid,
        badge_val["body"]["subject"].as_str().unwrap()
    );
    cited_profiles.insert(badge_val["profileRef"].as_str().unwrap().to_string());

    // Verify Endorsements E_0 .. E_{k-1}:
    for idx in 0..expected_endorsement_count {
        let erec = &grant.records[idx];
        assert_eq!(erec.envelope.signatures.len(), 1);
        let ebytes = decode_strict_base64(&erec.envelope.payload).unwrap();
        assert_eq!(evidence_ref(&ebytes), erec.record_ref);
        let eval: Value = serde_json::from_slice(&ebytes).unwrap();
        assert_eq!(eval["kind"], "Endorsement");
        assert_eq!(eval["seq"], 1);
        assert!(eval["previous"].is_null());

        let epref = eval["profileRef"].as_str().unwrap();
        assert!(blob_map.contains_key(epref));
        cited_profiles.insert(epref.to_string());

        let e_issuer = eval["issuer"].as_str().unwrap();
        let e_subject = eval["body"]["subject"].as_str().unwrap();
        assert_ne!(e_issuer, e_subject, "A5 §4.7 forbids self-endorsement");
        assert_eq!(eval["body"]["mayEndorse"], true);
        assert_eq!(eval["body"]["kinds"], badge_val["body"]["kinds"]);
        assert_eq!(
            eval["body"]["streamPrefixes"],
            json!([&expected_endpoint_prefix])
        );
        assert_eq!(
            eval["body"]["actorPrefixes"],
            badge_val["body"]["actorPrefixes"]
        );
        assert_eq!(eval["body"]["actsFor"], expected_principal);

        let estream = eval["stream"].as_str().unwrap();
        if idx == 0 {
            assert!(eval["body"].get("parent").is_none());
            let root_hex = e_issuer.strip_prefix("key:ed25519:sha256:").unwrap();
            let root_stream_prefix =
                format!("urn:r5e:stream:{expected_deployment}:authority:root:{root_hex}:grant:");
            let gtok = estream
                .strip_prefix(&root_stream_prefix)
                .expect("E_0 stream must be authority:root:<64hex>:grant:<16hex>");
            assert_eq!(gtok.len(), 16);
        } else {
            assert_eq!(
                eval["body"]["parent"].as_str().unwrap(),
                grant.records[idx - 1].record_ref
            );
            let del_prefix = format!("urn:r5e:stream:{expected_deployment}:authority:delegation:");
            let dtok = estream
                .strip_prefix(&del_prefix)
                .expect("intermediate E_i stream must be authority:delegation:<16hex>");
            assert_eq!(dtok.len(), 16);
        }

        let epae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &ebytes);
        let dsig = &erec.envelope.signatures[0];
        assert_eq!(dsig.keyid, e_issuer);
        let vk = vk_map.get(&dsig.keyid).expect("Endorsement signer key");
        let sb: [u8; 64] = decode_strict_base64(&dsig.sig).unwrap().try_into().unwrap();
        vk.verify(&epae, &Signature::from_bytes(&sb))
            .expect("valid Endorsement signature");
        active_signers.insert(dsig.keyid.clone());
    }

    assert_eq!(
        badge_val["body"]["parent"].as_str().unwrap(),
        grant.records[expected_endorsement_count - 1].record_ref
    );

    assert_eq!(
        cited_profiles.len(),
        grant.blobs.len(),
        "R8 set purity: zero extra uncited blobs"
    );
    assert_eq!(
        active_signers.len(),
        grant.keys.len(),
        "R8 set purity: zero extra non-signer keys"
    );

    (badge_rec.record_ref.clone(), expected_endpoint_prefix)
}

#[test]
fn offline_root_workload_badge_chains_airgap_cosign_and_adversarial_refusals() {
    let dir = temp_test_dir("badge-ceremony");
    let r1_path = dir.join("root1.key");
    let r2_path = dir.join("root2.key");
    let r3_path = dir.join("root3.key");
    let del_path = dir.join("delegator.key");
    let wk_path = dir.join("workload.key");
    let wk_pub_path = dir.join("workload.pub.json");

    let r1 = SigningKey::from_bytes(&[0x11; 32]);
    let r2 = SigningKey::from_bytes(&[0x22; 32]);
    let r3 = SigningKey::from_bytes(&[0x33; 32]);
    let del = SigningKey::from_bytes(&[0x44; 32]);
    let wk = SigningKey::from_bytes(&[0x55; 32]);
    let wk_pub_bytes = wk.verifying_key().to_bytes();
    let wk_id = ed25519_key_id(&wk_pub_bytes);

    write_private_key_file_0600(&r1_path, &r1.to_bytes(), true).unwrap();
    write_private_key_file_0600(&r2_path, &r2.to_bytes(), true).unwrap();
    write_private_key_file_0600(&r3_path, &r3.to_bytes(), true).unwrap();
    write_private_key_file_0600(&del_path, &del.to_bytes(), true).unwrap();
    write_private_key_file_0600(&wk_path, &wk.to_bytes(), true).unwrap();
    fs::write(
        &wk_pub_path,
        serde_json::to_vec(&json!({
            "keyid": &wk_id,
            "algorithm": "ed25519",
            "bytes": BASE64_STANDARD.encode(wk_pub_bytes),
        }))
        .unwrap(),
    )
    .unwrap();

    // 1. 1-root ceremony (ephemeral delegator key, `--may-endorse=false`):
    let grant_1r_path = dir.join("grant-1r.json");
    let out_1r = Command::new(bin_path())
        .args([
            "mint-workload-badge",
            "--root-key-file",
            r1_path.to_str().unwrap(),
            "--workload-key-file",
            wk_path.to_str().unwrap(),
            "--deployment",
            "meridian",
            "--principal",
            "urn:r5e:principal:meridian:alice",
            "--workload",
            "urn:r5e:workload:meridian:ci-runner",
            "--permitted-kind",
            "ToolCall",
            "--permitted-kind",
            "ToolResult",
            "--permitted-kind",
            "PolicyDecision",
            "--may-endorse=false",
            "--ttl-seconds",
            "3600",
            "--out-grant-file",
            grant_1r_path.to_str().unwrap(),
        ])
        .output()
        .expect("run 1-root mint-workload-badge");
    assert!(
        out_1r.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out_1r.stderr)
    );
    let sum_1r: Value = serde_json::from_slice(&out_1r.stdout).unwrap();
    assert_eq!(sum_1r["ephemeral_delegator"], true);
    assert!(
        sum_1r["revocation_note"]
            .as_str()
            .unwrap()
            .contains("Revocation")
            || sum_1r["revocation_note"]
                .as_str()
                .unwrap()
                .contains("revocations")
    );
    let grant_1r: SubmitGrantsRequest =
        serde_json::from_slice(&fs::read(&grant_1r_path).unwrap()).unwrap();
    verify_grant_bundle_cryptographically(
        &grant_1r,
        "meridian",
        1,
        "urn:r5e:principal:meridian:alice",
        "urn:r5e:workload:meridian:ci-runner",
    );

    // 2. 1-root with explicit `--delegator-key-file`:
    let grant_1r_del_path = dir.join("grant-1r-del.json");
    let out_1r_del = Command::new(bin_path())
        .args([
            "mint-workload-badge",
            "--root-key-file",
            r1_path.to_str().unwrap(),
            "--delegator-key-file",
            del_path.to_str().unwrap(),
            "--workload-key-file",
            wk_path.to_str().unwrap(),
            "--deployment",
            "meridian",
            "--principal",
            "urn:r5e:principal:meridian:alice",
            "--workload",
            "urn:r5e:workload:meridian:ci-runner",
            "--out-grant-file",
            grant_1r_del_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out_1r_del.status.success());
    let sum_1r_del: Value = serde_json::from_slice(&out_1r_del.stdout).unwrap();
    assert_eq!(sum_1r_del["ephemeral_delegator"], false);
    let grant_1r_del: SubmitGrantsRequest =
        serde_json::from_slice(&fs::read(&grant_1r_del_path).unwrap()).unwrap();
    verify_grant_bundle_cryptographically(
        &grant_1r_del,
        "meridian",
        1,
        "urn:r5e:principal:meridian:alice",
        "urn:r5e:workload:meridian:ci-runner",
    );

    // 3. 2-root chain (`R1 -> R2 -> W`) and 3-root chain (`R1 -> R2 -> R3 -> W`):
    let grant_2r_path = dir.join("grant-2r.json");
    let out_2r = Command::new(bin_path())
        .args([
            "mint-workload-badge",
            "--root-key-file",
            r1_path.to_str().unwrap(),
            "--root-key-file",
            r2_path.to_str().unwrap(),
            "--workload-key-file",
            wk_path.to_str().unwrap(),
            "--deployment",
            "meridian",
            "--principal",
            "urn:r5e:principal:meridian:alice",
            "--workload",
            "urn:r5e:workload:meridian:ci-runner",
            "--out-grant-file",
            grant_2r_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out_2r.status.success());
    let grant_2r: SubmitGrantsRequest =
        serde_json::from_slice(&fs::read(&grant_2r_path).unwrap()).unwrap();
    verify_grant_bundle_cryptographically(
        &grant_2r,
        "meridian",
        1,
        "urn:r5e:principal:meridian:alice",
        "urn:r5e:workload:meridian:ci-runner",
    );

    let grant_3r_path = dir.join("grant-3r.json");
    let out_3r = Command::new(bin_path())
        .args([
            "mint-workload-badge",
            "--root-key-file",
            r1_path.to_str().unwrap(),
            "--root-key-file",
            r2_path.to_str().unwrap(),
            "--root-key-file",
            r3_path.to_str().unwrap(),
            "--workload-key-file",
            wk_path.to_str().unwrap(),
            "--deployment",
            "meridian",
            "--principal",
            "urn:r5e:principal:meridian:alice",
            "--workload",
            "urn:r5e:workload:meridian:ci-runner",
            "--out-grant-file",
            grant_3r_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out_3r.status.success());
    let grant_3r: SubmitGrantsRequest =
        serde_json::from_slice(&fs::read(&grant_3r_path).unwrap()).unwrap();
    verify_grant_bundle_cryptographically(
        &grant_3r,
        "meridian",
        2,
        "urn:r5e:principal:meridian:alice",
        "urn:r5e:workload:meridian:ci-runner",
    );

    // 4. Air-gapped 2-step `--workload-public-key` + `cosign-workload-badge` + retention parity:
    let prepared_path = dir.join("prepared-badge.json");
    let airgap_grant_path = dir.join("grant-airgap.json");
    let airgap_state_path = dir.join("state-airgap.json");
    let prep_out = Command::new(bin_path())
        .args([
            "mint-workload-badge",
            "--root-key-file",
            r1_path.to_str().unwrap(),
            "--root-key-file",
            r2_path.to_str().unwrap(),
            "--workload-public-key",
            wk_pub_path.to_str().unwrap(),
            "--deployment",
            "meridian",
            "--principal",
            "urn:r5e:principal:meridian:alice",
            "--workload",
            "urn:r5e:workload:meridian:laptop-helper",
            "--purpose",
            "laptop-ci-build",
            "--out-prepared-badge",
            prepared_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        prep_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&prep_out.stderr)
    );

    // Tampered prepared draft (injecting forbidden `ModelCall` kind) MUST be refused by `cosign-workload-badge`:
    let mut tampered_prep: PreparedOfflineWorkloadBadge =
        serde_json::from_slice(&fs::read(&prepared_path).unwrap()).unwrap();
    tampered_prep.stream_prefix = "urn:r5e:stream:meridian:endpoint:tampered:".to_string();
    let tampered_prep_path = dir.join("tampered-prepared.json");
    fs::write(
        &tampered_prep_path,
        serde_json::to_vec(&tampered_prep).unwrap(),
    )
    .unwrap();
    let bad_cosign = Command::new(bin_path())
        .args([
            "cosign-workload-badge",
            "--prepared-badge",
            tampered_prep_path.to_str().unwrap(),
            "--workload-key-file",
            wk_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!bad_cosign.status.success());

    // Wrong workload key file on `cosign-workload-badge` MUST be refused:
    let wrong_wk_cosign = Command::new(bin_path())
        .args([
            "cosign-workload-badge",
            "--prepared-badge",
            prepared_path.to_str().unwrap(),
            "--workload-key-file",
            del_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!wrong_wk_cosign.status.success());

    // Honest `cosign-workload-badge` succeeds and emits `0600` EnrolledStateFile with retention parity:
    let ok_cosign = Command::new(bin_path())
        .args([
            "cosign-workload-badge",
            "--prepared-badge",
            prepared_path.to_str().unwrap(),
            "--workload-key-file",
            wk_path.to_str().unwrap(),
            "--retention-disposal",
            "by-record",
            "--keep-content-for-seconds",
            "86400",
            "--out-grant-file",
            airgap_grant_path.to_str().unwrap(),
            "--out-state",
            airgap_state_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        ok_cosign.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&ok_cosign.stderr)
    );
    let loaded_airgap_state = EnrolledStateFile::load(&airgap_state_path).unwrap();
    assert_eq!(
        loaded_airgap_state.retention,
        Some(json!({"disposal": "by-record", "keepContentForSeconds": 86400}))
    );
    assert_eq!(
        loaded_airgap_state.default_actor(),
        "urn:r5e:workload:meridian:laptop-helper"
    );
    assert_eq!(
        loaded_airgap_state.acts_for.as_deref(),
        Some("urn:r5e:principal:meridian:alice")
    );
    assert_eq!(
        loaded_airgap_state.purpose.as_deref(),
        Some("laptop-ci-build")
    );

    // Verify `Badge.body` conforms strictly to `Badge.json` (`additionalProperties: false`) even when `--purpose` is passed:
    let airgap_grant: SubmitGrantsRequest =
        serde_json::from_slice(&fs::read(&airgap_grant_path).unwrap()).unwrap();
    let airgap_badge_payload =
        decode_strict_base64(&airgap_grant.records.last().unwrap().envelope.payload).unwrap();
    let airgap_badge_val: Value = serde_json::from_slice(&airgap_badge_payload).unwrap();
    let airgap_badge_body = airgap_badge_val["body"].as_object().unwrap();
    let allowed_badge_keys = [
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
    assert!(
        !airgap_badge_body.contains_key("purpose"),
        "Badge.body must never contain purpose (Badge.json additionalProperties: false)"
    );
    for k in airgap_badge_body.keys() {
        assert!(
            allowed_badge_keys.contains(&k.as_str()),
            "unexpected property {k:?} in Badge.body"
        );
    }

    // Verify `cosign-workload-badge --gateway-url <url> --out-state <path>` (without `--retention-disposal`)
    // inherits `retention` from `GET /v1/deployment` just like `mint-workload-badge`:
    let ret_gw_state = Arc::new(Mutex::new(MockGrantAndEvidenceGateway::default()));
    let (ret_gw_url, ret_gw_handle) = spawn_mock_grant_and_evidence_gateway(
        "unused-token".to_string(),
        Arc::clone(&ret_gw_state),
    );
    let gw_retention_state_path = dir.join("state-gw-retention.json");
    let gw_ret_cosign = Command::new(bin_path())
        .args([
            "cosign-workload-badge",
            "--prepared-badge",
            prepared_path.to_str().unwrap(),
            "--workload-key-file",
            wk_path.to_str().unwrap(),
            "--gateway-url",
            &ret_gw_url,
            "--out-state",
            gw_retention_state_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        gw_ret_cosign.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&gw_ret_cosign.stderr)
    );
    let loaded_gw_ret_state = EnrolledStateFile::load(&gw_retention_state_path).unwrap();
    assert_eq!(
        loaded_gw_ret_state.retention,
        Some(json!({"disposal": "by-record", "keepContentForSeconds": 7200}))
    );
    if let Ok(mut sock) = std::net::TcpStream::connect(ret_gw_url.strip_prefix("http://").unwrap())
    {
        let _ = write!(sock, "GET /__stop HTTP/1.1\r\nHost: localhost\r\n\r\n");
    }
    let _ = ret_gw_handle.join();

    // 5. Adversarial refusals (`K2` future notBefore, `> 43200s` TTL, `--may-endorse=true`, forbidden kinds, self-endorsement):
    let mut future_params = OfflineWorkloadBadgeParams::new(
        "meridian",
        "urn:r5e:principal:meridian:alice",
        "urn:r5e:workload:meridian:ci",
    );
    future_params.captured_at = Some(
        chrono::DateTime::parse_from_rfc3339("2026-11-14T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
    );
    future_params.not_before = Some("2026-11-14T00:05:00Z".to_string());
    let err_future = r5e_endpoint_helper::offline_badge::mint_offline_workload_badge(
        std::slice::from_ref(&r1),
        None,
        &wk,
        &future_params,
    )
    .unwrap_err();
    assert!(err_future.contains("--not-before"), "got: {err_future}");

    for bad_args in [
        vec![
            "mint-workload-badge",
            "--root-key-file",
            r1_path.to_str().unwrap(),
            "--workload-key-file",
            wk_path.to_str().unwrap(),
            "--deployment",
            "meridian",
            "--principal",
            "urn:r5e:principal:meridian:alice",
            "--workload",
            "urn:r5e:workload:meridian:ci",
            "--ttl-seconds",
            "43201",
        ],
        vec![
            "mint-workload-badge",
            "--root-key-file",
            r1_path.to_str().unwrap(),
            "--workload-key-file",
            wk_path.to_str().unwrap(),
            "--deployment",
            "meridian",
            "--principal",
            "urn:r5e:principal:meridian:alice",
            "--workload",
            "urn:r5e:workload:meridian:ci",
            "--may-endorse=true",
        ],
        vec![
            "mint-workload-badge",
            "--root-key-file",
            r1_path.to_str().unwrap(),
            "--workload-key-file",
            wk_path.to_str().unwrap(),
            "--deployment",
            "meridian",
            "--principal",
            "urn:r5e:principal:meridian:alice",
            "--workload",
            "urn:r5e:workload:meridian:ci",
            "--permitted-kind",
            "ModelCall",
        ],
        vec![
            "mint-workload-badge",
            "--root-key-file",
            r1_path.to_str().unwrap(),
            "--workload-key-file",
            wk_path.to_str().unwrap(),
            "--deployment",
            "meridian",
            "--principal",
            "urn:r5e:principal:meridian:alice",
            "--workload",
            "urn:r5e:workload:meridian:ci",
            "--permitted-kind",
            "Endorsement",
        ],
        vec![
            "mint-workload-badge",
            "--root-key-file",
            r1_path.to_str().unwrap(),
            "--root-key-file",
            r1_path.to_str().unwrap(),
            "--workload-key-file",
            wk_path.to_str().unwrap(),
            "--deployment",
            "meridian",
            "--principal",
            "urn:r5e:principal:meridian:alice",
            "--workload",
            "urn:r5e:workload:meridian:ci",
        ],
    ] {
        let bad_res = Command::new(bin_path()).args(&bad_args).output().unwrap();
        assert!(
            !bad_res.status.success(),
            "expected refusal for args: {bad_args:?}"
        );
    }

    let _ = fs::remove_dir_all(&dir);
}

#[derive(Default)]
struct MockGrantAndEvidenceGateway {
    grants_received: Vec<SubmitGrantsRequest>,
    evidence_batches: Vec<ShipRecordsRequest>,
}

fn spawn_mock_grant_and_evidence_gateway(
    expected_token: String,
    state: Arc<Mutex<MockGrantAndEvidenceGateway>>,
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock gateway");
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");

    let handle = thread::spawn(move || {
        for stream_res in listener.incoming() {
            let Ok(mut sock) = stream_res else {
                break;
            };
            let mut reader = BufReader::new(sock.try_clone().unwrap());
            let mut req_line = String::new();
            if reader.read_line(&mut req_line).unwrap_or(0) == 0 {
                continue;
            }
            let parts: Vec<&str> = req_line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            let method = parts[0].to_string();
            let path = parts[1].to_string();

            let mut content_len = 0usize;
            let mut auth_hdr = String::new();
            loop {
                let mut hline = String::new();
                if reader.read_line(&mut hline).unwrap_or(0) == 0 {
                    break;
                }
                let trimmed = hline.trim_end_matches(&['\r', '\n'][..]);
                if trimmed.is_empty() {
                    break;
                }
                if let Some((k, v)) = trimmed.split_once(':') {
                    if k.trim().eq_ignore_ascii_case("content-length") {
                        content_len = v.trim().parse().unwrap_or(0);
                    } else if k.trim().eq_ignore_ascii_case("authorization") {
                        auth_hdr = v.trim().to_string();
                    }
                }
            }
            let mut body_buf = vec![0u8; content_len];
            if content_len > 0 {
                reader.read_exact(&mut body_buf).unwrap();
            }

            if method == "GET" && path == "/__stop" {
                let _ = sock.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                );
                break;
            }

            let respond = |sock: &mut std::net::TcpStream, code: u16, reason: &str, val: Value| {
                let bytes = serde_json::to_vec(&val).unwrap();
                let _ = write!(
                    sock,
                    "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    bytes.len()
                );
                let _ = sock.write_all(&bytes);
                let _ = sock.flush();
            };

            match (method.as_str(), path.as_str()) {
                ("GET", "/v1/deployment") => {
                    respond(
                        &mut sock,
                        200,
                        "OK",
                        json!({
                            "state": "claimed",
                            "deployment": "meridian",
                            "streamPrefix": "urn:r5e:stream:meridian:",
                            "retention": {
                                "disposal": "by-record",
                                "keepContentForSeconds": 7200
                            }
                        }),
                    );
                }
                ("POST", "/v1/deployment/grants") => {
                    let req: SubmitGrantsRequest = serde_json::from_slice(&body_buf).unwrap();
                    let recorded: Vec<String> =
                        req.records.iter().map(|r| r.record_ref.clone()).collect();
                    let badge_ref = recorded.last().cloned().unwrap_or_default();
                    state.lock().unwrap().grants_received.push(req);
                    respond(
                        &mut sock,
                        201,
                        "Created",
                        json!({
                            "recorded": recorded,
                            "badge": badge_ref,
                            "sealed": true,
                        }),
                    );
                }
                ("POST", "/v1/evidence/records") => {
                    if auth_hdr != format!("Bearer {expected_token}") {
                        respond(
                            &mut sock,
                            401,
                            "Unauthorized",
                            json!({"error": "unauthenticated"}),
                        );
                        continue;
                    }
                    let req: ShipRecordsRequest = serde_json::from_slice(&body_buf).unwrap();
                    let admitted: Vec<AdmittedRecordReceipt> = req
                        .records
                        .iter()
                        .map(|r| {
                            let pbytes = decode_strict_base64(&r.envelope.payload).unwrap();
                            let pval: Value = serde_json::from_slice(&pbytes).unwrap();
                            AdmittedRecordReceipt {
                                record_ref: r.record_ref.clone(),
                                stream: pval["stream"].as_str().unwrap_or_default().to_string(),
                                seq: pval["seq"].as_u64().unwrap_or(1),
                                status: "admitted".to_string(),
                                content_held: Vec::new(),
                                content_missing: Vec::new(),
                            }
                        })
                        .collect();
                    state.lock().unwrap().evidence_batches.push(req);
                    let resp = ShipRecordsResponse {
                        admitted,
                        http_status: Some(201),
                    };
                    respond(
                        &mut sock,
                        201,
                        "Created",
                        serde_json::to_value(resp).unwrap(),
                    );
                }
                _ => {
                    respond(&mut sock, 404, "Not Found", json!({"error": "not_found"}));
                }
            }
        }
    });

    (url, handle)
}

#[test]
fn encrypted_outbox_zero_plaintext_on_disk_tamper_refusal_and_legacy_flush_compat() {
    let dir = temp_test_dir("encrypted-outbox");
    let root_path = dir.join("root.key");
    let wk_gen_path = dir.join("workload-gen.key");
    let grant_path = dir.join("offline-grant.json");
    let state_path = dir.join("offline-state.json");
    let policy_path = dir.join("endpoint.cedar");
    let outbox_key_path = dir.join("outbox.key");
    let wrong_key_path = dir.join("wrong-outbox.key");
    let enc_outbox_dir = dir.join("enc-outbox");
    let plain_outbox_dir = dir.join("plain-outbox");
    let plain_state_path = dir.join("plain-state.json");

    let r1 = SigningKey::from_bytes(&[0x71; 32]);
    write_private_key_file_0600(&root_path, &r1.to_bytes(), true).unwrap();

    fs::write(
        &policy_path,
        r#"
permit(
    principal == Recurse::Agent::"endpoint-helper",
    action == Recurse::Action::"ExecCommand",
    resource
);
permit(
    principal == Recurse::Agent::"endpoint-helper",
    action == Recurse::Action::"InvokeMcpTool",
    resource
);
"#,
    )
    .unwrap();

    // Generate two distinct 0600 32-byte outbox keys via CLI:
    let gen1 = Command::new(bin_path())
        .args([
            "generate-outbox-key",
            "--out",
            outbox_key_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(gen1.status.success());
    let gen2 = Command::new(bin_path())
        .args([
            "generate-outbox-key",
            "--out",
            wrong_key_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(gen2.status.success());

    // Mint offline workload badge + two independent EnrolledStateFiles (`offline-state` & `plain-state`):
    let closed_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_addr = closed_listener.local_addr().unwrap();
    drop(closed_listener);
    let unreachable_gw = format!("http://{closed_addr}");

    let mint_out = Command::new(bin_path())
        .args([
            "mint-workload-badge",
            "--root-key-file",
            root_path.to_str().unwrap(),
            "--generate-workload-key-out",
            wk_gen_path.to_str().unwrap(),
            "--deployment",
            "meridian",
            "--gateway-url",
            &unreachable_gw,
            "--principal",
            "urn:r5e:principal:meridian:bob",
            "--workload",
            "urn:r5e:workload:meridian:bob-laptop",
            "--policy-file",
            policy_path.to_str().unwrap(),
            "--out-grant-file",
            grant_path.to_str().unwrap(),
            "--out-state",
            state_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        mint_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&mint_out.stderr)
    );
    fs::copy(&state_path, &plain_state_path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&plain_state_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    // 1. Offline `exec` + `mcp-proxy` with `--outbox-key-file` while gateway is unreachable:
    let canary_exec = "CANARY_SECRET_EXEC_PAYLOAD_99887766_DO_NOT_STORE_PLAINTEXT";
    let canary_mcp = "CANARY_SECRET_MCP_TOOL_RESULT_55443322_DO_NOT_STORE_PLAINTEXT";
    let bearer_tok = "r5e-test-bearer-secret-918273";

    let exec_res = Command::new(bin_path())
        .env("R5E_TOKEN", bearer_tok)
        .args([
            "exec",
            "--state",
            state_path.to_str().unwrap(),
            "--outbox",
            enc_outbox_dir.to_str().unwrap(),
            "--outbox-key-file",
            outbox_key_path.to_str().unwrap(),
            "--ship",
            "--",
            "/bin/sh",
            "-c",
            &format!("printf '%s' '{canary_exec}'"),
        ])
        .output()
        .unwrap();
    assert!(
        exec_res.status.success(),
        "exec stderr: {}",
        String::from_utf8_lossy(&exec_res.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&exec_res.stdout), canary_exec);

    // Run `mcp-proxy` offline with the same encrypted outbox:
    let mcp_server_script = format!(
        r#"while IFS= read -r line; do
  case "$line" in
    *'"tools/list"'*)
      printf '%s\n' '{{"jsonrpc":"2.0","id":1,"result":{{"tools":[{{"name":"secret_lookup","description":"lookup","inputSchema":{{"type":"object"}}}}]}}}}'
      ;;
    *'"tools/call"'*)
      printf '%s\n' '{{"jsonrpc":"2.0","id":2,"result":{{"content":[{{"type":"text","text":"{canary_mcp}"}}]}}}}'
      exit 0
      ;;
  esac
done"#
    );
    let mut mcp_child = Command::new(bin_path())
        .env("R5E_TOKEN", bearer_tok)
        .args([
            "mcp-proxy",
            "--server-id",
            "vault",
            "--state",
            state_path.to_str().unwrap(),
            "--outbox",
            enc_outbox_dir.to_str().unwrap(),
            "--outbox-key-file",
            outbox_key_path.to_str().unwrap(),
            "--ship",
            "--",
            "/bin/sh",
            "-c",
            &mcp_server_script,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let cstdin = mcp_child.stdin.as_mut().unwrap();
        writeln!(
            cstdin,
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{{}}}}"#
        )
        .unwrap();
        writeln!(
            cstdin,
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"secret_lookup","arguments":{{"q":"{canary_mcp}"}}}}}}"#
        )
        .unwrap();
    }
    let mcp_out = mcp_child.wait_with_output().unwrap();
    assert!(
        mcp_out.status.success(),
        "mcp-proxy stderr: {}",
        String::from_utf8_lossy(&mcp_out.stderr)
    );

    // 2. Recursive byte scan of `enc_outbox_dir`: ZERO plaintext, ZERO base64 canary, ZERO refs/URLs!
    let mut disk_files = Vec::new();
    read_all_files_recursively(&enc_outbox_dir, &mut disk_files);
    assert_eq!(
        disk_files.len(),
        1,
        "expected only outbox-queue.json in enc_outbox_dir"
    );
    let (qfile_path, qfile_bytes) = &disk_files[0];

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&enc_outbox_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(qfile_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    for forbidden_needle in [
        canary_exec.as_bytes(),
        BASE64_STANDARD.encode(canary_exec).as_bytes(),
        canary_mcp.as_bytes(),
        BASE64_STANDARD.encode(canary_mcp).as_bytes(),
        b"evidence:sha256:",
        b"bytes:sha256:",
        b"key:ed25519:",
        b"127.0.0.1",
        b"ToolCall",
        b"ToolResult",
    ] {
        assert!(
            !contains_subslice(qfile_bytes, forbidden_needle),
            "encrypted outbox leaked plaintext/metadata needle: {:?}",
            String::from_utf8_lossy(forbidden_needle)
        );
    }
    let enc_json: Value = serde_json::from_slice(qfile_bytes).unwrap();
    assert_eq!(enc_json["format"], ENCRYPTED_OUTBOX_QUEUE_FORMAT);
    assert_eq!(enc_json["cipher"], "chacha20-poly1305");
    assert!(!enc_json["records"].as_array().unwrap().is_empty());
    assert!(!enc_json["blobs"].as_array().unwrap().is_empty());

    // 3. Adversarial checks on key permissions, missing key, wrong key, tampering, and downgrade:
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let insecure_key_path = dir.join("insecure-0644.key");
        fs::copy(&outbox_key_path, &insecure_key_path).unwrap();
        fs::set_permissions(&insecure_key_path, fs::Permissions::from_mode(0o644)).unwrap();
        let bad_perm_res = Command::new(bin_path())
            .env("R5E_TOKEN", bearer_tok)
            .args([
                "flush-outbox",
                "--outbox",
                enc_outbox_dir.to_str().unwrap(),
                "--outbox-key-file",
                insecure_key_path.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(!bad_perm_res.status.success());
        assert!(String::from_utf8_lossy(&bad_perm_res.stderr).contains("0600"));
    }

    // Flush without key -> refused!
    let no_key_flush = Command::new(bin_path())
        .env("R5E_TOKEN", bearer_tok)
        .args(["flush-outbox", "--outbox", enc_outbox_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!no_key_flush.status.success());
    assert!(String::from_utf8_lossy(&no_key_flush.stderr).contains("encrypted"));

    // Exec on encrypted outbox without key -> refused BEFORE spawning child!
    let marker_file = dir.join("should-not-exist");
    let no_key_exec = Command::new(bin_path())
        .args([
            "exec",
            "--state",
            state_path.to_str().unwrap(),
            "--outbox",
            enc_outbox_dir.to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            &format!("touch '{}'", marker_file.display()),
        ])
        .output()
        .unwrap();
    assert!(!no_key_exec.status.success());
    assert!(
        !marker_file.exists(),
        "child must not spawn when encrypted outbox lacks key"
    );

    // Flush with wrong key -> refused!
    let wrong_key_flush = Command::new(bin_path())
        .env("R5E_TOKEN", bearer_tok)
        .args([
            "flush-outbox",
            "--outbox",
            enc_outbox_dir.to_str().unwrap(),
            "--outbox-key-file",
            wrong_key_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!wrong_key_flush.status.success());
    assert!(
        String::from_utf8_lossy(&wrong_key_flush.stderr).contains("authentication tag mismatch")
    );

    // Tampered manifest (deleting `records[0]` while keeping `meta`) -> refused!
    let saved_good_bytes = qfile_bytes.clone();
    let mut deleted_rec_json = enc_json.clone();
    deleted_rec_json["records"]
        .as_array_mut()
        .unwrap()
        .remove(0);
    fs::write(qfile_path, serde_json::to_vec(&deleted_rec_json).unwrap()).unwrap();
    let tamper_flush = Command::new(bin_path())
        .env("R5E_TOKEN", bearer_tok)
        .args([
            "flush-outbox",
            "--outbox",
            enc_outbox_dir.to_str().unwrap(),
            "--outbox-key-file",
            outbox_key_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!tamper_flush.status.success());

    // Duplicate entry `id` inside `records` -> explicitly refused by `decrypt_outbox_parts`!
    let mut dup_id_doc: r5e_endpoint_helper::outbox_cipher::EncryptedOutboxQueueFile =
        serde_json::from_slice(&saved_good_bytes).unwrap();
    dup_id_doc.records[1].id = dup_id_doc.records[0].id.clone();
    let loaded_key =
        r5e_endpoint_helper::outbox_cipher::OutboxKey::load_from_file_0600(&outbox_key_path)
            .unwrap();
    let dup_err =
        r5e_endpoint_helper::outbox_cipher::decrypt_outbox_parts(&loaded_key, &dup_id_doc)
            .unwrap_err();
    assert!(
        dup_err.contains("duplicate encrypted outbox record entry id"),
        "got: {dup_err}"
    );

    // Restore valid encrypted outbox bytes:
    fs::write(qfile_path, &saved_good_bytes).unwrap();

    // 4. Legacy unencrypted outbox (`plain_outbox_dir`, no key) queues and flushes seamlessly:
    let plain_exec = Command::new(bin_path())
        .args([
            "exec",
            "--state",
            plain_state_path.to_str().unwrap(),
            "--outbox",
            plain_outbox_dir.to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            "printf 'legacy-plain-ok'",
        ])
        .output()
        .unwrap();
    assert!(plain_exec.status.success());

    // Downgrade check: passing `--outbox-key-file` against a plaintext outbox is refused:
    let downgrade_check = Command::new(bin_path())
        .env("R5E_TOKEN", bearer_tok)
        .args([
            "flush-outbox",
            "--outbox",
            plain_outbox_dir.to_str().unwrap(),
            "--outbox-key-file",
            outbox_key_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!downgrade_check.status.success());

    // 5. Start live mock gateway, run `submit-grant`, flush BOTH encrypted (via `R5E_OUTBOX_KEY_FILE`) and legacy plaintext outboxes!
    let gw_state = Arc::new(Mutex::new(MockGrantAndEvidenceGateway::default()));
    let (live_gw_url, gw_handle) =
        spawn_mock_grant_and_evidence_gateway(bearer_tok.to_string(), Arc::clone(&gw_state));

    let submit_res = Command::new(bin_path())
        .args([
            "submit-grant",
            "--gateway-url",
            &live_gw_url,
            "--grant-file",
            grant_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        submit_res.status.success(),
        "submit-grant stderr: {}",
        String::from_utf8_lossy(&submit_res.stderr)
    );
    let submit_json: Value = serde_json::from_slice(&submit_res.stdout).unwrap();
    assert_eq!(submit_json["status"], 201);
    assert_eq!(submit_json["sealed"], true);

    let enc_flush_ok = Command::new(bin_path())
        .env("R5E_TOKEN", bearer_tok)
        .env("R5E_OUTBOX_KEY_FILE", outbox_key_path.to_str().unwrap())
        .args([
            "flush-outbox",
            "--outbox",
            enc_outbox_dir.to_str().unwrap(),
            "--gateway-url",
            &live_gw_url,
            "--state",
            state_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        enc_flush_ok.status.success(),
        "enc flush stderr: {}",
        String::from_utf8_lossy(&enc_flush_ok.stderr)
    );
    let enc_flush_summary: Value = serde_json::from_slice(&enc_flush_ok.stdout).unwrap();
    assert_eq!(enc_flush_summary["encrypted"], true);
    assert_eq!(enc_flush_summary["pending_after"], 0);
    assert!(enc_flush_summary["flushed"].as_u64().unwrap() >= 6);

    let plain_flush_ok = Command::new(bin_path())
        .env("R5E_TOKEN", bearer_tok)
        .args([
            "flush-outbox",
            "--outbox",
            plain_outbox_dir.to_str().unwrap(),
            "--gateway-url",
            &live_gw_url,
        ])
        .output()
        .unwrap();
    assert!(
        plain_flush_ok.status.success(),
        "plain flush stderr: {}",
        String::from_utf8_lossy(&plain_flush_ok.stderr)
    );
    let plain_flush_summary: Value = serde_json::from_slice(&plain_flush_ok.stdout).unwrap();
    assert_eq!(plain_flush_summary["encrypted"], false);
    assert_eq!(plain_flush_summary["pending_after"], 0);
    assert_eq!(plain_flush_summary["flushed"], 3);

    // Verify gateway received our grant AND decrypted our exact canary blobs:
    {
        let st = gw_state.lock().unwrap();
        assert_eq!(st.grants_received.len(), 1);
        let mut all_blob_bytes = Vec::new();
        for batch in &st.evidence_batches {
            for b in &batch.blobs {
                all_blob_bytes.extend_from_slice(&decode_strict_base64(&b.base64).unwrap());
            }
        }
        assert!(contains_subslice(&all_blob_bytes, canary_exec.as_bytes()));
        assert!(contains_subslice(&all_blob_bytes, canary_mcp.as_bytes()));
    }

    // Stop mock gateway cleanly:
    if let Ok(mut sock) = std::net::TcpStream::connect(live_gw_url.strip_prefix("http://").unwrap())
    {
        let _ = write!(sock, "GET /__stop HTTP/1.1\r\nHost: localhost\r\n\r\n");
    }
    let _ = gw_handle.join();
    let _ = fs::remove_dir_all(&dir);
}
