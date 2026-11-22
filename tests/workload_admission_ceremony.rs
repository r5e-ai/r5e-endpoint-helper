use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use r5e_endpoint_helper::attestation::{
    base_v2_schema_map, bytes_ref, decode_strict_base64, dsse_pae, ed25519_key_id,
    encode_canonical_json, sign_v2_record_multi, BlobEntry, CaptureProfile, DsseEnvelope,
    DsseSignature, EnrolledSessionOptions, FinalizeBadgeRequest, FinalizedBadgeResponse,
    PrepareBadgeRequest, PreparedBadgeResponse, PublicKeyEntry, SignedEndpointRecord,
    PROVENANCE_V2_PAYLOAD_TYPE,
};
use r5e_endpoint_helper::claim_http::{default_gateway_grant_kinds, default_workload_badge_kinds};
use r5e_endpoint_helper::enrolment_http::{
    enrol_endpoint_badge, enrol_endpoint_badge_with_options, EnrolBadgeOptions,
    EnrolmentClientConfig,
};
use r5e_endpoint_helper::evidence_http::{
    build_ship_request_from_recorder, is_admissible_workload_kind, open_session_over_http,
    revoke_badge_over_http, ship_records_over_http, AdmittedRecordReceipt, EnrolledStateFile,
    EvidenceClientConfig, EvidenceHttpError, OpenSessionRequest, ShipRecordsRequest,
    MAX_RECORDS_PER_BATCH,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

#[test]
fn default_gateway_grant_kinds_has_all_16_kinds_and_workload_defaults_match_a8() {
    let gw_kinds = default_gateway_grant_kinds();
    assert_eq!(
        gw_kinds,
        vec![
            "provenance.r5e.io/v2/SessionOpened",
            "provenance.r5e.io/v2/SessionClosed",
            "provenance.r5e.io/v2/PolicyDecision",
            "provenance.r5e.io/v2/ToolCall",
            "provenance.r5e.io/v2/ToolResult",
            "provenance.r5e.io/v2/Observation",
            "provenance.r5e.io/v2/ModelCall",
            "provenance.r5e.io/v2/ModelResponse",
            "provenance.r5e.io/v2/Disclosure",
            "provenance.r5e.io/v2/Verification",
            "provenance.r5e.io/v2/EpochSeal",
            "provenance.r5e.io/v2/Badge",
            "provenance.r5e.io/v2/Checkpoint",
            "provenance.r5e.io/v2/RetentionHold",
            "provenance.r5e.io/v2/RetentionHoldRelease",
            "provenance.r5e.io/v2/PayloadDisposition",
        ]
    );
    assert_eq!(gw_kinds.len(), 16);

    let wl_kinds = default_workload_badge_kinds();
    assert_eq!(
        wl_kinds,
        vec![
            "provenance.r5e.io/v2/SessionOpened",
            "provenance.r5e.io/v2/SessionClosed",
            "provenance.r5e.io/v2/PolicyDecision",
            "provenance.r5e.io/v2/ToolCall",
            "provenance.r5e.io/v2/ToolResult",
            "provenance.r5e.io/v2/Observation",
            "provenance.r5e.io/v2/Disclosure",
            "provenance.r5e.io/v2/Verification",
        ]
    );
    for k in &wl_kinds {
        assert!(is_admissible_workload_kind(k), "{k} must be admissible");
    }

    for forbidden in [
        "Badge",
        "provenance.r5e.io/v2/Badge",
        "provenance.r5e.io/v2/Endorsement",
        "provenance.r5e.io/v2/ChainStarted",
        "provenance.r5e.io/v2/Deployment",
        "provenance.r5e.io/v2/RootsChanged",
        "provenance.r5e.io/v2/RootChangeApproval",
        "provenance.r5e.io/v2/Revocation",
        "provenance.r5e.io/v2/EpochSeal",
        "provenance.r5e.io/v2/Checkpoint",
        "provenance.r5e.io/v2/DefinitionPublished",
        "provenance.r5e.io/v2/PublishedView",
        "provenance.r5e.io/v2/RetentionHold",
        "provenance.r5e.io/v2/RetentionHoldRelease",
        "provenance.r5e.io/v2/PayloadDisposition",
    ] {
        assert!(
            !is_admissible_workload_kind(forbidden),
            "{forbidden} must be rejected as workload operational kind"
        );
    }
}

#[derive(Default)]
struct MockA8GatewayState {
    gateway_retention: Option<Value>,
    expected_bearer: String,
    acts_for: Option<String>,
    opened_sessions: BTreeMap<String, String>, // session_urn -> principal
    received_client_session_ids: Vec<Option<String>>,
    session_counter: u64,
    revoked_badges: BTreeMap<String, String>, // badge_ref -> reason
    admitted_refs: BTreeSet<String>,
    held_blobs: BTreeSet<String>,
    stream_heads: BTreeMap<String, (u64, String)>,
    batch_sizes: Vec<usize>,
    prepared_badge_payload: Option<String>,
}

fn effective_retention_key(retention: Option<&Value>) -> String {
    match retention {
        None => "never".to_string(),
        Some(v) => match v.get("disposal").and_then(Value::as_str) {
            Some("never") => "never".to_string(),
            Some("by-record") => {
                let secs = v
                    .get("keepContentForSeconds")
                    .and_then(Value::as_u64)
                    .unwrap_or(u64::MAX);
                format!("keep_for:{secs}")
            }
            other => format!("invalid:{other:?}"),
        },
    }
}

fn spawn_mock_a8_gateway(
    state: Arc<Mutex<MockA8GatewayState>>,
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock A8 gateway");
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");

    let root_key = SigningKey::from_bytes(&[0x31; 32]);
    let gw_key = SigningKey::from_bytes(&[0x32; 32]);
    let root_id = ed25519_key_id(&root_key.verifying_key().to_bytes());
    let gw_id = ed25519_key_id(&gw_key.verifying_key().to_bytes());

    let handle = thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(mut sock) = incoming else { break };
            let mut reader = BufReader::new(sock.try_clone().unwrap());
            let mut req_line = String::new();
            if reader.read_line(&mut req_line).unwrap_or(0) == 0 {
                continue;
            }
            if req_line.starts_with("POST /__stop ") {
                let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
                break;
            }
            let parts: Vec<&str> = req_line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            let (method, path) = (parts[0], parts[1]);

            let mut content_len = 0usize;
            let mut auth_hdr = String::new();
            loop {
                let mut hdr = String::new();
                reader.read_line(&mut hdr).unwrap();
                let t = hdr.trim_end_matches(&['\r', '\n'][..]);
                if t.is_empty() {
                    break;
                }
                if let Some((n, v)) = t.split_once(':') {
                    if n.trim().eq_ignore_ascii_case("content-length") {
                        content_len = v.trim().parse().unwrap_or(0);
                    } else if n.trim().eq_ignore_ascii_case("authorization") {
                        auth_hdr = v.trim().to_string();
                    }
                }
            }
            let mut body_buf = vec![0u8; content_len];
            reader.read_exact(&mut body_buf).unwrap();

            let respond = |sock: &mut std::net::TcpStream,
                           status: u16,
                           reason: &str,
                           val: Value| {
                let bytes = serde_json::to_vec(&val).unwrap();
                let head = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    bytes.len()
                );
                sock.write_all(head.as_bytes()).unwrap();
                sock.write_all(&bytes).unwrap();
                sock.flush().unwrap();
            };

            let mut st = state.lock().unwrap();
            let expected_auth = format!("Bearer {}", st.expected_bearer);
            if auth_hdr != expected_auth {
                respond(
                    &mut sock,
                    401,
                    "Unauthorized",
                    json!({ "error": "unauthenticated" }),
                );
                continue;
            }

            // Build gateway's CaptureProfile blob with `st.gateway_retention`:
            let mut gw_prof = json!({
                "format": "r5e.capture-profile/v2",
                "schemas": Value::Object(base_v2_schema_map()),
                "authority": {
                    "bindings": [{
                        "streamPrefix": "urn:r5e:stream:meridian:",
                        "actorPrefixes": ["urn:r5e:"],
                        "issuerKeys": [&root_id, &gw_id],
                        "sealerKeys": [&gw_id],
                    }],
                    "checkpointKeys": [],
                },
                "durability": {
                    "failureDomain": "gateway-db",
                    "requiredPayloads": "submitted",
                    "onFailure": "refuse",
                },
                "policyRequiredKinds": [],
            });
            if let Some(ref ret) = st.gateway_retention {
                gw_prof
                    .as_object_mut()
                    .unwrap()
                    .insert("retention".to_string(), ret.clone());
            }
            let gw_prof_bytes = encode_canonical_json(&gw_prof).unwrap();
            let gw_prof_ref = bytes_ref(&gw_prof_bytes);

            let schemas = base_v2_schema_map();

            match (method, path) {
                ("POST", "/v1/authority/badges/prepare") => {
                    let prep_req: PrepareBadgeRequest = serde_json::from_slice(&body_buf).unwrap();
                    let subject_raw = decode_strict_base64(&prep_req.subject_key.bytes).unwrap();
                    let subject_arr: [u8; 32] = subject_raw.try_into().unwrap();
                    let subject_id = ed25519_key_id(&subject_arr);
                    let short_hex = &subject_id[subject_id.len() - 12..];
                    let wl_stream_prefix = format!("urn:r5e:stream:meridian:workload:{short_hex}:");

                    let mut actor_prefixes = Vec::new();
                    if let Some(ref af) = st.acts_for {
                        actor_prefixes.push(af.clone());
                    } else {
                        actor_prefixes.push("urn:r5e:service:ci".to_string());
                    }
                    if let Some(ref w) = prep_req.workload {
                        if !actor_prefixes.contains(w) {
                            actor_prefixes.push(w.clone());
                        }
                    }

                    let mut badge_body = json!({
                        "subject": &subject_id,
                        "subjectKey": {
                            "algorithm": "ed25519",
                            "bytes": &prep_req.subject_key.bytes,
                        },
                        "holder": &prep_req.holder,
                        "parent": "evidence:sha256:1111111111111111111111111111111111111111111111111111111111111111",
                        "streamPrefixes": [&wl_stream_prefix],
                        "actorPrefixes": actor_prefixes,
                        "kinds": &prep_req.requested_kinds,
                        "notBefore": "2026-11-12T11:59:00.000000Z",
                        "notAfter": "2026-11-12T13:00:00.000000Z",
                    });
                    if let Some(ref af) = st.acts_for {
                        badge_body
                            .as_object_mut()
                            .unwrap()
                            .insert("actsFor".to_string(), Value::String(af.clone()));
                    }
                    if let Some(ref w) = prep_req.workload {
                        badge_body
                            .as_object_mut()
                            .unwrap()
                            .insert("workload".to_string(), Value::String(w.clone()));
                    }

                    let badge_env = json!({
                        "apiVersion": "provenance.r5e.io/v2",
                        "kind": "Badge",
                        "schemaRef": schemas["provenance.r5e.io/v2/Badge"],
                        "profileRef": &gw_prof_ref,
                        "issuer": &gw_id,
                        "stream": format!("urn:r5e:stream:meridian:authority:badge:{short_hex}"),
                        "seq": 1,
                        "previous": null,
                        "actor": "urn:r5e:gateway:meridian",
                        "capturedAt": "2026-11-12T12:00:00.000000Z",
                        "body": badge_body,
                    });
                    let payload_bytes = encode_canonical_json(&badge_env).unwrap();
                    let payload_b64 = BASE64_STANDARD.encode(&payload_bytes);
                    st.prepared_badge_payload = Some(payload_b64.clone());

                    let resp = PreparedBadgeResponse {
                        ticket: "stateless-hmac-ticket-a8".to_string(),
                        payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
                        payload: payload_b64,
                    };
                    respond(&mut sock, 200, "OK", serde_json::to_value(resp).unwrap());
                }
                ("POST", "/v1/authority/badges/finalize") => {
                    let fin_req: FinalizeBadgeRequest = serde_json::from_slice(&body_buf).unwrap();
                    assert_eq!(
                        Some(fin_req.payload.as_str()),
                        st.prepared_badge_payload.as_deref()
                    );
                    let payload_bytes = decode_strict_base64(&fin_req.payload).unwrap();
                    let parsed_badge: Value = serde_json::from_slice(&payload_bytes).unwrap();
                    let wl_stream_prefix = parsed_badge["body"]["streamPrefixes"][0]
                        .as_str()
                        .unwrap()
                        .to_string();

                    let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &payload_bytes);
                    let gw_sig = gw_key.sign(&pae);
                    let badge_ref = format!(
                        "evidence:sha256:{}",
                        hex_lower(&Sha256::digest(&payload_bytes))
                    );

                    let mut end_map: Map<String, Value> = serde_json::from_value(json!({
                        "apiVersion": "provenance.r5e.io/v2",
                        "kind": "Endorsement",
                        "schemaRef": schemas["provenance.r5e.io/v2/Endorsement"],
                        "profileRef": &gw_prof_ref,
                        "stream": "urn:r5e:stream:meridian:authority:root:gw",
                        "seq": 1,
                        "previous": null,
                        "actor": "urn:r5e:operator:root",
                        "capturedAt": "2026-11-12T00:00:00.000000Z",
                        "body": {
                            "subject": &gw_id,
                            "mayEndorse": true,
                            "streamPrefixes": ["urn:r5e:stream:meridian:"],
                            "kinds": default_gateway_grant_kinds(),
                            "notBefore": "2026-11-12T00:00:00.000000Z",
                            "notAfter": "2026-12-12T00:00:00.000000Z",
                        }
                    }))
                    .unwrap();
                    end_map.insert("issuer".to_string(), Value::String(root_id.clone()));
                    let endorsement = sign_v2_record_multi(&[&root_key], end_map).unwrap();

                    let finalized = FinalizedBadgeResponse {
                        badge: SignedEndpointRecord {
                            record_ref: badge_ref,
                            envelope: DsseEnvelope {
                                payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
                                payload: fin_req.payload,
                                signatures: vec![
                                    DsseSignature {
                                        keyid: gw_id.clone(),
                                        sig: BASE64_STANDARD.encode(gw_sig.to_bytes()),
                                    },
                                    fin_req.subject_signature,
                                ],
                            },
                        },
                        stream_prefix: wl_stream_prefix,
                        authority_chain: vec![endorsement],
                        publications: Vec::new(),
                        keys: vec![
                            PublicKeyEntry {
                                keyid: root_id.clone(),
                                algorithm: "ed25519".to_string(),
                                bytes: BASE64_STANDARD.encode(root_key.verifying_key().to_bytes()),
                            },
                            PublicKeyEntry {
                                keyid: gw_id.clone(),
                                algorithm: "ed25519".to_string(),
                                bytes: BASE64_STANDARD.encode(gw_key.verifying_key().to_bytes()),
                            },
                        ],
                        blobs: vec![BlobEntry {
                            blob_ref: gw_prof_ref,
                            media_type: Some("application/json".to_string()),
                            base64: BASE64_STANDARD.encode(&gw_prof_bytes),
                        }],
                    };
                    respond(
                        &mut sock,
                        201,
                        "Created",
                        serde_json::to_value(finalized).unwrap(),
                    );
                }
                ("POST", "/v1/evidence/sessions") => {
                    let req_val: Value = serde_json::from_slice(&body_buf).unwrap();
                    let raw_client_id = req_val
                        .get("clientSessionId")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned);
                    st.received_client_session_ids.push(raw_client_id.clone());

                    let principal = st
                        .acts_for
                        .clone()
                        .unwrap_or_else(|| "urn:r5e:service:ci".to_string());

                    if let Some(cid) = raw_client_id {
                        let fp_full = hex_lower(&Sha256::digest(principal.as_bytes()));
                        let fp16 = &fp_full[..16];
                        let mut encoded = String::new();
                        for b in cid.bytes() {
                            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                                encoded.push(b as char);
                            } else {
                                use std::fmt::Write as _;
                                let _ = write!(&mut encoded, "%{b:02X}");
                            }
                        }
                        let sess_urn = format!("urn:r5e:session:meridian:{fp16}.{encoded}");
                        if st.opened_sessions.contains_key(&sess_urn) {
                            // Already open -> `200 OK` with ONLY `{"session": ...}` (no `ref` or `seq`)!
                            respond(
                                &mut sock,
                                200,
                                "OK",
                                json!({
                                    "session": sess_urn,
                                }),
                            );
                        } else {
                            st.session_counter += 1;
                            st.opened_sessions.insert(sess_urn.clone(), principal);
                            let fake_digest = Sha256::digest(sess_urn.as_bytes());
                            let anchor_ref = format!("evidence:sha256:{}", hex_lower(&fake_digest));
                            let seq = st.session_counter;
                            respond(
                                &mut sock,
                                201,
                                "Created",
                                json!({
                                    "session": sess_urn,
                                    "ref": anchor_ref,
                                    "seq": seq,
                                }),
                            );
                        }
                    } else {
                        st.session_counter += 1;
                        let sess_urn =
                            format!("urn:r5e:session:meridian:{:04}", st.session_counter);
                        st.opened_sessions.insert(sess_urn.clone(), principal);
                        let fake_digest = Sha256::digest(sess_urn.as_bytes());
                        let anchor_ref = format!("evidence:sha256:{}", hex_lower(&fake_digest));
                        let seq = st.session_counter;
                        respond(
                            &mut sock,
                            201,
                            "Created",
                            json!({
                                "session": sess_urn,
                                "ref": anchor_ref,
                                "seq": seq,
                            }),
                        );
                    }
                }
                ("POST", "/v1/evidence/records") => {
                    assert!(
                        body_buf.len() < 8_000_000,
                        "batch body exceeded 8MB gateway limit"
                    );
                    let req: ShipRecordsRequest = serde_json::from_slice(&body_buf).unwrap();
                    if req.records.is_empty() || req.records.len() > MAX_RECORDS_PER_BATCH {
                        respond(
                            &mut sock,
                            400,
                            "Bad Request",
                            json!({ "error": "too_many_records" }),
                        );
                        continue;
                    }
                    st.batch_sizes.push(req.records.len());

                    if !st.revoked_badges.is_empty() {
                        respond(
                            &mut sock,
                            422,
                            "Unprocessable Entity",
                            json!({
                                "error": "authority_ended",
                                "finding": "authority_ended",
                            }),
                        );
                        continue;
                    }

                    let blobs_map: BTreeMap<String, Vec<u8>> = req
                        .blobs
                        .iter()
                        .map(|b| {
                            let raw = decode_strict_base64(&b.base64).unwrap();
                            assert_eq!(bytes_ref(&raw), b.blob_ref);
                            (b.blob_ref.clone(), raw)
                        })
                        .collect();
                    let keys_map: BTreeMap<String, VerifyingKey> = req
                        .keys
                        .iter()
                        .map(|k| {
                            let raw = decode_strict_base64(&k.bytes).unwrap();
                            let arr: [u8; 32] = raw.try_into().unwrap();
                            assert_eq!(ed25519_key_id(&arr), k.keyid);
                            (k.keyid.clone(), VerifyingKey::from_bytes(&arr).unwrap())
                        })
                        .collect();

                    let gw_ret_key = effective_retention_key(st.gateway_retention.as_ref());
                    let mut error_resp: Option<(u16, &'static str, Value)> = None;
                    let mut receipts = Vec::new();
                    let mut any_new = false;

                    for rec in &req.records {
                        let payload_bytes = decode_strict_base64(&rec.envelope.payload).unwrap();
                        let expected_ref = format!(
                            "evidence:sha256:{}",
                            hex_lower(&Sha256::digest(&payload_bytes))
                        );
                        assert_eq!(rec.record_ref, expected_ref);

                        let parsed: Value = serde_json::from_slice(&payload_bytes).unwrap();
                        let kind = parsed["kind"].as_str().unwrap();
                        if !is_admissible_workload_kind(kind) {
                            error_resp = Some((
                                422,
                                "Unprocessable Entity",
                                json!({ "error": "kind_not_admissible_from_workload" }),
                            ));
                            break;
                        }

                        if st.admitted_refs.contains(&rec.record_ref) {
                            receipts.push(AdmittedRecordReceipt {
                                record_ref: rec.record_ref.clone(),
                                stream: parsed["stream"].as_str().unwrap().to_string(),
                                seq: parsed["seq"].as_u64().unwrap(),
                                status: "already_admitted".to_string(),
                                content_held: Vec::new(),
                                content_missing: Vec::new(),
                            });
                            continue;
                        }

                        // Verify Ed25519 signature over DSSE PAE:
                        let issuer = parsed["issuer"].as_str().unwrap();
                        let vk = keys_map.get(issuer).expect("signer key carried in batch");
                        let sig_bytes =
                            decode_strict_base64(&rec.envelope.signatures[0].sig).unwrap();
                        let sig = Signature::from_bytes(&sig_bytes.try_into().unwrap());
                        let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &payload_bytes);
                        vk.verify(&pae, &sig)
                            .expect("valid workload DSSE signature");

                        // Verify CaptureProfile carried + exact retention parity (A8 §2.3):
                        let prof_ref = parsed["profileRef"].as_str().unwrap();
                        let Some(prof_raw) = blobs_map.get(prof_ref) else {
                            error_resp = Some((
                                422,
                                "Unprocessable Entity",
                                json!({ "error": "profile_not_carried" }),
                            ));
                            break;
                        };
                        let prof_val: Value = serde_json::from_slice(prof_raw).unwrap();
                        let wl_ret_key = effective_retention_key(prof_val.get("retention"));
                        if wl_ret_key != gw_ret_key {
                            error_resp = Some((
                                422,
                                "Unprocessable Entity",
                                json!({
                                    "error": "profile_retention_mismatch",
                                    "expected": st.gateway_retention,
                                    "actual": prof_val.get("retention"),
                                }),
                            ));
                            break;
                        }

                        // Session anchor & principal check (A8 §3.3):
                        if let Some(sess_urn) = parsed.get("session").and_then(Value::as_str) {
                            let Some(anchor_principal) = st.opened_sessions.get(sess_urn) else {
                                error_resp = Some((
                                    409,
                                    "Conflict",
                                    json!({ "error": "session_not_opened" }),
                                ));
                                break;
                            };
                            let rec_principal = parsed
                                .get("onBehalfOf")
                                .and_then(Value::as_str)
                                .or_else(|| parsed.get("actor").and_then(Value::as_str))
                                .unwrap();
                            if rec_principal != anchor_principal {
                                error_resp = Some((
                                    409,
                                    "Conflict",
                                    json!({ "error": "session_belongs_to_another_principal" }),
                                ));
                                break;
                            }
                        } else if matches!(
                            kind,
                            "SessionOpened" | "SessionClosed" | "ToolCall" | "ToolResult"
                        ) {
                            error_resp = Some((
                                422,
                                "Unprocessable Entity",
                                json!({ "error": "session_required" }),
                            ));
                            break;
                        }

                        // Stream continuity check:
                        let stream = parsed["stream"].as_str().unwrap().to_string();
                        let seq = parsed["seq"].as_u64().unwrap();
                        match st.stream_heads.get(&stream) {
                            None => {
                                if seq != 1 || !parsed["previous"].is_null() {
                                    error_resp = Some((
                                        409,
                                        "Conflict",
                                        json!({ "error": "not_next_in_stream" }),
                                    ));
                                    break;
                                }
                            }
                            Some((prev_seq, prev_ref)) => {
                                if seq != prev_seq + 1
                                    || parsed["previous"].as_str() != Some(prev_ref.as_str())
                                {
                                    error_resp = Some((
                                        409,
                                        "Conflict",
                                        json!({ "error": "not_next_in_stream" }),
                                    ));
                                    break;
                                }
                            }
                        }

                        // Missing-content vs held-content accounting (A8 §2.5 & §4.3):
                        for bref in blobs_map.keys() {
                            st.held_blobs.insert(bref.clone());
                        }
                        let mut body_refs = Vec::new();
                        if let Some(cref) = parsed["body"].get("contentRef").and_then(Value::as_str)
                        {
                            body_refs.push(cref.to_string());
                        }
                        if let Some(arr) =
                            parsed["body"].get("contentRefs").and_then(Value::as_array)
                        {
                            for item in arr {
                                if let Some(s) = item.as_str() {
                                    body_refs.push(s.to_string());
                                }
                            }
                        }
                        let mut held = Vec::new();
                        let mut missing = Vec::new();
                        for r in body_refs {
                            if st.held_blobs.contains(&r) {
                                held.push(r);
                            } else {
                                missing.push(r);
                            }
                        }

                        st.stream_heads
                            .insert(stream.clone(), (seq, rec.record_ref.clone()));
                        st.admitted_refs.insert(rec.record_ref.clone());
                        any_new = true;
                        receipts.push(AdmittedRecordReceipt {
                            record_ref: rec.record_ref.clone(),
                            stream,
                            seq,
                            status: "admitted".to_string(),
                            content_held: held,
                            content_missing: missing,
                        });
                    }

                    if let Some((code, reason_phrase, err_val)) = error_resp {
                        respond(&mut sock, code, reason_phrase, err_val);
                    } else if any_new {
                        respond(&mut sock, 201, "Created", json!({ "admitted": receipts }));
                    } else {
                        respond(&mut sock, 200, "OK", json!({ "admitted": receipts }));
                    }
                }
                ("POST", "/v1/authority/badges/revoke") => {
                    let v: Value = serde_json::from_slice(&body_buf).unwrap();
                    let badge_ref = v["badge"].as_str().unwrap().to_string();
                    let reason_txt = v["reason"].as_str().unwrap().to_string();
                    assert!(!reason_txt.trim().is_empty());
                    st.revoked_badges
                        .insert(badge_ref.clone(), reason_txt.clone());
                    let fake_digest = Sha256::digest(format!("revoke:{badge_ref}").as_bytes());
                    respond(
                        &mut sock,
                        201,
                        "Created",
                        json!({
                            "revocation": format!("evidence:sha256:{}", hex_lower(&fake_digest)),
                            "target": badge_ref,
                            "reason": reason_txt,
                        }),
                    );
                }
                _ => {
                    respond(&mut sock, 404, "Not Found", json!({ "error": "not_found" }));
                }
            }
        }
    });

    (base_url, handle)
}

fn stop_mock_a8_gateway(base_url: &str, handle: thread::JoinHandle<()>) {
    let host_port = base_url.strip_prefix("http://").unwrap();
    if let Ok(mut s) = std::net::TcpStream::connect(host_port) {
        let _ = s.write_all(
            format!("POST /__stop HTTP/1.1\r\nHost: {host_port}\r\nContent-Length: 0\r\n\r\n")
                .as_bytes(),
        );
    }
    let _ = handle.join();
}

#[test]
fn enrolment_copies_gateway_retention_verbatim_for_by_record_never_and_absent_profiles() {
    let secret_token = "r5e-super-secret-retention-token-9911";
    let state = Arc::new(Mutex::new(MockA8GatewayState {
        gateway_retention: Some(json!({
            "disposal": "by-record",
            "keepContentForSeconds": 3600
        })),
        expected_bearer: secret_token.to_string(),
        acts_for: Some("urn:r5e:principal:lena".to_string()),
        ..Default::default()
    }));
    let (base_url, handle) = spawn_mock_a8_gateway(Arc::clone(&state));
    let cfg = EnrolmentClientConfig::new(&base_url, Some(secret_token.to_string()));
    assert!(
        !format!("{cfg:?}").contains(secret_token),
        "EnrolmentClientConfig Debug must redact bearer token"
    );

    // 1. Gateway profile with `by-record` (`keepContentForSeconds: 3600`):
    let sess_by_rec = enrol_endpoint_badge(
        &cfg,
        SigningKey::from_bytes(&[0x41; 32]),
        "endpoint-helper",
        Some("urn:r5e:workload:codex".to_string()),
        default_workload_badge_kinds(),
        None,
        Some(3600),
        b"permit(principal, action, resource);\n",
    )
    .expect("enrol with by-record retention");
    assert_eq!(
        sess_by_rec.retention,
        Some(json!({
            "disposal": "by-record",
            "keepContentForSeconds": 3600
        }))
    );
    let local_prof_blob = sess_by_rec
        .recorder
        .blob_entry(&sess_by_rec.local_profile_ref)
        .expect("local CaptureProfile blob stored");
    let local_prof_val: Value =
        serde_json::from_slice(&decode_strict_base64(&local_prof_blob.base64).unwrap()).unwrap();
    assert_eq!(
        local_prof_val["retention"],
        json!({
            "disposal": "by-record",
            "keepContentForSeconds": 3600
        })
    );

    // 2. Gateway profile with explicit `{"disposal": "never"}`:
    state.lock().unwrap().gateway_retention = Some(json!({ "disposal": "never" }));
    let sess_never = enrol_endpoint_badge(
        &cfg,
        SigningKey::from_bytes(&[0x42; 32]),
        "endpoint-helper",
        None,
        default_workload_badge_kinds(),
        None,
        Some(3600),
        b"permit(principal, action, resource);\n",
    )
    .expect("enrol with never retention");
    assert_eq!(sess_never.retention, Some(json!({ "disposal": "never" })));
    let never_blob = sess_never
        .recorder
        .blob_entry(&sess_never.local_profile_ref)
        .unwrap();
    let never_val: Value =
        serde_json::from_slice(&decode_strict_base64(&never_blob.base64).unwrap()).unwrap();
    assert_eq!(never_val["retention"], json!({ "disposal": "never" }));

    // 3. Gateway profile with `"retention"` omitted (`None`):
    state.lock().unwrap().gateway_retention = None;
    let sess_absent = enrol_endpoint_badge(
        &cfg,
        SigningKey::from_bytes(&[0x43; 32]),
        "endpoint-helper",
        None,
        default_workload_badge_kinds(),
        None,
        Some(3600),
        b"permit(principal, action, resource);\n",
    )
    .expect("enrol with absent retention");
    assert_eq!(sess_absent.retention, None);
    let absent_blob = sess_absent
        .recorder
        .blob_entry(&sess_absent.local_profile_ref)
        .unwrap();
    let absent_val: Value =
        serde_json::from_slice(&decode_strict_base64(&absent_blob.base64).unwrap()).unwrap();
    assert!(
        absent_val.get("retention").is_none(),
        "absent gateway retention must leave local CaptureProfile retention absent"
    );

    // 4. Explicit `CaptureProfile` / `EnrolledSessionOptions.retention_override` override:
    let (sess_override, _) = enrol_endpoint_badge_with_options(
        &cfg,
        SigningKey::from_bytes(&[0x44; 32]),
        "endpoint-helper",
        None,
        default_workload_badge_kinds(),
        None,
        Some(3600),
        b"permit(principal, action, resource);\n",
        &EnrolBadgeOptions {
            purpose: Some("unit-test-override".to_string()),
            session_options: EnrolledSessionOptions {
                retention_override: Some(Some(json!({
                    "disposal": "by-record",
                    "keepContentForSeconds": 900
                }))),
                policy_required_kinds: Some(Vec::new()),
                required_payloads: Some("submitted".to_string()),
            },
        },
    )
    .expect("enrol with explicit retention override");
    let custom_prof: CaptureProfile = sess_override.capture_profile.clone();
    assert_eq!(
        custom_prof.retention,
        Some(json!({
            "disposal": "by-record",
            "keepContentForSeconds": 900
        }))
    );
    // And verify shipping this intentionally mismatched profile triggers `422 profile_retention_mismatch`!
    let opened = open_session_over_http(&base_url, secret_token, &OpenSessionRequest::default())
        .expect("open session");
    let mut sess_mismatch = sess_override;
    sess_mismatch
        .record_v2_event(
            "events",
            "Observation",
            "urn:r5e:principal:lena",
            Some(&opened.session),
            "2026-11-12T12:05:00.000000Z",
            json!({ "topic": "mismatch.check", "contentRefs": [] }),
        )
        .unwrap();
    let mismatch_err = sess_mismatch
        .ship_to_gateway(&base_url, secret_token, true)
        .expect_err("mismatched retention must return 422 profile_retention_mismatch");
    assert_eq!(mismatch_err.http_status(), Some(422));
    assert_eq!(
        mismatch_err.error_code(),
        Some("profile_retention_mismatch")
    );
    assert!(!mismatch_err.to_string().contains(secret_token));

    stop_mock_a8_gateway(&base_url, handle);
}

#[test]
fn cli_end_to_end_enrol_open_session_record_ship_missing_content_ship_bundle_and_revoke_badge() {
    let secret_token = "r5e-live-run-8-secret-bearer-token-xyz987";
    let state = Arc::new(Mutex::new(MockA8GatewayState {
        gateway_retention: Some(json!({
            "disposal": "by-record",
            "keepContentForSeconds": 7200
        })),
        expected_bearer: secret_token.to_string(),
        acts_for: Some("urn:r5e:principal:lena".to_string()),
        ..Default::default()
    }));
    let (base_url, handle) = spawn_mock_a8_gateway(Arc::clone(&state));

    let tmp_dir = std::env::temp_dir().join(format!(
        "r5e-a8-cli-e2e-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    fs::create_dir_all(&tmp_dir).unwrap();
    let state_file = tmp_dir.join("enrolled-state.json");
    let input_file = tmp_dir.join("tool-input.json");
    let output_file = tmp_dir.join("tool-output.json");
    let bundle_dir = tmp_dir.join("exported-bundle");
    fs::create_dir_all(&bundle_dir).unwrap();
    let bundle_file = bundle_dir.join("bundle.json");

    let input_bytes = br#"{"path":"/etc/hosts"}"#;
    let output_bytes = br#"{"lines":12,"ok":true}"#;
    fs::write(&input_file, input_bytes).unwrap();
    fs::write(&output_file, output_bytes).unwrap();
    let expected_input_ref = bytes_ref(input_bytes);
    let expected_output_ref = bytes_ref(output_bytes);

    let bin = env!("CARGO_BIN_EXE_r5e-endpoint-helper");

    // 0. Raw `--bearer-token` flag MUST be rejected by clap (never accept raw token on CLI argv):
    let bad_flag = Command::new(bin)
        .args([
            "open-session",
            "--gateway-url",
            &base_url,
            "--bearer-token",
            secret_token,
        ])
        .output()
        .unwrap();
    assert!(!bad_flag.status.success());

    // 1. `enrol-badge` -> writes `0600` state file and prints public summary with zero secrets:
    let enrol_out = Command::new(bin)
        .env("TEST_A8_BEARER", secret_token)
        .args([
            "enrol-badge",
            "--gateway-url",
            &base_url,
            "--bearer-token-env",
            "TEST_A8_BEARER",
            "--workload",
            "urn:r5e:workload:codex",
            "--purpose",
            "live-run-8-e2e",
            "--ttl-seconds",
            "3600",
            "--out-state",
            state_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        enrol_out.status.success(),
        "enrol-badge stderr: {}",
        String::from_utf8_lossy(&enrol_out.stderr)
    );
    let enrol_stdout = String::from_utf8(enrol_out.stdout).unwrap();
    assert!(!enrol_stdout.contains(secret_token));
    assert!(!enrol_stdout.contains("workload_seed_b64"));

    let enrol_summary: Value = serde_json::from_str(enrol_stdout.trim()).unwrap();
    assert_eq!(enrol_summary["ok"], true);
    assert_eq!(
        enrol_summary["retention"],
        json!({ "disposal": "by-record", "keepContentForSeconds": 7200 })
    );
    let badge_ref = enrol_summary["badge_ref"].as_str().unwrap().to_string();
    assert!(badge_ref.starts_with("evidence:sha256:"));
    assert!(enrol_summary["subject_key_id"]
        .as_str()
        .unwrap()
        .starts_with("key:ed25519:sha256:"));
    assert!(enrol_summary["profile_ref"]
        .as_str()
        .unwrap()
        .starts_with("bytes:sha256:"));
    assert_eq!(enrol_summary["not_before"], "2026-11-12T11:59:00.000000Z");
    assert_eq!(enrol_summary["not_after"], "2026-11-12T13:00:00.000000Z");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&state_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "enrolled state file must have 0600 mode");
    }
    let loaded_st = EnrolledStateFile::load(&state_file).unwrap();
    assert!(
        !format!("{loaded_st:?}").contains(&loaded_st.workload_seed_b64),
        "EnrolledStateFile Debug must redact workload_seed_b64"
    );
    assert!(
        !enrol_stdout.contains(&loaded_st.workload_seed_b64),
        "enrol-badge stdout must never print workload seed"
    );

    // 2. `open-session` -> binds `session_urn` in `0600` state file and prints `{session, ref, seq}`:
    let open_out = Command::new(bin)
        .env("TEST_A8_BEARER", secret_token)
        .args([
            "open-session",
            "--bearer-token-env",
            "TEST_A8_BEARER",
            "--state",
            state_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        open_out.status.success(),
        "open-session stderr: {}",
        String::from_utf8_lossy(&open_out.stderr)
    );
    let open_json: Value = serde_json::from_slice(&open_out.stdout).unwrap();
    assert_eq!(open_json["session"], "urn:r5e:session:meridian:0001");
    assert_eq!(open_json["seq"], 1);
    assert!(open_json["ref"]
        .as_str()
        .unwrap()
        .starts_with("evidence:sha256:"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&state_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "updated state file must retain 0600 mode");
    }

    // 3. `record-event --ship` (`ToolCall` with inline payload blob -> `contentHeld`):
    let tc_out = Command::new(bin)
        .env("TEST_A8_BEARER", secret_token)
        .args([
            "record-event",
            "--state",
            state_file.to_str().unwrap(),
            "--kind",
            "ToolCall",
            "--tool-name",
            "Read",
            "--input-file",
            input_file.to_str().unwrap(),
            "--ship",
            "--bearer-token-env",
            "TEST_A8_BEARER",
        ])
        .output()
        .unwrap();
    assert!(
        tc_out.status.success(),
        "record-event ToolCall stderr: {}",
        String::from_utf8_lossy(&tc_out.stderr)
    );
    let tc_json: Value = serde_json::from_slice(&tc_out.stdout).unwrap();
    assert_eq!(tc_json["seq"], 1);
    assert_eq!(tc_json["shipped"], true);
    assert_eq!(tc_json["http_status"], 201);
    assert_eq!(tc_json["admitted"][0]["status"], "admitted");
    assert_eq!(
        tc_json["admitted"][0]["contentHeld"],
        json!([expected_input_ref])
    );
    assert_eq!(tc_json["admitted"][0]["contentMissing"], json!([]));
    let call_ref = tc_json["record_ref"].as_str().unwrap().to_string();

    // 4. `record-event --ship --omit-payload-blobs` (`ToolResult` -> `contentMissing` tolerance, A8 §4.3):
    let tr_out = Command::new(bin)
        .env("TEST_A8_BEARER", secret_token)
        .args([
            "record-event",
            "--state",
            state_file.to_str().unwrap(),
            "--kind",
            "ToolResult",
            "--call-ref",
            &call_ref,
            "--output-file",
            output_file.to_str().unwrap(),
            "--outcome",
            "completed",
            "--ship",
            "--omit-payload-blobs",
            "--bearer-token-env",
            "TEST_A8_BEARER",
        ])
        .output()
        .unwrap();
    assert!(
        tr_out.status.success(),
        "record-event ToolResult stderr: {}",
        String::from_utf8_lossy(&tr_out.stderr)
    );
    let tr_json: Value = serde_json::from_slice(&tr_out.stdout).unwrap();
    assert_eq!(tr_json["seq"], 2);
    assert_eq!(tr_json["http_status"], 201);
    assert_eq!(tr_json["admitted"].as_array().unwrap().len(), 1);
    assert_eq!(tr_json["admitted"][0]["contentHeld"], json!([]));
    assert_eq!(
        tr_json["admitted"][0]["contentMissing"],
        json!([expected_output_ref])
    );

    // 5. `record-and-ship` alias (`SessionClosed` + `--out-bundle`):
    let sc_out = Command::new(bin)
        .env("TEST_A8_BEARER", secret_token)
        .args([
            "record-and-ship",
            "--state",
            state_file.to_str().unwrap(),
            "--kind",
            "SessionClosed",
            "--outcome",
            "completed",
            "--out-bundle",
            bundle_file.to_str().unwrap(),
            "--bearer-token-env",
            "TEST_A8_BEARER",
        ])
        .output()
        .unwrap();
    assert!(
        sc_out.status.success(),
        "record-and-ship SessionClosed stderr: {}",
        String::from_utf8_lossy(&sc_out.stderr)
    );
    let sc_json: Value = serde_json::from_slice(&sc_out.stdout).unwrap();
    assert_eq!(sc_json["seq"], 3);
    assert_eq!(sc_json["shipped"], true);
    assert_eq!(sc_json["http_status"], 201);

    // 6. `ship-bundle --bundle-dir` -> filters out Badge/Endorsement and verifies 200 OK `already_admitted` idempotent replay:
    let replay_out = Command::new(bin)
        .env("TEST_A8_BEARER", secret_token)
        .args([
            "ship-bundle",
            "--gateway-url",
            &base_url,
            "--bundle-dir",
            bundle_dir.to_str().unwrap(),
            "--bearer-token-env",
            "TEST_A8_BEARER",
        ])
        .output()
        .unwrap();
    assert!(
        replay_out.status.success(),
        "ship-bundle stderr: {}",
        String::from_utf8_lossy(&replay_out.stderr)
    );
    let replay_json: Value = serde_json::from_slice(&replay_out.stdout).unwrap();
    assert_eq!(replay_json["httpStatus"], 200);
    let admitted_arr = replay_json["admitted"].as_array().unwrap();
    assert_eq!(admitted_arr.len(), 3);
    for item in admitted_arr {
        assert_eq!(item["status"], "already_admitted");
    }

    // 7. `revoke-badge` using `--state` -> revokes the enrolled badge (`POST /v1/authority/badges/revoke`):
    let rev_out = Command::new(bin)
        .env("TEST_A8_BEARER", secret_token)
        .args([
            "revoke-badge",
            "--state",
            state_file.to_str().unwrap(),
            "--reason",
            "workload session completed",
            "--bearer-token-env",
            "TEST_A8_BEARER",
        ])
        .output()
        .unwrap();
    assert!(
        rev_out.status.success(),
        "revoke-badge stderr: {}",
        String::from_utf8_lossy(&rev_out.stderr)
    );
    let rev_json: Value = serde_json::from_slice(&rev_out.stdout).unwrap();
    assert_eq!(rev_json["target"], badge_ref);
    assert_eq!(rev_json["reason"], "workload session completed");

    // 8. Post-revocation `record-event --ship` fails with `422 authority_ended` and leaks zero secrets:
    let post_rev = Command::new(bin)
        .env("TEST_A8_BEARER", secret_token)
        .args([
            "record-event",
            "--state",
            state_file.to_str().unwrap(),
            "--kind",
            "Observation",
            "--topic",
            "after.revoke",
            "--ship",
            "--bearer-token-env",
            "TEST_A8_BEARER",
        ])
        .output()
        .unwrap();
    assert!(!post_rev.status.success());
    let stderr_txt = String::from_utf8_lossy(&post_rev.stderr);
    assert!(stderr_txt.contains("authority_ended"));
    assert!(!stderr_txt.contains(secret_token));

    stop_mock_a8_gateway(&base_url, handle);
    let _ = fs::remove_dir_all(&tmp_dir);
}

#[test]
fn auto_chunks_over_64_records_preserving_consecutive_stream_seq_and_idempotent_replay() {
    let secret_token = "r5e-batch-split-token-778899";
    let state = Arc::new(Mutex::new(MockA8GatewayState {
        gateway_retention: Some(json!({ "disposal": "never" })),
        expected_bearer: secret_token.to_string(),
        acts_for: Some("urn:r5e:principal:lena".to_string()),
        ..Default::default()
    }));
    let (base_url, handle) = spawn_mock_a8_gateway(Arc::clone(&state));

    let cfg = EnrolmentClientConfig::new(&base_url, Some(secret_token.to_string()));
    let (mut session, _) = enrol_endpoint_badge_with_options(
        &cfg,
        SigningKey::from_bytes(&[0x55; 32]),
        "endpoint-helper",
        Some("urn:r5e:workload:batcher".to_string()),
        default_workload_badge_kinds(),
        None,
        Some(3600),
        b"permit(principal, action, resource);\n",
        &EnrolBadgeOptions {
            purpose: None,
            session_options: EnrolledSessionOptions {
                retention_override: None,
                policy_required_kinds: Some(Vec::new()),
                required_payloads: Some("submitted".to_string()),
            },
        },
    )
    .expect("enrol batcher");

    let opened = open_session_over_http(&base_url, secret_token, &OpenSessionRequest::default())
        .expect("open session");

    // Append 70 operational records (`> 64` batch limit):
    for idx in 1..=70u64 {
        let payload_bytes = format!("{{\"step\":{idx}}}").into_bytes();
        let cref = session
            .recorder
            .put_blob(&payload_bytes, Some("application/json"));
        session
            .record_v2_event(
                "events",
                "Observation",
                "urn:r5e:workload:batcher",
                Some(&opened.session),
                "2026-11-12T12:10:00.000000Z",
                json!({
                    "topic": format!("step.s{idx}"),
                    "contentRefs": [cref],
                }),
            )
            .unwrap();
    }

    let batch_responses = session
        .ship_to_gateway(&base_url, secret_token, true)
        .expect("ship 70 records across 2 batches");
    assert_eq!(batch_responses.len(), 2);
    assert_eq!(batch_responses[0].http_status, Some(201));
    assert_eq!(batch_responses[0].admitted.len(), 64);
    assert_eq!(batch_responses[0].admitted[0].seq, 1);
    assert_eq!(batch_responses[0].admitted[63].seq, 64);
    assert_eq!(batch_responses[1].http_status, Some(201));
    assert_eq!(batch_responses[1].admitted.len(), 6);
    assert_eq!(batch_responses[1].admitted[0].seq, 65);
    assert_eq!(batch_responses[1].admitted[5].seq, 70);

    assert_eq!(state.lock().unwrap().batch_sizes, vec![64, 6]);

    // Replay all 70 via `ship_records_over_http` -> aggregated `200 OK` with all 70 `already_admitted`:
    let full_req = build_ship_request_from_recorder(
        &session.recorder,
        Some(&session.helper_keyid),
        &BTreeSet::new(),
        true,
        None,
    )
    .unwrap();
    let replay = ship_records_over_http(&base_url, secret_token, &full_req)
        .expect("idempotent 70-record replay");
    assert_eq!(replay.http_status, Some(200));
    assert_eq!(replay.admitted.len(), 70);
    assert!(replay.all_already_admitted());
    assert_eq!(replay.already_admitted_count(), 70);
    assert_eq!(replay.newly_admitted_count(), 0);

    stop_mock_a8_gateway(&base_url, handle);
}

#[test]
fn structured_error_handling_scrubs_any_bearer_token_leakage() {
    let secret_token = "r5e-ultra-sensitive-bearer-token-do-not-leak";
    let cfg = EvidenceClientConfig::new("http://127.0.0.1:9", secret_token);
    assert!(
        !format!("{cfg:?}").contains(secret_token),
        "EvidenceClientConfig Debug must redact bearer token"
    );

    // Rogue server deliberately echoes the raw bearer token inside a 503 JSON error body:
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");
    let tok_copy = secret_token.to_string();
    let srv = thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(sock.try_clone().unwrap());
        let mut clen = 0usize;
        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line).unwrap_or(0);
            let t = line.trim_end_matches(&['\r', '\n'][..]);
            if n == 0 || t.is_empty() {
                break;
            }
            if let Some((k, v)) = t.split_once(':') {
                if k.trim().eq_ignore_ascii_case("content-length") {
                    clen = v.trim().parse().unwrap_or(0);
                }
            }
        }
        if clen > 0 {
            let mut drain = vec![0u8; clen];
            let _ = reader.read_exact(&mut drain);
        }
        let body = serde_json::to_vec(&json!({
            "error": "deployment_not_claimed",
            "detail": format!("rejected caller token {tok_copy}"),
        }))
        .unwrap();
        let head = format!(
            "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        sock.write_all(head.as_bytes()).unwrap();
        sock.write_all(&body).unwrap();
        sock.flush().unwrap();
    });

    let err = open_session_over_http(&url, secret_token, &OpenSessionRequest::default())
        .expect_err("503 deployment_not_claimed must fail");
    srv.join().unwrap();

    assert_eq!(err.http_status(), Some(503));
    assert_eq!(err.error_code(), Some("deployment_not_claimed"));
    assert!(
        matches!(err, EvidenceHttpError::ServiceUnavailable { .. }),
        "expected ServiceUnavailable variant, got {err:?}"
    );
    let display_str = format!("{err}");
    let debug_str = format!("{err:?}");
    assert!(
        !display_str.contains(secret_token),
        "Display must never contain bearer token: {display_str}"
    );
    assert!(
        !debug_str.contains(secret_token),
        "Debug must never contain bearer token: {debug_str}"
    );
    assert!(display_str.contains("[REDACTED]"));

    // Also verify `revoke_badge_over_http` pre-flight validation rejects malformed badge refs cleanly:
    let bad_ref = revoke_badge_over_http(&url, secret_token, "not-an-evidence-ref", "reason")
        .expect_err("invalid badge ref");
    assert!(matches!(bad_ref, EvidenceHttpError::Validation(_)));
    assert!(!format!("{bad_ref}").contains(secret_token));
}

#[test]
fn open_session_client_session_id_201_and_200_idempotency_validation_and_opaque_propagation() {
    let secret_token = "tok_client_session_id_ceremony_808";
    let state = Arc::new(Mutex::new(MockA8GatewayState {
        gateway_retention: Some(json!({ "disposal": "never" })),
        expected_bearer: secret_token.to_string(),
        acts_for: Some("urn:r5e:user:lena".to_string()),
        ..Default::default()
    }));
    let (base_url, handle) = spawn_mock_a8_gateway(Arc::clone(&state));
    let bin = env!("CARGO_BIN_EXE_r5e-endpoint-helper");

    // 1. Validate `clientSessionId` bounds (`1..=128` UTF-8 bytes): reject empty and >128 bytes!
    let err_empty = open_session_over_http(
        &base_url,
        secret_token,
        &OpenSessionRequest {
            client_session_id: Some(String::new()),
            ..Default::default()
        },
    )
    .expect_err("empty clientSessionId must be rejected");
    assert!(matches!(err_empty, EvidenceHttpError::Validation(_)));

    let over_128 = "x".repeat(129);
    let err_long = open_session_over_http(
        &base_url,
        secret_token,
        &OpenSessionRequest {
            client_session_id: Some(over_128.clone()),
            ..Default::default()
        },
    )
    .expect_err(">128-byte clientSessionId must be rejected");
    assert!(matches!(err_long, EvidenceHttpError::Validation(_)));

    // CLI also rejects empty and >128-byte `--client-session-id` before touching the network:
    for bad_cli_id in ["", over_128.as_str()] {
        let cli_bad = Command::new(bin)
            .env("TEST_CSID_BEARER", secret_token)
            .args([
                "open-session",
                "--gateway-url",
                &base_url,
                "--bearer-token-env",
                "TEST_CSID_BEARER",
                "--client-session-id",
                bad_cli_id,
            ])
            .output()
            .unwrap();
        assert_eq!(cli_bad.status.code(), Some(2));
    }

    // Exact 128-byte `clientSessionId` succeeds cleanly:
    let max_128 = "s".repeat(128);
    let opened_128 = open_session_over_http(
        &base_url,
        secret_token,
        &OpenSessionRequest {
            client_session_id: Some(max_128.clone()),
            ..Default::default()
        },
    )
    .expect("128-byte clientSessionId must succeed");
    assert!(!opened_128.already_open);
    assert_eq!(opened_128.http_status, Some(201));
    assert!(opened_128.record_ref.is_some());
    assert_eq!(opened_128.seq, Some(1));

    // 2. Enrol badge, then run CLI `open-session --client-session-id` twice with a raw unencoded ID:
    let tmp_dir = std::env::temp_dir().join(format!(
        "r5e-eh-csid-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&tmp_dir).unwrap();
    let state_file = tmp_dir.join("state.json");
    let cedar_file = tmp_dir.join("allow.cedar");
    fs::write(&cedar_file, "permit(principal, action, resource);\n").unwrap();

    let enrol_out = Command::new(bin)
        .env("TEST_CSID_BEARER", secret_token)
        .args([
            "enrol-badge",
            "--gateway-url",
            &base_url,
            "--bearer-token-env",
            "TEST_CSID_BEARER",
            "--holder",
            "csid-worker",
            "--cedar-policy",
            cedar_file.to_str().unwrap(),
            "--require-policy-for-tools",
            "--out-state",
            state_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(enrol_out.status.success());

    let raw_id = "my-session/run 42";
    let expected_fp = &hex_lower(&Sha256::digest(b"urn:r5e:user:lena"))[..16];
    let expected_urn = format!("urn:r5e:session:meridian:{expected_fp}.my-session%2Frun%2042");

    // First `open-session` -> `201 Created` (`already_open: false`, `ref`, `seq`):
    let open_1 = Command::new(bin)
        .env("TEST_CSID_BEARER", secret_token)
        .args([
            "open-session",
            "--state",
            state_file.to_str().unwrap(),
            "--bearer-token-env",
            "TEST_CSID_BEARER",
            "--client-session-id",
            raw_id,
        ])
        .output()
        .unwrap();
    assert!(
        open_1.status.success(),
        "open-session #1 failed: {}",
        String::from_utf8_lossy(&open_1.stderr)
    );
    let json_1: Value = serde_json::from_slice(&open_1.stdout).unwrap();
    assert_eq!(json_1["session"], expected_urn);
    assert_eq!(json_1["already_open"], false);
    assert_eq!(json_1["httpStatus"], 201);
    assert_eq!(json_1["seq"], 2);
    let initial_anchor_ref = json_1["ref"].as_str().unwrap().to_string();
    assert!(initial_anchor_ref.starts_with("evidence:sha256:"));

    // Second `open-session` with the same `--client-session-id` -> `200 OK` (`{"session": ...}` without `ref` or `seq`):
    let open_2 = Command::new(bin)
        .env("TEST_CSID_BEARER", secret_token)
        .args([
            "open-session",
            "--state",
            state_file.to_str().unwrap(),
            "--bearer-token-env",
            "TEST_CSID_BEARER",
            "--client-session-id",
            raw_id,
        ])
        .output()
        .unwrap();
    assert!(
        open_2.status.success(),
        "open-session #2 (200 already-open) failed: {}",
        String::from_utf8_lossy(&open_2.stderr)
    );
    let json_2: Value = serde_json::from_slice(&open_2.stdout).unwrap();
    assert_eq!(json_2["session"], expected_urn);
    assert_eq!(json_2["already_open"], true);
    assert_eq!(json_2["httpStatus"], 200);
    assert!(
        json_2.get("ref").is_none(),
        "200 response must omit absent ref"
    );
    assert!(
        json_2.get("seq").is_none(),
        "200 response must omit absent seq"
    );

    // Verify raw `clientSessionId` was transmitted WITHOUT pre-encoding, and `state.session_anchor_ref` was preserved!
    {
        let st = state.lock().unwrap();
        assert_eq!(
            st.received_client_session_ids,
            vec![
                Some(max_128),
                Some(raw_id.to_string()),
                Some(raw_id.to_string()),
            ]
        );
    }
    let reloaded_state = EnrolledStateFile::load(&state_file).unwrap();
    assert_eq!(
        reloaded_state.session_urn.as_deref(),
        Some(expected_urn.as_str())
    );
    assert_eq!(
        reloaded_state.session_anchor_ref.as_deref(),
        Some(initial_anchor_ref.as_str())
    );

    // 3. Verify `exec --ship` propagates the principal-fingerprinted `<16-hex>.<encoded_id>` session URN 100% opaquely:
    let exec_out = Command::new(bin)
        .env("TEST_CSID_BEARER", secret_token)
        .args([
            "exec",
            "--state",
            state_file.to_str().unwrap(),
            "--cedar-policy",
            cedar_file.to_str().unwrap(),
            "--ship",
            "--bearer-token-env",
            "TEST_CSID_BEARER",
            "--",
            "/bin/echo",
            "opaque-session-ok",
        ])
        .output()
        .unwrap();
    assert_eq!(exec_out.status.code(), Some(0));

    let final_state = EnrolledStateFile::load(&state_file).unwrap();
    assert_eq!(final_state.shipped_record_refs.len(), 3);
    for rec in final_state.recorder.records() {
        let p_bytes = decode_strict_base64(&rec.envelope.payload).unwrap();
        let p_val: Value = serde_json::from_slice(&p_bytes).unwrap();
        if p_val["issuer"] == final_state.subject_key_id {
            assert_eq!(p_val["session"], expected_urn);
        }
    }

    stop_mock_a8_gateway(&base_url, handle);
    let _ = fs::remove_dir_all(&tmp_dir);
}
