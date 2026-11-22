use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use r5e_endpoint_helper::attestation::{
    base_v2_schema_map, bytes_ref, decode_strict_base64, dsse_pae, ed25519_key_id,
    encode_canonical_json, encode_spki_ed25519_pem, evidence_ref, normalize_a9_details,
    sign_v2_record_multi, validate_a9_details, validate_and_normalize_v2_body,
    validate_observation_topic, write_private_key_file_0600, BlobEntry, PublicKeyEntry,
    SubjectPublicKey, DEFINITION_PUBLISHED_SCHEMA_REF, OBSERVATION_SCHEMA_REF,
    PAYLOAD_DISPOSITION_SCHEMA_REF, PROVENANCE_V2_PAYLOAD_TYPE, RETENTION_HOLD_RELEASE_SCHEMA_REF,
    RETENTION_HOLD_SCHEMA_REF, REVOCATION_SCHEMA_REF, ROOTS_CHANGED_SCHEMA_REF,
    ROOT_CHANGE_APPROVAL_SCHEMA_REF, TOOL_CALL_SCHEMA_REF, TOOL_RESULT_SCHEMA_REF,
};
use r5e_endpoint_helper::claim_http::{
    attach_external_claim_signature, default_gateway_grant_kinds, default_workload_badge_kinds,
    CarriedPublicationSet, PrepareClaimRequest, PrepareClaimRootEntry, PreparedClaimResponse,
};
use r5e_endpoint_helper::crypto_keys::test_support::{
    derive_ecdsa_public_key_uncompressed, sign_ecdsa_with_high_s_der,
};
use r5e_endpoint_helper::crypto_keys::{
    compute_key_id, encode_spki_public_key_pem, verify_signature, SignatureAlgorithm,
};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn definitions_dir() -> PathBuf {
    if let Some(val) = std::env::var_os("R5E_DEFINITIONS_DIR") {
        let dir = PathBuf::from(val);
        assert!(
            dir.join("index.json").is_file(),
            "R5E_DEFINITIONS_DIR={} missing index.json",
            dir.display()
        );
        return dir;
    }
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../r5e-spec/definitions");
    assert!(
        dir.join("index.json").is_file(),
        "default sibling definitions dir {} missing index.json (set R5E_DEFINITIONS_DIR)",
        dir.display()
    );
    dir
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

fn temp_test_dir(prefix: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("r5e-a9-{prefix}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp test dir");
    dir
}

fn helper_bin() -> &'static str {
    env!("CARGO_BIN_EXE_r5e-endpoint-helper")
}

/// Runs available independent A9 clean-room verifiers (`r5e_verify` in Python and/or `recurse_verify` in Rust)
/// on `bundle_path`, asserting exit status `0`, `summary.failed == 0`, and `summary.incomplete == 0`.
/// Skips gracefully if sibling verifiers are not built yet and neither `R5E_VERIFY_PY_DIR` nor `R5E_VERIFY_RS_BIN` is set.
fn assert_both_verifiers_zero_failed_zero_incomplete(
    bundle_path: &Path,
    trusted_profiles: &[&str],
    trusted_publishers: &[&str],
    trusted_roots: &[&str],
) {
    if let Some((py_dir, py_bin)) = resolve_py_verifier() {
        let mut cmd = Command::new(&py_bin);
        cmd.current_dir(&py_dir)
            .env("PYTHONPATH", &py_dir)
            .arg("-m")
            .arg("r5e_verify")
            .arg(bundle_path);
        for p in trusted_profiles {
            cmd.arg("--trusted-profile").arg(p);
        }
        for pub_spec in trusted_publishers {
            cmd.arg("--trusted-publisher").arg(pub_spec);
        }
        for r in trusted_roots {
            cmd.arg("--trusted-root").arg(r);
        }
        let out = cmd.output().expect("run python r5e_verify");
        let stdout_txt = String::from_utf8_lossy(&out.stdout);
        let stderr_txt = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "r5e_verify exited with {:?}\nstdout: {stdout_txt}\nstderr: {stderr_txt}",
            out.status.code()
        );
        let report: Value = serde_json::from_slice(&out.stdout).expect("r5e_verify JSON");
        assert_eq!(
            report["summary"]["failed"], 0,
            "r5e_verify report: {report}"
        );
        assert_eq!(
            report["summary"]["incomplete"], 0,
            "r5e_verify report had incomplete findings: {report}"
        );
    }

    if let Some(rs_bin) = resolve_rs_verifier_bin() {
        let mut cmd = Command::new(&rs_bin);
        cmd.arg(bundle_path);
        for p in trusted_profiles {
            cmd.arg("--trusted-profile").arg(p);
        }
        for pub_spec in trusted_publishers {
            cmd.arg("--trusted-publisher").arg(pub_spec);
        }
        for r in trusted_roots {
            cmd.arg("--trusted-root").arg(r);
        }
        let out = cmd.output().expect("run rust recurse_verify");
        let stdout_txt = String::from_utf8_lossy(&out.stdout);
        let stderr_txt = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "recurse_verify exited with {:?}\nstdout: {stdout_txt}\nstderr: {stderr_txt}",
            out.status.code()
        );
        let report: Value = serde_json::from_slice(&out.stdout).expect("recurse_verify JSON");
        assert_eq!(
            report["summary"]["failed"], 0,
            "recurse_verify report: {report}"
        );
        assert_eq!(
            report["summary"]["incomplete"], 0,
            "recurse_verify report had incomplete findings: {report}"
        );
    }
}

#[test]
fn a9_schema_refs_match_definitions_index_and_files_byte_for_byte() {
    let defs_dir = definitions_dir();
    let index_path = defs_dir.join("index.json");
    let index_raw = fs::read(&index_path).expect("read definitions/index.json");
    let index_map: BTreeMap<String, String> =
        serde_json::from_slice(&index_raw).expect("parse definitions/index.json");
    assert_eq!(index_map.len(), 28, "expected 28 A9 base definitions");

    let helper_map = base_v2_schema_map();
    assert_eq!(helper_map.len(), index_map.len());

    for (kind_path, expected_ref) in &index_map {
        let actual_ref = helper_map
            .get(kind_path)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("missing {kind_path} in base_v2_schema_map()"));
        assert_eq!(
            actual_ref, expected_ref,
            "schemaRef mismatch on {kind_path}"
        );

        let def_file = defs_dir.join(format!("{kind_path}.json"));
        let def_bytes = fs::read(&def_file)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", def_file.display()));
        assert_eq!(
            &bytes_ref(&def_bytes),
            expected_ref,
            "on-disk SHA-256 mismatch for {}",
            def_file.display()
        );
    }

    assert_eq!(
        DEFINITION_PUBLISHED_SCHEMA_REF,
        index_map["provenance.r5e.io/v2/DefinitionPublished"]
    );
    assert_eq!(
        OBSERVATION_SCHEMA_REF,
        index_map["provenance.r5e.io/v2/Observation"]
    );
    assert_eq!(
        PAYLOAD_DISPOSITION_SCHEMA_REF,
        index_map["provenance.r5e.io/v2/PayloadDisposition"]
    );
    assert_eq!(
        RETENTION_HOLD_SCHEMA_REF,
        index_map["provenance.r5e.io/v2/RetentionHold"]
    );
    assert_eq!(
        RETENTION_HOLD_RELEASE_SCHEMA_REF,
        index_map["provenance.r5e.io/v2/RetentionHoldRelease"]
    );
    assert_eq!(
        REVOCATION_SCHEMA_REF,
        index_map["provenance.r5e.io/v2/Revocation"]
    );
    assert_eq!(
        ROOTS_CHANGED_SCHEMA_REF,
        index_map["provenance.r5e.io/v2/RootsChanged"]
    );
    assert_eq!(
        ROOT_CHANGE_APPROVAL_SCHEMA_REF,
        index_map["provenance.r5e.io/v2/RootChangeApproval"]
    );
    assert_eq!(
        TOOL_CALL_SCHEMA_REF,
        index_map["provenance.r5e.io/v2/ToolCall"]
    );
    assert_eq!(
        TOOL_RESULT_SCHEMA_REF,
        index_map["provenance.r5e.io/v2/ToolResult"]
    );

    assert!(default_gateway_grant_kinds()
        .iter()
        .any(|k| k == "provenance.r5e.io/v2/ToolResult"));
    assert!(default_workload_badge_kinds()
        .iter()
        .any(|k| k == "provenance.r5e.io/v2/ToolResult"));
}

#[test]
fn a9_flat_details_observation_topic_and_call_id_enforced_everywhere() {
    // 1. Nested objects and scalar arrays flatten cleanly to A9 scalar entries:
    let raw_details: Map<String, Value> = serde_json::from_value(json!({
        "parser": {
            "name": "jq",
            "strict": true,
            "depth": 3
        },
        "tags": ["alpha", "beta"]
    }))
    .unwrap();
    let flat = normalize_a9_details(&raw_details).expect("flatten nested details");
    validate_a9_details(&flat, "flattened").expect("valid flat details");
    assert_eq!(flat["parser.name"], "jq");
    assert_eq!(flat["parser.strict"], true);
    assert_eq!(flat["parser.depth"], 3);
    assert_eq!(flat["tags"], "alpha,beta");

    // 2. Legacy `details.call_id` on `ToolCall` is promoted to top-level `body.callId`
    // and duplicate `derivedFrom` / `inputRefs` entries are deduplicated (`uniqueItems: true`):
    let dup_ref_a = format!("evidence:sha256:{}", "aa".repeat(32));
    let dup_ref_b = format!("evidence:sha256:{}", "bb".repeat(32));
    let mut legacy_tc = json!({
        "tool": "Bash",
        "contentRef": format!("bytes:sha256:{}", "11".repeat(32)),
        "mediaType": "application/json",
        "size": 2,
        "derivedFrom": [&dup_ref_a, &dup_ref_b, &dup_ref_a],
        "details": {
            "call_id": "legacy-call-99",
            "env": "sandbox"
        }
    });
    validate_and_normalize_v2_body("ToolCall", &mut legacy_tc).expect("promote call_id");
    assert_eq!(legacy_tc["callId"], "legacy-call-99");
    assert!(legacy_tc["details"].get("call_id").is_none());
    assert_eq!(legacy_tc["details"]["env"], "sandbox");
    assert_eq!(legacy_tc["derivedFrom"], json!([dup_ref_a, dup_ref_b]));

    // 3. Reject > 64 entries in Details:
    let mut too_many = Map::new();
    for idx in 0..65 {
        too_many.insert(format!("k{idx}"), Value::Number(idx.into()));
    }
    assert!(normalize_a9_details(&too_many).is_err());

    // 4. Reject invalid key names and > 2048 UTF-8 byte strings:
    let bad_key: Map<String, Value> = serde_json::from_value(json!({ "1bad": "x" })).unwrap();
    assert!(normalize_a9_details(&bad_key).is_err());
    let bad_slash: Map<String, Value> = serde_json::from_value(json!({ "bad/key": "x" })).unwrap();
    assert!(normalize_a9_details(&bad_slash).is_err());
    let overlong_val: Map<String, Value> =
        serde_json::from_value(json!({ "msg": "x".repeat(2049) })).unwrap();
    assert!(normalize_a9_details(&overlong_val).is_err());

    // 5. Enforce Observation.topic grammar (`^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$`, <= 128B):
    validate_observation_topic("mcp_tools_pinned", "ok").unwrap();
    validate_observation_topic("endpoint.observation.v2_check-ok", "ok").unwrap();
    assert!(validate_observation_topic("Upper.Case", "bad").is_err());
    assert!(validate_observation_topic("step.1", "bad").is_err());
    assert!(validate_observation_topic("", "bad").is_err());
    assert!(validate_observation_topic(&"a".repeat(129), "bad").is_err());

    // 6. Enforce ToolResult.call and callId bounds:
    let mut missing_call = json!({
        "contentRef": format!("bytes:sha256:{}", "22".repeat(32)),
        "mediaType": "application/json",
        "size": 2,
        "outcome": "completed"
    });
    assert!(validate_and_normalize_v2_body("ToolResult", &mut missing_call).is_err());

    let mut overlong_call_id = json!({
        "call": format!("evidence:sha256:{}", "33".repeat(32)),
        "callId": "c".repeat(257),
        "contentRef": format!("bytes:sha256:{}", "22".repeat(32)),
        "mediaType": "application/json",
        "size": 2,
        "outcome": "completed"
    });
    assert!(validate_and_normalize_v2_body("ToolResult", &mut overlong_call_id).is_err());
}

#[test]
fn exec_and_mcp_proxy_emit_toolresult_with_call_and_call_id_and_omit_when_denied_or_unknown() {
    let tmp = temp_test_dir("exec-mcp-toolresult");

    // 1. Prepare and finalize a real base `publications.json` using Ed25519 publisher key:
    let pub_sk = SigningKey::from_bytes(&[0x51; 32]);
    let pub_pem = encode_spki_ed25519_pem(&pub_sk.verifying_key().to_bytes());
    let pub_pem_path = tmp.join("publisher-pub.pem");
    fs::write(&pub_pem_path, &pub_pem).unwrap();

    let prep_pub_path = tmp.join("prepared-pub.json");
    let pub_pae_path = tmp.join("pub.pae");
    let pub_out_path = tmp.join("publications.json");

    let defs_dir = definitions_dir();
    let prep_out = Command::new(helper_bin())
        .args(["prepare-publication", "--definitions-dir"])
        .arg(&defs_dir)
        .arg("--publisher-public-key")
        .arg(&pub_pem_path)
        .args([
            "--algorithm",
            "ed25519",
            "--package",
            "r5e.provenance",
            "--captured-at",
            "2026-11-15T12:00:00.000000Z",
            "--out-prepared",
        ])
        .arg(&prep_pub_path)
        .arg("--out-pae")
        .arg(&pub_pae_path)
        .output()
        .expect("prepare-publication");
    assert!(
        prep_out.status.success(),
        "prepare-publication failed: {}",
        String::from_utf8_lossy(&prep_out.stderr)
    );
    let pae_bytes = fs::read(&pub_pae_path).unwrap();
    let pub_sig = pub_sk.sign(&pae_bytes);
    let fin_out = Command::new(helper_bin())
        .arg("finalize-publication")
        .arg("--prepared")
        .arg(&prep_pub_path)
        .arg("--signature-b64")
        .arg(BASE64_STANDARD.encode(pub_sig.to_bytes()))
        .arg("--out")
        .arg(&pub_out_path)
        .output()
        .expect("finalize-publication");
    assert!(
        fin_out.status.success(),
        "finalize-publication failed: {}",
        String::from_utf8_lossy(&fin_out.stderr)
    );
    let fin_summary: Value = serde_json::from_slice(&fin_out.stdout).unwrap();
    let publisher_key_id = fin_summary["publisher_key_id"]
        .as_str()
        .unwrap()
        .to_string();
    let pub_set: CarriedPublicationSet =
        serde_json::from_slice(&fs::read(&pub_out_path).unwrap()).unwrap();

    // 2. Mint an offline workload badge + EnrolledStateFile with a Cedar policy that permits
    //    `/bin/echo` and `demo-mcp:echo_tool`, and forbids everything else (`git push`, `drop_prod_table`):
    let root_sk = SigningKey::from_bytes(&[0x61; 32]);
    let root_id = ed25519_key_id(&root_sk.verifying_key().to_bytes());
    let root_key_path = tmp.join("root.pem");
    write_private_key_file_0600(&root_key_path, &[0x61; 32], true).unwrap();

    let wl_key_path = tmp.join("workload.pem");
    let state_path = tmp.join("state.json");
    let grant_path = tmp.join("grant.json");
    let cedar_path = tmp.join("policy.cedar");
    fs::write(
        &cedar_path,
        r#"
permit(
    principal == Recurse::Agent::"endpoint-helper",
    action == Recurse::Action::"ExecCommand",
    resource
) when {
    context.program == "/bin/echo"
};

permit(
    principal == Recurse::Agent::"endpoint-helper",
    action == Recurse::Action::"InvokeMcpTool",
    resource == Recurse::McpTool::"demo-mcp:echo_tool"
);
"#,
    )
    .unwrap();

    let mint_out = Command::new(helper_bin())
        .arg("mint-workload-badge")
        .arg("--root-key-file")
        .arg(&root_key_path)
        .arg("--generate-workload-key-out")
        .arg(&wl_key_path)
        .arg("--deployment")
        .arg("meridian")
        .arg("--principal")
        .arg("urn:r5e:principal:alice")
        .arg("--workload")
        .arg("urn:r5e:workload:codex")
        .arg("--policy-file")
        .arg(&cedar_path)
        .arg("--out-grant-file")
        .arg(&grant_path)
        .arg("--out-state")
        .arg(&state_path)
        .output()
        .expect("mint-workload-badge");
    assert!(
        mint_out.status.success(),
        "mint-workload-badge failed: {}",
        String::from_utf8_lossy(&mint_out.stderr)
    );
    let mint_summary: Value = serde_json::from_slice(&mint_out.stdout).unwrap();
    assert!(
        mint_summary["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some("provenance.r5e.io/v2/ToolResult")),
        "default offline workload badge kinds must authorize ToolResult"
    );

    // 3a. Allowed `exec --call-id call-exec-01 -- /bin/echo hello-a9`:
    let exec_ok = Command::new(helper_bin())
        .arg("exec")
        .arg("--state")
        .arg(&state_path)
        .arg("--offline")
        .arg("--call-id")
        .arg("call-exec-01")
        .arg("--")
        .arg("/bin/echo")
        .arg("hello-a9")
        .output()
        .expect("exec allowed");
    assert!(
        exec_ok.status.success(),
        "allowed exec failed: {}",
        String::from_utf8_lossy(&exec_ok.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&exec_ok.stdout).trim(), "hello-a9");

    // 3b. Denied `exec --call-id call-denied-99 -- /usr/bin/true` -> exit 77, NO ToolCall, NO ToolResult:
    let exec_denied = Command::new(helper_bin())
        .arg("exec")
        .arg("--state")
        .arg(&state_path)
        .arg("--offline")
        .arg("--call-id")
        .arg("call-denied-99")
        .arg("--")
        .arg("/usr/bin/true")
        .output()
        .expect("exec denied");
    assert_eq!(exec_denied.status.code(), Some(77));

    // 4. Run `mcp-proxy` with a Python child MCP server testing:
    //    - `tools/list` (`id: "list-1"`)
    //    - allowed `tools/call` (`id: "mcp-call-42"` -> `echo_tool`) + unsolicited unknown `id: "ghost-id-999"`
    //    - denied `tools/call` (`id: "denied-call-7"` -> `drop_prod_table`)
    //    - allowed `tools/call` with numeric JSON-RPC `id: 108` (`callId == "108"`)
    let mcp_server_py = tmp.join("mock_mcp_server.py");
    fs::write(
        &mcp_server_py,
        r#"import json, sys

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    rid = req.get("id")
    method = req.get("method")
    if method == "tools/list":
        resp = {
            "jsonrpc": "2.0",
            "id": rid,
            "result": {
                "tools": [
                    {"name": "echo_tool", "description": "Safe echo", "inputSchema": {"type": "object"}},
                    {"name": "drop_prod_table", "description": "Danger", "inputSchema": {"type": "object"}}
                ]
            }
        }
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
    elif method == "tools/call":
        # Emit an unsolicited response for an unknown call ID first to prove mcp-proxy never emits ToolResult for unknown IDs!
        ghost = {"jsonrpc": "2.0", "id": "ghost-id-999", "result": {"content": [{"type": "text", "text": "ghost"}]}}
        sys.stdout.write(json.dumps(ghost) + "\n")
        sys.stdout.flush()
        args = req.get("params", {}).get("arguments", {})
        resp = {
            "jsonrpc": "2.0",
            "id": rid,
            "result": {
                "content": [{"type": "text", "text": "echo:" + str(args.get("msg", ""))}]
            }
        }
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
"#,
    )
    .unwrap();

    let bundle_path = tmp.join("bundle.json");
    let mut proxy_child = Command::new(helper_bin())
        .arg("mcp-proxy")
        .arg("--server-id")
        .arg("demo-mcp")
        .arg("--state")
        .arg(&state_path)
        .arg("--offline")
        .arg("--out-bundle")
        .arg(&bundle_path)
        .arg("--")
        .arg("python3")
        .arg("-u")
        .arg(&mcp_server_py)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp-proxy");

    {
        let pstdin = proxy_child.stdin.as_mut().unwrap();
        let frames = [
            json!({"jsonrpc": "2.0", "id": "list-1", "method": "tools/list", "params": {}}),
            json!({"jsonrpc": "2.0", "id": "mcp-call-42", "method": "tools/call", "params": {"name": "echo_tool", "arguments": {"msg": "ok-str"}}}),
            json!({"jsonrpc": "2.0", "id": "denied-call-7", "method": "tools/call", "params": {"name": "drop_prod_table", "arguments": {}}}),
            json!({"jsonrpc": "2.0", "id": 108, "method": "tools/call", "params": {"name": "echo_tool", "arguments": {"msg": "ok-num"}}}),
        ];
        for f in &frames {
            writeln!(pstdin, "{f}").unwrap();
            pstdin.flush().unwrap();
        }
    }
    let proxy_out = proxy_child.wait_with_output().expect("wait mcp-proxy");
    assert!(
        proxy_out.status.success(),
        "mcp-proxy failed: {}",
        String::from_utf8_lossy(&proxy_out.stderr)
    );

    // 5. Inspect all workload records in exported `bundle.json`:
    let mut bundle_val: Value =
        serde_json::from_slice(&fs::read(&bundle_path).unwrap()).expect("parse bundle.json");
    let blobs_by_ref: BTreeMap<String, Vec<u8>> = bundle_val["blobs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| {
            (
                b["ref"].as_str().unwrap().to_string(),
                decode_strict_base64(b["base64"].as_str().unwrap()).unwrap(),
            )
        })
        .collect();

    let mut events: Vec<(String, String, Value)> = Vec::new();
    for r in bundle_val["records"].as_array().unwrap() {
        let r_ref = r["ref"].as_str().unwrap().to_string();
        let p_bytes = decode_strict_base64(r["envelope"]["payload"].as_str().unwrap()).unwrap();
        let p_val: Value = serde_json::from_slice(&p_bytes).unwrap();
        let kind = p_val["kind"].as_str().unwrap().to_string();
        if let Some(det) = p_val["body"].get("details") {
            let det_map = det.as_object().expect("details object");
            validate_a9_details(det_map, &format!("{kind}.details")).unwrap();
        }
        if matches!(
            kind.as_str(),
            "PolicyDecision" | "ToolCall" | "ToolResult" | "Observation"
        ) {
            events.push((r_ref, kind, p_val));
        }
    }

    let kind_seq: Vec<&str> = events.iter().map(|(_, k, _)| k.as_str()).collect();
    assert_eq!(
        kind_seq,
        vec![
            "PolicyDecision", // 0: exec /bin/echo allow
            "ToolCall",       // 1: exec /bin/echo (call-exec-01)
            "ToolResult",     // 2: exec /bin/echo result (call == events[1].0)
            "PolicyDecision", // 3: exec /usr/bin/true deny (NO ToolCall, NO ToolResult!)
            "Observation",    // 4: mcp_tools_pinned
            "PolicyDecision", // 5: mcp echo_tool allow (mcp-call-42)
            "ToolCall",       // 6: mcp echo_tool (callId == "mcp-call-42")
            "ToolResult", // 7: mcp echo_tool result (call == events[6].0, callId == "mcp-call-42"; ghost-id-999 omitted!)
            "PolicyDecision", // 8: mcp drop_prod_table deny (denied-call-7; NO ToolCall, NO ToolResult!)
            "PolicyDecision", // 9: mcp echo_tool allow (108)
            "ToolCall",       // 10: mcp echo_tool (callId == "108")
            "ToolResult",     // 11: mcp echo_tool result (call == events[10].0, callId == "108")
        ]
    );

    // Check `exec` ToolCall -> ToolResult linkage & top-level `callId`:
    assert_eq!(events[1].2["body"]["callId"], "call-exec-01");
    assert_eq!(events[2].2["body"]["call"], events[1].0);
    assert_eq!(events[2].2["body"]["callId"], "call-exec-01");
    assert_eq!(events[2].2["body"]["outcome"], "completed");
    let exec_res_blob: Value =
        serde_json::from_slice(&blobs_by_ref[events[2].2["body"]["contentRef"].as_str().unwrap()])
            .unwrap();
    assert_eq!(exec_res_blob["stdout"].as_str().unwrap().trim(), "hello-a9");

    // Check `mcp-proxy` string callId ("mcp-call-42") & integer callId ("108") ToolCall -> ToolResult linkage:
    assert_eq!(events[6].2["body"]["callId"], "mcp-call-42");
    assert_eq!(events[7].2["body"]["call"], events[6].0);
    assert_eq!(events[7].2["body"]["callId"], "mcp-call-42");
    assert_eq!(events[7].2["body"]["outcome"], "completed");
    let mcp_res_blob: Value =
        serde_json::from_slice(&blobs_by_ref[events[7].2["body"]["contentRef"].as_str().unwrap()])
            .unwrap();
    assert_eq!(mcp_res_blob["id"], "mcp-call-42");

    assert_eq!(events[10].2["body"]["callId"], "108");
    assert_eq!(events[11].2["body"]["call"], events[10].0);
    assert_eq!(events[11].2["body"]["callId"], "108");

    // Ensure denied call IDs and ghost call ID never leaked into any ToolCall or ToolResult:
    for (_, k, p) in &events {
        if k == "ToolCall" || k == "ToolResult" {
            let cid = p["body"]["callId"].as_str().unwrap_or("");
            assert_ne!(cid, "call-denied-99");
            assert_ne!(cid, "denied-call-7");
            assert_ne!(cid, "ghost-id-999");
        }
    }

    // 6. Carry `publications.json` into `bundle.json` (just as `Recurse.Provenance.Publication.carry/2` does)
    //    and verify the complete bundle with BOTH `r5e_verify` and `recurse_verify` (`0 failed, 0 incomplete`)!
    {
        let b_recs = bundle_val["records"].as_array_mut().unwrap();
        for pr in &pub_set.records {
            b_recs.push(serde_json::to_value(pr).unwrap());
        }
        let b_keys = bundle_val["keys"].as_array_mut().unwrap();
        for pk in &pub_set.keys {
            b_keys.push(serde_json::to_value(pk).unwrap());
        }
        let b_blobs = bundle_val["blobs"].as_array_mut().unwrap();
        for pb in &pub_set.blobs {
            b_blobs.push(serde_json::to_value(pb).unwrap());
        }
    }
    let carried_bundle_path = tmp.join("bundle-with-pubs.json");
    fs::write(
        &carried_bundle_path,
        encode_canonical_json(&bundle_val).unwrap(),
    )
    .unwrap();

    let local_profile_ref = mint_summary["state"]["local_profile_ref"]
        .as_str()
        .unwrap()
        .to_string();
    let pub_trust_arg = format!("{publisher_key_id}=r5e.io");
    assert_both_verifiers_zero_failed_zero_incomplete(
        &carried_bundle_path,
        &[&local_profile_ref],
        &[&pub_trust_arg],
        &[&root_id],
    );

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn prepare_and_finalize_publication_ed25519_es256_es384_high_s_der_openssl_and_cross_chain_proposal(
) {
    let tmp = temp_test_dir("publish-ceremony");

    let cross_chain_proposal = format!(
        "chain:evidence:sha256:{}/evidence:sha256:{}",
        "c".repeat(64),
        "d".repeat(64)
    );
    let same_chain_proposal = format!("evidence:sha256:{}", "a".repeat(64));
    let superseded_prev = format!("evidence:sha256:{}", "b".repeat(64));

    // Helper closure wrapping a finalized `CarriedPublicationSet` into a self-contained v2 bundle
    // and proving BOTH `r5e_verify` and `recurse_verify` report `failed: 0, incomplete: 0`!
    let verify_publication_file_with_clean_room_verifiers =
        |pub_json_path: &Path, publisher_key_id: &str| {
            let set: CarriedPublicationSet =
                serde_json::from_slice(&fs::read(pub_json_path).unwrap()).unwrap();
            assert_eq!(set.records.len(), 1);
            assert_eq!(set.keys.len(), 1);
            assert_eq!(set.blobs.len(), 29, "1 publisher profile + 28 definitions");

            let rec_payload: Value = serde_json::from_slice(
                &decode_strict_base64(&set.records[0].envelope.payload).unwrap(),
            )
            .unwrap();
            let stream = rec_payload["stream"].as_str().unwrap();
            let pub_profile_ref = rec_payload["profileRef"].as_str().unwrap();
            let bundle = json!({
                "format": "r5e.provenance-export/v2",
                "scope": {
                    "query": { "publication": set.records[0].record_ref },
                    "at": [{ "stream": stream, "seq": 1, "event": set.records[0].record_ref }],
                },
                "records": set.records,
                "blobs": set.blobs,
                "keys": set.keys,
                "seals": [],
                "checkpoints": [],
                "proofs": [],
                "publicationProofs": [],
                "omissions": [],
            });
            let b_path = pub_json_path.with_extension("bundle.json");
            fs::write(&b_path, encode_canonical_json(&bundle).unwrap()).unwrap();
            let trust_spec = format!("{publisher_key_id}=r5e.io");
            assert_both_verifiers_zero_failed_zero_incomplete(
                &b_path,
                &[pub_profile_ref],
                &[&trust_spec],
                &[],
            );
        };

    // -----------------------------------------------------------------------
    // Case A: Ed25519 + same-chain `--proposal` + `--previous` + expanded dir without index.json
    // -----------------------------------------------------------------------
    let defs_dir = definitions_dir();
    let no_index_dir = tmp.join("defs-no-index");
    for entry in ["core.r5e.io/v1", "provenance.r5e.io/v2"] {
        let src_sub = defs_dir.join(entry);
        let dst_sub = no_index_dir.join(entry);
        fs::create_dir_all(&dst_sub).unwrap();
        for f in fs::read_dir(&src_sub).unwrap() {
            let f = f.unwrap();
            fs::copy(f.path(), dst_sub.join(f.file_name())).unwrap();
        }
    }
    // Also copy package manifest JSONs to ensure non-`r5e.kind-definition/v1` files are ignored cleanly:
    fs::copy(
        defs_dir.join("r5e.core.json"),
        no_index_dir.join("r5e.core.json"),
    )
    .unwrap();

    let ed_sk = SigningKey::from_bytes(&[0x71; 32]);
    let ed_pub_b64 = BASE64_STANDARD.encode(ed_sk.verifying_key().to_bytes());
    let ed_prep = tmp.join("ed25519-prep.json");
    let ed_pae = tmp.join("ed25519.pae");
    let ed_out = tmp.join("ed25519-publications.json");

    let out_a = Command::new(helper_bin())
        .arg("prepare-publication")
        .arg("--definitions-dir")
        .arg(&no_index_dir)
        .arg("--publisher-public-key")
        .arg(&ed_pub_b64)
        .arg("--algorithm")
        .arg("ed25519")
        .arg("--package")
        .arg("r5e.provenance")
        .arg("--proposal")
        .arg(&same_chain_proposal)
        .arg("--previous")
        .arg(&superseded_prev)
        .arg("--stream")
        .arg("urn:r5e:stream:publisher:r5e:api:ed25519test")
        .arg("--captured-at")
        .arg("2026-11-15T14:00:00.000000Z")
        .arg("--out-prepared")
        .arg(&ed_prep)
        .arg("--out-pae")
        .arg(&ed_pae)
        .output()
        .unwrap();
    assert!(
        out_a.status.success(),
        "ed25519 prepare failed: {}",
        String::from_utf8_lossy(&out_a.stderr)
    );
    let ed_sig = ed_sk.sign(&fs::read(&ed_pae).unwrap());
    let ed_sig_file = tmp.join("ed25519.sig");
    fs::write(&ed_sig_file, ed_sig.to_bytes()).unwrap();

    let fin_a = Command::new(helper_bin())
        .arg("finalize-publication")
        .arg("--prepared")
        .arg(&ed_prep)
        .arg("--signature-file")
        .arg(&ed_sig_file)
        .arg("--out")
        .arg(&ed_out)
        .output()
        .unwrap();
    assert!(
        fin_a.status.success(),
        "ed25519 finalize failed: {}",
        String::from_utf8_lossy(&fin_a.stderr)
    );
    let fin_a_json: Value = serde_json::from_slice(&fin_a.stdout).unwrap();
    assert_eq!(fin_a_json["algorithm"], "ed25519");
    assert_eq!(fin_a_json["definition_count"], 28);
    assert_eq!(fin_a_json["signature_normalized"], false);
    verify_publication_file_with_clean_room_verifiers(
        &ed_out,
        fin_a_json["publisher_key_id"].as_str().unwrap(),
    );

    // -----------------------------------------------------------------------
    // Case B: ES256 with guaranteed HIGH-S (`s > floor(n / 2)`) ASN.1 DER signature
    //         + cross-chain `--proposal chain:evidence:sha256:.../evidence:sha256:...`
    // -----------------------------------------------------------------------
    let p256_secret = [0x23u8; 32];
    let p256_pub =
        derive_ecdsa_public_key_uncompressed(SignatureAlgorithm::Es256, &p256_secret).unwrap();
    let p256_pem = encode_spki_public_key_pem(SignatureAlgorithm::Es256, &p256_pub).unwrap();
    let p256_pem_path = tmp.join("p256-pub.pem");
    fs::write(&p256_pem_path, &p256_pem).unwrap();

    let p256_prep = tmp.join("es256-prep.json");
    let p256_pae = tmp.join("es256.pae");
    let p256_out = tmp.join("es256-publications.json");

    let out_b = Command::new(helper_bin())
        .arg("prepare-publication")
        .arg("--definitions-dir")
        .arg(&defs_dir)
        .arg("--publisher-public-key")
        .arg(&p256_pem_path)
        .arg("--algorithm")
        .arg("es256")
        .arg("--package")
        .arg("r5e.provenance")
        .arg("--proposal")
        .arg(&cross_chain_proposal)
        .arg("--captured-at")
        .arg("2026-11-15T15:00:00.000000Z")
        .arg("--out-prepared")
        .arg(&p256_prep)
        .arg("--out-pae")
        .arg(&p256_pae)
        .output()
        .unwrap();
    assert!(
        out_b.status.success(),
        "es256 prepare failed: {}",
        String::from_utf8_lossy(&out_b.stderr)
    );

    let p256_pae_bytes = fs::read(&p256_pae).unwrap();
    let (expected_low_s_64, high_s_der_p256) =
        sign_ecdsa_with_high_s_der(SignatureAlgorithm::Es256, &p256_secret, &p256_pae_bytes)
            .unwrap();
    assert_eq!(high_s_der_p256[0], 0x30, "must be ASN.1 DER SEQUENCE");
    // Raw high-S DER is NOT valid wire r||s before normalization:
    assert!(verify_signature(
        SignatureAlgorithm::Es256,
        &p256_pub,
        &p256_pae_bytes,
        &high_s_der_p256
    )
    .is_err());

    let p256_der_path = tmp.join("es256-high-s.der");
    fs::write(&p256_der_path, &high_s_der_p256).unwrap();

    let fin_b = Command::new(helper_bin())
        .arg("finalize-publication")
        .arg("--prepared")
        .arg(&p256_prep)
        .arg("--signature-file")
        .arg(&p256_der_path)
        .arg("--out")
        .arg(&p256_out)
        .output()
        .unwrap();
    assert!(
        fin_b.status.success(),
        "es256 high-S DER finalize failed: {}",
        String::from_utf8_lossy(&fin_b.stderr)
    );
    let fin_b_json: Value = serde_json::from_slice(&fin_b.stdout).unwrap();
    assert_eq!(fin_b_json["algorithm"], "es256");
    assert_eq!(fin_b_json["signature_normalized"], true);

    let p256_set: CarriedPublicationSet =
        serde_json::from_slice(&fs::read(&p256_out).unwrap()).unwrap();
    let wire_sig_p256 =
        decode_strict_base64(&p256_set.records[0].envelope.signatures[0].sig).unwrap();
    assert_eq!(wire_sig_p256.len(), 64);
    assert_eq!(
        wire_sig_p256, expected_low_s_64,
        "high-S ASN.1 DER must normalize to exact 64B canonical low-S r||s"
    );
    let p256_payload: Value = serde_json::from_slice(
        &decode_strict_base64(&p256_set.records[0].envelope.payload).unwrap(),
    )
    .unwrap();
    assert_eq!(p256_payload["body"]["proposal"], cross_chain_proposal);
    verify_publication_file_with_clean_room_verifiers(
        &p256_out,
        fin_b_json["publisher_key_id"].as_str().unwrap(),
    );

    // -----------------------------------------------------------------------
    // Case C: ES384 with guaranteed HIGH-S (`s > floor(n / 2)`) ASN.1 DER signature
    //         AND real `/usr/bin/openssl` P-384 DER signature
    // -----------------------------------------------------------------------
    let p384_secret = [0x37u8; 48];
    let p384_pub =
        derive_ecdsa_public_key_uncompressed(SignatureAlgorithm::Es384, &p384_secret).unwrap();
    let p384_pem = encode_spki_public_key_pem(SignatureAlgorithm::Es384, &p384_pub).unwrap();
    let p384_pem_path = tmp.join("p384-pub.pem");
    fs::write(&p384_pem_path, &p384_pem).unwrap();

    let p384_prep = tmp.join("es384-prep.json");
    let p384_pae = tmp.join("es384.pae");
    let p384_out = tmp.join("es384-publications.json");

    let out_c = Command::new(helper_bin())
        .arg("prepare-publication")
        .arg("--definitions-dir")
        .arg(&defs_dir)
        .arg("--publisher-public-key")
        .arg(&p384_pem_path)
        .arg("--algorithm")
        .arg("es384")
        .arg("--package")
        .arg("r5e.provenance")
        .arg("--captured-at")
        .arg("2026-11-15T16:00:00.000000Z")
        .arg("--out-prepared")
        .arg(&p384_prep)
        .arg("--out-pae")
        .arg(&p384_pae)
        .output()
        .unwrap();
    assert!(
        out_c.status.success(),
        "es384 prepare failed: {}",
        String::from_utf8_lossy(&out_c.stderr)
    );
    let p384_pae_bytes = fs::read(&p384_pae).unwrap();
    let (expected_low_s_96, high_s_der_p384) =
        sign_ecdsa_with_high_s_der(SignatureAlgorithm::Es384, &p384_secret, &p384_pae_bytes)
            .unwrap();
    let fin_c = Command::new(helper_bin())
        .arg("finalize-publication")
        .arg("--prepared")
        .arg(&p384_prep)
        .arg("--signature-b64")
        .arg(BASE64_STANDARD.encode(&high_s_der_p384))
        .arg("--out")
        .arg(&p384_out)
        .output()
        .unwrap();
    assert!(
        fin_c.status.success(),
        "es384 high-S DER finalize failed: {}",
        String::from_utf8_lossy(&fin_c.stderr)
    );
    let fin_c_json: Value = serde_json::from_slice(&fin_c.stdout).unwrap();
    assert_eq!(fin_c_json["algorithm"], "es384");
    assert_eq!(fin_c_json["signature_normalized"], true);
    let p384_set: CarriedPublicationSet =
        serde_json::from_slice(&fs::read(&p384_out).unwrap()).unwrap();
    let wire_sig_p384 =
        decode_strict_base64(&p384_set.records[0].envelope.signatures[0].sig).unwrap();
    assert_eq!(wire_sig_p384.len(), 96);
    assert_eq!(wire_sig_p384, expected_low_s_96);
    verify_publication_file_with_clean_room_verifiers(
        &p384_out,
        fin_c_json["publisher_key_id"].as_str().unwrap(),
    );

    // Real OpenSSL CLI signing check (simulating external `openssl dgst -sha256 -sign` / PKCS#11):
    if Path::new("/usr/bin/openssl").exists() {
        let ossl_priv = tmp.join("ossl-p256-priv.pem");
        let ossl_pub = tmp.join("ossl-p256-pub.pem");
        let ossl_prep = tmp.join("ossl-prep.json");
        let ossl_pae = tmp.join("ossl.pae");
        let ossl_sig = tmp.join("ossl.der.sig");
        let ossl_out = tmp.join("ossl-publications.json");

        assert!(Command::new("/usr/bin/openssl")
            .args([
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out"
            ])
            .arg(&ossl_priv)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/openssl")
            .args(["ec", "-in"])
            .arg(&ossl_priv)
            .args(["-pubout", "-out"])
            .arg(&ossl_pub)
            .status()
            .unwrap()
            .success());

        assert!(Command::new(helper_bin())
            .args(["prepare-publication", "--definitions-dir"])
            .arg(&defs_dir)
            .arg("--publisher-public-key")
            .arg(&ossl_pub)
            .args([
                "--captured-at",
                "2026-11-15T16:30:00.000000Z",
                "--out-prepared"
            ])
            .arg(&ossl_prep)
            .arg("--out-pae")
            .arg(&ossl_pae)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/openssl")
            .args(["dgst", "-sha256", "-sign"])
            .arg(&ossl_priv)
            .arg("-out")
            .arg(&ossl_sig)
            .arg(&ossl_pae)
            .status()
            .unwrap()
            .success());
        let ossl_fin = Command::new(helper_bin())
            .arg("finalize-publication")
            .arg("--prepared")
            .arg(&ossl_prep)
            .arg("--signature-file")
            .arg(&ossl_sig)
            .arg("--out")
            .arg(&ossl_out)
            .output()
            .unwrap();
        assert!(
            ossl_fin.status.success(),
            "openssl p256 DER finalize failed: {}",
            String::from_utf8_lossy(&ossl_fin.stderr)
        );
        let ossl_summary: Value = serde_json::from_slice(&ossl_fin.stdout).unwrap();
        verify_publication_file_with_clean_room_verifiers(
            &ossl_out,
            ossl_summary["publisher_key_id"].as_str().unwrap(),
        );
    }

    // -----------------------------------------------------------------------
    // Negative Cases: label in cross-chain proposal, bad signature, tampered blob
    // -----------------------------------------------------------------------
    let bad_label_out = Command::new(helper_bin())
        .arg("prepare-publication")
        .arg("--definitions-dir")
        .arg(&defs_dir)
        .arg("--publisher-public-key")
        .arg(&p256_pem_path)
        .arg("--proposal")
        .arg(format!("chain:r5e-dev/evidence:sha256:{}", "d".repeat(64)))
        .arg("--out-prepared")
        .arg(tmp.join("never.json"))
        .arg("--out-pae")
        .arg(tmp.join("never.pae"))
        .output()
        .unwrap();
    assert!(!bad_label_out.status.success());

    let never_written = tmp.join("refused-out.json");
    let mut bad_sig = expected_low_s_64.clone();
    bad_sig[0] ^= 0x01;
    let bad_sig_fin = Command::new(helper_bin())
        .arg("finalize-publication")
        .arg("--prepared")
        .arg(&p256_prep)
        .arg("--signature-b64")
        .arg(BASE64_STANDARD.encode(&bad_sig))
        .arg("--out")
        .arg(&never_written)
        .output()
        .unwrap();
    assert!(!bad_sig_fin.status.success());
    assert!(
        !never_written.exists(),
        "--out must NEVER be created when signature verification fails"
    );

    // Tamper with a definition blob inside `PreparedPublication` and verify `finalize-publication` refuses:
    let mut tampered_prep: Value = serde_json::from_slice(&fs::read(&p256_prep).unwrap()).unwrap();
    tampered_prep["blobs"][3]["base64"] = Value::String(BASE64_STANDARD.encode(b"{}"));
    let tampered_prep_path = tmp.join("tampered-prep.json");
    fs::write(
        &tampered_prep_path,
        serde_json::to_vec(&tampered_prep).unwrap(),
    )
    .unwrap();
    let tampered_fin = Command::new(helper_bin())
        .arg("finalize-publication")
        .arg("--prepared")
        .arg(&tampered_prep_path)
        .arg("--signature-file")
        .arg(&p256_der_path)
        .arg("--out")
        .arg(&never_written)
        .output()
        .unwrap();
    assert!(!tampered_fin.status.success());
    assert!(!never_written.exists());

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn detached_piv_high_s_der_cosign_workload_badge_and_claim_helpers_work_first_try() {
    let tmp = temp_test_dir("detached-cosign-and-claim");

    // 1. Detached ES256 high-S ASN.1 DER co-sign on `mint-workload-badge` + `cosign-workload-badge`:
    let root_seed = [0x81u8; 32];
    let root_sk = SigningKey::from_bytes(&root_seed);
    let root_id = ed25519_key_id(&root_sk.verifying_key().to_bytes());
    let root_key_path = tmp.join("root.pem");
    write_private_key_file_0600(&root_key_path, &root_seed, true).unwrap();

    let wl_p256_secret = [0x44u8; 32];
    let wl_p256_pub =
        derive_ecdsa_public_key_uncompressed(SignatureAlgorithm::Es256, &wl_p256_secret).unwrap();
    let wl_p256_pem = encode_spki_public_key_pem(SignatureAlgorithm::Es256, &wl_p256_pub).unwrap();
    let wl_p256_pem_path = tmp.join("wl-p256-pub.pem");
    fs::write(&wl_p256_pem_path, &wl_p256_pem).unwrap();

    let prep_badge_path = tmp.join("prepared-badge.json");
    let badge_pae_path = tmp.join("badge.pae");
    let grant_out_path = tmp.join("es256-badge-grant.json");

    let mint_prep = Command::new(helper_bin())
        .arg("mint-workload-badge")
        .arg("--root-key-file")
        .arg(&root_key_path)
        .arg("--workload-public-key")
        .arg(&wl_p256_pem_path)
        .arg("--deployment")
        .arg("meridian")
        .arg("--principal")
        .arg("urn:r5e:principal:alice")
        .arg("--workload")
        .arg("urn:r5e:workload:piv-agent")
        .arg("--out-prepared-badge")
        .arg(&prep_badge_path)
        .arg("--out-badge-pae")
        .arg(&badge_pae_path)
        .output()
        .unwrap();
    assert!(
        mint_prep.status.success(),
        "mint-workload-badge ES256 prepare failed: {}",
        String::from_utf8_lossy(&mint_prep.stderr)
    );

    let badge_pae = fs::read(&badge_pae_path).unwrap();
    let (wl_low_s_64, wl_high_s_der) =
        sign_ecdsa_with_high_s_der(SignatureAlgorithm::Es256, &wl_p256_secret, &badge_pae).unwrap();
    let wl_der_path = tmp.join("wl-high-s.der");
    fs::write(&wl_der_path, &wl_high_s_der).unwrap();

    let cosign_out = Command::new(helper_bin())
        .arg("cosign-workload-badge")
        .arg("--prepared-badge")
        .arg(&prep_badge_path)
        .arg("--signature-file")
        .arg(&wl_der_path)
        .arg("--out-grant-file")
        .arg(&grant_out_path)
        .output()
        .unwrap();
    assert!(
        cosign_out.status.success(),
        "cosign-workload-badge ES256 high-S DER failed: {}",
        String::from_utf8_lossy(&cosign_out.stderr)
    );
    let cosign_summary: Value = serde_json::from_slice(&cosign_out.stdout).unwrap();
    assert_eq!(cosign_summary["signature_normalized"], true);

    let grant_json: Value = serde_json::from_slice(&fs::read(&grant_out_path).unwrap()).unwrap();
    let badge_rec = grant_json["records"].as_array().unwrap().last().unwrap();
    let sig2_raw = decode_strict_base64(
        badge_rec["envelope"]["signatures"][1]["sig"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(sig2_raw, wl_low_s_64);

    // 2. Detached ES256 root signature (high-S DER) on `attach_external_claim_signature`
    //    with an ES384 hardware publisher `DefinitionPublished`:
    let pub384_secret = [0x55u8; 48];
    let pub384_pub =
        derive_ecdsa_public_key_uncompressed(SignatureAlgorithm::Es384, &pub384_secret).unwrap();
    let pub384_id = compute_key_id(SignatureAlgorithm::Es384, &pub384_pub).unwrap();
    let schemas = base_v2_schema_map();
    let defs_vec: Vec<Value> = schemas
        .iter()
        .map(|(k, v)| json!({ "kind": k, "definition": v }))
        .collect();
    let pub_profile_bytes = encode_canonical_json(&json!({
        "format": "r5e.capture-profile/v2",
        "schemas": schemas,
        "authority": {
            "bindings": [{
                "streamPrefix": "urn:r5e:stream:publisher:r5e:",
                "actorPrefixes": ["urn:r5e:publisher:"],
                "issuerKeys": [&pub384_id],
                "sealerKeys": []
            }],
            "checkpointKeys": []
        },
        "durability": {
            "failureDomain": "published once and carried",
            "requiredPayloads": "submitted",
            "onFailure": "refuse"
        },
        "policyRequiredKinds": [],
        "deploymentPolicyRef": bytes_ref(b"r5e.publisher/r5e")
    }))
    .unwrap();
    let pub_profile_ref = bytes_ref(&pub_profile_bytes);
    let pub_payload_bytes = encode_canonical_json(&json!({
        "apiVersion": "provenance.r5e.io/v2",
        "kind": "DefinitionPublished",
        "schemaRef": DEFINITION_PUBLISHED_SCHEMA_REF,
        "profileRef": &pub_profile_ref,
        "issuer": &pub384_id,
        "stream": "urn:r5e:stream:publisher:r5e:api:0123456789abcdef",
        "seq": 1,
        "previous": null,
        "actor": "urn:r5e:publisher:r5e",
        "capturedAt": "2026-11-15T12:00:00.000000Z",
        "body": { "definitions": &defs_vec, "package": "r5e.provenance" }
    }))
    .unwrap();
    let pub_pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &pub_payload_bytes);
    let (pub384_low_s, _) =
        sign_ecdsa_with_high_s_der(SignatureAlgorithm::Es384, &pub384_secret, &pub_pae).unwrap();
    let pub_rec = r5e_endpoint_helper::attestation::SignedEndpointRecord {
        record_ref: evidence_ref(&pub_payload_bytes),
        envelope: r5e_endpoint_helper::attestation::DsseEnvelope {
            payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
            payload: BASE64_STANDARD.encode(&pub_payload_bytes),
            signatures: vec![r5e_endpoint_helper::attestation::DsseSignature {
                keyid: pub384_id.clone(),
                sig: BASE64_STANDARD.encode(&pub384_low_s),
            }],
        },
    };

    let bootstrap_sk = SigningKey::from_bytes(&[0x66; 32]);
    let bootstrap_pub = bootstrap_sk.verifying_key().to_bytes();
    let bootstrap_id = ed25519_key_id(&bootstrap_pub);
    let bootstrap_profile_bytes = encode_canonical_json(&json!({
        "format": "r5e.capture-profile/v2",
        "schemas": base_v2_schema_map(),
        "authority": {
            "bindings": [{
                "streamPrefix": "urn:r5e:stream:r5e-api:start",
                "actorPrefixes": ["urn:r5e:"],
                "issuerKeys": [&bootstrap_id],
                "sealerKeys": []
            }],
            "checkpointKeys": []
        },
        "durability": {
            "failureDomain": "bootstrap",
            "requiredPayloads": "submitted",
            "onFailure": "refuse"
        },
        "policyRequiredKinds": [],
        "deploymentPolicyRef": bytes_ref(b"bootstrap")
    }))
    .unwrap();
    let bootstrap_profile_ref = bytes_ref(&bootstrap_profile_bytes);

    let cs_map: Map<String, Value> = serde_json::from_value(json!({
        "apiVersion": "provenance.r5e.io/v2",
        "kind": "ChainStarted",
        "schemaRef": base_v2_schema_map()["provenance.r5e.io/v2/ChainStarted"],
        "profileRef": &bootstrap_profile_ref,
        "stream": "urn:r5e:stream:r5e-api:start",
        "seq": 1,
        "previous": null,
        "actor": "urn:r5e:bootstrap:r5e-api",
        "capturedAt": "2026-11-15T12:01:00.000000Z",
        "body": {
            "deployment": "r5e-api",
            "bootstrap": &bootstrap_id,
            "bootstrapKey": {
                "algorithm": "ed25519",
                "bytes": BASE64_STANDARD.encode(bootstrap_pub)
            },
            "publication": &pub_rec.record_ref,
            "publisher": &pub384_id,
            "definitions": &defs_vec
        }
    }))
    .unwrap();
    let cs_rec = sign_v2_record_multi(&[&bootstrap_sk], cs_map).unwrap();

    let root_p256_secret = [0x77u8; 32];
    let root_p256_pub =
        derive_ecdsa_public_key_uncompressed(SignatureAlgorithm::Es256, &root_p256_secret).unwrap();
    let root_p256_id = compute_key_id(SignatureAlgorithm::Es256, &root_p256_pub).unwrap();
    let root_p256_entry = PublicKeyEntry {
        keyid: root_p256_id.clone(),
        algorithm: "es256".to_string(),
        bytes: BASE64_STANDARD.encode(&root_p256_pub),
    };

    let dep_payload_bytes = encode_canonical_json(&json!({
        "apiVersion": "provenance.r5e.io/v2",
        "kind": "Deployment",
        "schemaRef": base_v2_schema_map()["provenance.r5e.io/v2/Deployment"],
        "profileRef": &bootstrap_profile_ref,
        "issuer": &bootstrap_id,
        "stream": "urn:r5e:stream:r5e-api:start",
        "seq": 2,
        "previous": &cs_rec.record_ref,
        "actor": "urn:r5e:bootstrap:r5e-api",
        "capturedAt": "2026-11-15T12:01:05.000000Z",
        "body": {
            "accepts": &cs_rec.record_ref,
            "bootstrap": &bootstrap_id,
            "claimedBy": &root_p256_id,
            "roots": [{
                "key": &root_p256_id,
                "publicKey": {
                    "algorithm": "es256",
                    "bytes": &root_p256_entry.bytes
                },
                "holder": "operator",
                "custody": "hardware"
            }],
            "threshold": 1,
            "recoveryKeys": [root_id]
        }
    }))
    .unwrap();
    let dep_pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &dep_payload_bytes);
    let (dep_low_s_64, dep_high_s_der) =
        sign_ecdsa_with_high_s_der(SignatureAlgorithm::Es256, &root_p256_secret, &dep_pae).unwrap();

    let claim_req = PrepareClaimRequest {
        code: "block0-code".to_string(),
        claimed_by: root_p256_id.clone(),
        roots: vec![PrepareClaimRootEntry {
            public_key: SubjectPublicKey {
                algorithm: "es256".to_string(),
                bytes: root_p256_entry.bytes.clone(),
            },
            holder: Some("operator".to_string()),
            custody: Some("hardware".to_string()),
            identity: None,
        }],
        threshold: 1,
        recovery_keys: Some(vec![ed25519_key_id(&root_sk.verifying_key().to_bytes())]),
        custodians: None,
    };
    let prepared_claim = PreparedClaimResponse {
        ticket: "stateless-ticket-01".to_string(),
        expires: "2026-11-15T13:00:00.000000Z".to_string(),
        payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
        payload: BASE64_STANDARD.encode(&dep_payload_bytes),
        chain_started: cs_rec,
        publication: CarriedPublicationSet {
            records: vec![pub_rec],
            keys: vec![PublicKeyEntry {
                keyid: pub384_id.clone(),
                algorithm: "es384".to_string(),
                bytes: BASE64_STANDARD.encode(&pub384_pub),
            }],
            blobs: vec![BlobEntry {
                blob_ref: pub_profile_ref,
                media_type: None,
                base64: BASE64_STANDARD.encode(&pub_profile_bytes),
            }],
        },
        bootstrap_key: PublicKeyEntry {
            keyid: bootstrap_id,
            algorithm: "ed25519".to_string(),
            bytes: BASE64_STANDARD.encode(bootstrap_pub),
        },
        bootstrap_profile: BlobEntry {
            blob_ref: bootstrap_profile_ref,
            media_type: None,
            base64: BASE64_STANDARD.encode(&bootstrap_profile_bytes),
        },
    };

    let verified_claim = attach_external_claim_signature(
        &root_p256_entry,
        &claim_req,
        &prepared_claim,
        &[format!("{pub384_id}=r5e.io")],
        false,
        &dep_high_s_der,
        false,
    )
    .expect("attach ES256 high-S DER root signature on Deployment claim");
    assert!(verified_claim.inspection.publisher_trusted);
    assert_eq!(
        decode_strict_base64(&verified_claim.finalize_request.root_signature.sig).unwrap(),
        dep_low_s_64
    );

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn piv_hardware_ed25519_over_3000_byte_pae_is_refused_with_clear_message() {
    let tmp = temp_test_dir("piv-ed25519-limit");

    let ed_sk = SigningKey::from_bytes(&[0x91; 32]);
    let ed_pem = encode_spki_ed25519_pem(&ed_sk.verifying_key().to_bytes());
    let ed_pem_path = tmp.join("ed25519-9a.pem");
    fs::write(&ed_pem_path, &ed_pem).unwrap();

    let p256_priv = [0x61u8; 32];
    let p256_pub =
        derive_ecdsa_public_key_uncompressed(SignatureAlgorithm::Es256, &p256_priv).unwrap();
    let p256_pem = encode_spki_public_key_pem(SignatureAlgorithm::Es256, &p256_pub).unwrap();
    let p256_pem_path = tmp.join("es256-9a.pem");
    fs::write(&p256_pem_path, &p256_pem).unwrap();

    // 1. `prepare-publication --piv-hardware` with Ed25519 on 28 definitions (> 4,400 B PAE) refuses with `#6586` message:
    let defs_dir = definitions_dir();
    let pub_prep = tmp.join("pub-prep.json");
    let pub_pae = tmp.join("pub.pae");
    let out = Command::new(helper_bin())
        .args(["prepare-publication", "--definitions-dir"])
        .arg(&defs_dir)
        .arg("--publisher-public-key")
        .arg(&ed_pem_path)
        .arg("--piv-hardware")
        .arg("--out-prepared")
        .arg(&pub_prep)
        .arg("--out-pae")
        .arg(&pub_pae)
        .output()
        .expect("run prepare-publication --piv-hardware");
    assert_eq!(out.status.code(), Some(2));
    let stderr_txt = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr_txt.contains("PAE too long for PIV hardware Ed25519 (> 3000 bytes:")
            && stderr_txt.contains("split the endorsement or use es256"),
        "unexpected stderr: {stderr_txt}"
    );
    assert!(!pub_prep.exists());
    assert!(!pub_pae.exists());

    // 2. `prepare-endorsement` with Ed25519 whose PAE > 3,000 bytes refuses by default, while ES256 succeeds!
    let gw_sk = SigningKey::from_bytes(&[0x92; 32]);
    let gw_id = ed25519_key_id(&gw_sk.verifying_key().to_bytes());
    let big_details = json!({
        "noteA": "x".repeat(1800),
        "noteB": "y".repeat(1800)
    })
    .to_string();

    let end_prep = tmp.join("end-prep.json");
    let end_pae = tmp.join("end.pae");
    let out_ed_end = Command::new(helper_bin())
        .args(["prepare-endorsement", "--issuer-public-key"])
        .arg(&ed_pem_path)
        .args([
            "--subject",
            &gw_id,
            "--deployment",
            "piv-guard-test",
            "--details-json",
            &big_details,
            "--out-prepared",
        ])
        .arg(&end_prep)
        .arg("--out-pae")
        .arg(&end_pae)
        .output()
        .expect("run prepare-endorsement ed25519 > 3000B");
    assert_eq!(out_ed_end.status.code(), Some(2));
    let end_stderr = String::from_utf8_lossy(&out_ed_end.stderr);
    assert!(
        end_stderr.contains("PAE too long for PIV hardware Ed25519 (> 3000 bytes:")
            && end_stderr.contains("split the endorsement or use es256"),
        "unexpected endorsement stderr: {end_stderr}"
    );

    // Same > 3,000B endorsement with ES256 (`ECCP256`) succeeds because ECDSA pre-hashes with SHA-256!
    let out_es256_end = Command::new(helper_bin())
        .args(["prepare-endorsement", "--issuer-public-key"])
        .arg(&p256_pem_path)
        .args([
            "--subject",
            &gw_id,
            "--deployment",
            "piv-guard-test",
            "--details-json",
            &big_details,
            "--out-prepared",
        ])
        .arg(&end_prep)
        .arg("--out-pae")
        .arg(&end_pae)
        .output()
        .expect("run prepare-endorsement es256 > 3000B");
    assert!(
        out_es256_end.status.success(),
        "es256 prepare-endorsement failed: {}",
        String::from_utf8_lossy(&out_es256_end.stderr)
    );
    assert!(fs::read(&end_pae).unwrap().len() > 3000);

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn full_es256_publisher_and_es256_root_detached_piv_ceremony_verifies_end_to_end() {
    use std::io::{BufRead, BufReader, Read};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    let tmp = temp_test_dir("es256-piv-block0");

    // Hardware `es256` Publisher, `es256` Root #1, Custodian (`es256`), and Replacement Root #2 (`es256`):
    let pub_priv = [0x21u8; 32];
    let pub_uncompressed =
        derive_ecdsa_public_key_uncompressed(SignatureAlgorithm::Es256, &pub_priv).unwrap();
    let pub_kid = compute_key_id(SignatureAlgorithm::Es256, &pub_uncompressed).unwrap();
    let pub_pem = encode_spki_public_key_pem(SignatureAlgorithm::Es256, &pub_uncompressed).unwrap();
    let pub_pem_path = tmp.join("r5e-publisher.pem");
    fs::write(&pub_pem_path, &pub_pem).unwrap();

    let root1_priv = [0x31u8; 32];
    let root1_uncompressed =
        derive_ecdsa_public_key_uncompressed(SignatureAlgorithm::Es256, &root1_priv).unwrap();
    let root1_kid = compute_key_id(SignatureAlgorithm::Es256, &root1_uncompressed).unwrap();
    let root1_pem =
        encode_spki_public_key_pem(SignatureAlgorithm::Es256, &root1_uncompressed).unwrap();
    let root1_pem_path = tmp.join("r5e-root1.pem");
    fs::write(&root1_pem_path, &root1_pem).unwrap();

    let cust_priv = [0x41u8; 32];
    let cust_uncompressed =
        derive_ecdsa_public_key_uncompressed(SignatureAlgorithm::Es256, &cust_priv).unwrap();
    let cust_kid = compute_key_id(SignatureAlgorithm::Es256, &cust_uncompressed).unwrap();
    let cust_pem =
        encode_spki_public_key_pem(SignatureAlgorithm::Es256, &cust_uncompressed).unwrap();
    let cust_pem_path = tmp.join("custodian-es256.pem");
    fs::write(&cust_pem_path, &cust_pem).unwrap();

    let root2_priv = [0x51u8; 32];
    let root2_uncompressed =
        derive_ecdsa_public_key_uncompressed(SignatureAlgorithm::Es256, &root2_priv).unwrap();
    let root2_kid = compute_key_id(SignatureAlgorithm::Es256, &root2_uncompressed).unwrap();
    let root2_pem =
        encode_spki_public_key_pem(SignatureAlgorithm::Es256, &root2_uncompressed).unwrap();
    let root2_pem_path = tmp.join("r5e-root2.pem");
    fs::write(&root2_pem_path, &root2_pem).unwrap();

    assert!(pub_kid.starts_with("key:es256:sha256:"));
    assert!(root1_kid.starts_with("key:es256:sha256:"));
    assert!(cust_kid.starts_with("key:es256:sha256:"));
    assert!(root2_kid.starts_with("key:es256:sha256:"));

    // -----------------------------------------------------------------------
    // 1. Detached `es256` Publication (`prepare-publication` -> high-S DER -> `finalize-publication`)
    // -----------------------------------------------------------------------
    let defs_dir = definitions_dir();
    let pub_prep = tmp.join("pub-prep.json");
    let pub_pae = tmp.join("pub.pae");
    let publications_json = tmp.join("publications.json");

    let out_pub_prep = Command::new(helper_bin())
        .args(["prepare-publication", "--definitions-dir"])
        .arg(&defs_dir)
        .arg("--publisher-public-key")
        .arg(&pub_pem_path)
        .args([
            "--piv-hardware",
            "--package",
            "r5e.provenance",
            "--captured-at",
            "2026-11-16T06:00:00.000000Z",
            "--out-prepared",
        ])
        .arg(&pub_prep)
        .arg("--out-pae")
        .arg(&pub_pae)
        .output()
        .expect("prepare-publication es256");
    assert!(
        out_pub_prep.status.success(),
        "prepare-publication stderr: {}",
        String::from_utf8_lossy(&out_pub_prep.stderr)
    );

    let pub_pae_bytes = fs::read(&pub_pae).unwrap();
    assert!(pub_pae_bytes.len() > 4000);
    let (pub_low_s_64, pub_high_s_der) =
        sign_ecdsa_with_high_s_der(SignatureAlgorithm::Es256, &pub_priv, &pub_pae_bytes).unwrap();
    let pub_sig_der_path = tmp.join("pub-high-s.der");
    fs::write(&pub_sig_der_path, &pub_high_s_der).unwrap();

    let out_pub_fin = Command::new(helper_bin())
        .arg("finalize-publication")
        .arg("--prepared")
        .arg(&pub_prep)
        .arg("--signature-file")
        .arg(&pub_sig_der_path)
        .arg("--out")
        .arg(&publications_json)
        .output()
        .expect("finalize-publication es256");
    assert!(
        out_pub_fin.status.success(),
        "finalize-publication stderr: {}",
        String::from_utf8_lossy(&out_pub_fin.stderr)
    );
    let pub_fin_json: Value = serde_json::from_slice(&out_pub_fin.stdout).unwrap();
    assert_eq!(pub_fin_json["signature_normalized"], true);
    assert_eq!(pub_fin_json["publisher_key_id"], pub_kid);

    let pub_set: CarriedPublicationSet =
        serde_json::from_slice(&fs::read(&publications_json).unwrap()).unwrap();
    let pub_rec = pub_set.records[0].clone();
    assert_eq!(
        decode_strict_base64(&pub_rec.envelope.signatures[0].sig).unwrap(),
        pub_low_s_64
    );

    // -----------------------------------------------------------------------
    // 2. Mock Gateway HTTP Server supporting `es256` Claim, Grants, Principal, and Root Rotation
    // -----------------------------------------------------------------------
    let bootstrap_sk = SigningKey::from_bytes(&[0x71; 32]);
    let bootstrap_pub = bootstrap_sk.verifying_key().to_bytes();
    let bootstrap_id = ed25519_key_id(&bootstrap_pub);

    let gw_sk = SigningKey::from_bytes(&[0x72; 32]);
    let gw_pub = gw_sk.verifying_key().to_bytes();
    let gw_id = ed25519_key_id(&gw_pub);

    let deployment_slug = "block0-piv";
    let start_stream = format!("urn:r5e:stream:{deployment_slug}:start");
    let stream_prefix = format!("urn:r5e:stream:{deployment_slug}:");
    let schemas = base_v2_schema_map();

    let bootstrap_policy_ref = bytes_ref(b"r5e.bootstrap/block0-piv");
    let bootstrap_profile_doc = json!({
        "format": "r5e.capture-profile/v2",
        "schemas": schemas,
        "authority": {
            "bindings": [{
                "streamPrefix": &start_stream,
                "actorPrefixes": ["urn:r5e:node:"],
                "issuerKeys": [&bootstrap_id],
                "sealerKeys": []
            }],
            "checkpointKeys": []
        },
        "durability": {
            "failureDomain": "the node's own disk until shipped",
            "requiredPayloads": "submitted",
            "onFailure": "refuse"
        },
        "policyRequiredKinds": [],
        "deploymentPolicyRef": &bootstrap_policy_ref
    });
    let bootstrap_profile_bytes = encode_canonical_json(&bootstrap_profile_doc).unwrap();
    let bootstrap_profile_ref = bytes_ref(&bootstrap_profile_bytes);

    let pub_payload_val: Value =
        serde_json::from_slice(&decode_strict_base64(&pub_rec.envelope.payload).unwrap()).unwrap();
    let defs_arr = pub_payload_val["body"]["definitions"].clone();

    let cs_rec = sign_v2_record_multi(
        &[&bootstrap_sk],
        json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "ChainStarted",
            "schemaRef": base_v2_schema_map()["provenance.r5e.io/v2/ChainStarted"],
            "profileRef": &bootstrap_profile_ref,
            "stream": &start_stream,
            "seq": 1,
            "previous": null,
            "actor": "urn:r5e:node:block0-piv",
            "capturedAt": "2026-11-16T06:01:00.000000Z",
            "body": {
                "deployment": deployment_slug,
                "bootstrap": &bootstrap_id,
                "bootstrapKey": {
                    "algorithm": "ed25519",
                    "bytes": BASE64_STANDARD.encode(bootstrap_pub)
                },
                "publication": &pub_rec.record_ref,
                "publisher": &pub_kid,
                "definitions": defs_arr
            }
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .unwrap();

    #[derive(Default)]
    struct MockGatewayState {
        prepared_payload_b64: Option<String>,
        claimed_record: Option<r5e_endpoint_helper::attestation::SignedEndpointRecord>,
        accepted_grants: Vec<r5e_endpoint_helper::claim_http::SubmitGrantsRequest>,
        accepted_roots: Vec<r5e_endpoint_helper::root_rotation::SubmitRootChangeRequest>,
    }

    let state = Arc::new(Mutex::new(MockGatewayState::default()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let gw_url = format!("http://{addr}");

    let claim_code = "secret-piv-claim-code-9911";
    let code_file = tmp.join("claim.code");
    r5e_endpoint_helper::publication::write_atomic_file(&code_file, claim_code.as_bytes(), 0o600)
        .unwrap();

    let srv_state = Arc::clone(&state);
    let srv_cs_rec = cs_rec.clone();
    let srv_pub_set = pub_set.clone();
    let srv_bootstrap_sk = SigningKey::from_bytes(&bootstrap_sk.to_bytes());
    let srv_bootstrap_id = bootstrap_id.clone();
    let srv_bootstrap_pub_b64 = BASE64_STANDARD.encode(bootstrap_pub);
    let srv_bootstrap_prof_ref = bootstrap_profile_ref.clone();
    let srv_bootstrap_prof_b64 = BASE64_STANDARD.encode(&bootstrap_profile_bytes);
    let srv_gw_id = gw_id.clone();
    let srv_gw_pub_b64 = BASE64_STANDARD.encode(gw_pub);
    let srv_start_stream = start_stream.clone();
    let srv_stream_prefix = stream_prefix.clone();

    let server_handle = std::thread::spawn(move || {
        for stream_res in listener.incoming() {
            let Ok(mut tcp) = stream_res else { break };
            let mut reader = BufReader::new(tcp.try_clone().unwrap());
            let mut req_line = String::new();
            if reader.read_line(&mut req_line).unwrap_or(0) == 0 {
                continue;
            }
            let parts: Vec<&str> = req_line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            let (method, path) = (parts[0], parts[1]);
            let mut content_len = 0usize;
            loop {
                let mut h = String::new();
                if reader.read_line(&mut h).unwrap_or(0) == 0 || h.trim().is_empty() {
                    break;
                }
                if let Some((k, v)) = h.split_once(':') {
                    if k.trim().eq_ignore_ascii_case("content-length") {
                        content_len = v.trim().parse().unwrap_or(0);
                    }
                }
            }
            let mut body_buf = vec![0u8; content_len];
            if content_len > 0 {
                reader.read_exact(&mut body_buf).unwrap();
            }

            if method == "POST" && path == "/stop" {
                let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
                let _ = tcp.write_all(resp);
                break;
            }

            let (status_code, resp_val) = match (method, path) {
                ("POST", "/v1/deployment/claim/prepare") => {
                    let req_json: Value = serde_json::from_slice(&body_buf).unwrap();
                    assert_eq!(req_json["code"], claim_code);
                    let roots_in = req_json["roots"].as_array().unwrap();
                    let mut roots_out = Vec::new();
                    for r in roots_in {
                        let alg_str = r["publicKey"]["algorithm"].as_str().unwrap();
                        let b64 = r["publicKey"]["bytes"].as_str().unwrap();
                        let alg = SignatureAlgorithm::parse(alg_str).unwrap();
                        let raw = decode_strict_base64(b64).unwrap();
                        let kid = compute_key_id(alg, &raw).unwrap();
                        let mut m = Map::new();
                        m.insert("key".to_string(), Value::String(kid));
                        m.insert("publicKey".to_string(), r["publicKey"].clone());
                        for opt_k in ["holder", "custody", "identity"] {
                            if let Some(v) = r.get(opt_k) {
                                m.insert(opt_k.to_string(), v.clone());
                            }
                        }
                        roots_out.push(Value::Object(m));
                    }
                    let mut dep_body = Map::new();
                    dep_body.insert(
                        "accepts".to_string(),
                        Value::String(srv_cs_rec.record_ref.clone()),
                    );
                    dep_body.insert(
                        "bootstrap".to_string(),
                        Value::String(srv_bootstrap_id.clone()),
                    );
                    dep_body.insert("claimedBy".to_string(), req_json["claimedBy"].clone());
                    dep_body.insert("roots".to_string(), Value::Array(roots_out));
                    dep_body.insert("threshold".to_string(), req_json["threshold"].clone());
                    if let Some(rk) = req_json.get("recoveryKeys") {
                        dep_body.insert("recoveryKeys".to_string(), rk.clone());
                    }
                    if let Some(cust) = req_json.get("custodians") {
                        dep_body.insert("custodians".to_string(), cust.clone());
                    }
                    let dep_doc = json!({
                        "apiVersion": "provenance.r5e.io/v2",
                        "kind": "Deployment",
                        "schemaRef": base_v2_schema_map()["provenance.r5e.io/v2/Deployment"],
                        "profileRef": &srv_bootstrap_prof_ref,
                        "issuer": &srv_bootstrap_id,
                        "stream": &srv_start_stream,
                        "seq": 2,
                        "previous": &srv_cs_rec.record_ref,
                        "actor": "urn:r5e:node:block0-piv",
                        "capturedAt": "2026-11-16T06:02:00.000000Z",
                        "body": Value::Object(dep_body),
                    });
                    let dep_bytes = encode_canonical_json(&dep_doc).unwrap();
                    let dep_b64 = BASE64_STANDARD.encode(&dep_bytes);
                    srv_state.lock().unwrap().prepared_payload_b64 = Some(dep_b64.clone());
                    (
                        200,
                        json!({
                            "payloadType": PROVENANCE_V2_PAYLOAD_TYPE,
                            "payload": dep_b64,
                            "ticket": "piv-ticket-01",
                            "expires": "2026-11-16T06:12:00Z",
                            "chainStarted": &srv_cs_rec,
                            "bootstrapKey": {
                                "keyid": &srv_bootstrap_id,
                                "algorithm": "ed25519",
                                "bytes": &srv_bootstrap_pub_b64
                            },
                            "publication": &srv_pub_set,
                            "bootstrapProfile": {
                                "ref": &srv_bootstrap_prof_ref,
                                "base64": &srv_bootstrap_prof_b64
                            }
                        }),
                    )
                }
                ("POST", "/v1/deployment/claim/finalize") => {
                    let req_json: Value = serde_json::from_slice(&body_buf).unwrap();
                    assert_eq!(req_json["code"], claim_code);
                    let payload_b64 = req_json["payload"].as_str().unwrap();
                    let payload_bytes = decode_strict_base64(payload_b64).unwrap();
                    let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &payload_bytes);
                    let boot_sig = srv_bootstrap_sk.sign(&pae);
                    let root_sig_obj: r5e_endpoint_helper::attestation::DsseSignature =
                        serde_json::from_value(req_json["rootSignature"].clone()).unwrap();
                    // Verify gateway received canonical 64-byte low-S `r || s` (NOT ASN.1 DER!):
                    let root_sig_raw = decode_strict_base64(&root_sig_obj.sig).unwrap();
                    assert_eq!(root_sig_raw.len(), 64);
                    verify_signature(
                        SignatureAlgorithm::Es256,
                        &root1_uncompressed,
                        &pae,
                        &root_sig_raw,
                    )
                    .expect("gateway verifies canonical ES256 root signature");

                    let dep_ref = evidence_ref(&payload_bytes);
                    let dep_rec = r5e_endpoint_helper::attestation::SignedEndpointRecord {
                        record_ref: dep_ref.clone(),
                        envelope: r5e_endpoint_helper::attestation::DsseEnvelope {
                            payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
                            payload: payload_b64.to_string(),
                            signatures: vec![
                                r5e_endpoint_helper::attestation::DsseSignature {
                                    keyid: srv_bootstrap_id.clone(),
                                    sig: BASE64_STANDARD.encode(boot_sig.to_bytes()),
                                },
                                root_sig_obj,
                            ],
                        },
                    };
                    srv_state.lock().unwrap().claimed_record = Some(dep_rec.clone());
                    (
                        201,
                        json!({
                            "deploymentRecord": dep_rec,
                            "chain": dep_ref,
                            "chainStarted": &srv_cs_rec,
                            "gatewayKey": {
                                "keyid": &srv_gw_id,
                                "algorithm": "ed25519",
                                "bytes": &srv_gw_pub_b64
                            },
                            "streamPrefix": &srv_stream_prefix
                        }),
                    )
                }
                ("GET", "/v1/deployment") => {
                    let st = srv_state.lock().unwrap();
                    let dep_rec = st.claimed_record.clone().expect("already claimed");
                    (
                        200,
                        json!({
                            "deployment": deployment_slug,
                            "state": "claimed",
                            "chain": &dep_rec.record_ref,
                            "chainStarted": &srv_cs_rec,
                            "bootstrapKey": {
                                "keyid": &srv_bootstrap_id,
                                "algorithm": "ed25519",
                                "bytes": &srv_bootstrap_pub_b64
                            },
                            "deploymentRecord": dep_rec,
                            "gatewayKey": {
                                "keyid": &srv_gw_id,
                                "algorithm": "ed25519",
                                "bytes": &srv_gw_pub_b64
                            },
                            "streamPrefix": &srv_stream_prefix,
                            "grants": []
                        }),
                    )
                }
                ("POST", "/v1/deployment/grants") => {
                    let parsed: r5e_endpoint_helper::claim_http::SubmitGrantsRequest =
                        serde_json::from_slice(&body_buf).unwrap();
                    let refs: Vec<String> = parsed
                        .records
                        .iter()
                        .map(|r| r.record_ref.clone())
                        .collect();
                    srv_state.lock().unwrap().accepted_grants.push(parsed);
                    (201, json!({ "recorded": refs }))
                }
                ("POST", "/v1/deployment/roots") => {
                    let parsed: r5e_endpoint_helper::root_rotation::SubmitRootChangeRequest =
                        serde_json::from_slice(&body_buf).unwrap();
                    let mut refs: Vec<String> = parsed
                        .approvals
                        .iter()
                        .map(|r| r.record_ref.clone())
                        .collect();
                    refs.push(parsed.change.record_ref.clone());
                    srv_state.lock().unwrap().accepted_roots.push(parsed);
                    (201, json!({ "recorded": refs }))
                }
                other => panic!("unexpected mock gateway route: {other:?}"),
            };

            let resp_bytes = serde_json::to_vec(&resp_val).unwrap();
            let head = format!(
                "HTTP/1.1 {status_code} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                resp_bytes.len()
            );
            tcp.write_all(head.as_bytes()).unwrap();
            tcp.write_all(&resp_bytes).unwrap();
        }
    });

    // -----------------------------------------------------------------------
    // 3. Detached `es256` Claim (`prepare-claim` -> high-S DER -> `finalize-claim`)
    // -----------------------------------------------------------------------
    let claim_prep = tmp.join("claim-prep.json");
    let claim_pae = tmp.join("claim.pae");
    let claim_receipt = tmp.join("claim-receipt.json");
    let cust_spec = format!("mailto:lena@r5e.io={cust_kid}");
    let pub_pin = format!("{pub_kid}=core.r5e.io,provenance.r5e.io");

    let out_claim_prep = Command::new(helper_bin())
        .args([
            "prepare-claim",
            "--gateway-url",
            &gw_url,
            "--claim-code-file",
        ])
        .arg(&code_file)
        .arg("--root-public-key")
        .arg(&root1_pem_path)
        .args([
            "--holder",
            "person",
            "--custody",
            "hardware",
            "--identity",
            "mailto:lena@r5e.io",
            "--custodian",
            &cust_spec,
            "--trusted-publisher",
            &pub_pin,
            "--out-prepared",
        ])
        .arg(&claim_prep)
        .arg("--out-pae")
        .arg(&claim_pae)
        .output()
        .expect("prepare-claim es256");
    assert!(
        out_claim_prep.status.success(),
        "prepare-claim stderr: {}",
        String::from_utf8_lossy(&out_claim_prep.stderr)
    );

    // Zero secrets on disk: `claim-prep.json` must NOT contain `claim_code`!
    let claim_prep_raw = fs::read_to_string(&claim_prep).unwrap();
    assert!(!claim_prep_raw.contains(claim_code));

    let claim_pae_bytes = fs::read(&claim_pae).unwrap();
    let (_, claim_high_s_der) =
        sign_ecdsa_with_high_s_der(SignatureAlgorithm::Es256, &root1_priv, &claim_pae_bytes)
            .unwrap();
    let claim_sig_path = tmp.join("claim-high-s.der");
    fs::write(&claim_sig_path, &claim_high_s_der).unwrap();

    // Wrong-key signature MUST be refused locally BEFORE hitting `/v1/deployment/claim/finalize`:
    let (_, wrong_claim_der) =
        sign_ecdsa_with_high_s_der(SignatureAlgorithm::Es256, &root2_priv, &claim_pae_bytes)
            .unwrap();
    let wrong_claim_sig_path = tmp.join("wrong-claim.der");
    fs::write(&wrong_claim_sig_path, &wrong_claim_der).unwrap();
    let bad_fin = Command::new(helper_bin())
        .arg("finalize-claim")
        .arg("--prepared")
        .arg(&claim_prep)
        .arg("--claim-code-file")
        .arg(&code_file)
        .arg("--signature-file")
        .arg(&wrong_claim_sig_path)
        .output()
        .expect("finalize-claim wrong sig");
    assert!(!bad_fin.status.success());
    assert!(state.lock().unwrap().claimed_record.is_none());

    // Valid high-S ASN.1 DER signature normalizes to 64B low-S `r || s` and finalizes cleanly:
    let out_claim_fin = Command::new(helper_bin())
        .arg("finalize-claim")
        .arg("--prepared")
        .arg(&claim_prep)
        .arg("--claim-code-file")
        .arg(&code_file)
        .arg("--signature-file")
        .arg(&claim_sig_path)
        .arg("--out-receipt")
        .arg(&claim_receipt)
        .output()
        .expect("finalize-claim es256");
    assert!(
        out_claim_fin.status.success(),
        "finalize-claim stderr: {}",
        String::from_utf8_lossy(&out_claim_fin.stderr)
    );
    let claim_fin_json: Value = serde_json::from_slice(&out_claim_fin.stdout).unwrap();
    assert_eq!(claim_fin_json["signatureNormalized"], true);
    assert_eq!(claim_fin_json["rootKeyId"], root1_kid);
    assert_eq!(claim_fin_json["rootAlgorithm"], "es256");
    let chain_ref = claim_fin_json["chain"].as_str().unwrap().to_string();

    // -----------------------------------------------------------------------
    // 4. Detached `es256` Principal + Gateway Endorsement (`prepare-principal` / `prepare-endorsement`)
    // -----------------------------------------------------------------------
    let prin_prep = tmp.join("prin-prep.json");
    let prin_pae = tmp.join("prin.pae");
    let prin_out = tmp.join("principal.json");
    let out_prin_prep = Command::new(helper_bin())
        .arg("prepare-principal")
        .arg("--public-key")
        .arg(&cust_pem_path)
        .args([
            "--holder",
            "person",
            "--custody",
            "hardware",
            "--identity",
            "mailto:lena@r5e.io",
            "--gateway-url",
            &gw_url,
            "--captured-at",
            "2026-11-16T06:02:10.000000Z",
            "--out-prepared",
        ])
        .arg(&prin_prep)
        .arg("--out-pae")
        .arg(&prin_pae)
        .output()
        .expect("prepare-principal es256");
    assert!(
        out_prin_prep.status.success(),
        "prepare-principal stderr: {}",
        String::from_utf8_lossy(&out_prin_prep.stderr)
    );
    let (_, prin_high_s_der) = sign_ecdsa_with_high_s_der(
        SignatureAlgorithm::Es256,
        &cust_priv,
        &fs::read(&prin_pae).unwrap(),
    )
    .unwrap();
    let prin_sig_path = tmp.join("prin-high-s.der");
    fs::write(&prin_sig_path, &prin_high_s_der).unwrap();
    let out_prin_fin = Command::new(helper_bin())
        .arg("finalize-principal")
        .arg("--prepared")
        .arg(&prin_prep)
        .arg("--signature-file")
        .arg(&prin_sig_path)
        .arg("--out")
        .arg(&prin_out)
        .output()
        .expect("finalize-principal es256");
    assert!(
        out_prin_fin.status.success(),
        "finalize-principal stderr: {}",
        String::from_utf8_lossy(&out_prin_fin.stderr)
    );

    // Endorse counsel/custodian for RetentionHoldRelease AND endorse gateway working key:
    let cust_end_prep = tmp.join("cust-end-prep.json");
    let cust_end_pae = tmp.join("cust-end.pae");
    let cust_end_out = tmp.join("cust-end.json");
    let out_cust_end_prep = Command::new(helper_bin())
        .arg("prepare-endorsement")
        .arg("--issuer-public-key")
        .arg(&root1_pem_path)
        .arg("--subject-public-key")
        .arg(&cust_pem_path)
        .args([
            "--gateway-url",
            &gw_url,
            "--grant-token",
            "counsel01",
            "--kinds",
            "RetentionHoldRelease",
            "--omit-actor-prefixes",
            "--may-endorse=false",
            "--captured-at",
            "2026-11-16T06:02:15.000000Z",
            "--not-before",
            "2026-11-16T06:02:00.000000Z",
            "--out-prepared",
        ])
        .arg(&cust_end_prep)
        .arg("--out-pae")
        .arg(&cust_end_pae)
        .output()
        .expect("prepare-endorsement counsel");
    assert!(
        out_cust_end_prep.status.success(),
        "prepare-endorsement counsel stderr: {}",
        String::from_utf8_lossy(&out_cust_end_prep.stderr)
    );
    let (_, cust_end_der) = sign_ecdsa_with_high_s_der(
        SignatureAlgorithm::Es256,
        &root1_priv,
        &fs::read(&cust_end_pae).unwrap(),
    )
    .unwrap();
    let cust_end_sig = tmp.join("cust-end.der");
    fs::write(&cust_end_sig, &cust_end_der).unwrap();
    let out_cust_end_fin = Command::new(helper_bin())
        .arg("finalize-endorsement")
        .arg("--prepared")
        .arg(&cust_end_prep)
        .arg("--signature-file")
        .arg(&cust_end_sig)
        .arg("--with-grant-file")
        .arg(&prin_out)
        .arg("--out")
        .arg(&cust_end_out)
        .output()
        .expect("finalize-endorsement counsel + principal");
    assert!(
        out_cust_end_fin.status.success(),
        "finalize-endorsement counsel stderr: {}",
        String::from_utf8_lossy(&out_cust_end_fin.stderr)
    );

    // Gateway Endorsement from `es256` Root #1, merged with `[counsel Endorsement, Principal]` and `--submit`ed!
    let gw_end_prep = tmp.join("gw-end-prep.json");
    let gw_end_pae = tmp.join("gw-end.pae");
    let gw_end_out = tmp.join("gw-grant1.json");
    let out_gw_end_prep = Command::new(helper_bin())
        .arg("prepare-endorsement")
        .arg("--issuer-public-key")
        .arg(&root1_pem_path)
        .args([
            "--gateway-url",
            &gw_url,
            "--captured-at",
            "2026-11-16T06:02:20.000000Z",
            "--not-before",
            "2026-11-16T06:02:00.000000Z",
            "--out-prepared",
        ])
        .arg(&gw_end_prep)
        .arg("--out-pae")
        .arg(&gw_end_pae)
        .output()
        .expect("prepare-endorsement gateway root1");
    assert!(
        out_gw_end_prep.status.success(),
        "prepare-endorsement gateway stderr: {}",
        String::from_utf8_lossy(&out_gw_end_prep.stderr)
    );
    let (_, gw_end_der) = sign_ecdsa_with_high_s_der(
        SignatureAlgorithm::Es256,
        &root1_priv,
        &fs::read(&gw_end_pae).unwrap(),
    )
    .unwrap();
    let gw_end_sig = tmp.join("gw-end-high-s.der");
    fs::write(&gw_end_sig, &gw_end_der).unwrap();

    let out_gw_end_fin = Command::new(helper_bin())
        .arg("finalize-endorsement")
        .arg("--prepared")
        .arg(&gw_end_prep)
        .arg("--signature-file")
        .arg(&gw_end_sig)
        .arg("--with-grant-file")
        .arg(&cust_end_out)
        .arg("--out")
        .arg(&gw_end_out)
        .arg("--submit")
        .args(["--gateway-url", &gw_url])
        .output()
        .expect("finalize-endorsement --submit");
    assert!(
        out_gw_end_fin.status.success(),
        "finalize-endorsement --submit stderr: {}",
        String::from_utf8_lossy(&out_gw_end_fin.stderr)
    );
    let gw_end_fin_json: Value = serde_json::from_slice(&out_gw_end_fin.stdout).unwrap();
    assert_eq!(gw_end_fin_json["signatureNormalized"], true);
    assert_eq!(gw_end_fin_json["recordCount"], 3);
    assert_eq!(gw_end_fin_json["submitted"], true);

    // -----------------------------------------------------------------------
    // 5. Detached `es256` Quorum Root Rotation (`RootsChanged` + `RootChangeApproval` + Root #2 Grant)
    // -----------------------------------------------------------------------
    let rc_prep = tmp.join("rc-prep.json");
    let rc_pae = tmp.join("rc.pae");
    let proposal_path = tmp.join("proposal.json");
    let root2_spec = format!(
        "{};holder=person;custody=hardware;identity=mailto:lena@r5e.io",
        root2_pem_path.display()
    );

    let out_rc_prep = Command::new(helper_bin())
        .args([
            "prepare-root-change",
            "--deployment",
            deployment_slug,
            "--chain",
            &chain_ref,
            "--replaces",
            &chain_ref,
            "--seq",
            "3",
            "--authorization",
            "quorum",
            "--signer-public-key",
        ])
        .arg(&root1_pem_path)
        .args([
            "--root-key",
            &root2_spec,
            "--custodian",
            &cust_spec,
            "--reason",
            "Rotate hardware root to replacement ECCP256",
            "--captured-at",
            "2026-11-16T06:03:00.000000Z",
            "--out-prepared",
        ])
        .arg(&rc_prep)
        .arg("--out-pae")
        .arg(&rc_pae)
        .output()
        .expect("prepare-root-change es256");
    assert!(
        out_rc_prep.status.success(),
        "prepare-root-change stderr: {}",
        String::from_utf8_lossy(&out_rc_prep.stderr)
    );
    let (_, rc_der) = sign_ecdsa_with_high_s_der(
        SignatureAlgorithm::Es256,
        &root1_priv,
        &fs::read(&rc_pae).unwrap(),
    )
    .unwrap();
    let rc_sig = tmp.join("rc-high-s.der");
    fs::write(&rc_sig, &rc_der).unwrap();
    let out_rc_fin = Command::new(helper_bin())
        .arg("finalize-root-change")
        .arg("--prepared")
        .arg(&rc_prep)
        .arg("--signature-file")
        .arg(&rc_sig)
        .arg("--out")
        .arg(&proposal_path)
        .output()
        .expect("finalize-root-change es256");
    assert!(
        out_rc_fin.status.success(),
        "finalize-root-change stderr: {}",
        String::from_utf8_lossy(&out_rc_fin.stderr)
    );

    let ap_prep = tmp.join("ap-prep.json");
    let ap_pae = tmp.join("ap.pae");
    let out_ap_prep = Command::new(helper_bin())
        .arg("prepare-root-approval")
        .arg("--proposal")
        .arg(&proposal_path)
        .arg("--root-public-key")
        .arg(&root1_pem_path)
        .args([
            "--custodian",
            "mailto:lena@r5e.io",
            "--custodian-public-key",
        ])
        .arg(&cust_pem_path)
        .args([
            "--reason",
            "Custodian quorum sign-off on hardware root rotation",
            "--captured-at",
            "2026-11-16T06:03:05.000000Z",
            "--out-prepared",
        ])
        .arg(&ap_prep)
        .arg("--out-pae")
        .arg(&ap_pae)
        .output()
        .expect("prepare-root-approval es256");
    assert!(
        out_ap_prep.status.success(),
        "prepare-root-approval stderr: {}",
        String::from_utf8_lossy(&out_ap_prep.stderr)
    );
    let ap_pae_bytes = fs::read(&ap_pae).unwrap();
    let (_, ap_root_der) =
        sign_ecdsa_with_high_s_der(SignatureAlgorithm::Es256, &root1_priv, &ap_pae_bytes).unwrap();
    let (_, ap_cust_der) =
        sign_ecdsa_with_high_s_der(SignatureAlgorithm::Es256, &cust_priv, &ap_pae_bytes).unwrap();
    let ap_root_sig = tmp.join("ap-root.der");
    let ap_cust_sig = tmp.join("ap-cust.der");
    fs::write(&ap_root_sig, &ap_root_der).unwrap();
    fs::write(&ap_cust_sig, &ap_cust_der).unwrap();

    let out_ap_fin = Command::new(helper_bin())
        .arg("finalize-root-approval")
        .arg("--proposal")
        .arg(&proposal_path)
        .arg("--prepared")
        .arg(&ap_prep)
        .arg("--root-signature-file")
        .arg(&ap_root_sig)
        .arg("--custodian-signature-file")
        .arg(&ap_cust_sig)
        .output()
        .expect("finalize-root-approval es256");
    assert!(
        out_ap_fin.status.success(),
        "finalize-root-approval stderr: {}",
        String::from_utf8_lossy(&out_ap_fin.stderr)
    );
    let ap_fin_json: Value = serde_json::from_slice(&out_ap_fin.stdout).unwrap();
    assert_eq!(ap_fin_json["rootSignatureNormalized"], true);
    assert_eq!(ap_fin_json["custodianSignatureNormalized"], true);

    // Prepare & finalize replacement gateway Endorsement from `es256` Root #2:
    let gw2_prep = tmp.join("gw2-prep.json");
    let gw2_pae = tmp.join("gw2.pae");
    let gw2_out = tmp.join("gw-grant2.json");
    let out_gw2_prep = Command::new(helper_bin())
        .arg("prepare-endorsement")
        .arg("--issuer-public-key")
        .arg(&root2_pem_path)
        .args([
            "--gateway-url",
            &gw_url,
            "--captured-at",
            "2026-11-16T06:03:10.000000Z",
            "--not-before",
            "2026-11-16T06:01:00.000000Z",
            "--out-prepared",
        ])
        .arg(&gw2_prep)
        .arg("--out-pae")
        .arg(&gw2_pae)
        .output()
        .expect("prepare-endorsement root2");
    assert!(out_gw2_prep.status.success());
    let (_, gw2_der) = sign_ecdsa_with_high_s_der(
        SignatureAlgorithm::Es256,
        &root2_priv,
        &fs::read(&gw2_pae).unwrap(),
    )
    .unwrap();
    let gw2_sig = tmp.join("gw2.der");
    fs::write(&gw2_sig, &gw2_der).unwrap();
    let out_gw2_fin = Command::new(helper_bin())
        .arg("finalize-endorsement")
        .arg("--prepared")
        .arg(&gw2_prep)
        .arg("--signature-file")
        .arg(&gw2_sig)
        .arg("--out")
        .arg(&gw2_out)
        .output()
        .expect("finalize-endorsement root2");
    assert!(out_gw2_fin.status.success());

    let out_apply = Command::new(helper_bin())
        .args(["apply-root-change", "--gateway-url", &gw_url, "--proposal"])
        .arg(&proposal_path)
        .arg("--grant-file")
        .arg(&gw2_out)
        .output()
        .expect("apply-root-change --grant-file");
    assert!(
        out_apply.status.success(),
        "apply-root-change stderr: {}",
        String::from_utf8_lossy(&out_apply.stderr)
    );

    // Stop mock gateway cleanly:
    {
        if let Ok(mut s) = std::net::TcpStream::connect(addr) {
            let _ = s.write_all(b"POST /stop HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
    }
    let _ = server_handle.join();

    // -----------------------------------------------------------------------
    // 6. Verify Complete `es256` Publisher + `es256` Roots Export Bundle with BOTH Independent Verifiers!
    // -----------------------------------------------------------------------
    let st = state.lock().unwrap();
    let dep_rec = st.claimed_record.clone().unwrap();
    let grant_set_1 = st.accepted_grants[0].clone();
    let grant_set_2 = st.accepted_grants[1].clone();
    let root_change_set = st.accepted_roots[0].clone();

    let mut all_keys = BTreeMap::<String, PublicKeyEntry>::new();
    let mut all_blobs = BTreeMap::<String, BlobEntry>::new();
    assert_eq!(grant_set_1.records.len(), 3);
    assert_eq!(root_change_set.approvals.len(), 1);
    assert_eq!(grant_set_2.records.len(), 1);

    for k in pub_set
        .keys
        .iter()
        .cloned()
        .chain(std::iter::once(PublicKeyEntry {
            keyid: bootstrap_id.clone(),
            algorithm: "ed25519".to_string(),
            bytes: BASE64_STANDARD.encode(bootstrap_pub),
        }))
        .chain(std::iter::once(PublicKeyEntry {
            keyid: gw_id.clone(),
            algorithm: "ed25519".to_string(),
            bytes: BASE64_STANDARD.encode(gw_pub),
        }))
        .chain(grant_set_1.keys.iter().cloned())
        .chain(root_change_set.keys.iter().cloned())
        .chain(grant_set_2.keys.iter().cloned())
    {
        all_keys.insert(k.keyid.clone(), k);
    }

    for b in pub_set
        .blobs
        .iter()
        .cloned()
        .chain(std::iter::once(BlobEntry {
            blob_ref: bootstrap_profile_ref.clone(),
            media_type: Some("application/json".to_string()),
            base64: BASE64_STANDARD.encode(&bootstrap_profile_bytes),
        }))
        .chain(grant_set_1.blobs.iter().cloned())
        .chain(root_change_set.blobs.iter().cloned())
        .chain(grant_set_2.blobs.iter().cloned())
    {
        all_blobs.insert(b.blob_ref.clone(), b);
    }

    let verify_exported_chain_bundle =
        |label: &str, recs: Vec<r5e_endpoint_helper::attestation::SignedEndpointRecord>| {
            let mut stream_heads = BTreeMap::<String, (u64, String)>::new();
            let mut profile_refs = std::collections::BTreeSet::<String>::new();
            for rec in &recs {
                let opened: Value =
                    serde_json::from_slice(&decode_strict_base64(&rec.envelope.payload).unwrap())
                        .unwrap();
                let prof_ref = opened["profileRef"].as_str().unwrap().to_string();
                profile_refs.insert(prof_ref);
                if opened["kind"].as_str() == Some("DefinitionPublished") {
                    continue;
                }
                let s = opened["stream"].as_str().unwrap().to_string();
                let sq = opened["seq"].as_u64().unwrap();
                match stream_heads.get(&s) {
                    Some((prev_sq, _)) if *prev_sq >= sq => {}
                    _ => {
                        stream_heads.insert(s, (sq, rec.record_ref.clone()));
                    }
                }
            }
            let scope_at: Vec<Value> = stream_heads
            .into_iter()
            .map(|(stream, (seq, event))| json!({ "stream": stream, "seq": seq, "event": event }))
            .collect();

            let export_bundle = json!({
                "format": "r5e.provenance-export/v2",
                "scope": {
                    "query": { "chain": &chain_ref },
                    "at": scope_at,
                },
                "records": recs,
                "keys": all_keys.values().cloned().collect::<Vec<_>>(),
                "blobs": all_blobs.values().cloned().collect::<Vec<_>>(),
                "seals": [],
                "checkpoints": [],
                "proofs": [],
                "publicationProofs": [],
                "omissions": [],
            });
            let bundle_path = tmp.join(format!("{label}.json"));
            fs::write(&bundle_path, encode_canonical_json(&export_bundle).unwrap()).unwrap();

            if let Some((py_dir, py_bin)) = resolve_py_verifier() {
                let mut cmd = Command::new(&py_bin);
                cmd.current_dir(&py_dir)
                    .env("PYTHONPATH", &py_dir)
                    .arg("-m")
                    .arg("r5e_verify")
                    .arg(&bundle_path)
                    .arg("--trusted-chain")
                    .arg(&chain_ref)
                    .arg("--trusted-publisher")
                    .arg(&pub_pin);
                for pref in &profile_refs {
                    cmd.arg("--trusted-profile").arg(pref);
                }
                let out = cmd
                    .output()
                    .expect("run Python verifier on es256 PIV bundle");
                let stdout_txt = String::from_utf8_lossy(&out.stdout);
                let stderr_txt = String::from_utf8_lossy(&out.stderr);
                assert!(
                    out.status.success(),
                    "r5e_verify ({label}) failed ({:?}):\nstdout: {stdout_txt}\nstderr: {stderr_txt}",
                    out.status.code()
                );
                let report: Value = serde_json::from_slice(&out.stdout).unwrap();
                assert_eq!(report["summary"]["failed"], 0, "r5e_verify report: {report}");
                assert_eq!(
                    report["summary"]["incomplete"], 0,
                    "r5e_verify report had incomplete findings: {report}"
                );
            }

            if let Some(rs_bin) = resolve_rs_verifier_bin() {
                let mut cmd = Command::new(&rs_bin);
                cmd.arg(&bundle_path)
                    .arg("--trusted-chain")
                    .arg(&chain_ref)
                    .arg("--trusted-publisher")
                    .arg(&pub_pin);
                for pref in &profile_refs {
                    cmd.arg("--trusted-profile").arg(pref);
                }
                let out = cmd
                    .output()
                    .expect("run Rust verifier on es256 PIV bundle");
                let stdout_txt = String::from_utf8_lossy(&out.stdout);
                let stderr_txt = String::from_utf8_lossy(&out.stderr);
                assert!(
                    out.status.success(),
                    "recurse_verify ({label}) failed ({:?}):\nstdout: {stdout_txt}\nstderr: {stderr_txt}",
                    out.status.code()
                );
                let report: Value = serde_json::from_slice(&out.stdout).unwrap();
                assert_eq!(
                    report["summary"]["failed"], 0,
                    "recurse_verify report: {report}"
                );
                assert_eq!(
                    report["summary"]["incomplete"], 0,
                    "recurse_verify report had incomplete findings: {report}"
                );
            }
        };

    // Bundle A: Claimed deployment + ES256 Root #1 Endorsements + ES256 Principal (`failed == 0, incomplete == 0`):
    let pre_rotation_records: Vec<_> = std::iter::once(pub_rec.clone())
        .chain(std::iter::once(cs_rec.clone()))
        .chain(std::iter::once(dep_rec.clone()))
        .chain(grant_set_1.records.iter().cloned())
        .collect();
    verify_exported_chain_bundle("es256-piv-pre-rotation", pre_rotation_records);

    // Bundle B: Rotated deployment (`RootChangeApproval` [ES256, ES256] + `RootsChanged` ES256 -> ES256 Root #2 + ES256 Root #2 Endorsement + ES256 Principal; `failed == 0, incomplete == 0`):
    let post_rotation_records: Vec<_> = std::iter::once(pub_rec)
        .chain(std::iter::once(cs_rec))
        .chain(std::iter::once(dep_rec))
        .chain(root_change_set.approvals.iter().cloned())
        .chain(std::iter::once(root_change_set.change))
        .chain(grant_set_2.records.iter().cloned())
        .collect();
    verify_exported_chain_bundle("es256-piv-post-rotation", post_rotation_records);

    let _ = fs::remove_dir_all(&tmp);
}
