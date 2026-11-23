use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn temp_test_dir(label: &str) -> PathBuf {
    let unique = format!(
        "r5e-hooks-int-{label}-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    );
    let p = std::env::temp_dir().join(unique);
    fs::create_dir_all(&p).unwrap();
    p
}

fn run_hook_cli(args: &[&str], stdin_body: &str) -> (Option<i32>, String, String) {
    let bin = env!("CARGO_BIN_EXE_r5e-endpoint-helper");
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn r5e-endpoint-helper hook");
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(stdin_body.as_bytes()).unwrap();
    }
    let out = child.wait_with_output().expect("wait hook");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
        String::from_utf8_lossy(&out.stderr).trim().to_string(),
    )
}

#[test]
fn cli_hook_observe_is_fail_open_and_status_json_reports_queue() {
    let tmp = temp_test_dir("observe-status");
    let state_dir = tmp.join("state");
    let state_str = state_dir.to_str().unwrap();

    let (rc1, out1, _) = run_hook_cli(
        &[
            "hook",
            "antigravity",
            "--mode",
            "observe",
            "--gateway",
            "http://127.0.0.1:4000",
            "--state-dir",
            state_str,
        ],
        r#"{"hookEventName":"PostToolUse","conversationId":"cli-conv-1","stepIdx":1,"toolCall":{"id":"tc1","name":"run_command","args":{"CommandLine":"echo hi","api_key":"sk-secret-1234567890"}}}"#,
    );
    assert_eq!(rc1, Some(0));
    assert_eq!(serde_json::from_str::<Value>(&out1).unwrap(), json!({}));

    let (rc2, out2, _) = run_hook_cli(
        &[
            "hook",
            "antigravity",
            "--mode",
            "observe",
            "--gateway",
            "http://127.0.0.1:4000",
            "--state-dir",
            state_str,
        ],
        r#"{"hookEventName":"Stop","conversationId":"cli-conv-1","terminationReason":"NO_TOOL_CALL"}"#,
    );
    assert_eq!(rc2, Some(0));
    assert_eq!(
        serde_json::from_str::<Value>(&out2).unwrap(),
        json!({"decision": "stop"})
    );

    // Malformed stdin still fails open with exit 0 and `{}`.
    let (rc3, out3, _) = run_hook_cli(
        &[
            "hook",
            "claude-code",
            "--mode",
            "observe",
            "--state-dir",
            state_str,
        ],
        "{not valid json",
    );
    assert_eq!(rc3, Some(0));
    assert_eq!(serde_json::from_str::<Value>(&out3).unwrap(), json!({}));

    // Verify `status --json` schema.
    let bin = env!("CARGO_BIN_EXE_r5e-endpoint-helper");
    let status_out = Command::new(bin)
        .args(["status", "--state-dir", state_str, "--json"])
        .output()
        .expect("run status --json");
    assert!(status_out.status.success());
    let snap: Value = serde_json::from_slice(&status_out.stdout).unwrap();
    assert_eq!(snap["version"], env!("CARGO_PKG_VERSION"));
    assert!(snap.get("gateway_url").is_some());
    assert!(snap.get("enrolled").is_some());
    assert!(snap.get("badge_ref").is_some());
    assert!(snap.get("active_sessions").is_some());
    assert!(snap["queued_events"].as_u64().unwrap() >= 2);
    assert!(snap.get("last_ship_at").is_some());
    assert!(snap.get("last_error").is_some());

    // Verify secret was redacted before writing to events.jsonl.
    let queue_txt = fs::read_to_string(state_dir.join("sessions/cli-conv-1/events.jsonl")).unwrap();
    assert!(!queue_txt.contains("sk-secret-1234567890"));
    assert!(queue_txt.contains("[REDACTED]"));

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn cli_hook_enforce_and_install_hooks_work_across_clients() {
    let tmp = temp_test_dir("enforce-install");
    let state_dir = tmp.join("state");
    let cedar_path = tmp.join("guard.cedar");
    fs::write(
        &cedar_path,
        r#"
@id("deny-rm")
forbid (
    principal,
    action == Recurse::Action::"ExecCommand",
    resource
) when {
    context.program == "rm"
};
"#,
    )
    .unwrap();

    let (rc, out, _) = run_hook_cli(
        &[
            "hook",
            "antigravity",
            "--mode",
            "enforce",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--cedar-policy",
            cedar_path.to_str().unwrap(),
        ],
        r#"{"hookEventName":"PreToolUse","conversationId":"cli-conv-enf","toolCall":{"id":"tc9","name":"run_command","args":{"CommandLine":"rm -rf /tmp/demo"}}}"#,
    );
    assert_eq!(rc, Some(0));
    let parsed: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed["decision"], "deny");
    assert!(parsed["reason"]
        .as_str()
        .unwrap()
        .contains("forbid rule(s): deny-rm"));

    // install-hooks for antigravity, claude-code, and codex
    let bin = env!("CARGO_BIN_EXE_r5e-endpoint-helper");
    for (client, expected_file) in [
        ("antigravity", "hooks.json"),
        ("claude-code", "settings.json"),
        ("codex", "hooks.json"),
    ] {
        let cfg_dir = tmp.join(client);
        let install = Command::new(bin)
            .args([
                "install-hooks",
                client,
                "--gateway",
                "https://dev.r5e.io",
                "--mode",
                "observe",
                "--path",
                cfg_dir.to_str().unwrap(),
            ])
            .output()
            .expect("run install-hooks");
        assert!(
            install.status.success(),
            "install-hooks {client} failed: {}",
            String::from_utf8_lossy(&install.stderr)
        );
        let written = cfg_dir.join(expected_file);
        assert!(written.is_file(), "expected {}", written.display());
        let doc: Value = serde_json::from_str(&fs::read_to_string(&written).unwrap()).unwrap();
        assert!(serde_json::to_string(&doc)
            .unwrap()
            .contains("r5e-endpoint-helper"));
    }

    let _ = fs::remove_dir_all(&tmp);
}
