//! Native Rust agent lifecycle hooks (`hook`, `install-hooks`) and desktop/tray
//! telemetry snapshot (`status --json`) for Antigravity, Claude Code, and Codex.
//!
//! Design goals:
//! - Sub-20ms synchronous stdin -> stdout path with zero Python runtime dependency.
//! - Observe mode is strictly fail-open (`exit 0` + valid client JSON on stdout).
//! - Enforce mode evaluates `LocalCedarGate` synchronously on `PreToolUse` and
//!   returns structured block decisions on Cedar deny.
//! - Secret-redacting JSON serializer caps blobs at 16 KiB before persisting to
//!   `0600` per-conversation JSONL queues.
//! - Detached background drainer uses `File::try_lock()` advisory locking so
//!   concurrent tool calls never race on `state.json` or block the agent loop.

use crate::attestation::{encode_canonical_json, generate_os_random_seed_32, truncate_utf8_bytes};
use crate::enrolment_http::{
    enrol_endpoint_badge_with_options, EnrolBadgeOptions, EnrolmentClientConfig,
};
use crate::evidence_http::{
    build_ship_request_from_recorder, open_session_over_http, ship_records_batches_over_http,
    EnrolledStateFile, OpenSessionRequest,
};
use crate::policy_gate::{hex_lower, LocalActionKind, LocalCedarGate, Posture};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};

const DEFAULT_HOOK_WORKLOAD_KINDS: &[&str] = &[
    "provenance.r5e.io/v2/SessionOpened",
    "provenance.r5e.io/v2/SessionClosed",
    "provenance.r5e.io/v2/PolicyDecision",
    "provenance.r5e.io/v2/ToolCall",
    "provenance.r5e.io/v2/ToolResult",
    "provenance.r5e.io/v2/Observation",
    "provenance.r5e.io/v2/Disclosure",
    "provenance.r5e.io/v2/Verification",
];
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const MAX_HOOK_PAYLOAD_BYTES: usize = 16 * 1024;
pub const MAX_HOOK_STRING_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookClient {
    Antigravity,
    ClaudeCode,
    Codex,
}

impl HookClient {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Antigravity => "antigravity",
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
        }
    }

    pub fn actor_uri(self) -> String {
        format!("urn:r5e:agent:hook:{}", self.as_str())
    }

    pub fn workload_uri(self) -> String {
        format!("urn:r5e:workload:{}-hook", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HookMode {
    Observe,
    Enforce,
}

impl HookMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Enforce => "enforce",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalizedEventKind {
    SessionStart,
    PreToolUse,
    PostToolUse,
    Stop,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedHookEvent {
    pub client: HookClient,
    pub mode: HookMode,
    pub event_kind: NormalizedEventKind,
    pub conversation_id: String,
    pub captured_at: String,
    pub tool_name: Option<String>,
    pub call_id: Option<String>,
    pub step_idx: Option<i64>,
    pub args: Value,
    pub error: Option<String>,
    pub model_name: Option<String>,
    pub termination_reason: Option<String>,
    pub execution_num: Option<i64>,
    pub fully_idle: Option<bool>,
    pub cwd: Option<String>,
    pub enforce_outcome: Option<String>,
    pub enforce_reason: Option<String>,
    pub enforce_policy_ref: Option<String>,
    pub enforce_matching_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionMeta {
    pub gateway_url: Option<String>,
    pub badge_ref: Option<String>,
    pub session_urn: Option<String>,
    pub last_ship_at: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HookStatusSnapshot {
    pub version: String,
    pub gateway_url: Option<String>,
    pub enrolled: bool,
    pub badge_ref: Option<String>,
    pub active_sessions: usize,
    pub queued_events: usize,
    pub last_ship_at: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HookRunOptions {
    pub client: HookClient,
    pub mode: HookMode,
    pub gateway_url: String,
    pub state_dir: PathBuf,
    pub bearer_token_env: String,
    pub bearer_token_file: Option<PathBuf>,
    pub cedar_policy: Option<PathBuf>,
    pub spawn_drainer: bool,
}

#[derive(Debug, Clone)]
pub struct InstallHooksOptions {
    pub client: HookClient,
    pub mode: HookMode,
    pub gateway_url: String,
    pub target_dir: PathBuf,
    pub helper_bin: PathBuf,
    pub state_dir: Option<PathBuf>,
    pub cedar_policy: Option<PathBuf>,
    pub bearer_token_file: Option<PathBuf>,
}

pub fn default_hook_state_dir() -> PathBuf {
    if let Ok(val) = std::env::var("R5E_HOOK_STATE_DIR") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".config")
            .join("r5e")
            .join("hooks");
    }
    PathBuf::from(".r5e-hooks")
}

pub fn sanitize_conversation_id(raw: Option<&str>) -> String {
    let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return "unknown-conversation".to_string();
    };
    // If a client passes anything resembling a filesystem path or traversal, hash it
    // to an opaque identifier so no path or name can leak into permanent SessionOpened.details.
    if s.contains('/') || s.contains('\\') || s.contains("..") {
        let digest = hex_lower(&Sha256::digest(s.as_bytes()));
        return format!("conv-{}", &digest[..24]);
    }
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    if cleaned.is_empty() || cleaned.chars().all(|c| c == '_') {
        "unknown-conversation".to_string()
    } else {
        cleaned
    }
}

fn is_secret_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    const PATTERNS: &[&str] = &[
        "token",
        "secret",
        "password",
        "passwd",
        "pwd",
        "api_key",
        "apikey",
        "api-key",
        "authorization",
        "auth_header",
        "auth-header",
        "cookie",
        "private_key",
        "private-key",
        "signing_key",
        "signing-key",
        "seed",
        "credential",
        "bearer",
        "workos",
        "vertex",
    ];
    PATTERNS.iter().any(|p| lower.contains(p))
}

fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+' | b'/' | b'=' | b'~')
}

pub fn redact_string(input: &str) -> String {
    let mut s = input.to_string();

    // 1. Redact PEM private key blocks.
    while let Some(start) = s.find("-----BEGIN ") {
        if let Some(rel_end) = s[start..].find("PRIVATE KEY-----") {
            let after_hdr = start + rel_end + "PRIVATE KEY-----".len();
            if let Some(end_marker) = s[after_hdr..].find("PRIVATE KEY-----") {
                let block_end = after_hdr + end_marker + "PRIVATE KEY-----".len();
                s.replace_range(start..block_end, "[REDACTED]");
                continue;
            }
        }
        break;
    }

    // 2. Redact `Authorization:` and `Cookie:` header values (case-insensitive).
    for header in ["authorization:", "cookie:"] {
        let mut idx = 0usize;
        while idx < s.len() {
            let lower = s[idx..].to_ascii_lowercase();
            let Some(rel) = lower.find(header) else {
                break;
            };
            let hdr_start = idx + rel;
            let val_start = hdr_start + header.len();
            let bytes = s.as_bytes();
            let mut val_end = val_start;
            while val_end < bytes.len() && !matches!(bytes[val_end], b'\r' | b'\n' | b'\'' | b'"') {
                val_end += 1;
            }
            if val_end > val_start && !s[val_start..val_end].trim().starts_with("[REDACTED]") {
                let replacement = format!("{} [REDACTED]", &s[hdr_start..val_start]);
                let repl_len = replacement.len();
                s.replace_range(hdr_start..val_end, &replacement);
                idx = hdr_start + repl_len;
            } else {
                idx = val_end.max(val_start + 1);
            }
        }
    }

    // 3. Redact URL userinfo credentials (`scheme://user:pass@host` -> `scheme://[REDACTED]@host`).
    {
        let mut idx = 0usize;
        while let Some(rel) = s[idx..].find("://") {
            let auth_start = idx + rel + 3;
            let bytes = s.as_bytes();
            let mut end = auth_start;
            while end < bytes.len()
                && !matches!(
                    bytes[end],
                    b'/' | b'?' | b'#' | b' ' | b'\t' | b'\r' | b'\n' | b'\'' | b'"'
                )
            {
                end += 1;
            }
            if let Some(at_rel) = s[auth_start..end].rfind('@') {
                let userinfo = &s[auth_start..auth_start + at_rel];
                if userinfo.contains(':') && userinfo != "[REDACTED]" {
                    s.replace_range(auth_start..auth_start + at_rel, "[REDACTED]");
                    idx = auth_start + "[REDACTED]".len() + 1;
                    continue;
                }
            }
            idx = end.max(auth_start);
        }
    }

    // 4. Redact `Bearer <token>` (case-insensitive).
    loop {
        let lower = s.to_ascii_lowercase();
        let Some(pos) = lower.find("bearer ") else {
            break;
        };
        let bytes = s.as_bytes();
        let mut tok_start = pos + 7;
        while tok_start < bytes.len() && bytes[tok_start].is_ascii_whitespace() {
            tok_start += 1;
        }
        let mut tok_end = tok_start;
        while tok_end < bytes.len() && is_token_char(bytes[tok_end]) {
            tok_end += 1;
        }
        if tok_end.saturating_sub(tok_start) >= 8 {
            s.replace_range(pos..tok_end, "[REDACTED]");
        } else {
            break;
        }
    }

    // 5. Redact JWTs (`eyJ<part1>.<part2>.<part3>`).
    let mut search_from = 0usize;
    while let Some(rel) = s[search_from..].find("eyJ") {
        let start = search_from + rel;
        let bytes = s.as_bytes();
        let mut end = start;
        while end < bytes.len() && is_token_char(bytes[end]) {
            end += 1;
        }
        let candidate = &s[start..end];
        let parts: Vec<&str> = candidate.split('.').collect();
        if parts.len() == 3 && parts.iter().all(|p| p.len() >= 8) {
            s.replace_range(start..end, "[REDACTED]");
            search_from = start + "[REDACTED]".len();
        } else {
            search_from = end.max(start + 3);
        }
    }

    // 6. Redact well-known key prefixes (OpenAI, Anthropic, AWS, GitHub, Stripe, Slack, Google).
    const PREFIXES: &[&str] = &[
        "sk-ant-",
        "sk_live_",
        "sk_test_",
        "rk_live_",
        "rk_test_",
        "pk_live_",
        "sk-",
        "pk-",
        "rk-",
        "whsec_",
        "ghp_",
        "gho_",
        "github_pat_",
        "xoxb-",
        "xoxa-",
        "xoxp-",
        "xoxr-",
        "xoxs-",
        "AIza",
        "AKIA",
        "ASIA",
    ];
    for prefix in PREFIXES {
        let mut idx = 0usize;
        while let Some(rel) = s[idx..].find(prefix) {
            let start = idx + rel;
            let bytes = s.as_bytes();
            let mut end = start + prefix.len();
            while end < bytes.len() && is_token_char(bytes[end]) {
                end += 1;
            }
            if end.saturating_sub(start + prefix.len()) >= 10 {
                s.replace_range(start..end, "[REDACTED]");
                idx = start + "[REDACTED]".len();
            } else {
                idx = end.max(start + prefix.len());
            }
        }
    }

    // 7. Redact sensitive inline env var assignments (`R5E_TOKEN=...`, etc.).
    const ENV_VARS: &[&str] = &[
        "R5E_TOKEN=",
        "GOOGLE_VERTEX_API_KEY=",
        "OPENAI_API_KEY=",
        "ANTHROPIC_API_KEY=",
        "FLY_API_TOKEN=",
        "AWS_SECRET_ACCESS_KEY=",
        "STRIPE_API_KEY=",
    ];
    for env_prefix in ENV_VARS {
        let mut idx = 0usize;
        while let Some(rel) = s[idx..].find(env_prefix) {
            let start = idx + rel;
            let bytes = s.as_bytes();
            let mut end = start + env_prefix.len();
            while end < bytes.len() && !bytes[end].is_ascii_whitespace() {
                end += 1;
            }
            s.replace_range(start..end, "[REDACTED]");
            idx = start + "[REDACTED]".len();
        }
    }

    truncate_utf8_bytes(&s, MAX_HOOK_STRING_BYTES)
}

pub fn redact_json_value(val: &Value, depth: usize) -> Value {
    if depth > 6 {
        return Value::String("[truncated-depth]".to_string());
    }
    match val {
        Value::Null | Value::Bool(_) | Value::Number(_) => val.clone(),
        Value::String(s) => Value::String(redact_string(s)),
        Value::Array(arr) => {
            let mut out: Vec<Value> = arr
                .iter()
                .take(64)
                .map(|v| redact_json_value(v, depth + 1))
                .collect();
            if arr.len() > 64 {
                out.push(Value::String(format!("...[{} more items]", arr.len() - 64)));
            }
            Value::Array(out)
        }
        Value::Object(map) => {
            let mut out = Map::new();
            for (i, (k, v)) in map.iter().enumerate() {
                if i >= 64 {
                    out.insert("_truncated_keys".to_string(), json!(map.len() - 64));
                    break;
                }
                if is_secret_key(k) {
                    out.insert(k.clone(), Value::String("[REDACTED]".to_string()));
                } else {
                    out.insert(k.clone(), redact_json_value(v, depth + 1));
                }
            }
            Value::Object(out)
        }
    }
}

pub fn bounded_json_string(val: &Value) -> String {
    let serialized = serde_json::to_string(val).unwrap_or_else(|_| "{}".to_string());
    if serialized.len() <= MAX_HOOK_PAYLOAD_BYTES {
        return serialized;
    }
    let preview = truncate_utf8_bytes(&serialized, MAX_HOOK_PAYLOAD_BYTES.saturating_sub(256));
    serde_json::to_string(&json!({
        "truncated": true,
        "originalBytes": serialized.len(),
        "preview": preview,
    }))
    .unwrap_or_else(|_| "{}".to_string())
}

fn parse_event_kind(raw: &str) -> NormalizedEventKind {
    match raw {
        "SessionStart" | "session_start" => NormalizedEventKind::SessionStart,
        "PreToolUse" | "pre_tool_use" => NormalizedEventKind::PreToolUse,
        "PostToolUse" | "post_tool_use" => NormalizedEventKind::PostToolUse,
        "Stop" | "stop" => NormalizedEventKind::Stop,
        _ => NormalizedEventKind::Unknown,
    }
}

pub fn normalize_hook_payload(
    client: HookClient,
    mode: HookMode,
    payload: &Value,
) -> QueuedHookEvent {
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let event_raw = payload
        .get("hookEventName")
        .or_else(|| payload.get("hook_event_name"))
        .or_else(|| payload.get("event"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let event_kind = parse_event_kind(event_raw);

    let conv_raw = payload
        .get("conversationId")
        .or_else(|| payload.get("session_id"))
        .or_else(|| payload.get("conversation_id"))
        .and_then(Value::as_str);
    let conversation_id = sanitize_conversation_id(conv_raw);

    let (tool_name, call_id, raw_args) = match client {
        HookClient::Antigravity => {
            let tc = payload.get("toolCall");
            let name = tc
                .and_then(|v| v.get("name"))
                .and_then(Value::as_str)
                .map(|s| truncate_utf8_bytes(s, 128));
            let cid = tc
                .and_then(|v| v.get("id"))
                .and_then(Value::as_str)
                .map(|s| truncate_utf8_bytes(s, 256));
            let args = tc
                .and_then(|v| v.get("args"))
                .cloned()
                .unwrap_or_else(|| json!({}));
            (name, cid, args)
        }
        HookClient::ClaudeCode => {
            let name = payload
                .get("tool_name")
                .and_then(Value::as_str)
                .map(|s| truncate_utf8_bytes(s, 128));
            let cid = payload
                .get("tool_use_id")
                .and_then(Value::as_str)
                .map(|s| truncate_utf8_bytes(s, 256));
            let args = payload
                .get("tool_input")
                .cloned()
                .unwrap_or_else(|| json!({}));
            (name, cid, args)
        }
        HookClient::Codex => {
            let name = payload
                .get("tool_name")
                .or_else(|| payload.get("tool"))
                .and_then(Value::as_str)
                .map(|s| truncate_utf8_bytes(s, 128));
            let cid = payload
                .get("call_id")
                .or_else(|| payload.get("id"))
                .and_then(Value::as_str)
                .map(|s| truncate_utf8_bytes(s, 256));
            let args = payload
                .get("arguments")
                .or_else(|| payload.get("args"))
                .cloned()
                .unwrap_or_else(|| json!({}));
            (name, cid, args)
        }
    };

    let step_idx = payload.get("stepIdx").and_then(Value::as_i64);
    let error = payload
        .get("error")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(redact_string);
    let model_name = payload
        .get("modelName")
        .or_else(|| payload.get("model"))
        .and_then(Value::as_str)
        .map(|s| truncate_utf8_bytes(s, 128));
    let termination_reason = payload
        .get("terminationReason")
        .or_else(|| payload.get("stop_reason"))
        .and_then(Value::as_str)
        .map(|s| truncate_utf8_bytes(s, 128));
    let execution_num = payload.get("executionNum").and_then(Value::as_i64);
    let fully_idle = payload.get("fullyIdle").and_then(Value::as_bool);
    let cwd = payload
        .get("cwd")
        .and_then(Value::as_str)
        .map(|s| truncate_utf8_bytes(&redact_string(s), 512));

    QueuedHookEvent {
        client,
        mode,
        event_kind,
        conversation_id,
        captured_at: now,
        tool_name,
        call_id,
        step_idx,
        args: redact_json_value(&raw_args, 0),
        error,
        model_name,
        termination_reason,
        execution_num,
        fully_idle,
        cwd,
        enforce_outcome: None,
        enforce_reason: None,
        enforce_policy_ref: None,
        enforce_matching_ids: Vec::new(),
    }
}

fn ensure_dir_0700(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|e| format!("create dir {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

fn append_line_0600(path: &Path, line: &str) -> Result<(), String> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| format!("open {} for append: {e}", path.display()))?;
    writeln!(f, "{line}").map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(())
}

fn write_json_0600<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| format!("serialize {}: {e}", path.display()))?;
    let mut opts = OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| format!("open {} for write: {e}", path.display()))?;
    f.write_all(&bytes)
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(())
}

fn append_hook_log(state_dir: &Path, msg: &str) {
    let _ = ensure_dir_0700(state_dir);
    let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let _ = append_line_0600(&state_dir.join("hook.log"), &format!("{ts} {msg}"));
}

fn extract_raw_args_for_client(client: HookClient, payload: &Value) -> Value {
    match client {
        HookClient::Antigravity => payload
            .get("toolCall")
            .and_then(|v| v.get("args"))
            .cloned()
            .unwrap_or_else(|| json!({})),
        HookClient::ClaudeCode => payload
            .get("tool_input")
            .cloned()
            .unwrap_or_else(|| json!({})),
        HookClient::Codex => payload
            .get("arguments")
            .or_else(|| payload.get("args"))
            .cloned()
            .unwrap_or_else(|| json!({})),
    }
}

/// POSIX-like shell word splitter handling single quotes, double quotes, and backslash escapes.
pub fn split_shell_words(input: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut has_token = false;

    for ch in input.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            has_token = true;
            continue;
        }
        if in_single {
            if ch == '\'' {
                in_single = false;
            } else {
                current.push(ch);
            }
            has_token = true;
            continue;
        }
        if in_double {
            match ch {
                '"' => in_double = false,
                '\\' => escaped = true,
                _ => current.push(ch),
            }
            has_token = true;
            continue;
        }
        match ch {
            '\'' => {
                in_single = true;
                has_token = true;
            }
            '"' => {
                in_double = true;
                has_token = true;
            }
            '\\' => {
                escaped = true;
                has_token = true;
            }
            c if c.is_whitespace() => {
                if has_token {
                    words.push(std::mem::take(&mut current));
                    has_token = false;
                }
            }
            _ => {
                current.push(ch);
                has_token = true;
            }
        }
    }
    if escaped {
        current.push('\\');
    }
    if has_token {
        words.push(current);
    }
    words
}

fn basename_of(program: &str) -> String {
    Path::new(program)
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(program)
        .to_string()
}

fn is_shell_binary(basename: &str) -> bool {
    matches!(
        basename,
        "sh" | "bash" | "zsh" | "dash" | "ksh" | "fish" | "ash" | "csh" | "tcsh"
    )
}

fn is_shell_tool_name(tool: &str) -> bool {
    matches!(
        tool,
        "run_command"
            | "Bash"
            | "bash"
            | "sh"
            | "shell"
            | "shell_command"
            | "local_shell"
            | "exec"
            | "exec_command"
            | "terminal"
    )
}

fn extract_shell_wrapper_inner(program: &str, argv: &[String]) -> Option<String> {
    if !is_shell_binary(program) {
        return None;
    }
    for (idx, flag) in argv.iter().enumerate() {
        if flag == "-c"
            || (flag.starts_with('-')
                && !flag.starts_with("--")
                && flag.chars().skip(1).all(|c| c.is_ascii_alphabetic())
                && flag.contains('c'))
        {
            if let Some(inner) = argv.get(idx + 1) {
                if !inner.trim().is_empty() {
                    return Some(inner.clone());
                }
            }
        }
    }
    None
}

/// Builds one or more Cedar actions to evaluate from the **raw (unredacted, untruncated)**
/// tool arguments.
///
/// Handles quoted shell commands, Codex array `command` (`["bash", "-lc", "..."]`), and
/// `sh -c`/`bash -lc` shell wrappers (evaluating both the outer wrapper and unwrapped
/// inner command so forbid rules on either cannot be bypassed).
pub fn build_cedar_actions_for_hook(
    client: HookClient,
    tool_name: Option<&str>,
    raw_args: &Value,
) -> Vec<LocalActionKind> {
    let tool = tool_name.unwrap_or("unknown_tool");

    // 1. Codex / exec array `command` or `argv` (`["bash", "-lc", "rm -rf /"]`).
    let array_cmd: Option<Vec<String>> = raw_args
        .get("command")
        .or_else(|| raw_args.get("argv"))
        .or_else(|| raw_args.get("cmd"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .filter(|v| !v.is_empty());

    let string_cmd: Option<&str> = raw_args
        .get("CommandLine")
        .or_else(|| raw_args.get("command"))
        .or_else(|| raw_args.get("cmd"))
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty());

    let parsed_parts: Option<(Vec<String>, String)> = if let Some(parts) = array_cmd {
        let joined = parts.join(" ");
        Some((parts, joined))
    } else if let Some(cmd) =
        string_cmd.filter(|_| is_shell_tool_name(tool) || raw_args.get("CommandLine").is_some())
    {
        let parts = split_shell_words(cmd);
        if parts.is_empty() {
            None
        } else {
            Some((parts, cmd.to_string()))
        }
    } else {
        None
    };

    if let Some((parts, full_cmd_line)) = parsed_parts {
        let program = basename_of(&parts[0]);
        let argv = if parts.len() > 1 {
            parts[1..].to_vec()
        } else {
            Vec::new()
        };
        let mut actions = vec![LocalActionKind::ExecCommand {
            program: program.clone(),
            argv: argv.clone(),
            command_line: full_cmd_line,
        }];
        if let Some(inner_cmd) = extract_shell_wrapper_inner(&program, &argv) {
            let inner_parts = split_shell_words(&inner_cmd);
            if let Some(first_inner) = inner_parts.first() {
                let inner_prog = basename_of(first_inner);
                let inner_argv = if inner_parts.len() > 1 {
                    inner_parts[1..].to_vec()
                } else {
                    Vec::new()
                };
                actions.push(LocalActionKind::ExecCommand {
                    program: inner_prog,
                    argv: inner_argv,
                    command_line: inner_cmd,
                });
            }
        }
        return actions;
    }

    let args_bytes = serde_json::to_vec(raw_args).unwrap_or_default();
    let args_sha = hex_lower(&Sha256::digest(&args_bytes));
    vec![LocalActionKind::McpToolCall {
        server_id: client.as_str().to_string(),
        tool_name: tool.to_string(),
        descriptor_sha256: None,
        arguments_sha256: Some(args_sha),
    }]
}

fn default_stdout_for_event(client: HookClient, kind: NormalizedEventKind) -> Value {
    match (client, kind) {
        (HookClient::Antigravity, NormalizedEventKind::Stop) => json!({"decision": "stop"}),
        _ => json!({}),
    }
}

fn enforce_block_response(client: HookClient, reason: &str) -> Value {
    match client {
        HookClient::Antigravity => json!({"decision": "deny", "reason": reason}),
        HookClient::ClaudeCode | HookClient::Codex => {
            json!({"decision": "block", "reason": reason})
        }
    }
}

/// Runs the fast synchronous stdin -> stdout hook path.
///
/// In `observe` mode, errors are logged and swallowed so the hook remains strictly
/// fail-open (`exit 0` + valid client JSON). In `enforce` mode:
/// - Empty stdin, malformed JSON, or unrecognized event names ALWAYS fail closed.
/// - Cedar is evaluated against the **real (pre-redaction, pre-truncation)** args first;
///   redaction and 16 KiB capping are applied only to queued/stored telemetry.
/// - Missing `--cedar-policy`, unreadable/invalid Cedar, or any Cedar eval error fails closed.
pub fn run_hook_invocation(stdin_raw: &str, opts: &HookRunOptions) -> Value {
    if stdin_raw.trim().is_empty() {
        if opts.mode == HookMode::Enforce {
            append_hook_log(
                &opts.state_dir,
                "enforce fail-closed: unrecognized_or_empty_hook_event (empty stdin)",
            );
            return enforce_block_response(opts.client, "unrecognized_or_empty_hook_event");
        }
        return json!({});
    }

    let payload: Value = match serde_json::from_str(stdin_raw) {
        Ok(v) => v,
        Err(err) => {
            append_hook_log(&opts.state_dir, &format!("hook invalid stdin JSON: {err}"));
            if opts.mode == HookMode::Enforce {
                return enforce_block_response(
                    opts.client,
                    "Policy unavailable: malformed hook payload in enforce mode",
                );
            }
            json!({})
        }
    };

    // Extract raw (unredacted, untruncated) args BEFORE normalization/redaction for Cedar.
    let raw_args = extract_raw_args_for_client(opts.client, &payload);
    let mut ev = normalize_hook_payload(opts.client, opts.mode, &payload);

    if opts.mode == HookMode::Enforce && ev.event_kind == NormalizedEventKind::Unknown {
        append_hook_log(
            &opts.state_dir,
            "enforce fail-closed: unrecognized_or_empty_hook_event",
        );
        return enforce_block_response(opts.client, "unrecognized_or_empty_hook_event");
    }

    let mut response = default_stdout_for_event(opts.client, ev.event_kind);

    if opts.mode == HookMode::Enforce && ev.event_kind == NormalizedEventKind::PreToolUse {
        let Some(ref policy_path) = opts.cedar_policy else {
            let reason = "Policy unavailable (no_bundle): enforce mode requires --cedar-policy";
            append_hook_log(&opts.state_dir, reason);
            ev.enforce_outcome = Some("deny".to_string());
            ev.enforce_reason = Some(reason.to_string());
            response = enforce_block_response(opts.client, reason);
            let sess_dir = opts.state_dir.join("sessions").join(&ev.conversation_id);
            if ensure_dir_0700(&sess_dir).is_ok() {
                if let Ok(line) = serde_json::to_string(&ev) {
                    let _ = append_line_0600(&sess_dir.join("events.jsonl"), &line);
                }
            }
            return response;
        };

        match fs::read_to_string(policy_path)
            .map_err(|e| format!("read cedar policy {}: {e}", policy_path.display()))
            .and_then(|src| LocalCedarGate::from_cedar_src(&src, Posture::Enforce, false))
        {
            Ok(gate) => {
                let actions =
                    build_cedar_actions_for_hook(opts.client, ev.tool_name.as_deref(), &raw_args);
                let session_ctx = format!("urn:r5e:session:hook:{}", ev.conversation_id);
                let mut final_verdict = None;
                let mut eval_error: Option<String> = None;

                for action in &actions {
                    match gate.evaluate(opts.client.as_str(), &session_ctx, action) {
                        Ok(verdict) => {
                            let denied = !verdict.allowed_to_execute;
                            final_verdict = Some(verdict);
                            if denied {
                                break;
                            }
                        }
                        Err(err) => {
                            eval_error = Some(err);
                            break;
                        }
                    }
                }

                if let Some(err) = eval_error {
                    let reason = format!("Policy evaluation error (cedar_eval_error): {err}");
                    append_hook_log(&opts.state_dir, &reason);
                    ev.enforce_outcome = Some("deny".to_string());
                    ev.enforce_reason = Some(reason.clone());
                    response = enforce_block_response(opts.client, &reason);
                } else if let Some(verdict) = final_verdict {
                    ev.enforce_outcome = Some(verdict.cedar_decision.clone());
                    ev.enforce_policy_ref = Some(verdict.policy_bundle_ref.clone());
                    ev.enforce_matching_ids = verdict.matching_policy_ids.clone();
                    ev.enforce_reason = verdict.agent_message.clone();
                    if !verdict.allowed_to_execute {
                        let reason = verdict
                            .agent_message
                            .unwrap_or_else(|| "Blocked by organisation Cedar policy".to_string());
                        response = enforce_block_response(opts.client, &reason);
                    } else if opts.client == HookClient::Antigravity {
                        response = json!({"decision": "allow"});
                    }
                }
            }
            Err(err) => {
                let reason = format!("Policy unavailable (no_bundle): {err}");
                append_hook_log(&opts.state_dir, &reason);
                ev.enforce_outcome = Some("deny".to_string());
                ev.enforce_reason = Some(reason.clone());
                response = enforce_block_response(opts.client, &reason);
            }
        }
    }

    let sess_dir = opts.state_dir.join("sessions").join(&ev.conversation_id);
    if let Err(err) = ensure_dir_0700(&sess_dir) {
        append_hook_log(&opts.state_dir, &format!("hook mkdir error: {err}"));
        return response;
    }

    if let Ok(line) = serde_json::to_string(&ev) {
        if let Err(err) = append_line_0600(&sess_dir.join("events.jsonl"), &line) {
            append_hook_log(&opts.state_dir, &format!("hook enqueue error: {err}"));
            return response;
        }
    }

    if opts.spawn_drainer {
        if let Ok(exe) = std::env::current_exe() {
            let mut cmd = Command::new(exe);
            cmd.arg("hook")
                .arg(opts.client.as_str())
                .arg("--mode")
                .arg(opts.mode.as_str())
                .arg("--gateway")
                .arg(&opts.gateway_url)
                .arg("--state-dir")
                .arg(&opts.state_dir)
                .arg("--bearer-token-env")
                .arg(&opts.bearer_token_env)
                .arg("--drain")
                .arg(&ev.conversation_id)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            if let Some(ref tf) = opts.bearer_token_file {
                cmd.arg("--bearer-token-file").arg(tf);
            }
            if let Some(ref cp) = opts.cedar_policy {
                cmd.arg("--cedar-policy").arg(cp);
            }
            if let Err(err) = cmd.spawn() {
                append_hook_log(&opts.state_dir, &format!("hook spawn drainer error: {err}"));
            }
        }
    }

    response
}

fn resolve_bearer_token(token_env: &str, token_file: Option<&Path>) -> Result<String, String> {
    if let Some(path) = token_file {
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("read bearer token file {}: {e}", path.display()))?;
        let tok = raw.trim().to_string();
        if tok.is_empty() {
            return Err(format!("bearer token file {} is empty", path.display()));
        }
        return Ok(tok);
    }
    let val =
        std::env::var(token_env).map_err(|_| format!("bearer token env {token_env} is not set"))?;
    let tok = val.trim().to_string();
    if tok.is_empty() {
        return Err(format!("bearer token env {token_env} is empty"));
    }
    Ok(tok)
}

fn load_or_default_meta(path: &Path) -> SessionMeta {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn ensure_enrolled_and_opened(
    session_dir: &Path,
    conv_id: &str,
    first_ev: &QueuedHookEvent,
    opts: &HookRunOptions,
    bearer_token: &str,
) -> Result<EnrolledStateFile, String> {
    let state_path = session_dir.join("state.json");
    let mut state = if state_path.is_file() {
        EnrolledStateFile::load(&state_path)?
    } else {
        let seed = generate_os_random_seed_32()?;
        let helper_key = SigningKey::from_bytes(&seed);
        let cedar_bytes = match opts.cedar_policy {
            Some(ref p) => fs::read(p).unwrap_or_else(|_| b"// hook observe policy\n".to_vec()),
            None => b"// hook observe policy\n".to_vec(),
        };
        let holder = format!("{}-hook", opts.client.as_str());
        let enrol_cfg =
            EnrolmentClientConfig::new(&opts.gateway_url, Some(bearer_token.to_string()));
        let mut enrol_opts = EnrolBadgeOptions {
            purpose: Some(format!(
                "{} {} hook telemetry for conversation {conv_id}",
                opts.client.as_str(),
                opts.mode.as_str()
            )),
            ..Default::default()
        };
        enrol_opts.session_options.policy_required_kinds = Some(Vec::new());
        let requested_kinds: Vec<String> = DEFAULT_HOOK_WORKLOAD_KINDS
            .iter()
            .map(|k| (*k).to_string())
            .collect();
        let (enrolled_session, _finalized) = enrol_endpoint_badge_with_options(
            &enrol_cfg,
            helper_key,
            &holder,
            Some(opts.client.workload_uri()),
            requested_kinds,
            Some(vec!["urn:r5e:".to_string()]),
            None,
            &cedar_bytes,
            &enrol_opts,
        )
        .map_err(|e| format!("enrol-badge failed: {e}"))?;

        let st = EnrolledStateFile::from_enrolled_session(
            &opts.gateway_url,
            &holder,
            enrol_opts.purpose,
            &enrolled_session,
        );
        st.save_0600(&state_path, true)?;
        st
    };

    if state.session_urn.is_none() {
        let client_sid = truncate_utf8_bytes(&format!("{}-{conv_id}", opts.client.as_str()), 128);
        let mut details = Map::new();
        details.insert(
            "conversationId".to_string(),
            Value::String(conv_id.to_string()),
        );
        details.insert(
            "mode".to_string(),
            Value::String(opts.mode.as_str().to_string()),
        );
        details.insert(
            "source".to_string(),
            Value::String(format!("{}-hook", opts.client.as_str())),
        );
        if let Some(ref model) = first_ev.model_name {
            details.insert("modelName".to_string(), Value::String(model.clone()));
        }
        let open_req = OpenSessionRequest {
            client_session_id: Some(client_sid),
            purpose: Some(format!(
                "{} conversation {conv_id} ({})",
                opts.client.as_str(),
                opts.mode.as_str()
            )),
            workload: Some(opts.client.workload_uri()),
            details: Some(details),
        };
        let opened = open_session_over_http(&opts.gateway_url, bearer_token, &open_req)
            .map_err(|e| format!("open-session failed: {e}"))?;
        state.session_urn = Some(opened.session.clone());
        state.session_anchor_ref = opened.record_ref.clone();
        state.save_0600(&state_path, true)?;
        append_hook_log(
            &opts.state_dir,
            &format!(
                "open-session conv={conv_id} session={} already_open={}",
                opened.session, opened.already_open
            ),
        );
    }

    Ok(state)
}

/// Resolves the `capturedAt` timestamp for a queued event against `badge.notBefore`.
///
/// Because the first event of a conversation may be enqueued milliseconds before lazy
/// background badge enrolment completes, gateway `profile_bounds` requires
/// `capturedAt >= badge.notBefore`. When clamping is necessary, this returns
/// `(clamped_captured_at, Some(original_observed_at))` so callers record the true
/// observation timestamp in `body.details.observedAt` rather than silently rewriting
/// history.
pub fn resolve_captured_at(
    raw_captured_at: &str,
    badge_not_before: &str,
) -> (String, Option<String>) {
    if raw_captured_at >= badge_not_before {
        return (raw_captured_at.to_string(), None);
    }
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let clamped = if now.as_str() >= badge_not_before {
        now
    } else {
        badge_not_before.to_string()
    };
    (clamped, Some(raw_captured_at.to_string()))
}

fn append_queued_event_to_state(
    state: &mut EnrolledStateFile,
    ev: &QueuedHookEvent,
) -> Result<bool, String> {
    let actor = ev.client.actor_uri();
    let session_urn = state.session_urn.clone();
    let session_ref = session_urn.as_deref();
    let (captured_at, clamped_observed_at) =
        resolve_captured_at(&ev.captured_at, &state.not_before);

    match ev.event_kind {
        NormalizedEventKind::SessionStart | NormalizedEventKind::Unknown => Ok(false),
        NormalizedEventKind::PreToolUse => {
            let Some(ref outcome) = ev.enforce_outcome else {
                return Ok(false);
            };
            let tool = ev.tool_name.as_deref().unwrap_or("unknown_tool");
            let target_basename = Path::new(tool)
                .file_name()
                .and_then(|s| s.to_str())
                .filter(|s| !s.is_empty())
                .unwrap_or(tool);
            let args_text = bounded_json_string(&json!({
                "tool": tool,
                "callId": ev.call_id,
                "args": ev.args,
                "stepIdx": ev.step_idx,
            }));
            let args_ref = state
                .recorder
                .put_blob(args_text.as_bytes(), Some("application/json"));
            let policy_ref = ev
                .enforce_policy_ref
                .clone()
                .unwrap_or_else(|| state.deployment_policy_ref.clone());
            let mut eval = Map::new();
            eval.insert("policyRef".to_string(), Value::String(policy_ref));
            eval.insert("outcome".to_string(), Value::String(outcome.clone()));
            eval.insert("inputRefs".to_string(), json!([args_ref]));
            if let Some(ref reason) = ev.enforce_reason {
                if !reason.trim().is_empty() {
                    eval.insert("reason".to_string(), Value::String(reason.clone()));
                }
            }
            let mut pd_details = Map::new();
            pd_details.insert("posture".to_string(), json!("enforce"));
            pd_details.insert(
                "enforcementOutcome".to_string(),
                json!(if outcome == "allow" {
                    "allowed"
                } else {
                    "prevented"
                }),
            );
            pd_details.insert(
                "matchingPolicyIds".to_string(),
                json!(ev.enforce_matching_ids.join(",")),
            );
            pd_details.insert(
                "matchingPolicyCount".to_string(),
                json!(ev.enforce_matching_ids.len() as i64),
            );
            pd_details.insert("action".to_string(), json!("PreToolUse"));
            pd_details.insert(
                "target".to_string(),
                json!(truncate_utf8_bytes(target_basename, 256)),
            );
            if let Some(ref obs_at) = clamped_observed_at {
                pd_details.insert("observedAt".to_string(), json!(obs_at));
            }
            let body = json!({
                "subject": args_ref,
                "evaluation": Value::Object(eval),
                "details": Value::Object(pd_details),
            });
            state.append_workload_record(
                "events",
                "PolicyDecision",
                &actor,
                session_ref,
                &captured_at,
                body,
            )?;
            Ok(true)
        }
        NormalizedEventKind::PostToolUse => {
            let tool = ev.tool_name.as_deref().unwrap_or("unknown_tool");
            let call_id = ev
                .call_id
                .clone()
                .unwrap_or_else(|| format!("step-{}", ev.step_idx.unwrap_or(0)));
            let args_payload = json!({
                "tool": tool,
                "callId": call_id,
                "args": ev.args,
                "stepIdx": ev.step_idx,
                "cwd": ev.cwd,
                "modelName": ev.model_name,
            });
            let args_text = bounded_json_string(&args_payload);
            let args_ref = state
                .recorder
                .put_blob(args_text.as_bytes(), Some("application/json"));

            let mut tc_details = Map::new();
            tc_details.insert(
                "source".to_string(),
                Value::String(format!("{}-hook", ev.client.as_str())),
            );
            tc_details.insert(
                "mode".to_string(),
                Value::String(ev.mode.as_str().to_string()),
            );
            if let Some(step) = ev.step_idx {
                tc_details.insert("stepIdx".to_string(), json!(step));
            }
            if let Some(ref obs_at) = clamped_observed_at {
                tc_details.insert("observedAt".to_string(), json!(obs_at));
            }
            let tc_body = json!({
                "tool": truncate_utf8_bytes(tool, 128),
                "callId": truncate_utf8_bytes(&call_id, 256),
                "contentRef": args_ref,
                "mediaType": "application/json",
                "size": args_text.len() as i64,
                "summary": truncate_utf8_bytes(
                    &format!("{} {tool}", ev.client.as_str()),
                    256
                ),
                "details": tc_details,
            });
            let tc = state.append_workload_record(
                "events",
                "ToolCall",
                &actor,
                session_ref,
                &captured_at,
                tc_body,
            )?;

            let has_error = ev.error.as_deref().is_some_and(|s| !s.trim().is_empty());
            let mut res_payload = Map::new();
            res_payload.insert(
                "status".to_string(),
                Value::String(if has_error { "error" } else { "ok" }.to_string()),
            );
            res_payload.insert("tool".to_string(), Value::String(tool.to_string()));
            res_payload.insert("callId".to_string(), Value::String(call_id.clone()));
            if let Some(step) = ev.step_idx {
                res_payload.insert("stepIdx".to_string(), json!(step));
            }
            if let Some(ref err_str) = ev.error {
                res_payload.insert("error".to_string(), Value::String(err_str.clone()));
            }
            let res_text = bounded_json_string(&Value::Object(res_payload));
            let res_ref = state
                .recorder
                .put_blob(res_text.as_bytes(), Some("application/json"));

            let mut tr_details = Map::new();
            tr_details.insert(
                "status".to_string(),
                Value::String(if has_error { "error" } else { "ok" }.to_string()),
            );
            if let Some(step) = ev.step_idx {
                tr_details.insert("stepIdx".to_string(), json!(step));
            }
            let mut tr_body = Map::new();
            tr_body.insert("call".to_string(), Value::String(tc.record_ref));
            tr_body.insert(
                "callId".to_string(),
                Value::String(truncate_utf8_bytes(&call_id, 256)),
            );
            tr_body.insert("contentRef".to_string(), Value::String(res_ref));
            tr_body.insert(
                "mediaType".to_string(),
                Value::String("application/json".to_string()),
            );
            tr_body.insert("size".to_string(), json!(res_text.len() as i64));
            tr_body.insert(
                "outcome".to_string(),
                Value::String(if has_error { "failed" } else { "completed" }.to_string()),
            );
            tr_body.insert("details".to_string(), Value::Object(tr_details));
            // Keep raw tool error text strictly inside the erasable contentRef blob;
            // permanent ToolResult.body.reason carries only a closed generic code.
            if has_error {
                tr_body.insert(
                    "reason".to_string(),
                    Value::String("tool_error".to_string()),
                );
            }
            state.append_workload_record(
                "events",
                "ToolResult",
                &actor,
                session_ref,
                &captured_at,
                Value::Object(tr_body),
            )?;
            Ok(true)
        }
        NormalizedEventKind::Stop => {
            let model = ev.model_name.as_deref().unwrap_or("unknown");
            let term = ev.termination_reason.as_deref().unwrap_or("UNKNOWN");
            let obs_payload = json!({
                "kind": "turn.completed",
                "conversationId": ev.conversation_id,
                "modelName": model,
                "terminationReason": term,
                "executionNum": ev.execution_num,
                "fullyIdle": ev.fully_idle.unwrap_or(true),
            });
            let obs_text = bounded_json_string(&obs_payload);
            let obs_ref = state
                .recorder
                .put_blob(obs_text.as_bytes(), Some("application/json"));
            let mut obs_details = Map::new();
            obs_details.insert("kind".to_string(), json!("turn.completed"));
            obs_details.insert(
                "modelName".to_string(),
                json!(truncate_utf8_bytes(model, 128)),
            );
            obs_details.insert(
                "terminationReason".to_string(),
                json!(truncate_utf8_bytes(term, 128)),
            );
            if let Some(ref obs_at) = clamped_observed_at {
                obs_details.insert("observedAt".to_string(), json!(obs_at));
            }
            let obs_body = json!({
                "topic": "turn.completed",
                "contentRefs": [obs_ref],
                "details": Value::Object(obs_details),
            });
            state.append_workload_record(
                "events",
                "Observation",
                &actor,
                session_ref,
                &captured_at,
                obs_body,
            )?;
            Ok(true)
        }
    }
}

/// Drains pending JSONL events for `conv_id` under a non-blocking advisory file lock
/// (`File::try_lock`), enrolling/opening the session if needed and shipping to the gateway.
pub fn drain_conversation(conv_id: &str, opts: &HookRunOptions) -> Result<(), String> {
    let safe_id = sanitize_conversation_id(Some(conv_id));
    let session_dir = opts.state_dir.join("sessions").join(&safe_id);
    ensure_dir_0700(&session_dir)?;

    let lock_path = session_dir.join("ship.lock");
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| format!("open lock {}: {e}", lock_path.display()))?;

    match lock_file.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Ok(()),
        Err(std::fs::TryLockError::Error(err)) => {
            return Err(format!("lock {}: {err}", lock_path.display()));
        }
    }

    let meta_path = session_dir.join("meta.json");
    let mut meta = load_or_default_meta(&meta_path);
    meta.gateway_url = Some(opts.gateway_url.clone());

    let result = (|| -> Result<(), String> {
        let bearer_token =
            resolve_bearer_token(&opts.bearer_token_env, opts.bearer_token_file.as_deref())?;
        let queue_path = session_dir.join("events.jsonl");
        let cursor_path = session_dir.join("cursor.txt");
        let state_path = session_dir.join("state.json");

        for _ in 0..5 {
            if !queue_path.is_file() {
                break;
            }
            let content = fs::read_to_string(&queue_path)
                .map_err(|e| format!("read {}: {e}", queue_path.display()))?;
            let lines: Vec<&str> = content.lines().collect();
            let cursor: usize = fs::read_to_string(&cursor_path)
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
            if cursor >= lines.len() {
                break;
            }

            let pending = &lines[cursor..];
            // Skip any leading empty or corrupt JSONL lines so a single bad line never wedges the queue.
            let mut first_valid_idx = None;
            let mut first_ev: Option<QueuedHookEvent> = None;
            for (offset, line) in pending.iter().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<QueuedHookEvent>(line) {
                    Ok(ev) => {
                        first_valid_idx = Some(offset);
                        first_ev = Some(ev);
                        break;
                    }
                    Err(err) => {
                        append_hook_log(
                            &opts.state_dir,
                            &format!(
                                "drain skipping corrupt JSONL line {} in conv={safe_id}: {err}",
                                cursor + offset + 1
                            ),
                        );
                    }
                }
            }
            let Some(first_ev) = first_ev else {
                fs::write(&cursor_path, lines.len().to_string())
                    .map_err(|e| format!("write cursor: {e}"))?;
                break;
            };
            let start_offset = first_valid_idx.unwrap_or(0);
            if start_offset > 0 {
                fs::write(&cursor_path, (cursor + start_offset).to_string())
                    .map_err(|e| format!("write cursor: {e}"))?;
            }

            let mut state =
                ensure_enrolled_and_opened(&session_dir, &safe_id, &first_ev, opts, &bearer_token)?;
            meta.badge_ref = Some(state.badge_ref.clone());
            meta.session_urn = state.session_urn.clone();

            let mut processed = start_offset;
            let mut did_record = false;
            for line in &pending[start_offset..] {
                if line.trim().is_empty() {
                    processed += 1;
                    fs::write(&cursor_path, (cursor + processed).to_string())
                        .map_err(|e| format!("write cursor: {e}"))?;
                    continue;
                }
                match serde_json::from_str::<QueuedHookEvent>(line) {
                    Ok(ev) => {
                        if append_queued_event_to_state(&mut state, &ev)? {
                            did_record = true;
                        }
                    }
                    Err(err) => {
                        append_hook_log(
                            &opts.state_dir,
                            &format!(
                                "drain skipping corrupt JSONL line {} in conv={safe_id}: {err}",
                                cursor + processed + 1
                            ),
                        );
                    }
                }
                processed += 1;
                fs::write(&cursor_path, (cursor + processed).to_string())
                    .map_err(|e| format!("write cursor: {e}"))?;
            }
            state.save_0600(&state_path, true)?;

            if !did_record {
                continue;
            }

            let already_shipped: BTreeSet<String> =
                state.shipped_record_refs.iter().cloned().collect();
            let ship_req = build_ship_request_from_recorder(
                &state.recorder,
                Some(&state.subject_key_id),
                &already_shipped,
                true,
                None,
            )
            .map_err(|e| format!("build ship request: {e}"))?;
            if ship_req.records.is_empty() {
                continue;
            }

            let responses =
                ship_records_batches_over_http(&opts.gateway_url, &bearer_token, &ship_req)
                    .map_err(|e| format!("ship-bundle failed: {e}"))?;
            let mut total_admitted = 0usize;
            let mut total_missing = 0usize;
            for resp in &responses {
                for item in &resp.admitted {
                    total_admitted += 1;
                    total_missing += item.content_missing.len();
                    if !state.shipped_record_refs.contains(&item.record_ref) {
                        state.shipped_record_refs.push(item.record_ref.clone());
                    }
                }
            }
            state.save_0600(&state_path, true)?;

            let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            meta.last_ship_at = Some(now);
            meta.last_error = None;
            let _ = write_json_0600(&meta_path, &meta);
            append_hook_log(
                &opts.state_dir,
                &format!(
                    "ship conv={safe_id} admitted={total_admitted} contentMissing={total_missing}"
                ),
            );
        }
        Ok(())
    })();

    if let Err(ref err) = result {
        meta.last_error = Some(truncate_utf8_bytes(err, 512));
        let _ = write_json_0600(&meta_path, &meta);
        append_hook_log(
            &opts.state_dir,
            &format!("drain error conv={safe_id}: {err}"),
        );
    }

    let _ = lock_file.unlock();
    result
}

fn build_hook_command_string(opts: &InstallHooksOptions) -> String {
    let mut parts = vec![
        opts.helper_bin.display().to_string(),
        "hook".to_string(),
        opts.client.as_str().to_string(),
        "--mode".to_string(),
        opts.mode.as_str().to_string(),
        "--gateway".to_string(),
        opts.gateway_url.clone(),
    ];
    if let Some(ref dir) = opts.state_dir {
        parts.push("--state-dir".to_string());
        parts.push(dir.display().to_string());
    }
    if let Some(ref tf) = opts.bearer_token_file {
        parts.push("--bearer-token-file".to_string());
        parts.push(tf.display().to_string());
    }
    if let Some(ref cp) = opts.cedar_policy {
        parts.push("--cedar-policy".to_string());
        parts.push(cp.display().to_string());
    }
    parts.join(" ")
}

fn merge_event_hook_list(existing: Option<&Value>, entry: Value) -> Value {
    let mut arr: Vec<Value> = existing
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    arr.retain(|item| {
        let serialized = serde_json::to_string(item).unwrap_or_default();
        !serialized.contains("r5e-endpoint-helper")
    });
    arr.push(entry);
    Value::Array(arr)
}

/// Installs or updates the `r5e-endpoint-helper` hook entry for the target agent client
/// without clobbering existing user hooks.
pub fn install_hooks_config(opts: &InstallHooksOptions) -> Result<PathBuf, String> {
    if opts.mode == HookMode::Enforce && opts.cedar_policy.is_none() {
        return Err(
            "install-hooks --mode enforce requires --cedar-policy <FILE> (enforce fails closed without a policy)"
                .to_string(),
        );
    }
    fs::create_dir_all(&opts.target_dir)
        .map_err(|e| format!("create {}: {e}", opts.target_dir.display()))?;
    let cmd = build_hook_command_string(opts);

    let config_path = match opts.client {
        HookClient::Antigravity | HookClient::Codex => opts.target_dir.join("hooks.json"),
        HookClient::ClaudeCode => opts.target_dir.join("settings.json"),
    };

    let mut root: Value = if config_path.is_file() {
        let raw = fs::read_to_string(&config_path)
            .map_err(|e| format!("read {}: {e}", config_path.display()))?;
        if raw.trim().is_empty() {
            json!({})
        } else {
            serde_json::from_str(&raw)
                .map_err(|e| format!("parse existing {}: {e}", config_path.display()))?
        }
    } else {
        json!({})
    };

    let root_obj = root.as_object_mut().ok_or_else(|| {
        format!(
            "{} must contain a top-level JSON object",
            config_path.display()
        )
    })?;

    match opts.client {
        HookClient::Antigravity => {
            let hook_name = format!("r5e-{}", opts.mode.as_str());
            let handler = json!({
                "type": "command",
                "command": cmd,
                "timeout": 15,
            });
            let mut hook_spec = Map::new();
            hook_spec.insert("enabled".to_string(), json!(true));
            hook_spec.insert("SessionStart".to_string(), json!([handler.clone()]));
            if opts.mode == HookMode::Enforce {
                hook_spec.insert(
                    "PreToolUse".to_string(),
                    json!([{"matcher": "*", "hooks": [handler.clone()]}]),
                );
            }
            hook_spec.insert(
                "PostToolUse".to_string(),
                json!([{"matcher": "*", "hooks": [handler.clone()]}]),
            );
            hook_spec.insert("Stop".to_string(), json!([handler]));
            root_obj.insert(hook_name, Value::Object(hook_spec));
        }
        HookClient::ClaudeCode | HookClient::Codex => {
            let hooks_val = root_obj
                .entry("hooks".to_string())
                .or_insert_with(|| json!({}));
            let hooks_obj = hooks_val.as_object_mut().ok_or_else(|| {
                format!(
                    "`hooks` field in {} must be a JSON object",
                    config_path.display()
                )
            })?;
            let handler = json!({
                "type": "command",
                "command": cmd,
                "timeout": 15,
            });
            let flat_entry = json!({"hooks": [handler.clone()]});
            let matched_entry = json!({"matcher": "*", "hooks": [handler]});

            let ss = merge_event_hook_list(hooks_obj.get("SessionStart"), flat_entry.clone());
            hooks_obj.insert("SessionStart".to_string(), ss);
            if opts.mode == HookMode::Enforce {
                let pre = merge_event_hook_list(hooks_obj.get("PreToolUse"), matched_entry.clone());
                hooks_obj.insert("PreToolUse".to_string(), pre);
            }
            let post = merge_event_hook_list(hooks_obj.get("PostToolUse"), matched_entry);
            hooks_obj.insert("PostToolUse".to_string(), post);
            let stop = merge_event_hook_list(hooks_obj.get("Stop"), flat_entry);
            hooks_obj.insert("Stop".to_string(), stop);
        }
    }

    let formatted = serde_json::to_string_pretty(&root)
        .map_err(|e| format!("format {}: {e}", config_path.display()))?;
    write_string_atomic(&config_path, &format!("{formatted}\n"))?;
    Ok(config_path)
}

fn write_string_atomic(path: &Path, content: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("hooks.json");
    let tmp_path = parent.join(format!(
        ".{file_name}.tmp.{}.{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    fs::write(&tmp_path, content).map_err(|e| format!("write temp {}: {e}", tmp_path.display()))?;
    fs::rename(&tmp_path, path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        format!("rename {} -> {}: {e}", tmp_path.display(), path.display())
    })
}

/// Removes `r5e-endpoint-helper` hook entries for the target agent client without
/// disturbing other user hooks, writing the updated config atomically.
pub fn uninstall_hooks_config(
    client: HookClient,
    target_dir: &Path,
) -> Result<(PathBuf, bool), String> {
    let config_path = match client {
        HookClient::Antigravity | HookClient::Codex => target_dir.join("hooks.json"),
        HookClient::ClaudeCode => target_dir.join("settings.json"),
    };
    if !config_path.is_file() {
        return Ok((config_path, false));
    }
    let raw = fs::read_to_string(&config_path)
        .map_err(|e| format!("read {}: {e}", config_path.display()))?;
    if raw.trim().is_empty() {
        return Ok((config_path, false));
    }
    let mut root: Value = serde_json::from_str(&raw)
        .map_err(|e| format!("parse existing {}: {e}", config_path.display()))?;
    let root_obj = root.as_object_mut().ok_or_else(|| {
        format!(
            "{} must contain a top-level JSON object",
            config_path.display()
        )
    })?;

    let mut removed = false;
    match client {
        HookClient::Antigravity => {
            for key in ["r5e-observe", "r5e-enforce"] {
                if root_obj.remove(key).is_some() {
                    removed = true;
                }
            }
        }
        HookClient::ClaudeCode | HookClient::Codex => {
            if let Some(hooks_obj) = root_obj.get_mut("hooks").and_then(Value::as_object_mut) {
                for event_key in ["SessionStart", "PreToolUse", "PostToolUse", "Stop"] {
                    if let Some(arr) = hooks_obj.get_mut(event_key).and_then(Value::as_array_mut) {
                        let before = arr.len();
                        arr.retain(|item| {
                            let s = serde_json::to_string(item).unwrap_or_default();
                            !s.contains("r5e-endpoint-helper")
                        });
                        if arr.len() < before {
                            removed = true;
                        }
                    }
                }
            }
        }
    }

    if removed {
        let formatted = serde_json::to_string_pretty(&root)
            .map_err(|e| format!("format {}: {e}", config_path.display()))?;
        write_string_atomic(&config_path, &format!("{formatted}\n"))?;
    }
    Ok((config_path, removed))
}

/// Collects a machine-readable status snapshot for the desktop tray / Tauri app.
pub fn collect_status_snapshot(state_dir: &Path) -> HookStatusSnapshot {
    let mut snapshot = HookStatusSnapshot {
        version: env!("CARGO_PKG_VERSION").to_string(),
        gateway_url: None,
        enrolled: false,
        badge_ref: None,
        active_sessions: 0,
        queued_events: 0,
        last_ship_at: None,
        last_error: None,
    };

    let sessions_dir = state_dir.join("sessions");
    let Ok(entries) = fs::read_dir(&sessions_dir) else {
        return snapshot;
    };

    let mut dirs: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();

    for dir in dirs {
        let state_path = dir.join("state.json");
        if state_path.is_file() {
            if let Ok(st) = EnrolledStateFile::load(&state_path) {
                snapshot.enrolled = true;
                snapshot.gateway_url = Some(st.gateway_url);
                snapshot.badge_ref = Some(st.badge_ref);
                if st.session_urn.is_some() {
                    snapshot.active_sessions += 1;
                }
            }
        }

        let queue_path = dir.join("events.jsonl");
        if queue_path.is_file() {
            if let Ok(raw) = fs::read_to_string(&queue_path) {
                let total = raw.lines().filter(|l| !l.trim().is_empty()).count();
                let cursor: usize = fs::read_to_string(dir.join("cursor.txt"))
                    .ok()
                    .and_then(|s| s.trim().parse().ok())
                    .unwrap_or(0);
                snapshot.queued_events += total.saturating_sub(cursor);
            }
        }

        let meta = load_or_default_meta(&dir.join("meta.json"));
        if snapshot.gateway_url.is_none() {
            snapshot.gateway_url = meta.gateway_url;
        }
        if snapshot.badge_ref.is_none() {
            snapshot.badge_ref = meta.badge_ref;
        }
        if let Some(ship_at) = meta.last_ship_at {
            if snapshot
                .last_ship_at
                .as_deref()
                .is_none_or(|prev| ship_at.as_str() > prev)
            {
                snapshot.last_ship_at = Some(ship_at);
            }
        }
        if let Some(err) = meta.last_error {
            snapshot.last_error = Some(err);
        }
    }

    snapshot
}

pub fn encode_status_json(snapshot: &HookStatusSnapshot) -> Result<String, String> {
    let val = serde_json::to_value(snapshot).map_err(|e| format!("serialize status: {e}"))?;
    let bytes = encode_canonical_json(&val)?;
    String::from_utf8(bytes).map_err(|e| format!("utf8 status: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let unique = format!(
            "r5e-agent-hooks-{label}-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );
        let p = std::env::temp_dir().join(unique);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn redacts_secret_keys_bearer_jwts_and_api_keys() {
        let input = json!({
            "CommandLine": "curl -H 'Authorization: Bearer secret_token_123456789' https://example.com",
            "api_key": "sk-proj-1234567890abcdef",
            "nested": {
                "note": "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0MTIzNDUifQ.sig1234567890abcd and R5E_TOKEN=my_secret_val",
                "safe": "hello world"
            }
        });
        let redacted = redact_json_value(&input, 0);
        let dumped = serde_json::to_string(&redacted).unwrap();
        assert!(!dumped.contains("secret_token_123456789"));
        assert!(!dumped.contains("sk-proj-1234567890abcdef"));
        assert!(!dumped.contains("eyJhbGciOiJIUzI1NiJ9"));
        assert!(!dumped.contains("my_secret_val"));
        assert_eq!(redacted["api_key"], "[REDACTED]");
        assert_eq!(redacted["nested"]["safe"], "hello world");
    }

    #[test]
    fn caps_oversized_payload_at_16kb() {
        let huge = json!({"blob": "x".repeat(40_000)});
        let bounded = bounded_json_string(&huge);
        assert!(bounded.len() <= MAX_HOOK_PAYLOAD_BYTES);
        let parsed: Value = serde_json::from_str(&bounded).unwrap();
        assert_eq!(parsed["truncated"], true);
    }

    #[test]
    fn observe_mode_is_fail_open_and_enqueues_fast() {
        let dir = temp_dir("observe-fast");
        let opts = HookRunOptions {
            client: HookClient::Antigravity,
            mode: HookMode::Observe,
            gateway_url: "http://127.0.0.1:4000".to_string(),
            state_dir: dir.clone(),
            bearer_token_env: "R5E_TOKEN".to_string(),
            bearer_token_file: None,
            cedar_policy: None,
            spawn_drainer: false,
        };
        let post_out = run_hook_invocation(
            r#"{"hookEventName":"PostToolUse","conversationId":"conv-1","stepIdx":1,"toolCall":{"id":"c1","name":"run_command","args":{"CommandLine":"ls"}}}"#,
            &opts,
        );
        assert_eq!(post_out, json!({}));

        let stop_out = run_hook_invocation(
            r#"{"hookEventName":"Stop","conversationId":"conv-1","terminationReason":"NO_TOOL_CALL"}"#,
            &opts,
        );
        assert_eq!(stop_out, json!({"decision": "stop"}));

        let status = collect_status_snapshot(&dir);
        assert_eq!(status.queued_events, 2);
        assert!(!status.enrolled);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn enforce_mode_blocks_cedar_denied_pre_tool_use_for_antigravity_and_claude() {
        let dir = temp_dir("enforce");
        let cedar_path = dir.join("policy.cedar");
        fs::write(
            &cedar_path,
            r#"
@id("deny-curl")
forbid (
    principal,
    action == Recurse::Action::"ExecCommand",
    resource
) when {
    context.program == "curl"
};
"#,
        )
        .unwrap();

        let agy_opts = HookRunOptions {
            client: HookClient::Antigravity,
            mode: HookMode::Enforce,
            gateway_url: "http://127.0.0.1:4000".to_string(),
            state_dir: dir.clone(),
            bearer_token_env: "R5E_TOKEN".to_string(),
            bearer_token_file: None,
            cedar_policy: Some(cedar_path.clone()),
            spawn_drainer: false,
        };
        let agy_out = run_hook_invocation(
            r#"{"hookEventName":"PreToolUse","conversationId":"conv-2","toolCall":{"id":"c2","name":"run_command","args":{"CommandLine":"curl https://example.com"}}}"#,
            &agy_opts,
        );
        assert_eq!(agy_out["decision"], "deny");
        assert!(agy_out["reason"]
            .as_str()
            .unwrap()
            .contains("forbid rule(s): deny-curl"));

        let claude_opts = HookRunOptions {
            client: HookClient::ClaudeCode,
            ..agy_opts
        };
        let claude_out = run_hook_invocation(
            r#"{"hook_event_name":"PreToolUse","session_id":"conv-3","tool_name":"Bash","tool_use_id":"tu_1","tool_input":{"command":"curl https://example.com"}}"#,
            &claude_opts,
        );
        assert_eq!(claude_out["decision"], "block");
        assert!(claude_out["reason"]
            .as_str()
            .unwrap()
            .contains("forbid rule(s): deny-curl"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_hooks_merges_without_clobbering_existing_user_hooks() {
        let dir = temp_dir("install-merge");

        // Antigravity merge
        let agy_dir = dir.join("agy");
        fs::create_dir_all(&agy_dir).unwrap();
        fs::write(
            agy_dir.join("hooks.json"),
            r#"{"user-linter":{"enabled":true,"PostToolUse":[]}}"#,
        )
        .unwrap();
        let agy_path = install_hooks_config(&InstallHooksOptions {
            client: HookClient::Antigravity,
            mode: HookMode::Observe,
            gateway_url: "https://dev.r5e.io".to_string(),
            target_dir: agy_dir.clone(),
            helper_bin: PathBuf::from("/usr/local/bin/r5e-endpoint-helper"),
            state_dir: None,
            cedar_policy: None,
            bearer_token_file: None,
        })
        .unwrap();
        let agy_json: Value =
            serde_json::from_str(&fs::read_to_string(&agy_path).unwrap()).unwrap();
        assert!(agy_json.get("user-linter").is_some());
        assert_eq!(agy_json["r5e-observe"]["enabled"], true);

        // Claude Code merge
        let cc_dir = dir.join("claude");
        fs::create_dir_all(&cc_dir).unwrap();
        fs::write(
            cc_dir.join("settings.json"),
            r#"{"theme":"dark","hooks":{"PostToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"./my-hook.sh"}]}]}}"#,
        )
        .unwrap();
        let cc_path = install_hooks_config(&InstallHooksOptions {
            client: HookClient::ClaudeCode,
            mode: HookMode::Enforce,
            gateway_url: "https://dev.r5e.io".to_string(),
            target_dir: cc_dir.clone(),
            helper_bin: PathBuf::from("/usr/local/bin/r5e-endpoint-helper"),
            state_dir: None,
            cedar_policy: Some(PathBuf::from("/etc/r5e/policy.cedar")),
            bearer_token_file: None,
        })
        .unwrap();
        let cc_json: Value = serde_json::from_str(&fs::read_to_string(&cc_path).unwrap()).unwrap();
        assert_eq!(cc_json["theme"], "dark");
        let post_arr = cc_json["hooks"]["PostToolUse"].as_array().unwrap();
        assert_eq!(post_arr.len(), 2);
        assert!(cc_json["hooks"]["PreToolUse"].as_array().unwrap().len() == 1);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn enforce_mode_fails_closed_on_missing_policy_unreadable_file_invalid_cedar_and_malformed_stdin(
    ) {
        let dir = temp_dir("enforce-fail-closed");
        let pre_tool_payload = r#"{"hookEventName":"PreToolUse","conversationId":"conv-fc","toolCall":{"id":"c1","name":"run_command","args":{"CommandLine":"echo hi"}}}"#;

        // 1. Missing --cedar-policy -> deny (Antigravity) & block (Claude Code)
        let no_policy_opts = HookRunOptions {
            client: HookClient::Antigravity,
            mode: HookMode::Enforce,
            gateway_url: "http://127.0.0.1:4000".to_string(),
            state_dir: dir.clone(),
            bearer_token_env: "R5E_TOKEN".to_string(),
            bearer_token_file: None,
            cedar_policy: None,
            spawn_drainer: false,
        };
        let out_no_policy = run_hook_invocation(pre_tool_payload, &no_policy_opts);
        assert_eq!(out_no_policy["decision"], "deny");
        assert!(out_no_policy["reason"]
            .as_str()
            .unwrap()
            .contains("no_bundle"));

        // 2. Non-existent policy file -> deny
        let missing_file_opts = HookRunOptions {
            cedar_policy: Some(dir.join("does-not-exist.cedar")),
            ..no_policy_opts.clone()
        };
        let out_missing = run_hook_invocation(pre_tool_payload, &missing_file_opts);
        assert_eq!(out_missing["decision"], "deny");
        assert!(out_missing["reason"]
            .as_str()
            .unwrap()
            .contains("Policy unavailable"));

        // 3. Invalid Cedar syntax -> block (Claude Code)
        let bad_cedar = dir.join("broken.cedar");
        fs::write(&bad_cedar, "this is not valid cedar {{{{").unwrap();
        let bad_cedar_opts = HookRunOptions {
            client: HookClient::ClaudeCode,
            cedar_policy: Some(bad_cedar),
            ..no_policy_opts.clone()
        };
        let out_bad = run_hook_invocation(
            r#"{"hook_event_name":"PreToolUse","session_id":"conv-fc2","tool_name":"Bash","tool_input":{"command":"ls"}}"#,
            &bad_cedar_opts,
        );
        assert_eq!(out_bad["decision"], "block");
        assert!(out_bad["reason"]
            .as_str()
            .unwrap()
            .contains("Policy unavailable"));

        // 4. Malformed stdin JSON in enforce mode -> deny
        let out_malformed = run_hook_invocation("{broken", &no_policy_opts);
        assert_eq!(out_malformed["decision"], "deny");

        // 5. install-hooks --mode enforce without --cedar-policy -> refused
        let install_err = install_hooks_config(&InstallHooksOptions {
            client: HookClient::Antigravity,
            mode: HookMode::Enforce,
            gateway_url: "https://dev.r5e.io".to_string(),
            target_dir: dir.join("install"),
            helper_bin: PathBuf::from("/usr/local/bin/r5e-endpoint-helper"),
            state_dir: None,
            cedar_policy: None,
            bearer_token_file: None,
        })
        .unwrap_err();
        assert!(install_err.contains("--cedar-policy"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_captured_at_preserves_original_observed_at_when_clamped() {
        let (ts_unclamped, obs_unclamped) =
            resolve_captured_at("2026-11-23T06:00:05.000000Z", "2026-11-23T06:00:00Z");
        assert_eq!(ts_unclamped, "2026-11-23T06:00:05.000000Z");
        assert_eq!(obs_unclamped, None);

        let (ts_clamped, obs_clamped) =
            resolve_captured_at("2026-11-23T05:59:58.123456Z", "2099-01-01T00:00:00Z");
        assert_eq!(ts_clamped, "2099-01-01T00:00:00Z");
        assert_eq!(obs_clamped.as_deref(), Some("2026-11-23T05:59:58.123456Z"));
    }

    #[test]
    fn sanitize_conversation_id_hashes_path_like_inputs() {
        let hashed = sanitize_conversation_id(Some("/Users/alice/secret/project/../conv"));
        assert!(hashed.starts_with("conv-"));
        assert!(!hashed.contains("alice"));
        assert!(!hashed.contains('/'));
        assert!(!hashed.contains(".."));
        assert_eq!(
            sanitize_conversation_id(Some("conv_123-abc")),
            "conv_123-abc"
        );
    }

    #[test]
    fn redacts_broadened_secret_patterns_including_aws_stripe_slack_anthropic_userinfo_and_headers()
    {
        let input = json!({
            "anthropic": "sk-ant-api03-abcdefghijklmnop123456",
            "aws1": "AKIAIOSFODNN7EXAMPLE",
            "aws2": "ASIAIOSFODNN7EXAMPLE",
            "stripe": "sk_live_51abcdef1234567890 and rk_live_99abcdef1234567890",
            "slack": "xoxb-123456789012-abcdef and xoxp-987654321098-xyzabc",
            "google": "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGqe",
            "url": "https://alice:supersecretpass@db.example.com/app",
            "hdr": "Authorization: Basic dXNlcjpwYXNz\nCookie: session_id=topsecretcookie123",
            "pem": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC\n-----END PRIVATE KEY-----",
            "safe": "normal value"
        });
        let redacted = redact_json_value(&input, 0);
        let dumped = serde_json::to_string(&redacted).unwrap();
        for leaked in [
            "sk-ant-api03-abcdefghijklmnop123456",
            "AKIAIOSFODNN7EXAMPLE",
            "ASIAIOSFODNN7EXAMPLE",
            "sk_live_51abcdef1234567890",
            "rk_live_99abcdef1234567890",
            "xoxb-123456789012-abcdef",
            "xoxp-987654321098-xyzabc",
            "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGqe",
            "supersecretpass",
            "dXNlcjpwYXNz",
            "topsecretcookie123",
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC",
        ] {
            assert!(
                !dumped.contains(leaked),
                "secret leaked: {leaked} in {dumped}"
            );
        }
        assert!(dumped.contains("https://[REDACTED]@db.example.com/app"));
        assert_eq!(redacted["safe"], "normal value");
    }

    #[test]
    fn enforce_mode_closes_all_four_bypasses_empty_unknown_truncation_shell_and_codex_array() {
        let dir = temp_dir("enforce-4-bypasses");
        let cedar_path = dir.join("forbid.cedar");
        fs::write(
            &cedar_path,
            r#"
@id("permit-all-exec")
permit (
    principal,
    action == Recurse::Action::"ExecCommand",
    resource
);

@id("forbid-rm-or-secret-marker")
forbid (
    principal,
    action == Recurse::Action::"ExecCommand",
    resource
) when {
    context.program == "rm" ||
    context.program == "curl" ||
    context.command_line like "*FORBIDDEN_TAIL_MARKER*"
};
"#,
        )
        .unwrap();

        let opts = HookRunOptions {
            client: HookClient::Antigravity,
            mode: HookMode::Enforce,
            gateway_url: "http://127.0.0.1:4000".to_string(),
            state_dir: dir.clone(),
            bearer_token_env: "R5E_TOKEN".to_string(),
            bearer_token_file: None,
            cedar_policy: Some(cedar_path.clone()),
            spawn_drainer: false,
        };

        // Bypass 1a: Empty stdin -> denied
        let empty_out = run_hook_invocation("   ", &opts);
        assert_eq!(empty_out["decision"], "deny");
        assert_eq!(empty_out["reason"], "unrecognized_or_empty_hook_event");

        // Bypass 1b: Unrecognized event name -> denied (and block for Codex)
        let unknown_out = run_hook_invocation(
            r#"{"hookEventName":"SomeFutureEvent","conversationId":"c1"}"#,
            &opts,
        );
        assert_eq!(unknown_out["decision"], "deny");
        assert_eq!(unknown_out["reason"], "unrecognized_or_empty_hook_event");

        let codex_opts = HookRunOptions {
            client: HookClient::Codex,
            ..opts.clone()
        };
        let codex_unknown = run_hook_invocation(r#"{"event":"mystery_event"}"#, &codex_opts);
        assert_eq!(codex_unknown["decision"], "block");
        assert_eq!(codex_unknown["reason"], "unrecognized_or_empty_hook_event");

        // Bypass 2: Payload > 4096 bytes with forbidden marker past truncation point -> STILL denied!
        let long_cmd = format!("echo {} FORBIDDEN_TAIL_MARKER", "a".repeat(5000));
        let long_payload = json!({
            "hookEventName": "PreToolUse",
            "conversationId": "c-long",
            "toolCall": {
                "id": "tc-long",
                "name": "run_command",
                "args": {"CommandLine": long_cmd}
            }
        });
        let long_out = run_hook_invocation(&long_payload.to_string(), &opts);
        assert_eq!(
            long_out["decision"], "deny",
            "Cedar must evaluate pre-truncation command line"
        );
        assert!(long_out["reason"]
            .as_str()
            .unwrap()
            .contains("forbid-rm-or-secret-marker"));

        // Bypass 3a: Quoted `sh -c 'curl https://evil.example'` -> unwrapped and denied!
        let sh_payload = json!({
            "hookEventName": "PreToolUse",
            "conversationId": "c-sh",
            "toolCall": {
                "id": "tc-sh",
                "name": "run_command",
                "args": {"CommandLine": "sh -c 'curl https://evil.example'"}
            }
        });
        let sh_out = run_hook_invocation(&sh_payload.to_string(), &opts);
        assert_eq!(sh_out["decision"], "deny");
        assert!(sh_out["reason"]
            .as_str()
            .unwrap()
            .contains("forbid-rm-or-secret-marker"));

        // Bypass 3b: Codex array `command`: `["bash", "-lc", "rm -rf /tmp/demo"]` -> classified as ExecCommand and blocked!
        let codex_arr_payload = json!({
            "event": "PreToolUse",
            "session_id": "c-codex",
            "tool_name": "local_shell",
            "call_id": "cx-1",
            "arguments": {"command": ["bash", "-lc", "rm -rf /tmp/demo"]}
        });
        let codex_out = run_hook_invocation(&codex_arr_payload.to_string(), &codex_opts);
        assert_eq!(codex_out["decision"], "block");
        assert!(codex_out["reason"]
            .as_str()
            .unwrap()
            .contains("forbid-rm-or-secret-marker"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tool_result_permanent_reason_uses_closed_code_not_raw_error_text() {
        use crate::attestation::{
            decode_strict_base64, ed25519_key_id, CaptureProfile, EndpointBundleRecorder,
        };
        use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
        use base64::Engine;

        let seed = [7u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let key_id = ed25519_key_id(sk.verifying_key().as_bytes());
        let policy_ref =
            "bytes:sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .to_string();
        let profile = CaptureProfile {
            issuer_keys: vec![key_id.clone()],
            sealer_keys: vec![key_id.clone()],
            checkpoint_keys: Vec::new(),
            stream_prefix: "urn:r5e:stream:test:endpoint:1:".to_string(),
            actor_prefixes: vec!["urn:r5e:".to_string()],
            required_payloads: "submitted".to_string(),
            failure_domain: "managed-endpoint-local".to_string(),
            on_failure: "refuse".to_string(),
            deployment_policy_ref: Some(policy_ref.clone()),
            policy_required_kinds: Vec::new(),
            retention: None,
        };
        let mut recorder = EndpointBundleRecorder::new();
        let prof_ref = recorder.put_blob(b"{}", Some("application/json"));

        let mut state = EnrolledStateFile {
            format: "r5e.endpoint-enrolled-state/v1".to_string(),
            gateway_url: "http://127.0.0.1:4000".to_string(),
            workload_seed_b64: BASE64_STANDARD.encode(seed),
            subject_key_id: key_id,
            holder: "antigravity-hook".to_string(),
            workload: Some("urn:r5e:workload:antigravity-hook".to_string()),
            purpose: None,
            badge_ref:
                "evidence:sha256:2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
            stream_prefix: "urn:r5e:stream:test:endpoint:1:".to_string(),
            acts_for: Some("urn:r5e:principal:test:user".to_string()),
            actor_prefixes: vec!["urn:r5e:".to_string()],
            granted_kinds: DEFAULT_HOOK_WORKLOAD_KINDS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            not_before: "2026-01-01T00:00:00Z".to_string(),
            not_after: "2027-01-01T00:00:00Z".to_string(),
            local_profile_ref: prof_ref,
            deployment_policy_ref: policy_ref,
            retention: None,
            capture_profile: profile,
            session_urn: Some("urn:r5e:session:test:s1".to_string()),
            session_anchor_ref: None,
            recorder,
            shipped_record_refs: Vec::new(),
        };

        let ev = normalize_hook_payload(
            HookClient::Antigravity,
            HookMode::Observe,
            &json!({
                "hookEventName": "PostToolUse",
                "conversationId": "conv-err",
                "stepIdx": 3,
                "error": "sensitive stderr output from /Users/alice/private.txt",
                "toolCall": {"id": "tc-err", "name": "run_command", "args": {"CommandLine": "cat x"}}
            }),
        );
        append_queued_event_to_state(&mut state, &ev).expect("append PostToolUse");

        let tr_rec = state.recorder.records().last().expect("ToolResult record");
        let payload_bytes = decode_strict_base64(&tr_rec.envelope.payload).unwrap();
        let payload_val: Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload_val["kind"], "ToolResult");
        assert_eq!(payload_val["body"]["outcome"], "failed");
        assert_eq!(payload_val["body"]["reason"], "tool_error");
        let body_str = serde_json::to_string(&payload_val["body"]).unwrap();
        assert!(
            !body_str.contains("sensitive stderr"),
            "raw error text must never appear in permanent ToolResult.body: {body_str}"
        );
    }

    #[test]
    fn uninstall_hooks_removes_only_r5e_entries_and_preserves_user_hooks() {
        let dir = temp_dir("uninstall");
        let agy_dir = dir.join("agy");
        fs::create_dir_all(&agy_dir).unwrap();
        fs::write(
            agy_dir.join("hooks.json"),
            r#"{"user-linter":{"enabled":true,"PostToolUse":[]}}"#,
        )
        .unwrap();
        install_hooks_config(&InstallHooksOptions {
            client: HookClient::Antigravity,
            mode: HookMode::Observe,
            gateway_url: "https://dev.r5e.io".to_string(),
            target_dir: agy_dir.clone(),
            helper_bin: PathBuf::from("/usr/local/bin/r5e-endpoint-helper"),
            state_dir: None,
            cedar_policy: None,
            bearer_token_file: None,
        })
        .unwrap();

        let (cfg_path, removed) =
            uninstall_hooks_config(HookClient::Antigravity, &agy_dir).unwrap();
        assert!(removed);
        let after: Value = serde_json::from_str(&fs::read_to_string(&cfg_path).unwrap()).unwrap();
        assert!(after.get("user-linter").is_some());
        assert!(after.get("r5e-observe").is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_jsonl_lines_are_skipped_without_wedging_drain() {
        let dir = temp_dir("corrupt-jsonl");
        let sess_dir = dir.join("sessions/conv-corrupt");
        fs::create_dir_all(&sess_dir).unwrap();
        fs::write(
            sess_dir.join("events.jsonl"),
            "{this is corrupt json\nnot json either\n",
        )
        .unwrap();

        let opts = HookRunOptions {
            client: HookClient::Antigravity,
            mode: HookMode::Observe,
            gateway_url: "http://127.0.0.1:4000".to_string(),
            state_dir: dir.clone(),
            bearer_token_env: "R5E_TEST_CORRUPT_DRAIN_TOK".to_string(),
            bearer_token_file: None,
            cedar_policy: None,
            spawn_drainer: false,
        };
        std::env::set_var("R5E_TEST_CORRUPT_DRAIN_TOK", "dummy-token-for-corrupt-test");
        let res = drain_conversation("conv-corrupt", &opts);
        assert!(res.is_ok(), "corrupt JSONL should not fail drain: {res:?}");
        let cursor = fs::read_to_string(sess_dir.join("cursor.txt")).unwrap();
        assert_eq!(cursor.trim(), "2");

        let _ = fs::remove_dir_all(&dir);
    }
}
