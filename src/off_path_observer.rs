//! Off-path watched-harness session observer.
//!
//! When a developer runs a watched harness (`claude`, `codex`) directly against a personal
//! subscription or unrouted endpoint rather than through the organisation's gateway, this
//! module inspects the harness's local session JSONL metadata to emit a truthful
//! `observed_outside_path` coverage record—never claiming policy decided on those turns.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffPathSessionReport {
    pub harness: String,
    pub local_session_digest: String,
    pub turn_count: usize,
    pub tool_use_count: usize,
    pub distinct_tools: Vec<String>,
    /// Always `"observed_outside_path"` — never claims pre-execution gating.
    pub coverage_state: String,
    pub first_timestamp: Option<String>,
    pub last_timestamp: Option<String>,
}

/// Parses a watched harness's local JSONL transcript and summarizes off-path activity
/// without exporting prompt or reply text. Returns `None` if the transcript carries an
/// `r5e_gateway_routed: true` marker or has zero turns.
pub fn summarize_unrouted_harness_jsonl(
    harness: &str,
    session_key: &str,
    jsonl_text: &str,
) -> Option<OffPathSessionReport> {
    let mut turn_count = 0usize;
    let mut tool_use_count = 0usize;
    let mut tools = std::collections::BTreeSet::new();
    let mut first_ts: Option<String> = None;
    let mut last_ts: Option<String> = None;

    for line in jsonl_text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(entry) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };

        if entry
            .get("r5e_gateway_routed")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return None;
        }

        turn_count += 1;

        if let Some(ts) = entry.get("timestamp").and_then(Value::as_str) {
            if first_ts.is_none() {
                first_ts = Some(ts.to_string());
            }
            last_ts = Some(ts.to_string());
        }

        // Inspect Claude Code / Codex assistant content arrays or direct tool_call entries:
        if let Some(name) = entry.get("tool_name").and_then(Value::as_str) {
            tool_use_count += 1;
            tools.insert(name.to_string());
        }
        if let Some(blocks) = entry
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(Value::as_array)
        {
            for block in blocks {
                if block.get("type").and_then(Value::as_str) == Some("tool_use") {
                    tool_use_count += 1;
                    if let Some(name) = block.get("name").and_then(Value::as_str) {
                        tools.insert(name.to_string());
                    }
                }
            }
        }
    }

    if turn_count == 0 {
        return None;
    }

    let digest = Sha256::digest(format!("{harness}:{session_key}").as_bytes());
    Some(OffPathSessionReport {
        harness: harness.to_string(),
        local_session_digest: format!("sha256:{}", crate::policy_gate::hex_lower(&digest)),
        turn_count,
        tool_use_count,
        distinct_tools: tools.into_iter().collect(),
        coverage_state: "observed_outside_path".to_string(),
        first_timestamp: first_ts,
        last_timestamp: last_ts,
    })
}
