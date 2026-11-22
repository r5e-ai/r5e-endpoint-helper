//! Local MCP `stdio` JSON-RPC interceptor and descriptor-pinning guard.
//!
//! When an agent harness (Claude Code, Codex) spawns a local `stdio` MCP tool server on a
//! developer laptop, those JSON-RPC calls never cross the network gateway. This module
//! mediates the JSON-RPC stream in-process:
//!   1. Computes a canonical SHA-256 digest over `tools/list` descriptors and detects
//!      mid-session tool-description rug-pulls (`descriptor_changed`).
//!   2. Gates every `tools/call` request through `LocalCedarGate` BEFORE forwarding it to
//!      the child MCP server, synthesizing a clean MCP error result when withheld in
//!      `enforce` posture so the agent harness receives an actionable policy explanation.

use crate::attestation::{bytes_ref, encode_canonical_json};
use crate::policy_gate::{EnforcementOutcome, GateVerdict, LocalActionKind, LocalCedarGate};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescriptorObservation {
    pub descriptor_sha256: String,
    pub tool_names: Vec<String>,
    /// True if an earlier `tools/list` in the same session pinned a different digest!
    pub rug_pull_detected: bool,
    /// Canonical JSON bytes (`VERIFY-V2` §2.1) of the sorted `(name, description, inputSchema)`
    /// descriptor array that hashed to `descriptor_sha256`.
    #[serde(default, skip_serializing)]
    pub canonical_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct McpStdioSessionGuard {
    server_id: String,
    pinned_descriptor_sha256: Option<String>,
    latest_descriptor_sha256: Option<String>,
    block_on_rug_pull: bool,
    rug_pull_latched: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClientFrameDisposition {
    /// Non-`tools/call` JSON-RPC frame or allowed `tools/call`; forward bytes to MCP child.
    Forward {
        verdict: Option<GateVerdict>,
        tool_name: Option<String>,
    },
    /// Withheld in `enforce` posture, or blocked due to an unapproved MCP rug-pull; return
    /// `synthetic_response` directly to the harness without touching the child MCP server!
    InterceptWithResponse {
        verdict: GateVerdict,
        tool_name: String,
        synthetic_response: Value,
    },
}

/// Canonicalizes `params.arguments` (defaulting to `{}` when absent or `null`) using Provenance v2
/// canonical JSON encoding (`VERIFY-V2` §2.1) and returns `(bytes:sha256:<hex>, canonical_bytes)`.
pub fn canonical_tool_arguments_digest(frame: &Value) -> Result<(String, Vec<u8>), String> {
    let args_val = frame
        .get("params")
        .and_then(|p| p.get("arguments"))
        .filter(|v| !v.is_null())
        .cloned()
        .unwrap_or_else(|| json!({}));
    let canonical = encode_canonical_json(&args_val)?;
    Ok((bytes_ref(&canonical), canonical))
}

impl McpStdioSessionGuard {
    pub fn new(server_id: impl Into<String>) -> Self {
        Self::with_rug_pull_quarantine(server_id, false)
    }

    pub fn with_rug_pull_quarantine(server_id: impl Into<String>, block_on_rug_pull: bool) -> Self {
        Self {
            server_id: server_id.into(),
            pinned_descriptor_sha256: None,
            latest_descriptor_sha256: None,
            block_on_rug_pull,
            rug_pull_latched: false,
        }
    }

    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    pub fn set_block_on_rug_pull(&mut self, block_on_rug_pull: bool) {
        self.block_on_rug_pull = block_on_rug_pull;
    }

    pub fn block_on_rug_pull(&self) -> bool {
        self.block_on_rug_pull
    }

    pub fn is_rug_pull_latched(&self) -> bool {
        self.rug_pull_latched
    }

    pub fn pinned_descriptor_sha256(&self) -> Option<&str> {
        self.pinned_descriptor_sha256.as_deref()
    }

    pub fn latest_descriptor_sha256(&self) -> Option<&str> {
        self.latest_descriptor_sha256.as_deref()
    }

    /// Inspects a JSON-RPC response from the child MCP server; if it contains a `tools`
    /// array (`tools/list` result), computes a deterministic SHA-256 over Provenance v2
    /// canonical JSON (`VERIFY-V2` §2.1) of sorted `(name, description, inputSchema)` entries
    /// and checks for mid-session descriptor mutation.
    pub fn observe_server_response(&mut self, frame: &Value) -> Option<DescriptorObservation> {
        let tools = frame.get("result")?.get("tools")?.as_array()?;

        let mut normalized: Vec<Value> = tools
            .iter()
            .map(|t| {
                json!({
                    "name": t.get("name").cloned().unwrap_or(Value::Null),
                    "description": t.get("description").cloned().unwrap_or(Value::Null),
                    "inputSchema": t.get("inputSchema").cloned().unwrap_or(Value::Null),
                })
            })
            .collect();

        normalized.sort_by(|a, b| {
            let na = a.get("name").and_then(Value::as_str).unwrap_or("");
            let nb = b.get("name").and_then(Value::as_str).unwrap_or("");
            na.cmp(nb)
        });

        let tool_names: Vec<String> = normalized
            .iter()
            .filter_map(|t| t.get("name").and_then(Value::as_str).map(str::to_string))
            .collect();

        let canonical_bytes = encode_canonical_json(&Value::Array(normalized)).ok()?;
        let digest = bytes_ref(&canonical_bytes);
        self.latest_descriptor_sha256 = Some(digest.clone());

        let rug_pull_detected = match &self.pinned_descriptor_sha256 {
            None => {
                self.pinned_descriptor_sha256 = Some(digest.clone());
                false
            }
            Some(prev) => prev != &digest,
        };
        if rug_pull_detected {
            self.rug_pull_latched = true;
        }

        Some(DescriptorObservation {
            descriptor_sha256: digest,
            tool_names,
            rug_pull_detected,
            canonical_bytes,
        })
    }

    /// Evaluates an outbound JSON-RPC request from the harness before it reaches the
    /// local MCP server.
    ///
    /// When `block_on_rug_pull` is enabled and an earlier `tools/list` response mutated the
    /// pinned descriptor digest (`rug_pull_latched == true`), ALL subsequent `tools/call`
    /// requests are quarantined (`InterceptWithResponse`, `EnforcementOutcome::Prevented`)
    /// before touching the mutated MCP server.
    pub fn inspect_client_request(
        &self,
        frame: &Value,
        agent_id: &str,
        session_urn: &str,
        gate: &LocalCedarGate,
    ) -> Result<ClientFrameDisposition, String> {
        let method = frame.get("method").and_then(Value::as_str).unwrap_or("");
        if method != "tools/call" {
            return Ok(ClientFrameDisposition::Forward {
                verdict: None,
                tool_name: None,
            });
        }

        let tool_name = frame
            .get("params")
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(|| "MCP tools/call missing params.name".to_string())?
            .to_string();

        if self.block_on_rug_pull && self.rug_pull_latched {
            let req_id = frame.get("id").cloned().unwrap_or(Value::Null);
            let pinned = self
                .pinned_descriptor_sha256
                .as_deref()
                .unwrap_or("unpinned");
            let mutated = self
                .latest_descriptor_sha256
                .as_deref()
                .unwrap_or("unknown");
            let msg = format!(
                "Blocked on endpoint by MCP rug-pull quarantine for server '{}': tools/list descriptor mutated mid-session from {} to {}. Do not invoke tools on this server until restarted and re-verified.",
                self.server_id, pinned, mutated
            );
            let verdict = GateVerdict {
                allowed_to_execute: false,
                cedar_decision: "deny".to_string(),
                outcome: EnforcementOutcome::Prevented,
                policy_bundle_ref: gate.policy_bundle_ref().to_string(),
                matching_policy_ids: vec!["mcp-rug-pull-quarantine".to_string()],
                offline_mode: gate.offline_mode(),
                agent_message: Some(msg.clone()),
            };
            let synthetic_response = json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "isError": true,
                    "content": [
                        {
                            "type": "text",
                            "text": msg
                        }
                    ]
                }
            });
            return Ok(ClientFrameDisposition::InterceptWithResponse {
                verdict,
                tool_name,
                synthetic_response,
            });
        }

        let (arguments_sha256, _) = canonical_tool_arguments_digest(frame)?;

        let action = LocalActionKind::McpToolCall {
            server_id: self.server_id.clone(),
            tool_name: tool_name.clone(),
            descriptor_sha256: self.pinned_descriptor_sha256.clone(),
            arguments_sha256: Some(arguments_sha256),
        };

        let verdict = gate.evaluate(agent_id, session_urn, &action)?;
        if verdict.allowed_to_execute {
            Ok(ClientFrameDisposition::Forward {
                verdict: Some(verdict),
                tool_name: Some(tool_name),
            })
        } else {
            let req_id = frame.get("id").cloned().unwrap_or(Value::Null);
            let msg = verdict
                .agent_message
                .clone()
                .unwrap_or_else(|| "Tool call blocked by endpoint policy".to_string());
            let synthetic_response = json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "isError": true,
                    "content": [
                        {
                            "type": "text",
                            "text": msg
                        }
                    ]
                }
            });
            Ok(ClientFrameDisposition::InterceptWithResponse {
                verdict,
                tool_name,
                synthetic_response,
            })
        }
    }
}
