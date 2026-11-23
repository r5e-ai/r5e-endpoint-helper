//! Local Cedar policy evaluation gate.
//!
//! Runs the exact `cedar-policy = "=4.9.1"` engine used by the R5E Gateway directly on
//! the managed endpoint so local shell commands and local `stdio` MCP tool calls can be
//! decided synchronously (even while the laptop is offline) and reported truthfully as
//! `prevented` vs `observed`.

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, RestrictedExpression,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Posture {
    /// Never blocks execution; records what happened and whether policy would have withheld it.
    Observe,
    /// Synchronously stops withheld local commands/tools before they execute.
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementOutcome {
    /// Policy permitted the action and it proceeded.
    Allowed,
    /// Policy withheld the action, and in `enforce` posture the helper stopped it before running.
    Prevented,
    /// Policy withheld the action, and in `observe` posture the helper allowed it and recorded the bypass.
    ObservedWouldWithhold,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateVerdict {
    pub allowed_to_execute: bool,
    pub cedar_decision: String,
    pub outcome: EnforcementOutcome,
    pub policy_bundle_ref: String,
    pub matching_policy_ids: Vec<String>,
    pub offline_mode: bool,
    pub agent_message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LocalCedarGate {
    policies: PolicySet,
    policy_bundle_ref: String,
    posture: Posture,
    offline_mode: bool,
    policy_labels: HashMap<String, String>,
    duplicate_id_warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalActionKind {
    /// A child shell or binary command started by a watched harness (`bash -c ...`, `git push ...`).
    ExecCommand {
        program: String,
        argv: Vec<String>,
        command_line: String,
    },
    /// A local `stdio` MCP tool invocation that never traverses the network gateway.
    McpToolCall {
        server_id: String,
        tool_name: String,
        descriptor_sha256: Option<String>,
        arguments_sha256: Option<String>,
    },
}

impl LocalCedarGate {
    pub fn from_cedar_src(
        cedar_src: &str,
        posture: Posture,
        offline_mode: bool,
    ) -> Result<Self, String> {
        let policies = PolicySet::from_str(cedar_src)
            .map_err(|err| format!("invalid Cedar policy bundle: {err}"))?;
        let digest = Sha256::digest(cedar_src.as_bytes());
        let policy_bundle_ref = format!("bytes:sha256:{}", hex_lower(&digest));

        let mut annotation_counts: HashMap<String, usize> = HashMap::new();
        for policy in policies.policies() {
            if let Some(ann) = policy
                .annotation("id")
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                *annotation_counts.entry(ann.to_string()).or_insert(0) += 1;
            }
        }

        let mut policy_labels = HashMap::new();
        let mut duplicate_id_warnings = Vec::new();
        for policy in policies.policies() {
            let pid = policy.id().to_string();
            let label = match policy
                .annotation("id")
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                Some(ann) if annotation_counts.get(ann).copied().unwrap_or(0) > 1 => {
                    let disambiguated = format!("{ann}#{pid}");
                    let warning = format!(
                        "duplicate Cedar @id({ann:?}) on {pid}; disambiguating as {disambiguated}"
                    );
                    eprintln!("r5e-endpoint-helper: warning: {warning}");
                    duplicate_id_warnings.push(warning);
                    disambiguated
                }
                Some(ann) => ann.to_string(),
                None => pid.clone(),
            };
            policy_labels.insert(pid, label);
        }
        duplicate_id_warnings.sort();

        Ok(Self {
            policies,
            policy_bundle_ref,
            posture,
            offline_mode,
            policy_labels,
            duplicate_id_warnings,
        })
    }

    pub fn duplicate_id_warnings(&self) -> &[String] {
        &self.duplicate_id_warnings
    }

    pub fn policy_bundle_ref(&self) -> &str {
        &self.policy_bundle_ref
    }

    pub fn posture(&self) -> Posture {
        self.posture
    }

    pub fn offline_mode(&self) -> bool {
        self.offline_mode
    }

    /// Evaluates a local action initiated by `agent_id` inside `session_urn`.
    pub fn evaluate(
        &self,
        agent_id: &str,
        session_urn: &str,
        action: &LocalActionKind,
    ) -> Result<GateVerdict, String> {
        let principal = EntityUid::from_type_name_and_id(
            "Recurse::Agent".parse().map_err(|e| format!("{e}"))?,
            agent_id.parse().map_err(|e| format!("{e}"))?,
        );

        let (action_uid, resource_uid, ctx_fields) = match action {
            LocalActionKind::ExecCommand {
                program,
                argv,
                command_line,
            } => {
                let act = EntityUid::from_type_name_and_id(
                    "Recurse::Action".parse().map_err(|e| format!("{e}"))?,
                    "ExecCommand".parse().map_err(|e| format!("{e}"))?,
                );
                let res = EntityUid::from_type_name_and_id(
                    "Recurse::Resource".parse().map_err(|e| format!("{e}"))?,
                    program.parse().map_err(|e| format!("{e}"))?,
                );
                let mut map = HashMap::new();
                map.insert(
                    "program".to_string(),
                    RestrictedExpression::new_string(program.clone()),
                );
                map.insert(
                    "command_line".to_string(),
                    RestrictedExpression::new_string(command_line.clone()),
                );
                map.insert(
                    "session".to_string(),
                    RestrictedExpression::new_string(session_urn.to_string()),
                );
                map.insert(
                    "argc".to_string(),
                    RestrictedExpression::new_long(argv.len() as i64),
                );
                (act, res, map)
            }
            LocalActionKind::McpToolCall {
                server_id,
                tool_name,
                descriptor_sha256,
                arguments_sha256,
            } => {
                let act = EntityUid::from_type_name_and_id(
                    "Recurse::Action".parse().map_err(|e| format!("{e}"))?,
                    "InvokeMcpTool".parse().map_err(|e| format!("{e}"))?,
                );
                let res_id = format!("{server_id}:{tool_name}");
                let res = EntityUid::from_type_name_and_id(
                    "Recurse::McpTool".parse().map_err(|e| format!("{e}"))?,
                    res_id.parse().map_err(|e| format!("{e}"))?,
                );
                let mut map = HashMap::new();
                map.insert(
                    "server_id".to_string(),
                    RestrictedExpression::new_string(server_id.clone()),
                );
                map.insert(
                    "tool_name".to_string(),
                    RestrictedExpression::new_string(tool_name.clone()),
                );
                map.insert(
                    "session".to_string(),
                    RestrictedExpression::new_string(session_urn.to_string()),
                );
                if let Some(pin) = descriptor_sha256 {
                    map.insert(
                        "descriptor_sha256".to_string(),
                        RestrictedExpression::new_string(pin.clone()),
                    );
                }
                if let Some(args_digest) = arguments_sha256 {
                    map.insert(
                        "arguments_sha256".to_string(),
                        RestrictedExpression::new_string(args_digest.clone()),
                    );
                }
                (act, res, map)
            }
        };

        let context = Context::from_pairs(ctx_fields)
            .map_err(|err| format!("failed to construct Cedar context: {err}"))?;
        let request = Request::new(principal, action_uid, resource_uid, context, None)
            .map_err(|err| format!("invalid Cedar request: {err}"))?;
        let entities = Entities::empty();
        let authorizer = Authorizer::new();
        let response = authorizer.is_authorized(&request, &self.policies, &entities);

        let eval_errors: Vec<String> = response
            .diagnostics()
            .errors()
            .map(ToString::to_string)
            .collect();
        if !eval_errors.is_empty() && self.posture == Posture::Enforce {
            return Ok(GateVerdict {
                allowed_to_execute: false,
                cedar_decision: "deny".to_string(),
                outcome: EnforcementOutcome::Prevented,
                policy_bundle_ref: self.policy_bundle_ref.clone(),
                matching_policy_ids: vec!["cedar_eval_error".to_string()],
                offline_mode: self.offline_mode,
                agent_message: Some(format!(
                    "Blocked on endpoint by organisation policy ({}) — cedar_eval_error: {}",
                    self.policy_bundle_ref,
                    eval_errors.join("; ")
                )),
            });
        }

        let mut matching_ids: Vec<String> = response
            .diagnostics()
            .reason()
            .map(|id| {
                let pid = id.to_string();
                self.policy_labels.get(&pid).cloned().unwrap_or(pid)
            })
            .collect();
        matching_ids.sort();

        match (response.decision(), self.posture) {
            (Decision::Allow, _) => Ok(GateVerdict {
                allowed_to_execute: true,
                cedar_decision: "allow".to_string(),
                outcome: EnforcementOutcome::Allowed,
                policy_bundle_ref: self.policy_bundle_ref.clone(),
                matching_policy_ids: matching_ids,
                offline_mode: self.offline_mode,
                agent_message: None,
            }),
            (Decision::Deny, Posture::Enforce) => {
                let rule_note = if matching_ids.is_empty() {
                    "default-deny (no permit rule matched)".to_string()
                } else {
                    format!("forbid rule(s): {}", matching_ids.join(", "))
                };
                Ok(GateVerdict {
                    allowed_to_execute: false,
                    cedar_decision: "deny".to_string(),
                    outcome: EnforcementOutcome::Prevented,
                    policy_bundle_ref: self.policy_bundle_ref.clone(),
                    matching_policy_ids: matching_ids,
                    offline_mode: self.offline_mode,
                    agent_message: Some(format!(
                        "Blocked on endpoint by organisation policy ({}) — {}. Do not attempt to work around this restriction via another local script.",
                        self.policy_bundle_ref, rule_note
                    )),
                })
            }
            (Decision::Deny, Posture::Observe) => Ok(GateVerdict {
                allowed_to_execute: true,
                cedar_decision: "deny".to_string(),
                outcome: EnforcementOutcome::ObservedWouldWithhold,
                policy_bundle_ref: self.policy_bundle_ref.clone(),
                matching_policy_ids: matching_ids,
                offline_mode: self.offline_mode,
                agent_message: None,
            }),
        }
    }
}

pub fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cedar_id_annotation_replaces_positional_policy_id_in_verdict_and_reason() {
        let cedar = r#"
@id("allow-spec-tools")
permit (
    principal,
    action == Recurse::Action::"ExecCommand",
    resource
) when {
    context.program == "wc"
};

@id("deny-secret-or-external-network")
forbid (
    principal,
    action == Recurse::Action::"ExecCommand",
    resource
) when {
    context.program == "curl"
};
"#;
        let gate = LocalCedarGate::from_cedar_src(cedar, Posture::Enforce, false)
            .expect("valid cedar policy");

        let allow = gate
            .evaluate(
                "agent-1",
                "urn:r5e:session:test:1",
                &LocalActionKind::ExecCommand {
                    program: "wc".to_string(),
                    argv: vec!["-l".to_string(), "README.md".to_string()],
                    command_line: "wc -l README.md".to_string(),
                },
            )
            .expect("evaluate allow");
        assert!(allow.allowed_to_execute);
        assert_eq!(allow.matching_policy_ids, vec!["allow-spec-tools"]);

        let deny = gate
            .evaluate(
                "agent-1",
                "urn:r5e:session:test:1",
                &LocalActionKind::ExecCommand {
                    program: "curl".to_string(),
                    argv: vec!["https://example.com".to_string()],
                    command_line: "curl https://example.com".to_string(),
                },
            )
            .expect("evaluate deny");
        assert!(!deny.allowed_to_execute);
        assert_eq!(
            deny.matching_policy_ids,
            vec!["deny-secret-or-external-network"]
        );
        let msg = deny.agent_message.expect("deny agent_message");
        assert!(
            msg.contains("forbid rule(s): deny-secret-or-external-network"),
            "unexpected deny message: {msg}"
        );
        assert!(
            !msg.contains("policy1"),
            "positional policy id leaked into deny message: {msg}"
        );
    }

    #[test]
    fn cedar_missing_or_blank_id_annotation_falls_back_to_positional_policy_id() {
        let cedar = r#"
permit (
    principal,
    action == Recurse::Action::"ExecCommand",
    resource
) when {
    context.program == "echo"
};

@id("   ")
forbid (
    principal,
    action == Recurse::Action::"ExecCommand",
    resource
) when {
    context.program == "rm"
};
"#;
        let gate = LocalCedarGate::from_cedar_src(cedar, Posture::Enforce, false)
            .expect("valid cedar policy");

        let allow = gate
            .evaluate(
                "agent-1",
                "urn:r5e:session:test:1",
                &LocalActionKind::ExecCommand {
                    program: "echo".to_string(),
                    argv: vec!["hi".to_string()],
                    command_line: "echo hi".to_string(),
                },
            )
            .expect("evaluate allow");
        assert_eq!(allow.matching_policy_ids, vec!["policy0"]);

        let deny = gate
            .evaluate(
                "agent-1",
                "urn:r5e:session:test:1",
                &LocalActionKind::ExecCommand {
                    program: "rm".to_string(),
                    argv: vec!["-rf".to_string(), "/tmp/x".to_string()],
                    command_line: "rm -rf /tmp/x".to_string(),
                },
            )
            .expect("evaluate deny");
        assert_eq!(deny.matching_policy_ids, vec!["policy1"]);
        let msg = deny.agent_message.expect("deny agent_message");
        assert!(msg.contains("forbid rule(s): policy1"));
    }

    #[test]
    fn duplicate_cedar_id_annotations_are_disambiguated_with_policy_id_and_warn() {
        let cedar = r#"
@id("deny-dangerous")
forbid (
    principal,
    action == Recurse::Action::"ExecCommand",
    resource
) when {
    context.program == "rm"
};

@id("deny-dangerous")
forbid (
    principal,
    action == Recurse::Action::"ExecCommand",
    resource
) when {
    context.command_line like "*-rf*"
};
"#;
        let gate = LocalCedarGate::from_cedar_src(cedar, Posture::Enforce, false)
            .expect("valid cedar policy");
        assert_eq!(gate.duplicate_id_warnings().len(), 2);
        assert!(gate.duplicate_id_warnings()[0].contains("deny-dangerous#policy0"));
        assert!(gate.duplicate_id_warnings()[1].contains("deny-dangerous#policy1"));

        let deny = gate
            .evaluate(
                "agent-1",
                "urn:r5e:session:test:1",
                &LocalActionKind::ExecCommand {
                    program: "rm".to_string(),
                    argv: vec!["-rf".to_string(), "/tmp/x".to_string()],
                    command_line: "rm -rf /tmp/x".to_string(),
                },
            )
            .expect("evaluate deny");
        assert_eq!(
            deny.matching_policy_ids,
            vec!["deny-dangerous#policy0", "deny-dangerous#policy1"]
        );
        let msg = deny.agent_message.expect("deny agent_message");
        assert!(
            msg.contains("forbid rule(s): deny-dangerous#policy0, deny-dangerous#policy1"),
            "unexpected deny message: {msg}"
        );
    }

    #[test]
    fn cedar_evaluation_error_in_forbid_rule_fails_closed_as_deny_in_enforce_mode() {
        let cedar = r#"
@id("permit-echo")
permit (
    principal,
    action == Recurse::Action::"ExecCommand",
    resource
) when {
    context.program == "echo"
};

@id("forbid-with-eval-error")
forbid (
    principal,
    action == Recurse::Action::"ExecCommand",
    resource
) when {
    context.nonexistent_attr == "secret"
};
"#;
        let gate = LocalCedarGate::from_cedar_src(cedar, Posture::Enforce, false)
            .expect("valid cedar syntax");
        let verdict = gate
            .evaluate(
                "agent-1",
                "urn:r5e:session:test:1",
                &LocalActionKind::ExecCommand {
                    program: "echo".to_string(),
                    argv: vec!["hi".to_string()],
                    command_line: "echo hi".to_string(),
                },
            )
            .expect("evaluate");
        assert!(
            !verdict.allowed_to_execute,
            "errored forbid rule must fail closed as deny in enforce mode"
        );
        assert_eq!(verdict.cedar_decision, "deny");
        assert_eq!(verdict.outcome, EnforcementOutcome::Prevented);
        assert_eq!(verdict.matching_policy_ids, vec!["cedar_eval_error"]);
        assert!(verdict
            .agent_message
            .as_deref()
            .unwrap_or_default()
            .contains("cedar_eval_error"));
    }
}
