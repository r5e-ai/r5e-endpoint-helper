//! Zero-login on-device disclosure and privacy boundary.
//!
//! Ensures any person on a managed laptop can inspect—offline and without signing in—who
//! installed the helper, which specific agent harnesses it watches, what fields leave the
//! machine, what it never touches, and the recent records actually emitted.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Immutable statement of what the endpoint helper never inspects.
pub const NEVER_COLLECTED: &[&str] = &[
    "Browser tabs, cookies, history, or web sessions",
    "Email, chat clients, or calendar applications",
    "Unrelated terminal shells not started by or running a watched harness",
    "Files on disk not read or written by a watched harness session",
    "Keystrokes outside watched harness processes",
];

/// Honest boundary statement required by Journey 02 Stories 2, 3, and 5.
pub const SUPERVISION_BOUNDARY_STATEMENT: &str =
    "Prevents or records local commands and local MCP tool calls started by watched harnesses \
     under the cached organisation policy. Holds for a managed machine whose local administrator \
     is not working against the helper; not hostile-root confinement.";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmittedSummaryItem {
    pub captured_at: String,
    pub session: String,
    pub kind: String,
    pub summary: String,
    pub effect: String,
    pub record_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HelperDisclosure {
    pub deployed_by: String,
    pub deployed_at: String,
    pub policy_bundle_ref: String,
    pub posture: String,
    pub watched_harnesses: Vec<String>,
    pub collected_fields: Vec<String>,
    pub never_collected: Vec<String>,
    pub retention_summary: String,
    pub authorized_readers: Vec<String>,
    pub self_record_url: String,
    pub supervision_boundary: String,
    pub recent_sent_items: Vec<EmittedSummaryItem>,
}

/// Bounded in-memory ring buffer of the most recent items emitted from this laptop,
/// backing the user-visible "last things sent" disclosure view.
#[derive(Debug, Clone)]
pub struct DisclosureLedger {
    max_entries: usize,
    items: VecDeque<EmittedSummaryItem>,
}

impl DisclosureLedger {
    pub fn new(max_entries: usize) -> Self {
        Self {
            max_entries: max_entries.max(1),
            items: VecDeque::new(),
        }
    }

    pub fn record(&mut self, item: EmittedSummaryItem) {
        if self.items.len() >= self.max_entries {
            self.items.pop_front();
        }
        self.items.push_back(item);
    }

    pub fn recent(&self) -> Vec<EmittedSummaryItem> {
        self.items.iter().cloned().collect()
    }
}

impl HelperDisclosure {
    /// Renders a plain-language terminal/menu-bar disclosure readable without network or login.
    pub fn render_plain_text(&self) -> String {
        let mut out = String::new();
        out.push_str("R5E Endpoint Helper — On-Device Disclosure (Offline)\n");
        out.push_str("====================================================\n");
        out.push_str(&format!(
            "Installed by: {} on {}\n",
            self.deployed_by, self.deployed_at
        ));
        out.push_str(&format!(
            "Active posture: {} (policy {})\n",
            self.posture, self.policy_bundle_ref
        ));
        out.push_str(&format!(
            "Watched harnesses ONLY: {}\n\n",
            self.watched_harnesses.join(", ")
        ));
        out.push_str("What is sent to your organisation:\n");
        for item in &self.collected_fields {
            out.push_str(&format!("  - {item}\n"));
        }
        out.push_str("\nWhat is NEVER read or collected:\n");
        for item in &self.never_collected {
            out.push_str(&format!("  - {item}\n"));
        }
        out.push_str(&format!(
            "\nRetention & access: {}\nAuthorized readers: {}\nYour own session record: {}\n",
            self.retention_summary,
            self.authorized_readers.join(", "),
            self.self_record_url
        ));
        out.push_str(&format!("\nBoundary: {}\n", self.supervision_boundary));
        out.push_str(&format!(
            "\nLast {} item(s) emitted from this device:\n",
            self.recent_sent_items.len()
        ));
        for entry in &self.recent_sent_items {
            out.push_str(&format!(
                "  [{}] {} ({}) — {} [{}]\n",
                entry.captured_at, entry.kind, entry.effect, entry.summary, entry.record_ref
            ));
        }
        out
    }
}
