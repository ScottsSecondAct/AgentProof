//! Audit log — immutable record of every policy evaluation.
//!
//! Every call to [`PolicyEngine::evaluate`] can optionally produce an
//! [`AuditEntry`] that gets appended to the log. This provides the
//! compliance trail that enterprise customers need.
//!
//! The log supports:
//! - In-memory ring buffer (for development/testing)
//! - JSON Lines file output (for production)
//! - Structured queries over the log

use std::collections::VecDeque;
use std::io::Write;

use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

use crate::engine::PolicyResult;
use crate::event::Event;

/// A single audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique entry ID (monotonically increasing)
    pub id: u64,
    /// Timestamp (milliseconds since epoch)
    pub timestamp_ms: u64,
    /// Policy that was evaluated
    pub policy_name: SmolStr,
    /// The event that triggered evaluation
    pub event_type: SmolStr,
    /// Final verdict
    pub verdict: SmolStr,
    /// Reason for the verdict (if any)
    pub reason: Option<String>,
    /// Rule IDs that triggered
    pub triggered_rules: Vec<u32>,
    /// Number of invariant violations
    pub violation_count: usize,
    /// Violation details
    pub violations: Vec<ViolationEntry>,
    /// Constraint violation details
    pub constraint_violations: Vec<ConstraintViolationEntry>,
    /// Evaluation latency in microseconds
    pub eval_time_us: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViolationEntry {
    pub proof_name: SmolStr,
    pub invariant_name: SmolStr,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintViolationEntry {
    pub kind: SmolStr,
    pub target: SmolStr,
    pub limit: u64,
    pub current: u64,
}

impl AuditEntry {
    pub fn from_result(id: u64, policy_name: &str, event: &Event, result: &PolicyResult) -> Self {
        Self {
            id,
            timestamp_ms: event.timestamp_ms,
            policy_name: SmolStr::new(policy_name),
            event_type: event.event_type.clone(),
            verdict: SmolStr::new(format!("{:?}", result.verdict)),
            reason: result.reason.clone(),
            triggered_rules: result.triggered_rules.clone(),
            violation_count: result.violations.len(),
            violations: result
                .violations
                .iter()
                .map(|v| ViolationEntry {
                    proof_name: v.proof_name.clone(),
                    invariant_name: v.invariant_name.clone(),
                    message: v.message.clone(),
                })
                .collect(),
            constraint_violations: result
                .constraint_violations
                .iter()
                .map(|cv| ConstraintViolationEntry {
                    kind: SmolStr::new(format!("{:?}", cv.kind)),
                    target: cv.target.clone(),
                    limit: cv.limit,
                    current: cv.current,
                })
                .collect(),
            eval_time_us: result.eval_time_us,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Audit log — append-only storage
// ═══════════════════════════════════════════════════════════════════════

/// An append-only audit log.
pub struct AuditLog {
    /// In-memory ring buffer
    entries: VecDeque<AuditEntry>,
    /// Maximum entries to keep in memory
    max_entries: usize,
    /// Next entry ID
    next_id: u64,
    /// Optional file writer for persistent logging
    file_writer: Option<Box<dyn Write + Send>>,
}

impl AuditLog {
    /// Create an in-memory audit log with a maximum size.
    pub fn in_memory(max_entries: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(max_entries.min(10_000)),
            max_entries,
            next_id: 0,
            file_writer: None,
        }
    }

    /// Create an audit log that also writes to a JSON Lines file.
    pub fn with_file(max_entries: usize, writer: Box<dyn Write + Send>) -> Self {
        Self {
            entries: VecDeque::with_capacity(max_entries.min(10_000)),
            max_entries,
            next_id: 0,
            file_writer: Some(writer),
        }
    }

    /// Record a policy evaluation result.
    pub fn record(&mut self, policy_name: &str, event: &Event, result: &PolicyResult) -> u64 {
        let id = self.next_id;
        self.next_id += 1;

        let entry = AuditEntry::from_result(id, policy_name, event, result);

        // Write to file if configured
        if let Some(ref mut writer) = self.file_writer {
            if let Ok(json) = serde_json::to_string(&entry) {
                let _ = writeln!(writer, "{json}");
                let _ = writer.flush();
            }
        }

        // Add to ring buffer
        if self.entries.len() >= self.max_entries {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);

        id
    }

    /// Get the total number of entries recorded (including evicted ones).
    pub fn total_recorded(&self) -> u64 {
        self.next_id
    }

    /// Get the number of entries currently in the buffer.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get the most recent N entries.
    pub fn recent(&self, n: usize) -> Vec<&AuditEntry> {
        self.entries.iter().rev().take(n).collect()
    }

    /// Get all entries with a specific verdict.
    pub fn by_verdict(&self, verdict: &str) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.verdict == verdict)
            .collect()
    }

    /// Get all entries with violations.
    pub fn with_violations(&self) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.violation_count > 0)
            .collect()
    }

    /// Get all entries for a specific event type.
    pub fn by_event_type(&self, event_type: &str) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.event_type == event_type)
            .collect()
    }

    /// Compute summary statistics.
    pub fn stats(&self) -> AuditStats {
        let total = self.entries.len();
        let allows = self.entries.iter().filter(|e| e.verdict == "Allow").count();
        let denies = self.entries.iter().filter(|e| e.verdict == "Deny").count();
        let audits = self.entries.iter().filter(|e| e.verdict == "Audit").count();
        let redacts = self
            .entries
            .iter()
            .filter(|e| e.verdict == "Redact")
            .count();
        let violations = self
            .entries
            .iter()
            .filter(|e| e.violation_count > 0)
            .count();
        let avg_eval_us = if total > 0 {
            self.entries.iter().map(|e| e.eval_time_us).sum::<u64>() / total as u64
        } else {
            0
        };
        let max_eval_us = self
            .entries
            .iter()
            .map(|e| e.eval_time_us)
            .max()
            .unwrap_or(0);

        AuditStats {
            total_entries: self.next_id,
            buffered_entries: total,
            allows,
            denies,
            audits,
            redacts,
            violations,
            avg_eval_us,
            max_eval_us,
        }
    }
}

/// Summary statistics from the audit log.
#[derive(Debug, Clone)]
pub struct AuditStats {
    pub total_entries: u64,
    pub buffered_entries: usize,
    pub allows: usize,
    pub denies: usize,
    pub audits: usize,
    pub redacts: usize,
    pub violations: usize,
    pub avg_eval_us: u64,
    pub max_eval_us: u64,
}

impl std::fmt::Display for AuditStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Audit log: {} total ({} buffered)",
            self.total_entries, self.buffered_entries
        )?;
        writeln!(
            f,
            "Verdicts: {} allow, {} deny, {} audit, {} redact",
            self.allows, self.denies, self.audits, self.redacts
        )?;
        writeln!(f, "Violations: {}", self.violations)?;
        writeln!(
            f,
            "Latency: avg {}us, max {}us",
            self.avg_eval_us, self.max_eval_us
        )?;
        Ok(())
    }
}
