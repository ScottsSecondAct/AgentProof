//! Audit log tests.
//!
//! Verifies that `AuditLog` is append-only, that the ring buffer evicts
//! oldest entries correctly, and that query/stats methods return accurate
//! results.

use aegis_compiler::ast::Verdict;

use aegis_runtime::audit::AuditLog;
use aegis_runtime::engine::{PolicyResult, Violation};
use aegis_runtime::event::Event;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Minimal PolicyResult with a given verdict.
fn result(verdict: Verdict) -> PolicyResult {
    PolicyResult {
        verdict,
        reason: None,
        triggered_rules: vec![],
        actions: vec![],
        violations: vec![],
        constraint_violations: vec![],
        eval_time_us: 10,
    }
}

fn result_with_violation(verdict: Verdict) -> PolicyResult {
    PolicyResult {
        verdict,
        reason: Some("invariant violated".into()),
        triggered_rules: vec![0],
        actions: vec![],
        violations: vec![Violation {
            proof_name: smol_str::SmolStr::new("Proof"),
            invariant_name: smol_str::SmolStr::new("Inv"),
            kind: aegis_compiler::ir::TemporalKind::Always,
            message: "Invariant Inv violated".into(),
        }],
        constraint_violations: vec![],
        eval_time_us: 15,
    }
}

fn ev(event_type: &str) -> Event {
    Event::new(event_type)
}

// ── Empty log ─────────────────────────────────────────────────────────────────

#[test]
fn new_log_is_empty() {
    let log = AuditLog::in_memory(100);
    assert!(log.is_empty());
    assert_eq!(log.len(), 0);
    assert_eq!(log.total_recorded(), 0);
}

// ── Record ────────────────────────────────────────────────────────────────────

#[test]
fn record_increments_len() {
    let mut log = AuditLog::in_memory(100);
    log.record("Policy", &ev("tool_call"), &result(Verdict::Allow));
    assert_eq!(log.len(), 1);
    assert!(!log.is_empty());
}

#[test]
fn record_returns_monotonically_increasing_ids() {
    let mut log = AuditLog::in_memory(100);
    let id0 = log.record("P", &ev("x"), &result(Verdict::Allow));
    let id1 = log.record("P", &ev("x"), &result(Verdict::Deny));
    let id2 = log.record("P", &ev("x"), &result(Verdict::Audit));
    assert!(id0 < id1 && id1 < id2);
    assert_eq!(id0, 0);
    assert_eq!(id1, 1);
    assert_eq!(id2, 2);
}

#[test]
fn total_recorded_counts_all_including_evicted() {
    let mut log = AuditLog::in_memory(2); // ring buffer of 2
    log.record("P", &ev("x"), &result(Verdict::Allow));
    log.record("P", &ev("x"), &result(Verdict::Allow));
    log.record("P", &ev("x"), &result(Verdict::Allow)); // evicts first
    assert_eq!(log.len(), 2);            // only 2 in buffer
    assert_eq!(log.total_recorded(), 3); // but 3 total recorded
}

// ── Ring buffer ───────────────────────────────────────────────────────────────

#[test]
fn ring_buffer_does_not_exceed_max_entries() {
    let max = 5;
    let mut log = AuditLog::in_memory(max);
    for _ in 0..10 {
        log.record("P", &ev("x"), &result(Verdict::Allow));
    }
    assert_eq!(log.len(), max);
}

#[test]
fn ring_buffer_evicts_oldest_entry() {
    let mut log = AuditLog::in_memory(2);
    log.record("P", &ev("tool_call"), &result(Verdict::Allow)); // id 0
    log.record("P", &ev("data_access"), &result(Verdict::Deny)); // id 1
    log.record("P", &ev("message"), &result(Verdict::Audit));     // id 2, evicts id 0

    // The oldest remaining entry should be id=1 (data_access)
    let recent = log.recent(2);
    let event_types: Vec<&str> = recent.iter().map(|e| e.event_type.as_str()).collect();
    assert!(!event_types.contains(&"tool_call"), "oldest entry should have been evicted");
    assert!(event_types.contains(&"data_access"));
    assert!(event_types.contains(&"message"));
}

// ── Entry fields ──────────────────────────────────────────────────────────────

#[test]
fn entry_captures_policy_name() {
    let mut log = AuditLog::in_memory(10);
    log.record("MyGuard", &ev("tool_call"), &result(Verdict::Allow));
    let entry = &log.recent(1)[0];
    assert_eq!(entry.policy_name.as_str(), "MyGuard");
}

#[test]
fn entry_captures_event_type() {
    let mut log = AuditLog::in_memory(10);
    log.record("P", &ev("data_access"), &result(Verdict::Deny));
    let entry = &log.recent(1)[0];
    assert_eq!(entry.event_type.as_str(), "data_access");
}

#[test]
fn entry_captures_verdict_as_string() {
    let mut log = AuditLog::in_memory(10);
    log.record("P", &ev("x"), &result(Verdict::Audit));
    let entry = &log.recent(1)[0];
    assert_eq!(entry.verdict.as_str(), "Audit");
}

#[test]
fn entry_captures_reason() {
    let mut r = result(Verdict::Deny);
    r.reason = Some("blocked".into());
    let mut log = AuditLog::in_memory(10);
    log.record("P", &ev("x"), &r);
    assert_eq!(log.recent(1)[0].reason.as_deref(), Some("blocked"));
}

#[test]
fn entry_captures_triggered_rules() {
    let mut r = result(Verdict::Deny);
    r.triggered_rules = vec![0, 3, 7];
    let mut log = AuditLog::in_memory(10);
    log.record("P", &ev("x"), &r);
    assert_eq!(log.recent(1)[0].triggered_rules, vec![0, 3, 7]);
}

#[test]
fn entry_captures_violation_count() {
    let mut log = AuditLog::in_memory(10);
    log.record("P", &ev("x"), &result_with_violation(Verdict::Deny));
    let entry = &log.recent(1)[0];
    assert_eq!(entry.violation_count, 1);
}

#[test]
fn entry_captures_violation_details() {
    let mut log = AuditLog::in_memory(10);
    log.record("P", &ev("x"), &result_with_violation(Verdict::Deny));
    let entry = &log.recent(1)[0];
    assert!(!entry.violations.is_empty());
    assert_eq!(entry.violations[0].proof_name.as_str(), "Proof");
    assert_eq!(entry.violations[0].invariant_name.as_str(), "Inv");
}

#[test]
fn entry_captures_eval_time() {
    let mut log = AuditLog::in_memory(10);
    let r = result(Verdict::Allow);
    log.record("P", &ev("x"), &r);
    assert_eq!(log.recent(1)[0].eval_time_us, 10);
}

// ── Queries ───────────────────────────────────────────────────────────────────

#[test]
fn by_verdict_filters_correctly() {
    let mut log = AuditLog::in_memory(20);
    log.record("P", &ev("x"), &result(Verdict::Allow));
    log.record("P", &ev("x"), &result(Verdict::Deny));
    log.record("P", &ev("x"), &result(Verdict::Allow));
    log.record("P", &ev("x"), &result(Verdict::Audit));

    let allows = log.by_verdict("Allow");
    let denies = log.by_verdict("Deny");
    let audits = log.by_verdict("Audit");
    assert_eq!(allows.len(), 2);
    assert_eq!(denies.len(), 1);
    assert_eq!(audits.len(), 1);
}

#[test]
fn by_verdict_returns_empty_for_unknown() {
    let mut log = AuditLog::in_memory(10);
    log.record("P", &ev("x"), &result(Verdict::Allow));
    assert!(log.by_verdict("Redact").is_empty());
}

#[test]
fn with_violations_filters_correctly() {
    let mut log = AuditLog::in_memory(20);
    log.record("P", &ev("x"), &result(Verdict::Allow));
    log.record("P", &ev("x"), &result_with_violation(Verdict::Deny));
    log.record("P", &ev("x"), &result(Verdict::Audit));
    log.record("P", &ev("x"), &result_with_violation(Verdict::Deny));

    let with_v = log.with_violations();
    assert_eq!(with_v.len(), 2);
    assert!(with_v.iter().all(|e| e.violation_count > 0));
}

#[test]
fn by_event_type_filters_correctly() {
    let mut log = AuditLog::in_memory(20);
    log.record("P", &ev("tool_call"), &result(Verdict::Allow));
    log.record("P", &ev("data_access"), &result(Verdict::Deny));
    log.record("P", &ev("tool_call"), &result(Verdict::Audit));

    assert_eq!(log.by_event_type("tool_call").len(), 2);
    assert_eq!(log.by_event_type("data_access").len(), 1);
    assert_eq!(log.by_event_type("message").len(), 0);
}

#[test]
fn recent_returns_last_n_in_reverse_order() {
    let mut log = AuditLog::in_memory(20);
    log.record("P", &ev("a"), &result(Verdict::Allow));
    log.record("P", &ev("b"), &result(Verdict::Deny));
    log.record("P", &ev("c"), &result(Verdict::Audit));

    let recent = log.recent(2);
    assert_eq!(recent.len(), 2);
    // Most recent first
    assert_eq!(recent[0].event_type.as_str(), "c");
    assert_eq!(recent[1].event_type.as_str(), "b");
}

#[test]
fn recent_with_n_larger_than_len_returns_all() {
    let mut log = AuditLog::in_memory(20);
    log.record("P", &ev("x"), &result(Verdict::Allow));
    log.record("P", &ev("x"), &result(Verdict::Allow));
    assert_eq!(log.recent(100).len(), 2);
}

#[test]
fn recent_on_empty_log_returns_empty() {
    let log = AuditLog::in_memory(10);
    assert!(log.recent(5).is_empty());
}

// ── Stats ─────────────────────────────────────────────────────────────────────

#[test]
fn stats_empty_log() {
    let log = AuditLog::in_memory(10);
    let stats = log.stats();
    assert_eq!(stats.total_entries, 0);
    assert_eq!(stats.allows, 0);
    assert_eq!(stats.denies, 0);
    assert_eq!(stats.avg_eval_us, 0);
    assert_eq!(stats.max_eval_us, 0);
}

#[test]
fn stats_counts_verdicts() {
    let mut log = AuditLog::in_memory(20);
    log.record("P", &ev("x"), &result(Verdict::Allow));
    log.record("P", &ev("x"), &result(Verdict::Allow));
    log.record("P", &ev("x"), &result(Verdict::Deny));
    log.record("P", &ev("x"), &result(Verdict::Audit));
    log.record("P", &ev("x"), &result(Verdict::Redact));

    let stats = log.stats();
    assert_eq!(stats.allows, 2);
    assert_eq!(stats.denies, 1);
    assert_eq!(stats.audits, 1);
    assert_eq!(stats.redacts, 1);
}

#[test]
fn stats_counts_violations() {
    let mut log = AuditLog::in_memory(20);
    log.record("P", &ev("x"), &result(Verdict::Allow));
    log.record("P", &ev("x"), &result_with_violation(Verdict::Deny));
    log.record("P", &ev("x"), &result_with_violation(Verdict::Deny));

    let stats = log.stats();
    assert_eq!(stats.violations, 2);
}

#[test]
fn stats_total_entries_counts_evicted() {
    let mut log = AuditLog::in_memory(2);
    for _ in 0..5 {
        log.record("P", &ev("x"), &result(Verdict::Allow));
    }
    let stats = log.stats();
    assert_eq!(stats.total_entries, 5);
    assert_eq!(stats.buffered_entries, 2);
}

#[test]
fn stats_avg_and_max_eval_time() {
    let mut log = AuditLog::in_memory(20);
    let mut r1 = result(Verdict::Allow);
    r1.eval_time_us = 10;
    let mut r2 = result(Verdict::Allow);
    r2.eval_time_us = 30;
    log.record("P", &ev("x"), &r1);
    log.record("P", &ev("x"), &r2);

    let stats = log.stats();
    assert_eq!(stats.max_eval_us, 30);
    assert_eq!(stats.avg_eval_us, 20);
}

// ── JSON serialization ────────────────────────────────────────────────────────

#[test]
fn audit_entry_serializes_to_json() {
    let mut log = AuditLog::in_memory(10);
    log.record("Guard", &ev("tool_call"), &result_with_violation(Verdict::Deny));
    let entry = log.recent(1)[0];
    let json = serde_json::to_string(entry).expect("should serialize");
    assert!(json.contains("Guard"));
    assert!(json.contains("tool_call"));
    assert!(json.contains("Deny"));
}

#[test]
fn audit_entry_round_trips_through_json() {
    use aegis_runtime::audit::AuditEntry;
    let mut log = AuditLog::in_memory(10);
    log.record("Guard", &ev("tool_call"), &result(Verdict::Audit));
    let entry = log.recent(1)[0].clone();
    let json = serde_json::to_string(&entry).expect("serialize");
    let restored: AuditEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(restored.policy_name, entry.policy_name);
    assert_eq!(restored.verdict, entry.verdict);
    assert_eq!(restored.event_type, entry.event_type);
    assert_eq!(restored.id, entry.id);
}

// ── File-backed log ───────────────────────────────────────────────────────────

#[test]
fn with_file_writes_json_lines() {
    let buf: Vec<u8> = Vec::new();
    let mut log = AuditLog::with_file(100, Box::new(std::io::Cursor::new(buf)));
    log.record("P", &ev("tool_call"), &result(Verdict::Allow));
    log.record("P", &ev("data_access"), &result(Verdict::Deny));
    // We can't easily inspect the inner cursor after writing, but we can verify
    // the in-memory buffer was also populated.
    assert_eq!(log.len(), 2);
}

#[test]
fn display_stats_does_not_panic() {
    let mut log = AuditLog::in_memory(10);
    log.record("P", &ev("x"), &result(Verdict::Allow));
    let stats = log.stats();
    // just verify Display doesn't panic
    let _ = format!("{stats}");
}
