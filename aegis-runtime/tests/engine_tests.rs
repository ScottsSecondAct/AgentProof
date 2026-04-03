//! Policy engine integration tests.
//!
//! Exercises `PolicyEngine::evaluate` end-to-end: rule matching, verdict
//! selection, state machine advances, and rate limit enforcement.

use aegis_compiler::ast::{ConstraintKind, Literal, SeverityLevel, Verdict};
use aegis_compiler::ir::{
    CompiledConstraint, CompiledPolicy, CompiledRule, IRExpr, IRVerdict, PolicyMetadata,
    RefPath, RefRoot, StateMachineBuilder, TemporalKind,
};
use smol_str::SmolStr;

use aegis_runtime::engine::PolicyEngine;
use aegis_runtime::event::{Event, Value};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn s(v: &str) -> SmolStr {
    SmolStr::new(v)
}

/// Minimal policy with no rules, no state machines.
fn empty_policy(name: &str) -> CompiledPolicy {
    CompiledPolicy {
        name: s(name),
        severity: SeverityLevel::High,
        scopes: vec![],
        rules: vec![],
        constraints: vec![],
        state_machines: vec![],
        metadata: PolicyMetadata {
            annotations: vec![],
            source_hash: 0,
            compiler_version: s("test"),
        },
    }
}

/// Rule with no condition that produces a given verdict.
fn unconditional_rule(id: u32, on_event: &str, verdict: Verdict) -> CompiledRule {
    CompiledRule {
        id,
        on_events: vec![s(on_event)],
        condition: None,
        verdicts: vec![IRVerdict {
            verdict,
            message: None,
        }],
        actions: vec![],
        severity: None,
    }
}

/// Rule with a boolean literal condition.
fn conditional_rule(id: u32, on_event: &str, condition: bool, verdict: Verdict) -> CompiledRule {
    CompiledRule {
        id,
        on_events: vec![s(on_event)],
        condition: Some(IRExpr::Literal(Literal::Bool(condition))),
        verdicts: vec![IRVerdict {
            verdict,
            message: None,
        }],
        actions: vec![],
        severity: None,
    }
}

/// Rule whose condition checks `event.field == literal_string`.
fn field_eq_rule(id: u32, on_event: &str, field: &str, value: &str, verdict: Verdict) -> CompiledRule {
    use aegis_compiler::ast::BinaryOp;
    let cond = IRExpr::Binary {
        op: BinaryOp::Eq,
        left: Box::new(IRExpr::Ref(RefPath {
            root: RefRoot::Event,
            fields: vec![s(field)],
        })),
        right: Box::new(IRExpr::Literal(Literal::String(s(value)))),
    };
    CompiledRule {
        id,
        on_events: vec![s(on_event)],
        condition: Some(cond),
        verdicts: vec![IRVerdict { verdict, message: None }],
        actions: vec![],
        severity: None,
    }
}

fn policy_with_rule(rule: CompiledRule) -> CompiledPolicy {
    let mut p = empty_policy("Test");
    p.rules.push(rule);
    p
}

fn tool_call(tool_name: &str) -> Event {
    Event::new("tool_call").with_field("tool_name", Value::String(s(tool_name)))
}

// ── Basic verdict logic ───────────────────────────────────────────────────────

#[test]
fn empty_policy_allows_all_events() {
    let mut engine = PolicyEngine::new(empty_policy("Empty"));
    let result = engine.evaluate(&Event::new("anything"));
    assert_eq!(result.verdict, Verdict::Allow);
}

#[test]
fn unconditional_deny_rule_triggers() {
    let rule = unconditional_rule(0, "tool_call", Verdict::Deny);
    let mut engine = PolicyEngine::new(policy_with_rule(rule));
    let result = engine.evaluate(&tool_call("http_get"));
    assert_eq!(result.verdict, Verdict::Deny);
    assert!(result.triggered_rules.contains(&0));
}

#[test]
fn unconditional_audit_rule_triggers() {
    let rule = unconditional_rule(0, "tool_call", Verdict::Audit);
    let mut engine = PolicyEngine::new(policy_with_rule(rule));
    let result = engine.evaluate(&tool_call("anything"));
    assert_eq!(result.verdict, Verdict::Audit);
}

#[test]
fn conditional_rule_true_triggers() {
    let rule = conditional_rule(0, "tool_call", true, Verdict::Deny);
    let mut engine = PolicyEngine::new(policy_with_rule(rule));
    let result = engine.evaluate(&tool_call("any"));
    assert_eq!(result.verdict, Verdict::Deny);
}

#[test]
fn conditional_rule_false_does_not_trigger() {
    let rule = conditional_rule(0, "tool_call", false, Verdict::Deny);
    let mut engine = PolicyEngine::new(policy_with_rule(rule));
    let result = engine.evaluate(&tool_call("any"));
    assert_eq!(result.verdict, Verdict::Allow);
    assert!(result.triggered_rules.is_empty());
}

#[test]
fn rule_only_fires_on_matching_event_type() {
    let rule = unconditional_rule(0, "data_access", Verdict::Deny);
    let mut engine = PolicyEngine::new(policy_with_rule(rule));
    // tool_call should not match the data_access rule
    let result = engine.evaluate(&tool_call("any"));
    assert_eq!(result.verdict, Verdict::Allow);
}

#[test]
fn rule_with_empty_on_events_fires_on_all() {
    let mut rule = unconditional_rule(0, "tool_call", Verdict::Deny);
    rule.on_events.clear(); // no filter → fires on any event
    let mut engine = PolicyEngine::new(policy_with_rule(rule));
    assert_eq!(engine.evaluate(&Event::new("data_access")).verdict, Verdict::Deny);
    assert_eq!(engine.evaluate(&Event::new("message")).verdict, Verdict::Deny);
}

#[test]
fn deny_overrides_audit() {
    let mut p = empty_policy("Test");
    p.rules.push(unconditional_rule(0, "tool_call", Verdict::Audit));
    p.rules.push(unconditional_rule(1, "tool_call", Verdict::Deny));
    let mut engine = PolicyEngine::new(p);
    let result = engine.evaluate(&tool_call("any"));
    assert_eq!(result.verdict, Verdict::Deny);
}

#[test]
fn field_condition_triggers_on_matching_value() {
    let rule = field_eq_rule(0, "tool_call", "tool_name", "http_get", Verdict::Deny);
    let mut engine = PolicyEngine::new(policy_with_rule(rule));
    let result = engine.evaluate(&tool_call("http_get"));
    assert_eq!(result.verdict, Verdict::Deny);
}

#[test]
fn field_condition_does_not_trigger_on_different_value() {
    let rule = field_eq_rule(0, "tool_call", "tool_name", "http_get", Verdict::Deny);
    let mut engine = PolicyEngine::new(policy_with_rule(rule));
    let result = engine.evaluate(&tool_call("db_query"));
    assert_eq!(result.verdict, Verdict::Allow);
}

#[test]
fn rule_with_message_populates_reason() {
    let cond = IRExpr::Literal(Literal::Bool(true));
    let msg = IRExpr::Literal(Literal::String(s("blocked by policy")));
    let rule = CompiledRule {
        id: 0,
        on_events: vec![s("tool_call")],
        condition: Some(cond),
        verdicts: vec![IRVerdict {
            verdict: Verdict::Deny,
            message: Some(Box::new(msg)),
        }],
        actions: vec![],
        severity: None,
    };
    let mut engine = PolicyEngine::new(policy_with_rule(rule));
    let result = engine.evaluate(&tool_call("any"));
    assert_eq!(result.reason.as_deref(), Some("blocked by policy"));
}

#[test]
fn multiple_triggered_rules_all_listed() {
    let mut p = empty_policy("Test");
    p.rules.push(unconditional_rule(0, "tool_call", Verdict::Audit));
    p.rules.push(unconditional_rule(1, "tool_call", Verdict::Audit));
    let mut engine = PolicyEngine::new(p);
    let result = engine.evaluate(&tool_call("any"));
    assert!(result.triggered_rules.contains(&0));
    assert!(result.triggered_rules.contains(&1));
}

// ── Event counter and reset ───────────────────────────────────────────────────

#[test]
fn event_count_increments_on_each_evaluation() {
    let mut engine = PolicyEngine::new(empty_policy("Test"));
    assert_eq!(engine.event_count(), 0);
    engine.evaluate(&Event::new("a"));
    assert_eq!(engine.event_count(), 1);
    engine.evaluate(&Event::new("b"));
    assert_eq!(engine.event_count(), 2);
}

#[test]
fn reset_clears_event_count() {
    let mut engine = PolicyEngine::new(empty_policy("Test"));
    engine.evaluate(&Event::new("a"));
    engine.evaluate(&Event::new("b"));
    engine.reset();
    assert_eq!(engine.event_count(), 0);
}

#[test]
fn policy_name_returns_correct_name() {
    let engine = PolicyEngine::new(empty_policy("MyGuard"));
    assert_eq!(engine.policy_name(), "MyGuard");
}

// ── Status ────────────────────────────────────────────────────────────────────

#[test]
fn status_reflects_policy_metadata() {
    let mut p = empty_policy("StatusTest");
    p.rules.push(unconditional_rule(0, "x", Verdict::Allow));
    let engine = PolicyEngine::new(p);
    let status = engine.status();
    assert_eq!(status.policy_name.as_str(), "StatusTest");
    assert_eq!(status.total_rules, 1);
    assert_eq!(status.total_state_machines, 0);
    assert_eq!(status.events_processed, 0);
}

#[test]
fn status_events_processed_increments() {
    let mut engine = PolicyEngine::new(empty_policy("Test"));
    engine.evaluate(&Event::new("x"));
    engine.evaluate(&Event::new("y"));
    assert_eq!(engine.status().events_processed, 2);
}

// ── State machine: always ─────────────────────────────────────────────────────

/// Build an `always(condition)` state machine where `condition` is a literal bool.
fn always_sm(condition: bool) -> aegis_compiler::ir::StateMachine {
    let predicate = IRExpr::Literal(Literal::Bool(condition));
    StateMachineBuilder::new().compile_always(s("Proof"), s("Inv"), predicate, None)
}

fn policy_with_sm(sm: aegis_compiler::ir::StateMachine) -> CompiledPolicy {
    let mut p = empty_policy("Test");
    p.state_machines.push(sm);
    p
}

#[test]
fn always_true_stays_satisfied_indefinitely() {
    let mut engine = PolicyEngine::new(policy_with_sm(always_sm(true)));
    for _ in 0..5 {
        let result = engine.evaluate(&Event::new("any"));
        assert!(result.violations.is_empty(), "always(true) should never violate");
        assert_eq!(result.verdict, Verdict::Allow);
    }
}

#[test]
fn always_false_violates_on_first_event() {
    let mut engine = PolicyEngine::new(policy_with_sm(always_sm(false)));
    let result = engine.evaluate(&Event::new("any"));
    assert!(!result.violations.is_empty());
    assert_eq!(result.verdict, Verdict::Deny);
}

#[test]
fn always_false_keeps_violating_on_subsequent_events() {
    let mut engine = PolicyEngine::new(policy_with_sm(always_sm(false)));
    engine.evaluate(&Event::new("any"));
    let result = engine.evaluate(&Event::new("any"));
    // Already in violated (terminal) state — violation still reported
    assert!(!result.violations.is_empty());
}

#[test]
fn always_violation_sets_reason() {
    let mut engine = PolicyEngine::new(policy_with_sm(always_sm(false)));
    let result = engine.evaluate(&Event::new("any"));
    assert!(result.reason.is_some());
    let reason = result.reason.unwrap();
    assert!(reason.contains("Invariant"), "reason should mention Invariant, got: {reason}");
}

#[test]
fn always_satisfied_shows_in_status() {
    let mut engine = PolicyEngine::new(policy_with_sm(always_sm(true)));
    engine.evaluate(&Event::new("any"));
    let status = engine.status();
    assert_eq!(status.total_state_machines, 1);
    assert_eq!(status.active_state_machines, 1);
    assert_eq!(status.violated_state_machines, 0);
}

#[test]
fn reset_after_violation_restores_active_state() {
    let mut engine = PolicyEngine::new(policy_with_sm(always_sm(false)));
    engine.evaluate(&Event::new("any")); // violate
    engine.reset();
    // After reset, should be back to active
    assert_eq!(engine.status().active_state_machines, 1);
    assert_eq!(engine.status().violated_state_machines, 0);
}

// ── State machine: never ──────────────────────────────────────────────────────

/// Build a `never(condition)` state machine.
fn never_sm(condition: bool) -> aegis_compiler::ir::StateMachine {
    let predicate = IRExpr::Literal(Literal::Bool(condition));
    StateMachineBuilder::new().compile_never(s("Proof"), s("Inv"), predicate)
}

#[test]
fn never_false_never_violates() {
    let mut engine = PolicyEngine::new(policy_with_sm(never_sm(false)));
    for _ in 0..5 {
        let result = engine.evaluate(&Event::new("any"));
        assert!(result.violations.is_empty(), "never(false) should never violate");
        assert_eq!(result.verdict, Verdict::Allow);
    }
}

#[test]
fn never_true_violates_on_first_event() {
    let mut engine = PolicyEngine::new(policy_with_sm(never_sm(true)));
    let result = engine.evaluate(&Event::new("any"));
    assert!(!result.violations.is_empty());
    assert_eq!(result.verdict, Verdict::Deny);
}

// ── State machine: eventually ─────────────────────────────────────────────────

fn eventually_sm_with_deadline(condition: bool, deadline_ms: u64) -> aegis_compiler::ir::StateMachine {
    let predicate = IRExpr::Literal(Literal::Bool(condition));
    StateMachineBuilder::new().compile_eventually(s("Proof"), s("Inv"), predicate, Some(deadline_ms))
}

fn eventually_sm_no_deadline(condition: bool) -> aegis_compiler::ir::StateMachine {
    let predicate = IRExpr::Literal(Literal::Bool(condition));
    StateMachineBuilder::new().compile_eventually(s("Proof"), s("Inv"), predicate, None)
}

#[test]
fn eventually_satisfied_when_condition_true() {
    let mut engine = PolicyEngine::new(policy_with_sm(eventually_sm_no_deadline(true)));
    let result = engine.evaluate(&Event::new("any"));
    // condition is immediately true → transitions to Satisfied
    assert!(result.violations.is_empty());
    assert_eq!(engine.status().satisfied_state_machines, 1);
}

#[test]
fn eventually_without_deadline_stays_waiting_indefinitely() {
    let mut engine = PolicyEngine::new(policy_with_sm(eventually_sm_no_deadline(false)));
    // condition is false and no deadline → stays in waiting (Active), no violation
    for _ in 0..5 {
        let result = engine.evaluate(&Event::new("any"));
        assert!(result.violations.is_empty(), "eventually without deadline should not violate");
        assert_eq!(result.verdict, Verdict::Allow);
    }
}

#[test]
fn eventually_with_deadline_violates_when_expired() {
    // Build a state machine with a 1ms deadline.
    // The state machine start_time is set to current_time_ms() at engine creation.
    // We send an event with a timestamp well after that (engine_start + 10_000ms)
    // so the elapsed time far exceeds the 1ms deadline.
    let sm = eventually_sm_with_deadline(false, 1);
    let mut engine = PolicyEngine::new(policy_with_sm(sm));
    let engine_start = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let mut ev = Event::new("any");
    ev.timestamp_ms = engine_start + 10_000; // 10 seconds after engine creation
    let result = engine.evaluate(&ev);
    assert!(!result.violations.is_empty(), "deadline should have expired → violation");
    assert_eq!(result.verdict, Verdict::Deny);
}

#[test]
fn eventually_sm_kind_is_eventually() {
    let sm = eventually_sm_no_deadline(true);
    assert_eq!(sm.kind, TemporalKind::Eventually);
}

// ── Rate limiter ──────────────────────────────────────────────────────────────

fn rate_limited_policy(limit: u64, window_ms: u64) -> CompiledPolicy {
    let mut p = empty_policy("RateTest");
    p.constraints.push(CompiledConstraint {
        kind: ConstraintKind::RateLimit,
        target: s("tool_call"),
        limit,
        window_millis: window_ms,
    });
    p
}

#[test]
fn rate_limit_under_limit_allows() {
    let mut engine = PolicyEngine::new(rate_limited_policy(5, 60_000));
    for i in 0..5 {
        let mut ev = Event::new("tool_call");
        ev.timestamp_ms = 1000 + i * 100;
        let result = engine.evaluate(&ev);
        assert_eq!(result.verdict, Verdict::Allow, "event {i} should be allowed");
    }
}

#[test]
fn rate_limit_at_limit_allows() {
    let mut engine = PolicyEngine::new(rate_limited_policy(3, 60_000));
    // exactly 3 events = at limit (not exceeded)
    for i in 0..3 {
        let mut ev = Event::new("tool_call");
        ev.timestamp_ms = 1000 + i * 100;
        let result = engine.evaluate(&ev);
        assert_eq!(result.verdict, Verdict::Allow, "event {i} at limit should allow");
    }
}

#[test]
fn rate_limit_over_limit_denies() {
    let mut engine = PolicyEngine::new(rate_limited_policy(3, 60_000));
    // Send 3 allowed events first
    for i in 0..3 {
        let mut ev = Event::new("tool_call");
        ev.timestamp_ms = 1000 + i * 100;
        engine.evaluate(&ev);
    }
    // 4th event should be denied
    let mut over = Event::new("tool_call");
    over.timestamp_ms = 1400;
    let result = engine.evaluate(&over);
    assert_eq!(result.verdict, Verdict::Deny);
    assert!(!result.constraint_violations.is_empty());
}

#[test]
fn rate_limit_sliding_window_evicts_old_events() {
    // Window = 1000ms, limit = 2
    let mut engine = PolicyEngine::new(rate_limited_policy(2, 1000));

    // Two events at t=0
    for i in 0..2 {
        let mut ev = Event::new("tool_call");
        ev.timestamp_ms = 100 * i;
        engine.evaluate(&ev);
    }
    // Third event at t=0 → over limit
    let mut over = Event::new("tool_call");
    over.timestamp_ms = 200;
    assert_eq!(engine.evaluate(&over).verdict, Verdict::Deny);

    // Event at t=1500 — old events (t=0,100) are outside 1000ms window → under limit again
    let mut new_window = Event::new("tool_call");
    new_window.timestamp_ms = 1500;
    assert_eq!(engine.evaluate(&new_window).verdict, Verdict::Allow);
}

#[test]
fn rate_limit_only_counts_matching_event_type() {
    let mut engine = PolicyEngine::new(rate_limited_policy(2, 60_000));
    // data_access events should not count against tool_call limit
    for i in 0..5 {
        let mut ev = Event::new("data_access");
        ev.timestamp_ms = 1000 + i * 100;
        let result = engine.evaluate(&ev);
        assert_eq!(result.verdict, Verdict::Allow, "data_access should not hit tool_call limit");
    }
}

#[test]
fn constraint_violation_details_are_correct() {
    let mut engine = PolicyEngine::new(rate_limited_policy(1, 60_000));
    let mut ev = Event::new("tool_call");
    ev.timestamp_ms = 1000;
    engine.evaluate(&ev); // at limit
    let mut ev2 = Event::new("tool_call");
    ev2.timestamp_ms = 1100;
    let result = engine.evaluate(&ev2);
    assert!(!result.constraint_violations.is_empty());
    let cv = &result.constraint_violations[0];
    assert_eq!(cv.limit, 1);
    assert_eq!(cv.current, 2);
}

#[test]
fn reset_clears_rate_limiter_state() {
    let mut engine = PolicyEngine::new(rate_limited_policy(1, 60_000));
    let mut ev = Event::new("tool_call");
    ev.timestamp_ms = 1000;
    engine.evaluate(&ev);
    engine.reset();
    // After reset the counter is clear — first event allowed again
    let mut ev2 = Event::new("tool_call");
    ev2.timestamp_ms = 2000;
    assert_eq!(engine.evaluate(&ev2).verdict, Verdict::Allow);
}
