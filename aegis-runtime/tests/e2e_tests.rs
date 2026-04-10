//! End-to-end pipeline tests.
//!
//! These tests exercise the full pipeline: `.aegis` source text → parser →
//! type checker → lowering → `CompiledPolicy` → bytecode round-trip →
//! `PolicyEngine::evaluate` → verdict.
//!
//! No stubs or pre-compiled artefacts: each test compiles a policy from source
//! and immediately evaluates events against it.

use std::time::{SystemTime, UNIX_EPOCH};

use aegis_compiler::ast::Verdict;
use aegis_compiler::{bytecode, lower, parser};
use aegis_runtime::engine::PolicyEngine;
use aegis_runtime::event::{Event, Value};
use smol_str::SmolStr;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn s(v: &str) -> SmolStr {
    SmolStr::new(v)
}

/// Compile a `.aegis` source string to a `PolicyEngine`.
///
/// Panics on parse or compile errors, making test failures obvious.
fn engine_from_source(source: &str) -> PolicyEngine {
    let (program, parse_diags) = parser::parse_source(source, "test.aegis");
    if parse_diags.has_errors() {
        let rendered = parse_diags.render(source, "test.aegis");
        panic!("parse errors:\n{rendered}");
    }

    let (compiled, compile_diags) = lower::compile(&program);
    if compile_diags.has_errors() {
        let rendered = compile_diags.render(source, "test.aegis");
        panic!("compile errors:\n{rendered}");
    }

    assert!(
        !compiled.is_empty(),
        "source must define at least one policy"
    );

    // Round-trip through bytecode to verify the full serialization path.
    let bytes = bytecode::to_bytecode(&compiled[0]).expect("bytecode serialization failed");
    let policy = bytecode::from_bytecode(&bytes).expect("bytecode deserialization failed");

    PolicyEngine::new(policy)
}

fn tool_call(tool: &str) -> Event {
    Event::new("tool_call").with_field("tool_name", Value::String(s(tool)))
}

// ── Unconditional rules ───────────────────────────────────────────────────────

const DENY_ALL: &str = r#"
policy DenyAll {
    on tool_call {
        deny
    }
}
"#;

#[test]
fn e2e_unconditional_deny_rule() {
    let mut engine = engine_from_source(DENY_ALL);
    let result = engine.evaluate(&tool_call("http_get"));
    assert_eq!(result.verdict, Verdict::Deny);
}

const ALLOW_ALL: &str = r#"
policy AllowAll {
    on tool_call {
        allow
    }
}
"#;

#[test]
fn e2e_unconditional_allow_rule() {
    let mut engine = engine_from_source(ALLOW_ALL);
    let result = engine.evaluate(&tool_call("anything"));
    assert_eq!(result.verdict, Verdict::Allow);
}

// ── Conditional rules ─────────────────────────────────────────────────────────

const BLOCK_HTTP_GET: &str = r#"
policy BlockHttpGet {
    on tool_call {
        when event.tool_name == "http_get"
        deny
    }
}
"#;

#[test]
fn e2e_conditional_deny_on_matching_tool() {
    let mut engine = engine_from_source(BLOCK_HTTP_GET);
    assert_eq!(
        engine.evaluate(&tool_call("http_get")).verdict,
        Verdict::Deny
    );
}

#[test]
fn e2e_conditional_allow_on_non_matching_tool() {
    let mut engine = engine_from_source(BLOCK_HTTP_GET);
    assert_eq!(
        engine.evaluate(&tool_call("db_query")).verdict,
        Verdict::Allow
    );
}

// ── Audit rules ───────────────────────────────────────────────────────────────

const AUDIT_WRITE: &str = r#"
policy AuditWrites {
    on tool_call {
        when event.tool_name == "file_write"
        audit
    }
}
"#;

#[test]
fn e2e_audit_rule_produces_audit_verdict() {
    let mut engine = engine_from_source(AUDIT_WRITE);
    assert_eq!(
        engine.evaluate(&tool_call("file_write")).verdict,
        Verdict::Audit
    );
}

#[test]
fn e2e_audit_rule_non_matching_tool_allows() {
    let mut engine = engine_from_source(AUDIT_WRITE);
    assert_eq!(
        engine.evaluate(&tool_call("http_get")).verdict,
        Verdict::Allow
    );
}

// ── never invariant ───────────────────────────────────────────────────────────

const NEVER_EXEC: &str = r#"
policy NoExec {
    proof SafeTools {
        invariant NoShell {
            never(event.tool_name == "exec")
        }
    }
}
"#;

#[test]
fn e2e_always_invariant_allows_safe_tools() {
    let mut engine = engine_from_source(NEVER_EXEC);
    for _ in 0..5 {
        assert_eq!(
            engine.evaluate(&tool_call("http_get")).verdict,
            Verdict::Allow
        );
    }
}

#[test]
fn e2e_never_invariant_denies_on_violation() {
    let mut engine = engine_from_source(NEVER_EXEC);
    let result = engine.evaluate(&tool_call("exec"));
    assert_eq!(result.verdict, Verdict::Deny);
    assert!(!result.violations.is_empty());
}

#[test]
fn e2e_never_invariant_violation_persists() {
    let mut engine = engine_from_source(NEVER_EXEC);
    engine.evaluate(&tool_call("exec")); // violate
                                         // All subsequent events are denied.
    assert_eq!(
        engine.evaluate(&tool_call("http_get")).verdict,
        Verdict::Deny
    );
}

// ── Rate limit constraint ─────────────────────────────────────────────────────

const RATE_LIMITED: &str = r#"
policy RateLimited {
    rate_limit tool_call: 2 per 1m
}
"#;

#[test]
fn e2e_rate_limit_allows_within_budget() {
    let mut engine = engine_from_source(RATE_LIMITED);
    let mut ev = Event::new("tool_call");
    ev.timestamp_ms = 1000;
    assert_eq!(engine.evaluate(&ev).verdict, Verdict::Allow);
    ev.timestamp_ms = 2000;
    assert_eq!(engine.evaluate(&ev).verdict, Verdict::Allow);
}

#[test]
fn e2e_rate_limit_denies_over_budget() {
    let mut engine = engine_from_source(RATE_LIMITED);
    for i in 0u64..2 {
        let mut ev = Event::new("tool_call");
        ev.timestamp_ms = 1000 + i * 100;
        engine.evaluate(&ev);
    }
    let mut over = Event::new("tool_call");
    over.timestamp_ms = 1300;
    assert_eq!(engine.evaluate(&over).verdict, Verdict::Deny);
}

// ── Event count and policy name ───────────────────────────────────────────────

#[test]
fn e2e_event_count_increments() {
    let mut engine = engine_from_source(DENY_ALL);
    assert_eq!(engine.event_count(), 0);
    engine.evaluate(&tool_call("x"));
    engine.evaluate(&tool_call("y"));
    assert_eq!(engine.event_count(), 2);
}

#[test]
fn e2e_policy_name_from_source() {
    let engine = engine_from_source(DENY_ALL);
    assert_eq!(engine.policy_name(), "DenyAll");
}

// ── Bytecode file round-trip ──────────────────────────────────────────────────

#[test]
fn e2e_bytecode_file_round_trip() {
    let (program, _) = parser::parse_source(BLOCK_HTTP_GET, "test.aegis");
    let (compiled, _) = lower::compile(&program);
    assert!(!compiled.is_empty());

    let dir = std::env::temp_dir();
    let path = dir.join("e2e_test_policy.aegisc");

    bytecode::write_file(&path, &compiled[0]).expect("write_file failed");
    let restored = bytecode::read_file(&path).expect("read_file failed");

    assert_eq!(restored.name, compiled[0].name);
    assert_eq!(restored.rules.len(), compiled[0].rules.len());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn e2e_engine_from_file_produces_correct_verdicts() {
    let (program, _) = parser::parse_source(BLOCK_HTTP_GET, "test.aegis");
    let (compiled, _) = lower::compile(&program);

    let dir = std::env::temp_dir();
    let path = dir.join("e2e_test_verdicts.aegisc");
    bytecode::write_file(&path, &compiled[0]).unwrap();

    let policy = bytecode::read_file(&path).unwrap();
    let mut engine = PolicyEngine::new(policy);

    assert_eq!(
        engine.evaluate(&tool_call("http_get")).verdict,
        Verdict::Deny
    );
    assert_eq!(
        engine.evaluate(&tool_call("db_query")).verdict,
        Verdict::Allow
    );

    let _ = std::fs::remove_file(&path);
}

// ── always invariant ──────────────────────────────────────────────────────────

const ALWAYS_PUBLIC: &str = r#"
policy AlwaysPublic {
    proof DataPolicy {
        invariant NoSecretAccess {
            always(event.classification != "secret")
        }
    }
}
"#;

#[test]
fn e2e_always_allows_while_condition_holds() {
    let mut engine = engine_from_source(ALWAYS_PUBLIC);
    for _ in 0..5 {
        let ev = Event::new("data_access").with_field("classification", Value::String(s("public")));
        assert_eq!(engine.evaluate(&ev).verdict, Verdict::Allow);
    }
}

#[test]
fn e2e_always_denies_on_violation() {
    let mut engine = engine_from_source(ALWAYS_PUBLIC);
    let ev = Event::new("data_access").with_field("classification", Value::String(s("secret")));
    let result = engine.evaluate(&ev);
    assert_eq!(result.verdict, Verdict::Deny);
    assert!(!result.violations.is_empty());
}

#[test]
fn e2e_always_violation_is_permanent() {
    let mut engine = engine_from_source(ALWAYS_PUBLIC);
    // Violate once.
    let bad = Event::new("data_access").with_field("classification", Value::String(s("secret")));
    engine.evaluate(&bad);
    // Safe events afterwards are still denied — the session is poisoned.
    let good = Event::new("data_access").with_field("classification", Value::String(s("public")));
    assert_eq!(engine.evaluate(&good).verdict, Verdict::Deny);
}

// ── eventually invariant ──────────────────────────────────────────────────────

const EVENTUALLY_CHECKPOINT: &str = r#"
policy MustCheckpoint {
    proof Progress {
        invariant CheckpointRequired {
            eventually(event.tool_name == "checkpoint") within 5000ms
        }
    }
}
"#;

#[test]
fn e2e_eventually_satisfied_before_deadline() {
    let mut engine = engine_from_source(EVENTUALLY_CHECKPOINT);
    let ev = Event::new("tool_call").with_field("tool_name", Value::String(s("checkpoint")));
    assert_eq!(engine.evaluate(&ev).verdict, Verdict::Allow);
}

#[test]
fn e2e_eventually_denies_after_deadline_expires() {
    let mut engine = engine_from_source(EVENTUALLY_CHECKPOINT);
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    // Send an irrelevant event well past the 5000ms deadline.
    let mut ev = Event::new("tool_call");
    ev.timestamp_ms = now_ms + 6_000; // 6 s after engine start
    ev.fields
        .insert(s("tool_name"), Value::String(s("http_get")));
    let result = engine.evaluate(&ev);
    assert_eq!(result.verdict, Verdict::Deny);
    assert!(!result.violations.is_empty());
}

#[test]
fn e2e_eventually_non_matching_event_does_not_satisfy() {
    let mut engine = engine_from_source(EVENTUALLY_CHECKPOINT);
    // A tool_call that is NOT a checkpoint must not satisfy the invariant.
    let ev = Event::new("tool_call").with_field("tool_name", Value::String(s("http_get")));
    // Machine should still be active (waiting) — no violation yet.
    assert_eq!(engine.evaluate(&ev).verdict, Verdict::Allow);
}

// ── before invariant ──────────────────────────────────────────────────────────

const APPROVAL_BEFORE_DELETE: &str = r#"
policy ApprovalGate {
    proof DeletionPolicy {
        invariant ApprovalFirst {
            before(
                event.tool_name == "approve",
                event.tool_name == "delete"
            )
        }
    }
}
"#;

#[test]
fn e2e_before_allows_when_first_arg_occurs_first() {
    let mut engine = engine_from_source(APPROVAL_BEFORE_DELETE);
    let approve = Event::new("tool_call").with_field("tool_name", Value::String(s("approve")));
    assert_eq!(engine.evaluate(&approve).verdict, Verdict::Allow);
    // Delete is now allowed because approval came first.
    let delete = Event::new("tool_call").with_field("tool_name", Value::String(s("delete")));
    assert_eq!(engine.evaluate(&delete).verdict, Verdict::Allow);
}

#[test]
fn e2e_before_denies_when_second_arg_occurs_first() {
    let mut engine = engine_from_source(APPROVAL_BEFORE_DELETE);
    let delete = Event::new("tool_call").with_field("tool_name", Value::String(s("delete")));
    let result = engine.evaluate(&delete);
    assert_eq!(result.verdict, Verdict::Deny);
    assert!(!result.violations.is_empty());
}

#[test]
fn e2e_before_unrelated_events_do_not_trigger_violation() {
    let mut engine = engine_from_source(APPROVAL_BEFORE_DELETE);
    for _ in 0..3 {
        let ev = Event::new("tool_call").with_field("tool_name", Value::String(s("http_get")));
        assert_eq!(engine.evaluate(&ev).verdict, Verdict::Allow);
    }
}

// ── after invariant ───────────────────────────────────────────────────────────

// after(condition, trigger): after `trigger` fires, the very next event must
// satisfy `condition`.  Here: after a PII data_access, the next event must
// NOT be an external_request.
const NO_EXFILTRATION_AFTER_PII: &str = r#"
policy ExfilGuard {
    proof Exfiltration {
        invariant NoPIIThenExternal {
            after(
                !(event.event_type == "external_request"),
                event.event_type == "data_access" && event.classification == "PII"
            )
        }
    }
}
"#;

#[test]
fn e2e_after_allows_when_condition_holds_after_trigger() {
    let mut engine = engine_from_source(NO_EXFILTRATION_AFTER_PII);
    // Trigger: PII data access.
    let pii = Event::new("data_access").with_field("classification", Value::String(s("PII")));
    assert_eq!(engine.evaluate(&pii).verdict, Verdict::Allow);
    // Next event: a safe tool call — condition !(event_type == external_request) holds.
    let safe = Event::new("tool_call");
    assert_eq!(engine.evaluate(&safe).verdict, Verdict::Allow);
}

#[test]
fn e2e_after_denies_when_condition_fails_after_trigger() {
    let mut engine = engine_from_source(NO_EXFILTRATION_AFTER_PII);
    // Trigger.
    let pii = Event::new("data_access").with_field("classification", Value::String(s("PII")));
    engine.evaluate(&pii);
    // Next event: external_request — condition fails.
    let exfil = Event::new("external_request");
    let result = engine.evaluate(&exfil);
    assert_eq!(result.verdict, Verdict::Deny);
    assert!(!result.violations.is_empty());
}

#[test]
fn e2e_after_no_trigger_means_no_violation() {
    let mut engine = engine_from_source(NO_EXFILTRATION_AFTER_PII);
    // external_request events without a prior PII trigger are fine.
    for _ in 0..3 {
        let ev = Event::new("external_request");
        assert_eq!(engine.evaluate(&ev).verdict, Verdict::Allow);
    }
}

// ── until invariant ───────────────────────────────────────────────────────────

// `hold until release`: `event.status != "breach"` must hold on every event
// until `event.status == "cleared"` fires.
//
// NOTE: The `until` operator has lower precedence than `!=` only if the hold
// expression is parenthesised.  Without parentheses, `a != b until c` parses
// as `a != (b until c)` (a relational comparison against a temporal expr),
// which produces no state machine.  Always wrap complex hold conditions: `(φ)
// until ψ`.
const QUARANTINE_UNTIL_CLEARED: &str = r#"
policy QuarantinePolicy {
    proof QuarantineGate {
        invariant StayQuarantinedUntilCleared {
            (event.status != "breach") until event.status == "cleared"
        }
    }
}
"#;

#[test]
fn e2e_until_allows_while_hold_condition_holds() {
    let mut engine = engine_from_source(QUARANTINE_UNTIL_CLEARED);
    for _ in 0..3 {
        let ev = Event::new("status_check").with_field("status", Value::String(s("ok")));
        assert_eq!(engine.evaluate(&ev).verdict, Verdict::Allow);
    }
}

#[test]
fn e2e_until_satisfies_when_release_occurs() {
    let mut engine = engine_from_source(QUARANTINE_UNTIL_CLEARED);
    let cleared = Event::new("status_check").with_field("status", Value::String(s("cleared")));
    assert_eq!(engine.evaluate(&cleared).verdict, Verdict::Allow);
}

#[test]
fn e2e_until_denies_when_hold_breaks_before_release() {
    let mut engine = engine_from_source(QUARANTINE_UNTIL_CLEARED);
    let breach = Event::new("status_check").with_field("status", Value::String(s("breach")));
    let result = engine.evaluate(&breach);
    assert_eq!(result.verdict, Verdict::Deny);
    assert!(!result.violations.is_empty());
}

// ── event.event_type synthetic field ─────────────────────────────────────────

#[test]
fn e2e_event_type_is_accessible_as_field_in_proof_predicates() {
    // Verify that `event.event_type` resolves correctly inside proof invariants
    // (where `on <event_type> { ... }` block filtering is unavailable).
    const CHECK_EVENT_TYPE: &str = r#"
    policy EventTypeCheck {
        proof TypeGate {
            invariant NoExternalRequests {
                never(event.event_type == "external_request")
            }
        }
    }
    "#;
    let mut engine = engine_from_source(CHECK_EVENT_TYPE);
    // A non-matching event type should be allowed.
    assert_eq!(
        engine.evaluate(&Event::new("tool_call")).verdict,
        Verdict::Allow
    );
    // The prohibited type must be denied.
    let result = engine.evaluate(&Event::new("external_request"));
    assert_eq!(result.verdict, Verdict::Deny);
    assert!(!result.violations.is_empty());
}
