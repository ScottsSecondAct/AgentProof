//! End-to-end pipeline tests.
//!
//! These tests exercise the full pipeline: `.aegis` source text → parser →
//! type checker → lowering → `CompiledPolicy` → bytecode round-trip →
//! `PolicyEngine::evaluate` → verdict.
//!
//! No stubs or pre-compiled artefacts: each test compiles a policy from source
//! and immediately evaluates events against it.

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

    assert!(!compiled.is_empty(), "source must define at least one policy");

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
    assert_eq!(engine.evaluate(&tool_call("http_get")).verdict, Verdict::Deny);
}

#[test]
fn e2e_conditional_allow_on_non_matching_tool() {
    let mut engine = engine_from_source(BLOCK_HTTP_GET);
    assert_eq!(engine.evaluate(&tool_call("db_query")).verdict, Verdict::Allow);
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
    assert_eq!(engine.evaluate(&tool_call("file_write")).verdict, Verdict::Audit);
}

#[test]
fn e2e_audit_rule_non_matching_tool_allows() {
    let mut engine = engine_from_source(AUDIT_WRITE);
    assert_eq!(engine.evaluate(&tool_call("http_get")).verdict, Verdict::Allow);
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
        assert_eq!(engine.evaluate(&tool_call("http_get")).verdict, Verdict::Allow);
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
    assert_eq!(engine.evaluate(&tool_call("http_get")).verdict, Verdict::Deny);
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

    assert_eq!(engine.evaluate(&tool_call("http_get")).verdict, Verdict::Deny);
    assert_eq!(engine.evaluate(&tool_call("db_query")).verdict, Verdict::Allow);

    let _ = std::fs::remove_file(&path);
}
