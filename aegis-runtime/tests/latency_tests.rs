//! Latency regression tests.
#![cfg(not(debug_assertions))]
//!
//! Enforces the hard <10ms p99 latency requirement documented in CLAUDE.md.
//! Each test compiles a policy from source, runs N evaluations, and asserts
//! that the 99th-percentile `eval_time_us` stays within budget.
//!
//! These tests are gated on `#[cfg(not(debug_assertions))]` because debug
//! builds disable optimisations and will always exceed the threshold.
//! Run them with:
//!
//!   cargo test --release -p aegis-runtime --test latency_tests
//!
//! CI should run this suite in addition to the regular debug test suite.

use aegis_compiler::{lower, parser};
use aegis_runtime::engine::PolicyEngine;
use aegis_runtime::event::{Event, Value};
use smol_str::SmolStr;

fn s(v: &str) -> SmolStr {
    SmolStr::new(v)
}

fn engine_from_source(source: &str) -> PolicyEngine {
    let (program, parse_diags) = parser::parse_source(source, "latency_test.aegis");
    assert!(
        !parse_diags.has_errors(),
        "parse errors:\n{}",
        parse_diags.render(source, "latency_test.aegis")
    );
    let (compiled, compile_diags) = lower::compile(&program);
    assert!(
        !compile_diags.has_errors(),
        "compile errors:\n{}",
        compile_diags.render(source, "latency_test.aegis")
    );
    assert!(!compiled.is_empty(), "must define at least one policy");
    PolicyEngine::new(compiled.into_iter().next().unwrap())
}

/// Compute the p99 value from a sorted-in-place slice of u64 measurements.
fn p99(samples: &mut Vec<u64>) -> u64 {
    samples.sort_unstable();
    let idx = (samples.len() as f64 * 0.99) as usize;
    samples[idx.min(samples.len() - 1)]
}

// ─────────────────────────────────────────────────────────────────────────────
//  Policies under test
// ─────────────────────────────────────────────────────────────────────────────

/// A realistic production-style policy: 5 rules, 2 temporal invariants, 1
/// rate limit.  This is the primary benchmark for the <10ms SLA.
const REALISTIC_POLICY: &str = r#"
policy RealisticGuard {
    rate_limit tool_call: 100 per 1m

    on tool_call {
        when event.tool_name in ["drop_table", "truncate_table", "delete_database"]
        deny with "DDL operations prohibited"
        severity critical
    }

    on tool_call {
        when event.tool_name == "exec"
        deny with "Shell execution prohibited"
        severity high
    }

    on external_request {
        when !(event.domain in ["internal.corp", "api.internal.corp"])
        deny with "External domain not in allowlist"
        severity high
    }

    on data_access {
        when event.classification == "PII"
        audit with "PII record accessed"
        severity medium
    }

    on tool_call {
        audit
    }

    proof SafetyInvariants {
        invariant NoShellExec {
            never(event.tool_name == "exec")
        }
        invariant NoSecretData {
            always(event.classification != "secret")
        }
    }
}
"#;

/// Minimal policy (no rules, no invariants) — establishes the overhead floor.
const BASELINE_POLICY: &str = r#"
policy Baseline {}
"#;

/// Policy with only temporal invariants — no per-event rules.
const INVARIANTS_ONLY_POLICY: &str = r#"
policy InvariantsOnly {
    proof Safety {
        invariant NoExec {
            never(event.tool_name == "exec")
        }
        invariant NoSecret {
            always(event.classification != "secret")
        }
    }
}
"#;

// ─────────────────────────────────────────────────────────────────────────────
//  Latency assertion helper
// ─────────────────────────────────────────────────────────────────────────────

const ITERATIONS: usize = 1_000;
const P99_BUDGET_US: u64 = 10_000; // 10 ms

fn assert_p99_within_budget(label: &str, engine: &mut PolicyEngine, event: &Event) {
    let mut samples: Vec<u64> = (0..ITERATIONS)
        .map(|_| engine.evaluate(event).eval_time_us)
        .collect();
    let p99_us = p99(&mut samples);
    assert!(
        p99_us < P99_BUDGET_US,
        "{label}: p99 latency {p99_us}µs exceeds {P99_BUDGET_US}µs (10ms) budget"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests (release-mode only)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn latency_p99_baseline_policy() {
    let mut engine = engine_from_source(BASELINE_POLICY);
    let event = Event::new("tool_call").with_field("tool_name", Value::String(s("search")));
    assert_p99_within_budget("baseline", &mut engine, &event);
}

#[test]
fn latency_p99_realistic_policy_allow_path() {
    let mut engine = engine_from_source(REALISTIC_POLICY);
    // An event that matches the audit rule but does not violate any invariant.
    let event = Event::new("tool_call").with_field("tool_name", Value::String(s("search")));
    assert_p99_within_budget("realistic/allow", &mut engine, &event);
}

#[test]
fn latency_p99_realistic_policy_deny_path() {
    let mut engine = engine_from_source(REALISTIC_POLICY);
    // An event that hits the deny rule on the first match.
    let event = Event::new("tool_call")
        .with_field("tool_name", Value::String(s("drop_table")));
    assert_p99_within_budget("realistic/deny", &mut engine, &event);
}

#[test]
fn latency_p99_realistic_policy_external_request() {
    let mut engine = engine_from_source(REALISTIC_POLICY);
    let event = Event::new("external_request")
        .with_field("domain", Value::String(s("evil.example.com")));
    assert_p99_within_budget("realistic/external_deny", &mut engine, &event);
}

#[test]
fn latency_p99_invariants_only_policy() {
    let mut engine = engine_from_source(INVARIANTS_ONLY_POLICY);
    let event = Event::new("tool_call").with_field("tool_name", Value::String(s("search")));
    assert_p99_within_budget("invariants_only", &mut engine, &event);
}
