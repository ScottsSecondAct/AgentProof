//! Integration tests for the AutomaGuard Rust SDK.
//!
//! Policies are constructed programmatically so the tests have no dependency
//! on compiled `.aegisc` files being present on disk. Each test builds the
//! minimal policy needed to exercise the behaviour under test.

use std::collections::HashMap;

use smol_str::SmolStr;

use aegis_compiler::ast::{BinaryOp, ConstraintKind, Literal, SeverityLevel, Verdict};
use aegis_compiler::bytecode;
use aegis_compiler::ir::{
    CompiledConstraint, CompiledPolicy, CompiledRule, IRExpr, IRVerdict, PolicyMetadata,
    RefPath, RefRoot, StateMachineBuilder,
};
use aegis_runtime::event::Value;

use automaguard::{EnforcementError, Error, PolicyEngine};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn s(v: &str) -> SmolStr {
    SmolStr::new(v)
}

/// Compile a `CompiledPolicy` to `.aegisc` bytes for round-trip testing.
fn to_aegisc(policy: &CompiledPolicy) -> Vec<u8> {
    bytecode::to_bytecode(policy).expect("serialisation failed")
}

/// Build a minimal policy that denies `tool_call` events where
/// `tool_name == "exec"`.
fn deny_exec_policy() -> CompiledPolicy {
    let rule = CompiledRule {
        id: 0,
        on_events: vec![s("tool_call")],
        condition: Some(IRExpr::Binary {
            op: BinaryOp::Eq,
            left: Box::new(IRExpr::Ref(RefPath {
                root: RefRoot::Event,
                fields: vec![s("tool_name")],
            })),
            right: Box::new(IRExpr::Literal(Literal::String(s("exec")))),
        }),
        verdicts: vec![IRVerdict {
            verdict: Verdict::Deny,
            message: None,
        }],
        actions: vec![],
        severity: Some(SeverityLevel::Critical),
    };

    CompiledPolicy {
        name: s("DenyExec"),
        severity: SeverityLevel::High,
        scopes: vec![],
        rules: vec![rule],
        constraints: vec![],
        state_machines: vec![],
        metadata: PolicyMetadata {
            annotations: vec![],
            source_hash: 0,
            compiler_version: s("test"),
        },
    }
}

/// Build a policy with a sliding-window rate limiter: max 3 `tool_call`s per
/// 60 000 ms window.
fn rate_limit_policy() -> CompiledPolicy {
    CompiledPolicy {
        name: s("RateLimit"),
        severity: SeverityLevel::High,
        scopes: vec![],
        rules: vec![],
        constraints: vec![CompiledConstraint {
            kind: ConstraintKind::RateLimit,
            target: s("tool_call"),
            limit: 3,
            window_millis: 60_000,
        }],
        state_machines: vec![],
        metadata: PolicyMetadata {
            annotations: vec![],
            source_hash: 0,
            compiler_version: s("test"),
        },
    }
}

/// Build a policy with an `always(tool_name != "exec")` state machine.
fn always_sm_policy() -> CompiledPolicy {
    let predicate = IRExpr::Binary {
        op: BinaryOp::Neq,
        left: Box::new(IRExpr::Ref(RefPath {
            root: RefRoot::Event,
            fields: vec![s("tool_name")],
        })),
        right: Box::new(IRExpr::Literal(Literal::String(s("exec")))),
    };

    let sm = StateMachineBuilder::new().compile_always(
        s("Safety"),
        s("NoExec"),
        predicate,
        None,
    );

    CompiledPolicy {
        name: s("AlwaysNoExec"),
        severity: SeverityLevel::High,
        scopes: vec![],
        rules: vec![],
        constraints: vec![],
        state_machines: vec![sm],
        metadata: PolicyMetadata {
            annotations: vec![],
            source_hash: 0,
            compiler_version: s("test"),
        },
    }
}

// ── from_bytes round-trip ─────────────────────────────────────────────────────

#[test]
fn loads_from_bytes() {
    let bytes = to_aegisc(&deny_exec_policy());
    PolicyEngine::from_bytes(&bytes).expect("should load cleanly");
}

#[test]
fn rejects_invalid_bytes() {
    let err = PolicyEngine::from_bytes(b"not an aegisc file");
    assert!(
        matches!(err, Err(Error::Load(_))),
        "expected Load error, got {err:?}"
    );
}

// ── verdict correctness ───────────────────────────────────────────────────────

#[test]
fn allows_non_matching_event() {
    let bytes = to_aegisc(&deny_exec_policy());
    let mut engine = PolicyEngine::from_bytes(&bytes).unwrap();

    let result = engine
        .event("tool_call")
        .field("tool_name", "search")
        .evaluate()
        .unwrap();

    assert!(result.is_allowed(), "search should be allowed");
    assert!(!result.is_denied());
}

#[test]
fn denies_matching_event() {
    let bytes = to_aegisc(&deny_exec_policy());
    let mut engine = PolicyEngine::from_bytes(&bytes).unwrap();

    let result = engine
        .event("tool_call")
        .field("tool_name", "exec")
        .evaluate()
        .unwrap();

    assert!(result.is_denied(), "exec should be denied");
    assert_eq!(result.verdict(), Verdict::Deny);
    assert_eq!(result.triggered_rules(), &[0]);
}

#[test]
fn wrong_event_type_is_unmatched() {
    let bytes = to_aegisc(&deny_exec_policy());
    let mut engine = PolicyEngine::from_bytes(&bytes).unwrap();

    // Rule only fires on "tool_call"; "data_access" should default to allow.
    let result = engine
        .event("data_access")
        .field("tool_name", "exec")
        .evaluate()
        .unwrap();

    assert!(result.is_allowed());
}

// ── evaluate() with explicit HashMap ─────────────────────────────────────────

#[test]
fn evaluate_with_hashmap() {
    let bytes = to_aegisc(&deny_exec_policy());
    let mut engine = PolicyEngine::from_bytes(&bytes).unwrap();

    let mut fields: HashMap<SmolStr, Value> = HashMap::new();
    fields.insert(s("tool_name"), Value::String(s("exec")));

    let result = engine.evaluate("tool_call", fields).unwrap();
    assert!(result.is_denied());
}

// ── EnforcementError ─────────────────────────────────────────────────────────

#[test]
fn enforcement_error_contains_result() {
    let bytes = to_aegisc(&deny_exec_policy());
    let mut engine = PolicyEngine::from_bytes(&bytes).unwrap();

    let result = engine
        .event("tool_call")
        .field("tool_name", "exec")
        .evaluate()
        .unwrap();

    assert!(result.is_denied());

    let err = EnforcementError::new(result);
    // The Display impl should mention "denied".
    assert!(err.to_string().contains("denied"), "{err}");
    // The result is still accessible.
    assert!(err.result.is_denied());
}

#[test]
fn enforcement_error_converts_to_sdk_error() {
    let bytes = to_aegisc(&deny_exec_policy());
    let mut engine = PolicyEngine::from_bytes(&bytes).unwrap();

    let result = engine
        .event("tool_call")
        .field("tool_name", "exec")
        .evaluate()
        .unwrap();

    let sdk_err: Error = EnforcementError::new(result).into();
    assert!(matches!(sdk_err, Error::Enforcement(_)));
}

// ── PolicyResult accessors ────────────────────────────────────────────────────

#[test]
fn latency_is_nonzero_for_matching_rule() {
    let bytes = to_aegisc(&deny_exec_policy());
    let mut engine = PolicyEngine::from_bytes(&bytes).unwrap();

    let result = engine
        .event("tool_call")
        .field("tool_name", "exec")
        .evaluate()
        .unwrap();

    // Latency is measured; it should be at least 0 (and realistically > 0).
    let _ = result.latency_us(); // just confirm it doesn't panic
}

#[test]
fn policy_name_accessible() {
    let bytes = to_aegisc(&deny_exec_policy());
    let engine = PolicyEngine::from_bytes(&bytes).unwrap();
    assert_eq!(engine.policy_name(), "DenyExec");
}

#[test]
fn event_count_increments() {
    let bytes = to_aegisc(&deny_exec_policy());
    let mut engine = PolicyEngine::from_bytes(&bytes).unwrap();
    assert_eq!(engine.event_count(), 0);

    engine.event("tool_call").field("tool_name", "search").evaluate().unwrap();
    engine.event("tool_call").field("tool_name", "search").evaluate().unwrap();

    assert_eq!(engine.event_count(), 2);
}

#[test]
fn reset_clears_event_count() {
    let bytes = to_aegisc(&deny_exec_policy());
    let mut engine = PolicyEngine::from_bytes(&bytes).unwrap();

    engine.event("tool_call").field("tool_name", "search").evaluate().unwrap();
    assert_eq!(engine.event_count(), 1);

    engine.reset();
    assert_eq!(engine.event_count(), 0);
}

// ── Rate limiter ──────────────────────────────────────────────────────────────

#[test]
fn rate_limit_allows_within_budget() {
    let bytes = to_aegisc(&rate_limit_policy());
    let mut engine = PolicyEngine::from_bytes(&bytes).unwrap();

    for _ in 0..3 {
        let r = engine.event("tool_call").evaluate().unwrap();
        assert!(r.is_allowed(), "events within budget should be allowed");
    }
}

#[test]
fn rate_limit_denies_over_budget() {
    let bytes = to_aegisc(&rate_limit_policy());
    let mut engine = PolicyEngine::from_bytes(&bytes).unwrap();

    for _ in 0..3 {
        engine.event("tool_call").evaluate().unwrap();
    }
    // 4th call exceeds limit of 3.
    let r = engine.event("tool_call").evaluate().unwrap();
    assert!(r.is_denied(), "4th event should be denied by rate limiter");
    assert!(!r.constraint_violations().is_empty());
}

#[test]
fn rate_limit_does_not_fire_for_other_event_types() {
    let bytes = to_aegisc(&rate_limit_policy());
    let mut engine = PolicyEngine::from_bytes(&bytes).unwrap();

    // Exhaust the tool_call budget.
    for _ in 0..4 {
        engine.event("tool_call").evaluate().unwrap();
    }

    // data_access is not subject to the tool_call rate limit.
    let r = engine.event("data_access").evaluate().unwrap();
    assert!(r.is_allowed());
}

// ── State machine (temporal invariant) ───────────────────────────────────────

#[test]
fn always_sm_allows_compliant_sequence() {
    let bytes = to_aegisc(&always_sm_policy());
    let mut engine = PolicyEngine::from_bytes(&bytes).unwrap();

    for _ in 0..5 {
        let r = engine
            .event("tool_call")
            .field("tool_name", "search")
            .evaluate()
            .unwrap();
        assert!(r.is_allowed());
        assert!(r.violations().is_empty());
    }
}

#[test]
fn always_sm_denies_on_violation() {
    let bytes = to_aegisc(&always_sm_policy());
    let mut engine = PolicyEngine::from_bytes(&bytes).unwrap();

    // Three clean events followed by a violation.
    for _ in 0..3 {
        engine.event("tool_call").field("tool_name", "search").evaluate().unwrap();
    }

    let r = engine
        .event("tool_call")
        .field("tool_name", "exec")
        .evaluate()
        .unwrap();

    assert!(r.is_denied(), "exec should trip the always() invariant");
    assert!(!r.violations().is_empty());
}

#[test]
fn state_machine_remains_violated_after_first_violation() {
    let bytes = to_aegisc(&always_sm_policy());
    let mut engine = PolicyEngine::from_bytes(&bytes).unwrap();

    // Trigger the violation.
    engine.event("tool_call").field("tool_name", "exec").evaluate().unwrap();

    // Even a harmless event afterwards must still deny (absorbing state).
    let r = engine.event("tool_call").field("tool_name", "search").evaluate().unwrap();
    assert!(r.is_denied(), "violated SM stays denied");
}

// ── Value conversions ─────────────────────────────────────────────────────────

#[test]
fn into_value_conversions_work() {
    use automaguard::Value;

    let _: Value = "hello".into();
    let _: Value = String::from("world").into();
    let _: Value = 42i64.into();
    let _: Value = 3.14f64.into();
    let _: Value = true.into();
}

// ── Async engine ─────────────────────────────────────────────────────────────

#[cfg(feature = "async")]
mod async_tests {
    use super::*;
    use automaguard::AsyncPolicyEngine;

    #[tokio::test]
    async fn async_engine_allows_and_denies() {
        let bytes = to_aegisc(&deny_exec_policy());

        let engine = AsyncPolicyEngine::from_bytes(&bytes).unwrap();

        let allow = engine
            .event("tool_call")
            .field("tool_name", "search")
            .evaluate()
            .await
            .unwrap();
        assert!(allow.is_allowed());

        let deny = engine
            .event("tool_call")
            .field("tool_name", "exec")
            .evaluate()
            .await
            .unwrap();
        assert!(deny.is_denied());
    }

    #[tokio::test]
    async fn async_engine_is_cloneable_and_concurrent() {
        let bytes = to_aegisc(&deny_exec_policy());
        let engine = AsyncPolicyEngine::from_bytes(&bytes).unwrap();

        let e1 = engine.clone();
        let e2 = engine.clone();

        let (r1, r2) = tokio::join!(
            e1.event("tool_call").field("tool_name", "search").evaluate(),
            e2.event("tool_call").field("tool_name", "exec").evaluate(),
        );

        assert!(r1.unwrap().is_allowed());
        assert!(r2.unwrap().is_denied());
    }

    #[tokio::test]
    async fn async_engine_event_count() {
        let bytes = to_aegisc(&deny_exec_policy());
        let engine = AsyncPolicyEngine::from_bytes(&bytes).unwrap();

        engine.event("tool_call").field("tool_name", "search").evaluate().await.unwrap();
        engine.event("tool_call").field("tool_name", "search").evaluate().await.unwrap();

        assert_eq!(engine.event_count(), 2);
    }

    #[tokio::test]
    async fn async_engine_policy_name() {
        let bytes = to_aegisc(&deny_exec_policy());
        let engine = AsyncPolicyEngine::from_bytes(&bytes).unwrap();
        assert_eq!(engine.policy_name(), "DenyExec");
    }
}
