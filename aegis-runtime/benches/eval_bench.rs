//! Runtime evaluator benchmarks.
//!
//! Validates the <10ms p99 latency guarantee for policy evaluation.
//! Run with: `cargo bench -p aegis-runtime`
//!
//! Benchmark scenarios (in order of complexity):
//!
//! | Scenario              | Rules | SMs | Rate limiters | Purpose                          |
//! |-----------------------|-------|-----|---------------|----------------------------------|
//! | `baseline`            |   0   |  0  |       0       | Event construction overhead      |
//! | `single_allow`        |   1   |  0  |       0       | Minimum rule dispatch cost       |
//! | `field_condition`     |   1   |  0  |       0       | Field-equality condition eval    |
//! | `multi_rule`          |   5   |  0  |       0       | Rule-scan cost                   |
//! | `realistic`           |  10   |  2  |       1       | Representative production policy |
//! | `rate_limit`          |   0   |  0  |       1       | Sliding-window rate limiter cost |
//! | `state_machines_only` |   0   |  4  |       0       | SM advancement overhead          |
//! | `deep_field_access`   |   1   |  0  |       0       | Nested-map field resolution      |

use std::collections::HashMap;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use smol_str::SmolStr;

use aegis_compiler::ast::{BinaryOp, ConstraintKind, Literal, SeverityLevel, Verdict};
use aegis_compiler::ir::{
    CompiledConstraint, CompiledPolicy, CompiledRule, IRExpr, IRVerdict, PolicyMetadata,
    RefPath, RefRoot, StateMachineBuilder,
};

use aegis_runtime::engine::PolicyEngine;
use aegis_runtime::event::{Event, Value};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn s(v: &str) -> SmolStr {
    SmolStr::new(v)
}

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
            compiler_version: s("bench"),
        },
    }
}

/// Rule with no condition, fires on `tool_call`.
fn unconditional_rule(id: u32, verdict: Verdict) -> CompiledRule {
    CompiledRule {
        id,
        on_events: vec![s("tool_call")],
        condition: None,
        verdicts: vec![IRVerdict { verdict, message: None }],
        actions: vec![],
        severity: None,
    }
}

/// Rule whose condition is `event.tool == literal_string`.
fn field_eq_rule(id: u32, field: &str, value: &str, verdict: Verdict) -> CompiledRule {
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
        on_events: vec![s("tool_call")],
        condition: Some(cond),
        verdicts: vec![IRVerdict { verdict, message: None }],
        actions: vec![],
        severity: None,
    }
}

/// Rule with a compound condition: `event.tool == "http_request" AND event.url != ""`
fn compound_condition_rule(id: u32) -> CompiledRule {
    let cond = IRExpr::Binary {
        op: BinaryOp::And,
        left: Box::new(IRExpr::Binary {
            op: BinaryOp::Eq,
            left: Box::new(IRExpr::Ref(RefPath {
                root: RefRoot::Event,
                fields: vec![s("tool")],
            })),
            right: Box::new(IRExpr::Literal(Literal::String(s("http_request")))),
        }),
        right: Box::new(IRExpr::Binary {
            op: BinaryOp::Neq,
            left: Box::new(IRExpr::Ref(RefPath {
                root: RefRoot::Event,
                fields: vec![s("url")],
            })),
            right: Box::new(IRExpr::Literal(Literal::String(s("")))),
        }),
    };
    CompiledRule {
        id,
        on_events: vec![s("tool_call")],
        condition: Some(cond),
        verdicts: vec![IRVerdict { verdict: Verdict::Deny, message: None }],
        actions: vec![],
        severity: None,
    }
}

/// An `always(event.tool != "exec")` state machine.
fn always_not_exec_sm() -> aegis_compiler::ir::StateMachine {
    let predicate = IRExpr::Binary {
        op: BinaryOp::Neq,
        left: Box::new(IRExpr::Ref(RefPath {
            root: RefRoot::Event,
            fields: vec![s("tool")],
        })),
        right: Box::new(IRExpr::Literal(Literal::String(s("exec")))),
    };
    StateMachineBuilder::new().compile_always(s("Safety"), s("NoExec"), predicate, None)
}

/// A `never(event.url starts with "file://")` state machine (approximated with equality).
fn never_file_url_sm() -> aegis_compiler::ir::StateMachine {
    let predicate = IRExpr::Binary {
        op: BinaryOp::Eq,
        left: Box::new(IRExpr::Ref(RefPath {
            root: RefRoot::Event,
            fields: vec![s("scheme")],
        })),
        right: Box::new(IRExpr::Literal(Literal::String(s("file")))),
    };
    StateMachineBuilder::new().compile_never(s("Safety"), s("NoFile"), predicate)
}

/// An `eventually(event.tool == "verify")` state machine without deadline.
fn eventually_sm() -> aegis_compiler::ir::StateMachine {
    let predicate = IRExpr::Binary {
        op: BinaryOp::Eq,
        left: Box::new(IRExpr::Ref(RefPath {
            root: RefRoot::Event,
            fields: vec![s("tool")],
        })),
        right: Box::new(IRExpr::Literal(Literal::String(s("verify")))),
    };
    StateMachineBuilder::new().compile_eventually(s("Safety"), s("MustVerify"), predicate, None)
}

fn rate_limit_constraint(target: &str, limit: u64, window_ms: u64) -> CompiledConstraint {
    CompiledConstraint {
        kind: ConstraintKind::RateLimit,
        target: s(target),
        limit,
        window_millis: window_ms,
    }
}

/// A representative tool_call event with common fields.
fn tool_call_event(tool: &str, url: &str) -> Event {
    Event::new("tool_call")
        .with_field("tool", Value::String(s(tool)))
        .with_field("url", Value::String(s(url)))
        .with_field("method", Value::String(s("GET")))
        .with_field("scheme", Value::String(s("https")))
        .with_field("timeout_ms", Value::Int(5000))
}

/// Event with a deeply nested payload (simulates large LLM tool call args).
fn nested_event() -> Event {
    let inner = {
        let mut m = HashMap::new();
        m.insert(s("host"), Value::String(s("api.example.com")));
        m.insert(s("port"), Value::Int(443));
        m.insert(s("tls"), Value::Bool(true));
        Value::Map(m)
    };
    let endpoint = {
        let mut m = HashMap::new();
        m.insert(s("url"), Value::String(s("https://api.example.com/v2/data")));
        m.insert(s("connection"), inner);
        Value::Map(m)
    };
    let mut args = HashMap::new();
    args.insert(s("endpoint"), endpoint);
    args.insert(s("payload_size"), Value::Int(1024));
    args.insert(s("retry_count"), Value::Int(3));

    let mut ev = Event::new("external_request");
    ev.fields.extend(args);
    ev
}

// ── Policy factories ──────────────────────────────────────────────────────────

fn policy_baseline() -> CompiledPolicy {
    empty_policy("baseline")
}

fn policy_single_allow() -> CompiledPolicy {
    let mut p = empty_policy("single_allow");
    p.rules.push(unconditional_rule(0, Verdict::Allow));
    p
}

fn policy_field_condition() -> CompiledPolicy {
    let mut p = empty_policy("field_condition");
    // Deny if tool == "exec"; otherwise allow
    p.rules.push(field_eq_rule(0, "tool", "exec", Verdict::Deny));
    p
}

fn policy_multi_rule() -> CompiledPolicy {
    let mut p = empty_policy("multi_rule");
    // 5 rules: audit on various tool names
    for (i, name) in ["exec", "shell", "rm", "sudo", "chmod"].iter().enumerate() {
        p.rules.push(field_eq_rule(i as u32, "tool", name, Verdict::Audit));
    }
    p
}

/// The primary production-representative benchmark:
/// 10 rules + 2 state machines + 1 rate limiter.
fn policy_realistic() -> CompiledPolicy {
    let mut p = empty_policy("realistic");

    // 8 field-equality rules (common allow-list / deny-list pattern)
    let allowed_tools = ["search", "read_file", "write_file", "db_query",
                         "list_dir", "stat", "env_read", "log_write"];
    for (i, name) in allowed_tools.iter().enumerate() {
        p.rules.push(field_eq_rule(i as u32, "tool", name, Verdict::Allow));
    }

    // 1 compound-condition deny rule (tool=http_request with non-empty url)
    p.rules.push(compound_condition_rule(8));

    // 1 unconditional audit rule for all unmatched tool_calls
    p.rules.push(unconditional_rule(9, Verdict::Audit));

    // 2 state machines
    p.state_machines.push(always_not_exec_sm());
    p.state_machines.push(never_file_url_sm());

    // 1 rate limiter: max 100 tool_calls per minute
    p.constraints.push(rate_limit_constraint("tool_call", 100, 60_000));

    p
}

fn policy_rate_limit_only() -> CompiledPolicy {
    let mut p = empty_policy("rate_limit");
    p.constraints.push(rate_limit_constraint("tool_call", 1_000_000, 60_000));
    p
}

fn policy_state_machines_only() -> CompiledPolicy {
    let mut p = empty_policy("state_machines");
    p.state_machines.push(always_not_exec_sm());
    p.state_machines.push(never_file_url_sm());
    p.state_machines.push(eventually_sm());
    // 4th SM: another always for breadth
    let pred = IRExpr::Literal(Literal::Bool(true));
    p.state_machines.push(
        StateMachineBuilder::new().compile_always(s("P"), s("I"), pred, None),
    );
    p
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

/// Benchmark each policy scenario against a representative event.
fn bench_evaluate(c: &mut Criterion) {
    let scenarios: &[(&str, fn() -> CompiledPolicy)] = &[
        ("baseline",            policy_baseline),
        ("single_allow",        policy_single_allow),
        ("field_condition",     policy_field_condition),
        ("multi_rule_5",        policy_multi_rule),
        ("realistic_10r_2sm",   policy_realistic),
        ("rate_limit_only",     policy_rate_limit_only),
        ("state_machines_4",    policy_state_machines_only),
    ];

    let event = tool_call_event("http_request", "https://api.example.com/data");

    let mut group = c.benchmark_group("evaluate");
    group.throughput(Throughput::Elements(1));

    for (name, make_policy) in scenarios {
        group.bench_with_input(
            BenchmarkId::new("policy", name),
            name,
            |b, _| {
                b.iter_batched(
                    || PolicyEngine::new(make_policy()),
                    |mut engine| {
                        let result = engine.evaluate(&event);
                        // Prevent the compiler from optimising away the evaluation.
                        std::hint::black_box(result.verdict)
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

/// Benchmark throughput: how many events/second can the realistic policy sustain?
///
/// Uses a pre-warmed engine (reused across iterations) to measure steady-state
/// throughput rather than cold-start cost.
fn bench_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");
    group.throughput(Throughput::Elements(1));

    // Realistic policy, steady-state (engine warmed up before iterations start)
    group.bench_function("realistic_steady_state", |b| {
        let mut engine = PolicyEngine::new(policy_realistic());
        let event = tool_call_event("search", "https://api.example.com/search?q=test");
        b.iter(|| {
            let result = engine.evaluate(&event);
            std::hint::black_box(result.verdict)
        });
    });

    // Baseline steady-state for comparison
    group.bench_function("baseline_steady_state", |b| {
        let mut engine = PolicyEngine::new(policy_baseline());
        let event = tool_call_event("search", "");
        b.iter(|| {
            let result = engine.evaluate(&event);
            std::hint::black_box(result.verdict)
        });
    });

    group.finish();
}

/// Benchmark evaluation with a deeply nested event payload.
///
/// Exercises the field resolution path for complex, real-world tool call arguments.
fn bench_nested_event(c: &mut Criterion) {
    let mut group = c.benchmark_group("nested_event");
    group.throughput(Throughput::Elements(1));

    group.bench_function("realistic_policy_nested_payload", |b| {
        b.iter_batched(
            || {
                let engine = PolicyEngine::new(policy_realistic());
                let event = nested_event();
                (engine, event)
            },
            |(mut engine, event)| {
                let result = engine.evaluate(&event);
                std::hint::black_box(result.verdict)
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmark a stream of 100 events through the realistic policy.
///
/// Exercises rate-limiter sliding-window eviction and state machine
/// advancement across a realistic burst of agent activity.
fn bench_event_stream(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_stream");

    let stream: Vec<Event> = (0..100)
        .map(|i| {
            let tool = if i % 10 == 0 { "http_request" } else { "search" };
            let url = if i % 10 == 0 { "https://api.external.com/data" } else { "" };
            tool_call_event(tool, url)
        })
        .collect();

    group.throughput(Throughput::Elements(stream.len() as u64));

    group.bench_function("100_events_realistic_policy", |b| {
        b.iter_batched(
            || PolicyEngine::new(policy_realistic()),
            |mut engine| {
                for event in &stream {
                    let result = engine.evaluate(event);
                    std::hint::black_box(result.verdict);
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_evaluate,
    bench_throughput,
    bench_nested_event,
    bench_event_stream,
);
criterion_main!(benches);
