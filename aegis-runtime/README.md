# aegis-runtime

The runtime verifier for [AgentProof](https://github.com/ScottsSecondAct/agentproof). Loads compiled `.aegisc` policies, intercepts agent events, evaluates rules, advances state machines, enforces rate limits, and returns verdicts — all in under 10 milliseconds.

This is the hot path. If you're looking at this crate, you care about latency.

## What It Does

The runtime sits in the agent's execution path. For every tool call an agent attempts:

1. Receives an `Event` (tool name, parameters, session context)
2. Evaluates compiled rules from the loaded policy
3. Advances temporal state machines (tracking `always`, `eventually`, `until` invariants)
4. Checks rate limit windows
5. Returns a `Verdict`: allow, deny (with reason and severity), audit, or redact
6. Logs the decision to an append-only audit trail

The runtime *never* parses policy source. It operates entirely on pre-compiled IR produced by [`aegis-compiler`](../aegis-compiler/).

## Usage

### As a Library (Rust)

```rust
use aegis_runtime::{PolicyEngine, Event, Value};
use std::collections::HashMap;

// Load a compiled policy
let engine = PolicyEngine::from_file("guard.aegisc")?;

// Build an event from an intercepted tool call
let mut fields = HashMap::new();
fields.insert("tool".into(), Value::String("http_request".into()));
fields.insert("url".into(), Value::String("https://api.external.com".into()));
fields.insert("method".into(), Value::String("POST".into()));

let event = Event::tool_call(fields);

// Evaluate
let result = engine.evaluate(&event)?;

match result.verdict {
    Verdict::Allow => { /* proceed with tool call */ }
    Verdict::Deny { reason, severity } => {
        eprintln!("Blocked: {} (severity: {:?})", reason, severity);
    }
    Verdict::Audit => { /* allow but flag for review */ }
    Verdict::Redact { fields } => { /* allow with sanitized fields */ }
}

// Every evaluation is logged
println!("Evaluation took: {}μs", result.eval_time_us);
```

Most users won't use this crate directly — the [Python SDK](../agentproof-python/) wraps it via pyo3. This crate is for Rust-native integrations, custom framework adapters, or embedding the verifier in non-Python environments.

## Building

```bash
cargo build --release
cargo test
cargo bench  # run latency benchmarks
```

## Performance

The <10ms target is a hard requirement, not a goal. Design decisions that support it:

- **Compiled state machines, not interpreted rules.** Temporal invariants are pre-compiled to deterministic automata. Transitions are table lookups.
- **No allocations on the hot path** where possible. The expression evaluator reuses buffers. Event fields use `SmolStr`.
- **No network I/O in `evaluate()`.** Audit logging is batched and async. The evaluation path is purely computational.
- **Sliding windows for rate limits**, not fixed time buckets (prevents burst-at-boundary exploits).

## Module Structure

- **`engine/`** — `PolicyEngine`: loads policies, manages state, entry point for `evaluate()`.
- **`eval/`** — Expression evaluator: resolves compiled IR expressions against event fields. Produces `Value` results.
- **`state/`** — State machine executor: advances compiled automata per event, tracks temporal invariant status, handles `within` timeouts.
- **`audit/`** — Append-only verdict logging. Every evaluation produces an `AuditEntry` with event, matched rules, transitions, verdict, timestamp, and latency.

## Key Types

| Type | Role |
|------|------|
| `Event` | An intercepted agent action (type tag + timestamp + dynamic field map) |
| `Value` | Runtime dynamic type: String, Int, Float, Bool, List, Map, Null |
| `Verdict` | Output: Allow, Deny, Audit, or Redact |
| `PolicyEngine` | Owns compiled rules, active state machines, rate limit windows |
| `AuditEntry` | Immutable log record of one evaluation |

## Thread Safety

`PolicyEngine` is thread-safe. You can share a single engine across threads in an async web server (the Python SDK wraps it in a `Mutex` for pyo3). State machine instances are keyed by `(policy_id, invariant_id, session_id)`, so concurrent sessions don't interfere.

## License

Apache 2.0