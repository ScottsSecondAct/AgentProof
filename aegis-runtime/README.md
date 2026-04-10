# aegis-runtime

The runtime verifier for [AutomaGuard](https://github.com/ScottsSecondAct/AutomaGuard). Loads compiled `.aegisc` policies, intercepts agent events, evaluates rules, advances state machines, enforces rate limits, and returns verdicts — all in under 10 milliseconds.

This is the hot path. If you're looking at this crate, you care about latency.

## What It Does

The runtime sits in the agent's execution path. For every tool call an agent attempts:

1. Receives an `Event` (tool name, parameters, session context)
2. Evaluates compiled rules from the loaded policy
3. Advances temporal state machines (tracking `always`, `eventually`, `until` invariants)
4. Checks rate limit windows
5. Returns a `PolicyResult` containing the verdict (allow, deny, audit, or redact), reason, triggered rules, and latency
6. Logs the decision to an append-only audit trail

The runtime *never* parses policy source. It operates entirely on pre-compiled IR produced by [`aegis-compiler`](../aegis-compiler/).

## Usage

### As a Library (Rust)

```rust
use aegis_runtime::{PolicyEngine, Event, Value};
use aegis_compiler::ast::Verdict;
use std::collections::HashMap;

// Load a compiled policy
let engine = PolicyEngine::from_file("guard.aegisc")?;

// Build an event from an intercepted tool call
let event = Event::new("tool_call")
    .with_field("tool", Value::String("http_request".into()))
    .with_field("url", Value::String("https://api.external.com".into()))
    .with_field("method", Value::String("POST".into()));

// Evaluate
let result = engine.evaluate(&event);

match result.verdict {
    Verdict::Allow  => { /* proceed with tool call */ }
    Verdict::Deny   => {
        let reason = result.reason.as_deref().unwrap_or("policy violation");
        eprintln!("Blocked: {}", reason);
    }
    Verdict::Audit  => { /* allow but flag for review */ }
    Verdict::Redact => { /* allow with sanitized fields */ }
}

println!("Evaluation took: {}μs", result.eval_time_us);
```

Most users won't use this crate directly — the [Python SDK](../automaguard-python/) wraps it via pyo3, and the [Rust SDK](../automaguard-rs/) provides an ergonomic higher-level wrapper. This crate is for embedding the verifier directly in custom Rust services.

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

All modules are flat files under `src/`:

- **`engine.rs`** — `PolicyEngine`: loads policies, manages state, entry point for `evaluate()`.
- **`eval.rs`** — Expression evaluator: resolves compiled IR expressions against event fields. Produces `Value` results.
- **`event.rs`** — `Event` and `Value` types: the input to the verifier.
- **`audit.rs`** — Append-only verdict logging. Every evaluation produces an `AuditEntry` with event, matched rules, transitions, verdict, timestamp, and latency.

## Key Types

| Type | Role |
|------|------|
| `Event` | An intercepted agent action (type tag + timestamp + dynamic field map) |
| `Value` | Runtime dynamic type: String, Int, Float, Bool, List, Map, Duration, Null |
| `PolicyResult` | Output: verdict (Allow/Deny/Audit/Redact), optional reason, triggered rule IDs, latency |
| `PolicyEngine` | Owns compiled rules, active state machines, rate limit windows |
| `AuditEntry` | Immutable log record of one evaluation |

## Thread Safety

`PolicyEngine::evaluate()` takes `&mut self` and is not internally synchronized. For concurrent access across threads (e.g. in an async web server), wrap it in a `Mutex`. The Python SDK does this automatically via a `Mutex<PolicyEngine>` inside the pyo3 class. State machine instances are owned by the engine and advanced in-place per call.

## License

Apache 2.0
