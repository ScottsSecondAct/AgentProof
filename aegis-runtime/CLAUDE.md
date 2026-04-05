# aegis-runtime

The runtime verifier. Loads compiled `.aegisc` policies, intercepts agent events, evaluates rules, advances state machines, enforces rate limits, and returns verdicts. This is the hot path — latency matters above all else.

## Performance Target

**< 10ms per event evaluation.** This is a hard requirement, not a goal. Agent tool calls happen synchronously; if the verifier is slow, the agent is slow. Benchmark regressions above 10ms are blocking.

## Module Map

- **`engine/`** — The core `PolicyEngine`. Loads `CompiledPolicy` from `.aegisc` bytecode or JSON. Manages active policy state. Entry point: `engine.evaluate(event) -> Verdict`.
- **`eval/`** — Expression evaluator. Evaluates compiled IR expressions (`IrExpr`) against an `Event`'s field map. Produces `Value` results. Must be allocation-light on the hot path.
- **`state/`** — State machine executor. Advances compiled automata on each event. Tracks temporal invariant status: `always` monitors for violations, `eventually` monitors for satisfaction within windows, `until` tracks precondition holding. Handles timeout-driven transitions for `within` clauses.
- **`audit/`** — Verdict logging. Append-only. Every evaluation produces an `AuditEntry` with: event, matched rules, state machine transitions, final verdict, timestamp, and latency. The dashboard reads from this layer.

## Key Types

- **`Event`** — An intercepted agent action. Carries: event type (tool_call, data_access, etc.), timestamp, and a `HashMap<SmolStr, Value>` of dynamic fields. This is the boundary between the SDK and the verifier.
- **`Value`** — Runtime dynamic type: String, Int, Float, Bool, List, Map, Null. The expression evaluator operates on these.
- **`Verdict`** — The output: Allow, Deny (with reason + severity), Audit (log but allow), Redact (allow but sanitize fields).
- **`PolicyEngine`** — Owns compiled rules, active state machines, and rate limit windows. Thread-safe (interior mutability via atomics/locks where needed for concurrent evaluation).

## Design Constraints

- **No policy parsing at runtime.** The engine loads pre-compiled IR. If you're tempted to add a "parse from string" convenience method, don't — that belongs in the compiler crate.
- **No network I/O in the evaluation path.** Audit logging can be async/batched, but `evaluate()` itself must be synchronous and allocation-minimal.
- **State machines are the hard part.** The `state/` module manages per-session automaton instances. An agent may have multiple active temporal invariants being tracked simultaneously. State machine instances are keyed by (policy_id, invariant_id, session_id).
- **Rate limit windows use sliding windows, not fixed buckets.** This prevents burst-at-boundary exploits.

## Dependencies

- `aegis-compiler` — for `CompiledPolicy`, `IrExpr`, `StateMachine`, and all IR types. This is a compile-time dependency only; at runtime we operate on deserialized data.
- `serde` / `serde_json` — for `.aegisc` deserialization.
- `smol_str` — consistent with the compiler's string representation.
- `tokio` — **only** for the MCP proxy interceptor (planned). The core `evaluate()` path is synchronous.

## Working in This Crate

- When modifying the expression evaluator (`eval/`), benchmark before and after. Use `cargo bench` with the runtime benchmark suite.
- State machine transitions must be deterministic given the same event sequence. If you're debugging a state machine issue, enable the `trace` feature flag for step-by-step transition logging.
- The `AuditEntry` struct is append-only by design. Adding fields is fine; removing or renaming fields is a breaking change for the dashboard.
- `Event` construction happens in the Python SDK (via pyo3), not here. If you need to change the `Event` schema, coordinate with `automaguard-python/`.

## Testing

- **Unit tests**: Each evaluator operation (binary ops, field access, function calls) gets dedicated tests with edge cases (null fields, type mismatches, overflow).
- **State machine tests**: For each temporal operator, test the happy path, violation path, and timeout path. Test interleaved events across multiple simultaneous invariants.
- **Benchmarks**: `cargo bench` suite with realistic event payloads. Track p50, p95, p99 latencies. The CI should fail if p99 exceeds 10ms on the benchmark suite.
- **Fuzz testing**: The expression evaluator should be fuzz-tested with arbitrary `Value` inputs to catch panics.