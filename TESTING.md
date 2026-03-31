# Testing Status

## aegis-compiler — 245 tests, all passing

### Unit tests (inline `#[cfg(test)]`, 149 tests)

| Module | Tests | Coverage |
|--------|-------|----------|
| `ast/span.rs` | 11 | `Span` methods, `Spanned<T>` construction and mapping |
| `ast/nodes.rs` | 13 | `DurationLit::to_millis` (all 5 units), `QualifiedName` helpers |
| `types/mod.rs` | 33 | `Ty` predicates, subtyping rules (Never/Error/widening/covariance), `TypeEnv` scoping |
| `diagnostics/mod.rs` | 28 | `DiagnosticSink` emit/count, all named constructors (E0001–E0202), rendering |
| `ir/mod.rs` | 46 | `StateMachineBuilder` for always/eventually/never/until, state kinds, transitions, sequential IDs |
| `bytecode.rs` | 18 | Header fields, round-trip (minimal/metadata/SMs), error cases, JSON output |

### Integration tests (`tests/`, 96 tests)

| File | Tests | Coverage |
|------|-------|----------|
| `tests/adapter_tests.rs` | 42 | `SimpleToken`, `parse_duration_literal`, all token→enum mappings, `OwnedQualifiedName` |
| `tests/checker_tests.rs` | 52 | Valid programs (no errors), E0001–E0304 diagnostic codes, binary op type rules |
| `tests/lowering_tests.rs` | 44 | Empty/minimal policies, metadata, multiple policies, rules (all fields), constraints, proofs/state machines |

### What's not yet tested in aegis-compiler

- **Parse-from-source**: The ANTLR4 parser is not yet integrated. Tests construct ASTs programmatically. Once the grammar generates Rust code, add tests that compile `.aegis` source text end-to-end through the full pipeline.
- **Span accuracy**: Checker and lowering tests use `Span::DUMMY` throughout; no tests verify that error spans point to the correct source location.
- **CLI subcommands**: `aegisc compile`, `check`, `dump`, `inspect` have no automated tests.
- **Policy inheritance / `extends`**: Lowering tests cover the happy path; multi-level inheritance chains and diamond inheritance are not tested.

---

## aegis-runtime — 0 tests

The runtime has no tests at all. Source modules: `engine.rs`, `eval.rs`, `event.rs`, `audit.rs`.

### Needed

- **Evaluator unit tests** (`eval.rs`): binary ops on all type combinations, field access, function calls, null/missing-field edge cases, type-mismatch error paths.
- **State machine tests** (`engine.rs`): happy path (constraint never violated), violation path (constraint violated mid-sequence), timeout path (deadline expires without `eventually` being satisfied) — for each of `always`, `eventually`, `never`, `until`.
- **Rate-limit / quota tests**: window sliding, limit enforcement, reset after window expiry.
- **Audit log tests** (`audit.rs`): every verdict is appended, log is append-only, entries are serializable.
- **Benchmarks**: the <10ms p99 latency guarantee is a core product claim with zero performance validation. Use `criterion` to measure a realistic policy evaluation (10-rule policy, 2 state machines) against a synthetic event stream.
- **Fuzz tests**: `cargo-fuzz` target on the expression evaluator with arbitrary `Event` payloads.

---

## agentproof-python — 0 tests

No tests exist. Source: `src/lib.rs` (pyo3 bindings).

### Needed

- **Round-trip tests**: Python `dict` → Rust `Event` → evaluate against a compiled policy → Python result `dict`. Verify verdict, diagnostics, and metadata survive the boundary.
- **OpenAI client wrapper**: mock `openai.OpenAI` client, assert tool calls are intercepted and verdicts applied.
- **LangChain callback handler**: mock chain invocation, assert the handler fires on tool events and blocks on deny.
- **Pure Python fallback**: when the Rust extension is not importable, assert the fallback raises a clear error (not a silent no-op).
- **Framework edge cases**: Unicode in tool arguments, deeply nested JSON payloads, missing required fields, very large payloads.

---

## End-to-end — 0 tests

### Needed (minimum viable)

1. Write a `.aegis` policy file to a temp directory.
2. Run `aegisc compile` to produce a `.aegisc` bytecode file.
3. Load the bytecode via the Python SDK.
4. Feed a sequence of synthetic agent events.
5. Assert the returned verdicts match expectations (allow, deny, audit).

This test exercises the full pipeline: grammar → compiler → bytecode → runtime → Python binding.

---

## Critical gaps (priority order)

1. **Runtime benchmarks** — the <10ms p99 claim has no validation.
2. **Runtime evaluator + state machine unit tests** — core correctness of the product.
3. **End-to-end compile→evaluate test** — exercises the full pipeline.
4. **ANTLR4 parse-from-source** — blocked on parser integration; needed before any public release.
