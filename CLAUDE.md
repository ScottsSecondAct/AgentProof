# AutomaGuard

AutomaGuard is a formal verification and policy enforcement engine for production AI agents. It provides mathematical guarantees — not best-effort checks — that agents comply with safety and behavioral constraints.

## What This Is

Three components:

1. **Aegis Policy Language** — a domain-specific language for expressing agent constraints, compiled (not interpreted) to state machines
2. **Runtime Verifier** — a Rust engine that evaluates agent events against compiled policies at <10ms latency
3. **Python SDK** — pyo3 bindings providing drop-in enforcement for LangChain, OpenAI, and raw tool-calling agents

The dashboard (Next.js) and TypeScript SDK are planned but not yet built.

## Project Layout

```
AutomaGuard/
├── CLAUDE.md                  # You are here
├── aegis-compiler/            # Rust: parser, type checker, IR lowering, bytecode
│   ├── src/aegis.pest         # pest PEG grammar
│   └── CLAUDE.md
├── aegis-runtime/             # Rust: event evaluation, state machines, rate limits
│   └── CLAUDE.md
├── automaguard-python/         # Rust (pyo3) + Python: SDK and framework integrations
│   └── CLAUDE.md
├── examples/                  # Example .aegis policy files
└── dashboard/                 # (planned) Next.js + Tailwind compliance UI
```

## Architecture in One Paragraph

`.aegis` source → pest PEG parse (`src/aegis.pest`) → typed AST → `TypeChecker` → validated AST → `Lowering` → `CompiledPolicy` (with state machines) → `.aegisc` bytecode. At runtime, the verifier loads `.aegisc` files, intercepts agent tool calls, evaluates compiled rules, advances state machines for temporal invariants, enforces rate limits, and returns verdicts (allow/deny/audit/redact). The Python SDK wraps this via pyo3 so users write `enforce(client, policy="guard.aegisc")`.

## Language and Tooling

- **Rust edition**: 2021
- **Minimum Rust version**: stable (no nightly features)
- **Python**: 3.9+ via maturin build backend
- **Parser**: pest PEG (`aegis-compiler/src/aegis.pest`)
- **Key crates**: `serde`, `serde_json`, `smol_str`, `thiserror`, `pest`, `pest_derive`, `pyo3`, `tokio` (runtime only)

## Coding Conventions

### Rust

- Run `cargo fmt` before committing. No exceptions.
- Run `cargo clippy -- -D warnings` — treat all warnings as errors.
- **No `unwrap()` or `expect()` in library code.** Use `Result`/`Option` propagation. `unwrap()` is acceptable only in tests and the CLI's `main()`.
- Prefer `SmolStr` over `String` for identifiers and short strings (inline-able, cheap to clone).
- Every public type and function gets a doc comment. Module-level `//!` docs explain the module's role in the pipeline.
- Error types use `thiserror` derive macros. User-facing error messages must include source spans.
- Prefer exhaustive `match` over `_ =>` wildcards — the compiler should catch new variants.

### Python

- Type hints on all public API functions.
- Docstrings on all public classes and methods.
- Keep the Python layer thin — business logic belongs in Rust.

### General

- Commit messages: imperative mood, e.g., "Add rate limit window tracking to runtime"
- No force pushes to `main`.
- Tests go in the same crate under `#[cfg(test)]` modules or in a `tests/` directory for integration tests.

## Key Design Decisions

- **Compiled, not interpreted.** Policies compile to state machines. The runtime does not parse or evaluate policy source at request time. This is what makes <10ms latency possible and what differentiates AutomaGuard from regex/validator approaches.
- **Temporal logic is the moat.** `always`, `eventually`, `until`, `never` compile to Büchi-like automata. This provides mathematical guarantees that sequence-level constraints hold, not just per-event checks.
- **The verifier is the product.** The compiler is a means to an end. Optimize for runtime performance and correctness above compiler elegance.
- **Append-only audit trail.** Every verdict is logged. Nothing is mutable after the fact. This is a compliance requirement, not a nice-to-have.

## Testing Philosophy

- Unit tests for each compiler pass (parser → AST, AST → type check, type check → IR, IR → bytecode).
- Property-based tests for the runtime evaluator (round-trip serialization, state machine transitions).
- Integration tests that compile a `.aegis` file and verify runtime behavior end-to-end.
- Latency benchmarks for the runtime verifier — regressions above 10ms on the benchmark suite are blocking.

## What Not to Do

- Don't add async to the compiler. Only the runtime needs async (for the MCP proxy interceptor).
- Don't use `Box<dyn Error>` — use concrete error enums.
- Don't introduce new dependencies without justification. The runtime must stay lean.
- Don't implement YAML/JSON policy formats. The Aegis Policy Language is the interface; alternative formats dilute the moat.