# aegis-compiler

The Aegis policy language compiler. Transforms `.aegis` source into `.aegisc` bytecode containing compiled state machines, flattened rules, and resolved metadata.

## Pipeline

```
.aegis source
  → pest PEG parser (src/aegis.pest + src/parser.rs)
  → AST (ast/nodes.rs — every node carries a Span with real byte offsets)
  → TypeChecker (checker/mod.rs — two-pass: register declarations, then check bodies)
  → Validated AST
  → Lowering (lower.rs — flatten inheritance, compile temporal → state machines)
  → CompiledPolicy (ir/mod.rs)
  → Bytecode serialization (bytecode.rs → .aegisc file)
```

## Module Map

- **`aegis.pest`** — pest PEG grammar for the full Aegis language. This is the authoritative parser definition.
- **`parser.rs`** — AST builder. Calls `pest` to parse source text and walks the resulting parse tree to produce `Program`. Entry point: `parse_source(source, filename) -> (Program, DiagnosticSink)`.
- **`ast/`** — AST node definitions. `TemporalExpr` variants map to LTL: `Always` = □φ, `Eventually` = ◇φ, `Never` = □¬φ, `Until` = φUψ, `Next` = Xφ. Every node wraps content in `Spanned<T>` for error reporting.
- **`types/`** — Semantic type system. Subtyping: `never` is bottom, `int <: float`, covariant collections, union subtyping. `TypeEnv` does scoped name resolution with push/pop.
- **`checker/`** — Type checker. Two-pass design so forward references work. Enforces structural constraints: temporal operators only inside `proof`/`invariant` blocks, no nested temporals in v1, `when` clauses must be boolean, rate limits require numeric limit + duration.
- **`ir/`** — Compiled policy IR. `StateMachineBuilder` compiles temporal invariants to explicit automata: `always(φ)` → 2-state, `eventually(φ) within T` → 3-state, `until(φ, ψ)` → 3-state. This is the serialization boundary with the runtime.
- **`lower.rs`** — Lowering pass. Resolves policy inheritance, inlines imports, flattens rules, compiles patterns to decision trees, and invokes `StateMachineBuilder` for temporal invariants.
- **`bytecode.rs`** — `.aegisc` file format: 4-byte magic (`0xAE915C01`), 2-byte version, 2-byte flags, 4-byte payload length, JSON-serialized `CompiledPolicy`. JSON payload means the runtime can also accept policies over HTTP.
- **`diagnostics/`** — Error/warning collection with span-based rendering. All user-facing messages flow through here.
- **`cli.rs`** — `aegisc` binary. Subcommands: `compile`, `check`, `dump`, `inspect`.

## Working in This Crate

- The grammar is `src/aegis.pest`. To change the language syntax, edit the pest grammar first, then update `parser.rs` to handle new rules, then update downstream passes.
- When adding new AST nodes, update in order: `ast/nodes.rs` → `parser.rs` → `checker/mod.rs` → `lower.rs` → `ir/mod.rs`. Missing any step will produce compile errors (by design — exhaustive matches catch it).
- The `CheckContext` struct in the checker tracks structural position (in_proof, in_rule, temporal_depth). If you add new structural constraints, extend this struct.
- `CompiledPolicy` in `ir/` is the contract with `aegis-runtime`. Changes here require coordinated updates to both crates.

## Testing

- Parser tests (`tests/parse_tests.rs`): parse `.aegis` source text → assert AST structure. Use `parser::parse_source` directly.
- Type checker tests (`tests/checker_tests.rs`): programmatically constructed programs with type errors → assert specific diagnostic codes and spans.
- Lowering tests (`tests/lowering_tests.rs`): policies with inheritance/temporal/rate-limit → assert correct IR output.
- Bytecode round-trip: compile → serialize → deserialize → assert equality.
- CLI tests (`tests/cli_tests.rs`): exercise each `aegisc` subcommand (compile, check, dump, inspect) with real temp files.