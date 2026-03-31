# aegis-compiler

The Aegis policy language compiler. Transforms `.aegis` source into `.aegisc` bytecode containing compiled state machines, flattened rules, and resolved metadata.

## Pipeline

```
.aegis source
  → ANTLR4 lexer/parser (AegisLexer.g4 + AegisParser.g4)
  → Adapter (token/context mapping to bridge types)
  → AST (ast/nodes.rs — every node carries a Span)
  → TypeChecker (checker/mod.rs — two-pass: register declarations, then check bodies)
  → Validated AST
  → Lowering (lower/mod.rs — flatten inheritance, compile temporal → state machines)
  → CompiledPolicy (ir/mod.rs)
  → Bytecode serialization (bytecode.rs → .aegisc file)
```

## Module Map

- **`ast/`** — AST node definitions. `TemporalExpr` variants map to LTL: `Always` = □φ, `Eventually` = ◇φ, `Never` = □¬φ, `Until` = φUψ, `Next` = Xφ. Every node wraps content in `Spanned<T>` for error reporting.
- **`types/`** — Semantic type system. Subtyping: `never` is bottom, `int <: float`, covariant collections, union subtyping. `TypeEnv` does scoped name resolution with push/pop.
- **`checker/`** — Type checker. Two-pass design so forward references work. Enforces structural constraints: temporal operators only inside `proof`/`invariant` blocks, no nested temporals in v1, `when` clauses must be boolean, rate limits require numeric limit + duration.
- **`ir/`** — Compiled policy IR. `StateMachineBuilder` compiles temporal invariants to explicit automata: `always(φ)` → 2-state, `eventually(φ) within T` → 3-state, `until(φ, ψ)` → 3-state. This is the serialization boundary with the runtime.
- **`lower/`** — Lowering pass. Resolves policy inheritance, inlines imports, flattens rules, compiles patterns to decision trees, and invokes `StateMachineBuilder` for temporal invariants.
- **`bytecode.rs`** — `.aegisc` file format: 4-byte magic (`0xAE915C01`), 2-byte version, 2-byte flags, 4-byte payload length, JSON-serialized `CompiledPolicy`. JSON payload means the runtime can also accept policies over HTTP.
- **`adapter.rs`** — Bridge between ANTLR4-generated parser and the AST builder. Token-to-enum mapping functions. Intentionally thin.
- **`visitor.rs`** — Visitor trait and bridge types for the ANTLR4 adapter layer.
- **`diagnostics.rs`** — Error/warning collection with span-based rendering. All user-facing messages flow through here.
- **`cli.rs`** — `aegisc` binary. Subcommands: `compile`, `check`, `dump`, `inspect`.

## Working in This Crate

- The grammar files (`AegisLexer.g4`, `AegisParser.g4`) live in the project root, not in this crate. They're shared with any future tooling (LSP, formatter).
- When adding new AST nodes, update in order: `ast/nodes.rs` → `visitor.rs` → `checker/mod.rs` → `lower/mod.rs` → `ir/mod.rs`. Missing any step will produce compile errors (by design — exhaustive matches catch it).
- The `CheckContext` struct in the checker tracks structural position (in_proof, in_rule, temporal_depth). If you add new structural constraints, extend this struct.
- `CompiledPolicy` in `ir/` is the contract with `aegis-runtime`. Changes here require coordinated updates to both crates.

## Testing

- Parser tests: valid and invalid `.aegis` snippets → assert AST structure or expected diagnostics.
- Type checker tests: programs with type errors → assert specific diagnostic codes and spans.
- Lowering tests: policies with inheritance/temporal/rate-limit → assert correct IR output.
- Bytecode round-trip: compile → serialize → deserialize → assert equality.
- The CLI's demo pipeline (`aegisc compile --demo`) constructs a minimal AST and runs the full pipeline. Use this to verify end-to-end wiring after refactors.