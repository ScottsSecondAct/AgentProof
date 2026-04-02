# Testing Status

## aegis-compiler — 492 tests, all passing

### Unit tests (inline `#[cfg(test)]`, 152 tests)

| Module | Tests | Coverage |
|--------|-------|----------|
| `ast/span.rs` | 14 | `Span` methods, `Spanned<T>` construction, mapping, merge |
| `ast/nodes.rs` | 13 | `DurationLit::to_millis` (all 5 units), `QualifiedName` helpers |
| `bytecode.rs` | 20 | Header fields, magic/version/flags, round-trip (minimal/metadata/SMs), error cases, JSON output |
| `diagnostics/mod.rs` | 25 | `DiagnosticSink` emit/count, all named constructors (E0001–E0202), rendering, offset→line/col |
| `ir/mod.rs` | 44 | `StateMachineBuilder` for always/eventually/never/until, state kinds, transitions, sequential IDs |
| `types/mod.rs` | 33 | `Ty` predicates, subtyping rules (Never/Error/widening/covariance), `TypeEnv` scoping |
| `parser.rs` | 3 | Internal parser helpers |

### Integration tests (`tests/`, 340 tests)

| File | Tests | Coverage |
|------|-------|----------|
| `tests/checker_tests.rs` | 100 | Valid programs (no errors), E0001–E0304 diagnostic codes, binary op type rules; `event.field` and `context.field` bindings in `when` clauses; `MethodCall` (deferred resolution, args still checked); `Count` (no-filter / bool-filter / non-bool-filter → E0101); `Match` (expr arms, verdict arm, block arm, empty arms); `Lambda` (untyped param, typed param, param visible in body); `Block` (expr/binding/verdict/action statements, empty block); `Object` literal; policy-level `Binding` (untyped, typed, type mismatch → E0100, binding visible in rule scope); policy-level `Function` (happy path, return mismatch → E0100, callable from rule); `Import` declarations (module, named, coexisting with policies); event field type refinement (`tool_call`/`external_request`/`data_access`/`message` schemas, known-field happy path, unknown-field → E0108, dynamic fallback for unknown event names, multi-event rules) |
| `tests/cli_tests.rs` | 35 | `aegisc` subcommands: no-args, unknown, version, help; compile/check/dump/inspect with stub and semantically rich `.aegis` files (using `event.field` conditions); bytecode structure assertions (name, rule count, state machine count) |
| `tests/lowering_tests.rs` | 98 | Empty/minimal policies, metadata, multiple policies, rules (all fields), constraints, proofs/state machines, inheritance chains, inheritance member merging; diamond topology (sibling policies sharing a common base): rule/state-machine/constraint counts verified to be exact with no duplication; `next`/`before`/`after` temporal operators; all `lower_expr` variants (Context, FieldAccess, IndexAccess, Call, MethodCall, Unary, Predicate, Quantifier, Count, Match, Lambda, List, Object); all `resolve_name` root variants (Event, Context, Policy, local, unresolved); all match pattern types (Wildcard, Literal, Binding, Destructure, Guard, Or) |
| `tests/parse_tests.rs` | 101 | Parse-from-source: all declaration types, expressions, temporal operators, constraints, proofs, imports, annotations; parse error recovery; `severity info`; string-literal scope targets; policy binding/function members; rule severity/constraint clauses; `redact` verdict; `escalate` action; `eventually within`; arithmetic operators (Sub/Mul/Div/Mod); unary negation; postfix field access and method call; `ends_with` predicate; match expressions with all pattern forms; object literals; `none`/`exists` quantifiers; float and raw-string literals; `List<T>`/`Map<K,V>`/`Set<T>`/union type annotations; block statements (binding/verdict/action/expr) |
| `tests/span_tests.rs` | 6 | Span accuracy: E0304/E0301/E0202 spans are non-zero and cover the expected token; rendered output contains filename, correct line number, and diagnostic code |

### Line coverage (measured with `cargo llvm-cov`)

| File | Lines hit | Coverage |
|------|-----------|----------|
| `ast/nodes.rs` | 87/87 | 100% |
| `ast/span.rs` | 97/97 | 100% |
| `types/mod.rs` | ~100% | (updated with `event_schema`) |
| `ir/mod.rs` | 297/306 | 97.1% |
| `bytecode.rs` | 266/275 | 96.7% |
| `diagnostics/mod.rs` | 330/355 | 93.0% |
| `parser.rs` | 1143/1319 | 86.7% |
| `cli.rs` | 179/216 | 82.9% |
| `lower.rs` | 664/799 | 83.1% |
| `checker/mod.rs` | ~641/806 | ~79.5% |
| **Total** | **~4700/5350** | **~87.8%** |

### Known gaps in `checker/mod.rs` (~20% uncovered)

Coverage improved from 61.6% to ~79.5% after Task 4 and Task 5.  The remaining
uncovered regions fall into six groups:

- **`Expr::FieldAccess` (fully dead, ~30 lines)**: The pest grammar's greedy
  `qualified_name` rule means dot-separated access always arrives as a
  multi-segment `Identifier` node, never as a `FieldAccess` node.  This branch
  cannot be reached from any parser-produced AST.  It can only be exercised by
  constructing the node manually in a test, or it should be removed.

- **Temporal operators `Next`, `Before`, `After`, `Until` (~50 lines)**: The
  checker tests cover `always` and `never` inside proofs but none of the
  remaining four temporal forms.  Each has a non-bool-condition error path that
  is also uncovered.

- **`Expr::Call` (~35 lines)**: Function call expressions (including argument
  count and type checking) are never constructed in checker tests.  The
  policy-level `Function` declaration tests confirm that functions are
  registered, but no test calls them.

- **`Expr::IndexAccess` (~25 lines)**: List and map index expressions are
  never tested.  Covers the bad-index-type path (E0102) and the
  "cannot index into T" path (E0103).

- **`resolve_type` for container types (~25 lines)**: `List<T>`, `Map<K,V>`,
  `Set<T>`, and `Named` type annotations in bindings and function signatures
  are never passed through the type resolver in checker tests.

- **Error paths inside covered functions (~20 lines)**: `RuleClause::Action`
  inside rules; per-rule `Constraint` clause; `check_action_args` Positional/
  Named variants; constraint with wrong limit or window type (E0303); invariant
  with a non-bool/non-temporal condition (E0200); `starts_with`/`ends_with`
  with a non-string argument; list element type mismatch; `Implies` operator
  with non-bool operands; string concatenation via `+`.

### Design decisions

- **Cross-policy ancestry inlining**: Compiled policies inline their full inheritance chain so that individual `.aegisc` files can be loaded without their base policies present. When multiple policies extend the same base, the base's compiled members appear in each policy's bytecode independently. This is intentional — the `collect_inherited_members` function uses a `HashSet`-based visited guard that prevents duplication *within* a single policy's compilation; cross-policy inlining is by design. Tests in `lowering_tests.rs` (diamond topology suite) verify that base rules, constraints, and state machines each appear exactly once per derived compiled policy.

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

This test exercises the full pipeline: source → parser → compiler → bytecode → runtime → Python binding.

---

## Critical gaps (priority order)

1. **Runtime benchmarks** — the <10ms p99 claim has no validation.
2. **Runtime evaluator + state machine unit tests** — core correctness of the product.
3. **End-to-end compile→evaluate test** — exercises the full pipeline.
