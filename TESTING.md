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

## aegis-runtime — 184 tests, all passing

### Integration tests (`tests/`, 184 tests)

| File | Tests | Coverage |
|------|-------|----------|
| `tests/eval_tests.rs` | 118 | Literal evaluation (bool/int/float/string/duration/regex); event/context/policy/local references; missing-field → Null; nested path resolution; arithmetic (Add/Sub/Mul/Div/Mod, int+float widening, string concat, div-by-zero → Null); comparison (Lt/Le/Gt/Ge, cross-type → false); equality (int/float cross-type, null==null); logical short-circuit (And/Or/Implies false-antecedent); membership (`in` list/map/non-collection); unary (Not, Neg int/float/string→Null); predicates (Contains string/list, Matches exact/prefix/suffix/substring, StartsWith/EndsWith, non-string→false); quantifiers (All/Any/None/Exists with empty/match/no-match lists, non-list collection); Count (no filter, with filter, non-list→0, empty→0); List literal; built-ins (len/length/to_string/str/abs/min/max, unknown→Null); method calls on String/List/Map (to_upper, to_lower, trim, split, first/last, has_key, etc.); decision trees (Leaf, VerdictLeaf, Switch literal/guard/default/no-match-no-default→Null) |
| `tests/engine_tests.rs` | 36 | Empty policy → allow; unconditional deny/audit rule; conditional rule true/false; event-type filter; wildcard (empty on_events); deny overrides audit; field equality condition; verdict reason message; multiple triggered rules; event count increment; reset; policy name; `status()` metadata and event count; state machine `always(true)` happy path, `always(false)` violates on first event and persists, reason string; `always` status after satisfaction; reset restores active state; `never(false)` happy path, `never(true)` violates; `eventually` satisfied immediately, eventually without deadline never violates, eventually deadline expired → deny; rate limit under/at/over limit; sliding window eviction; rate limit scoped to event type; constraint violation details; reset clears rate limiter |
| `tests/audit_tests.rs` | 30 | Empty log is_empty/len/total_recorded; record increments len; monotonically increasing IDs; ring buffer never exceeds max_entries; ring buffer evicts oldest; total_recorded counts evicted entries; entry fields (policy_name, event_type, verdict, reason, triggered_rules, violation_count, violation details, eval_time_us); by_verdict filter; by_verdict empty result; with_violations filter; by_event_type filter; recent returns last N in reverse order; recent with n>len; recent on empty; stats (empty, verdict counts, violation count, total vs buffered, avg/max eval time); JSON serialization; round-trip JSON deserialization; with_file populates in-memory buffer; Display stats |

### Benchmarks (`benches/eval_bench.rs`)

Run with: `cargo bench -p aegis-runtime`

| Benchmark | Result | 10ms budget |
|-----------|--------|-------------|
| `evaluate/baseline` | ~38 ns | 263× headroom |
| `evaluate/single_allow` | ~104 ns | 96× headroom |
| `evaluate/field_condition` | ~104 ns | 96× headroom |
| `evaluate/multi_rule_5` | ~750 ns | 13× headroom |
| `evaluate/realistic_10r_2sm` | **~2.4 µs** | **4.2× headroom** |
| `evaluate/rate_limit_only` | ~104 ns | 96× headroom |
| `evaluate/state_machines_4` | ~1.4 µs | 7× headroom |
| `throughput/realistic_steady_state` | ~760 ns | 1.3M events/s |
| `nested_event/realistic_policy_nested_payload` | ~2.2 µs | 4.5× headroom |
| `event_stream/100_events` | ~535 µs total / ~5.4 µs per event | — |

The <10ms p99 guarantee is confirmed with substantial headroom on the primary scenario (`realistic_10r_2sm`: 10 rules, 2 state machines, 1 rate limiter).
- **Fuzz tests**: `cargo-fuzz` target on the expression evaluator with arbitrary `Event` payloads.
- **`until` state machine tests**: the `compile_until` path is exercised by the compiler IR tests but not by the runtime engine tests.
- **Context-aware eval tests**: `EvalContext` with nested context/policy fields accessed via multi-segment paths.

---

## automaguard-python — 91 tests, all passing

### Python tests (`tests/`, 91 tests)

| File | Tests | Coverage |
|------|-------|----------|
| `tests/test_policy_result.py` | 11 | `PolicyResult` defaults; mutable-default isolation; `allowed`/`denied` properties for all four verdicts; `from_dict()` full dict, empty dict, missing optional fields, unknown keys |
| `tests/test_engine.py` | 26 | `from_file` (missing file, bad magic, valid file, Path/str/missing name); `from_bytes` (valid, bad magic, empty dict); `from_json` (with/without name); pure-Python fallback always-allow, no-fields, reason text; native engine proxying; event count increment/reset; native count delegation; `status()`/`repr()` with and without native; `set_context`/`set_config` no-native noop and native delegation |
| `tests/test_enforce.py` | 22 | `EnforcementError` message, fallback reason, result attribute; `_handle_result` for deny (raise/block/log/unknown mode), allow, audit callback, redact callback; `enforce()` invalid type, missing file, accepts engine, non-OpenAI returns `_GenericProxy`; `_GenericProxy` attr passthrough, callable wrapping, allow/deny/log modes, setattr delegation, tool name in fields, kwargs in fields |
| `tests/test_interceptors.py` | 32 | `AutomaGuardCallbackHandler` construction (engine, invalid type, missing file, on_deny default/configurable); `on_tool_start` allow/deny/audit with all on_deny modes; event/deny counts; `on_tool_end` noop; `on_tool_error` logs; `results` returns copy; `intercept_tool_call` allow, function-name default, name override, deny raise/log, kwargs fields, metadata attachment, `__name__` preservation, audit passthrough |

All tests run against the pure-Python fallback path — no native Rust extension required.

### Still needed

- **Round-trip tests** (requires built extension): Python `dict` → Rust `Event` → evaluate against a compiled policy → Python result `dict`. Verify verdict, diagnostics, and metadata survive the pyo3 boundary.
- **OpenAI client wrapper**: mock `openai.OpenAI` client, assert tool calls are intercepted and verdicts applied.
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

1. **End-to-end compile→evaluate test** — exercises the full pipeline.
2. **Python SDK round-trip tests** — requires the compiled native extension; verify the pyo3 boundary preserves verdict, reason, triggered_rules, and eval_time_us.
