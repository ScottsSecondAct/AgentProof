# Testing Status

## aegis-compiler — 569 tests, all passing

### Unit tests (inline `#[cfg(test)]`, 212 tests)

| Module | Tests | Coverage |
|--------|-------|----------|
| `ast/span.rs` | 14 | `Span` methods, `Spanned<T>` construction, mapping, merge |
| `ast/nodes.rs` | 13 | `DurationLit::to_millis` (all 5 units), `QualifiedName` helpers |
| `bytecode.rs` | 20 | Header fields, magic/version/flags, round-trip (minimal/metadata/SMs), error cases, JSON output |
| `diagnostics/mod.rs` | 25 | `DiagnosticSink` emit/count, all named constructors (E0001–E0202), rendering, offset→line/col |
| `ir/mod.rs` | 84 | `StateMachineBuilder` for always/eventually/never/until/next, `compile_next`/`compile_always_next`/`compile_always_implies_next` state counts, transition guards, labels, sequential IDs |
| `bytecode.rs` | 29 | Header fields, magic/version/flags, round-trip (minimal/metadata/SMs), error cases, JSON output, `write_file`/`read_file` round-trips, `inspect_header` |
| `types/mod.rs` | 33 | `Ty` predicates, subtyping rules (Never/Error/widening/covariance), `TypeEnv` scoping |
| `parser.rs` | 3 | Internal parser helpers |

### Integration tests (`tests/`, 356 tests)

| File | Tests | Coverage |
|------|-------|----------|
| `tests/checker_tests.rs` | 117 | Valid programs (no errors), E0001–E0304 diagnostic codes, binary op type rules; `event.field` and `context.field` bindings in `when` clauses; `MethodCall` (deferred resolution, args still checked); `Count` (no-filter / bool-filter / non-bool-filter → E0101); `Match` (expr arms, verdict arm, block arm, empty arms); `Lambda` (untyped param, typed param, param visible in body); `Block` (expr/binding/verdict/action statements, empty block); `Object` literal; policy-level `Binding` (untyped, typed, type mismatch → E0100, binding visible in rule scope); policy-level `Function` (happy path, return mismatch → E0100, callable from rule); `Import` declarations (module, named, coexisting with policies); event field type refinement (`tool_call`/`external_request`/`data_access`/`message` schemas, known-field happy path, unknown-field → E0108, dynamic fallback for unknown event names, multi-event rules); `next` inside `always` permitted, `always(trigger implies next(ψ))` permitted, `next` inside `eventually`/`never`/`next` rejected (E0203); `until`/`before`/`after` happy paths, outside-proof E0202, non-bool operands |
| `tests/cli_tests.rs` | 35 | `aegisc` subcommands: no-args, unknown, version, help; compile/check/dump/inspect with stub and semantically rich `.aegis` files (using `event.field` conditions); bytecode structure assertions (name, rule count, state machine count) |
| `tests/lowering_tests.rs` | 109 | Empty/minimal policies, metadata, multiple policies, rules (all fields), constraints, proofs/state machines, inheritance chains, inheritance member merging; diamond topology (sibling policies sharing a common base): rule/state-machine/constraint counts verified to be exact with no duplication; `next`/`before`/`after` temporal operators; all `lower_expr` variants (Context, FieldAccess, IndexAccess, Call, MethodCall, Unary, Predicate, Quantifier, Count, Match, Lambda, List, Object); all `resolve_name` root variants (Event, Context, Policy, local, unresolved); all match pattern types (Wildcard, Literal, Binding, Destructure, Guard, Or); `always(next(ψ))` and `always(trigger implies next(ψ))` composite state machine compilation (state/transition counts, initial label, violating state index) |
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
| `checker/mod.rs` | ~496/806 | ~61.5% |
| **Total** | **~4564/5350** | **~85.2%** |

### Known gaps in `checker/mod.rs` (~38% uncovered)

Coverage sits at ~61.5%.  The remaining
uncovered regions fall into six groups:

- **`Expr::FieldAccess` (fully dead, ~30 lines)**: The pest grammar's greedy
  `qualified_name` rule means dot-separated access always arrives as a
  multi-segment `Identifier` node, never as a `FieldAccess` node.  This branch
  cannot be reached from any parser-produced AST.  It can only be exercised by
  constructing the node manually in a test, or it should be removed.

- **Temporal operators `Next`, `Before`, `After`, `Until`**: Checker tests now
  cover `next` inside `always` (permitted), `next` inside
  `eventually`/`never`/`next` (E0203), and `until`/`before`/`after` happy
  paths, outside-proof E0202, and non-bool operands (12 new tests).
  Still uncovered: `next` as a standalone top-level proof expression (not nested
  inside `always`); the non-bool-condition error path for standalone `next`.

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
  with a non-string argument; list element type mismatch; string concatenation
  via `+`.

### Known gaps in `ir/mod.rs`

All `StateMachineBuilder` methods now have direct unit tests: `compile_always`,
`compile_eventually`, `compile_never`, `compile_until`, `compile_next`,
`compile_always_next`, and `compile_always_implies_next` (40 new tests added).

### Known gaps in `lower.rs`

- **`next(φ)` decision tree path**: The `expr_contains_next` defensive guard and
  the pattern-dispatch logic inside `lower_temporal_to_sm` are exercised by
  integration tests but not directly unit-tested.
- **`Verdict::Redact` in rules**: The `lower_rule` function has a `Redact` arm
  but no test emits `redact` verdict policies end-to-end through the lowerer.
- **`lower_lambda`, `lower_object`, `lower_index_access`**: Covered indirectly
  via `lower_expr` integration tests but the individual functions have no
  targeted tests for their error paths.

### Known gaps in `bytecode.rs`

`write_file`, `read_file`, and `inspect_header` now have direct unit tests
(9 new tests). Remaining gap: file I/O error paths for write failures (disk
full, permission denied on parent directory) are not triggered in tests.

### Design decisions

- **Cross-policy ancestry inlining**: Compiled policies inline their full inheritance chain so that individual `.aegisc` files can be loaded without their base policies present. When multiple policies extend the same base, the base's compiled members appear in each policy's bytecode independently. This is intentional — the `collect_inherited_members` function uses a `HashSet`-based visited guard that prevents duplication *within* a single policy's compilation; cross-policy inlining is by design. Tests in `lowering_tests.rs` (diamond topology suite) verify that base rules, constraints, and state machines each appear exactly once per derived compiled policy.

---

## aegis-ffi — 14 tests, all passing

### Unit tests (inline `#[cfg(test)]`, 14 tests)

| Test | Coverage |
|------|----------|
| `engine_from_bytes_success` | `aegis_engine_from_bytes` happy path |
| `engine_from_bytes_invalid` | Invalid bytes → NULL + error string |
| `engine_from_file_missing` | Missing file path → NULL + error string |
| `evaluate_allow` | Non-matching event → `{"verdict":"allow",...}` |
| `evaluate_deny` | Matching deny rule → `{"verdict":"deny","reason":"..."}` |
| `evaluate_empty_fields` | Empty `fields_json` (`"{}"`) → allow |
| `evaluate_null_event_type` | Null event_type pointer → NULL + error |
| `evaluate_null_fields` | Null fields_json pointer → NULL + error |
| `evaluate_invalid_json` | Malformed JSON → NULL + error |
| `evaluate_null_engine` | Null engine pointer → NULL + error |
| `result_free_null` | `aegis_result_free(NULL)` is a no-op |
| `engine_free_null` | `aegis_engine_free(NULL)` is a no-op |
| `last_error_thread_local` | Error is cleared between calls on same thread |
| `round_trip_json_fields` | Int, float, bool, string fields survive the boundary |

All tests are `unsafe` blocks calling the raw C ABI directly, verifying null
safety and JSON round-trip correctness at the FFI boundary.

---

## aegis-runtime — 234 tests, all passing

### Integration tests (`tests/`, 234 tests)

| File | Tests | Coverage |
|------|-------|----------|
| `tests/eval_tests.rs` | 125 | Literal evaluation (bool/int/float/string/duration/regex); event/context/policy/local references; missing-field → Null; nested path resolution; arithmetic (Add/Sub/Mul/Div/Mod, int+float widening, string concat, div-by-zero → Null); comparison (Lt/Le/Gt/Ge, cross-type → false); equality (int/float cross-type, null==null); logical short-circuit (And/Or/Implies false-antecedent); membership (`in` list/map/non-collection); unary (Not, Neg int/float/string→Null); predicates (Contains string/list, Matches exact/prefix/suffix/substring, StartsWith/EndsWith, non-string→false); quantifiers (All/Any/None/Exists with empty/match/no-match lists, non-list collection); Count (no filter, with filter, non-list→0, empty→0); List literal; built-ins (len/length/to_string/str/abs/min/max, unknown→Null); method calls on String/List/Map (to_upper, to_lower, trim, split, first/last, has_key, etc.); decision trees (Leaf, VerdictLeaf, Switch literal/guard/default/no-match-no-default→Null); `RefRoot::Local` (slot 0/1/unbound → Null, bool, used in binary expression, multiple independent slots, shadows event field) |
| `tests/engine_tests.rs` | 64 | Empty policy → allow; unconditional deny/audit rule; conditional rule true/false; event-type filter; wildcard (empty on_events); deny overrides audit; field equality condition; verdict reason message; multiple triggered rules; event count increment; reset; policy name; `status()` metadata and event count; state machine `always(true)` happy path, `always(false)` violates on first event and persists, reason string; `always` status after satisfaction; reset restores active state; `never(false)` happy path, `never(true)` violates; `eventually` satisfied immediately, eventually without deadline never violates, eventually deadline expired → deny; rate limit under/at/over limit; sliding window eviction; rate limit scoped to event type; constraint violation details; reset clears rate limiter; standalone `next(φ)` (first event allowed, second allowed/denied, violation persists); `always(next(ψ))` (first allowed, subsequent allowed/denied, continues checking); `always(trigger implies next(ψ))` (no trigger allows, trigger+valid allows, trigger+wrong denies, resets after valid, violation permanent, three full cycles, violations vec populated); `set_context` visible in rules, persists across events, can be overridden; `set_config` visible in policy-ref conditions, persists; reset does not clear context/config; `until` hold-true/release-false stays active, hold-false violates, release-true satisfies, field-driven phases, violation permanent |
| `tests/audit_tests.rs` | 30 | Empty log is_empty/len/total_recorded; record increments len; monotonically increasing IDs; ring buffer never exceeds max_entries; ring buffer evicts oldest; total_recorded counts evicted entries; entry fields (policy_name, event_type, verdict, reason, triggered_rules, violation_count, violation details, eval_time_us); by_verdict filter; by_verdict empty result; with_violations filter; by_event_type filter; recent returns last N in reverse order; recent with n>len; recent on empty; stats (empty, verdict counts, violation count, total vs buffered, avg/max eval time); JSON serialization; round-trip JSON deserialization; with_file populates in-memory buffer; Display stats |
| `tests/e2e_tests.rs` | 15 | Full pipeline: source → parser → lower → bytecode → engine → verdict. Unconditional deny/allow; conditional deny/allow; audit rule; never-invariant allows/violates/persists; rate limit allow/deny; event count increments; policy name from source; bytecode file round-trip; engine loaded from file produces correct verdicts |

### Known gaps in `engine.rs`

`set_context`, `set_config`, and the `until` state machine are now tested at
the Rust level (12 new engine tests). No remaining critical gaps.

### Known gaps in `eval.rs`

- **`RefRoot::Local` references**: Now tested — 7 new tests cover slot 0/1,
  unbound → Null, bool value, used in binary expression, multiple independent
  slots, and shadowing of event fields.
- **Integer overflow in arithmetic**: `Add`/`Sub`/`Mul` between large i64
  values — the saturating-vs-wrapping behaviour is unspecified in tests.
- **Nested quantifiers**: `All`/`Any` inside another `All`/`Any` or inside a
  `Count` filter are never tested.
- **Decision tree guards with complex expressions**: The `Switch` guard path is
  exercised but only with simple boolean literals, not with field comparisons or
  compound logic.

### Known gaps in `event.rs`

- **`with_fields` builder**: Never called in tests; only `Event { fields: ..., .. }`
  literal construction is used.
- **`to_value` / `matches_pattern`**: Internal helpers on `Value` that back the
  `Matches` predicate are covered indirectly but never tested in isolation.

### Known gaps in `audit.rs`

- **File write errors**: `AuditLog::with_file` opens a file for append. Tests
  call it with a valid temp path; write errors (disk full, permissions) are
  never triggered.
- **Edge cases in `stats()`**: `stats()` with exactly one entry (avg == max);
  `total_recorded` overflow on extremely long-running logs.

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

---

## automaguard-mcp-proxy — 31 tests, all passing

### Unit tests (inline `#[cfg(test)]`, 31 tests)

| Module | Tests | Coverage |
|--------|-------|----------|
| `src/bridge.rs` | 7 | `mcp_tool_call_to_event` sets `tool_name`/`tool` fields; event_type is `"tool_call"`; string/bool/int arguments; nested map under `"arguments"` key; null arguments |
| `src/jsonrpc.rs` | 18 | `is_request` true/false; `is_notification` true/false; `error_response` sets jsonrpc/id/code/message/no-method-or-result/data; `POLICY_VIOLATION_CODE == -32001`; round-trip: request/error-response/notification through JSON |
| `src/proxy.rs` | 6 | `extract_tool_call` returns name+arguments; no-params → unknown; missing `name` → unknown; missing `arguments` → empty object; empty arguments; nested arguments |

### Known gaps in `automaguard-mcp-proxy`

- **`src/proxy.rs` async paths (0 tests)**: `intercept_loop`, `spawn_writer`,
  and `spawn_relay` are async and require a running tokio runtime + real
  subprocess. Missing coverage:
  - Non-`tools/call` message forwarded unchanged.
  - `tools/call` allowed by policy (forwarded to upstream).
  - `tools/call` denied (JSON-RPC `-32001` error response written to client).
  - Malformed JSON on stdin (loop continues).
  - stdin EOF terminates cleanly.
  - `spawn_writer`: channel closed before all messages drained.
  - `spawn_relay`: upstream process exits before client.

- **`src/error.rs` (0 tests)**: Error variants are never directly tested. The
  `Display` output for each variant is unverified.

- **Integration tests (0)**: No test starts a real subprocess, feeds it
  JSON-RPC messages over its stdin, and asserts the proxy's stdout contains the
  correct response. An integration test using a trivial echo MCP server would
  catch wiring bugs not visible in unit tests.

---

## automaguard-rs — 23 tests, all passing

### Integration tests (`tests/integration.rs`, 23 tests)

| Test | Coverage |
|------|----------|
| `loads_from_bytes` | `PolicyEngine::from_bytes` round-trip |
| `rejects_invalid_bytes` | Bad bytes → `Error::Load` |
| `allows_non_matching_event` | Non-matching condition → `is_allowed()` |
| `denies_matching_event` | Matching deny rule → `is_denied()`, `triggered_rules` |
| `wrong_event_type_is_unmatched` | Wrong event type → allow (scoped rules) |
| `evaluate_with_hashmap` | `engine.evaluate(type, HashMap)` API |
| `enforcement_error_contains_result` | `EnforcementError::new()`, `Display`, result accessor |
| `enforcement_error_converts_to_sdk_error` | `From<EnforcementError> for Error` |
| `latency_is_nonzero_for_matching_rule` | `latency_us()` accessor doesn't panic |
| `policy_name_accessible` | `engine.policy_name()` returns correct name |
| `event_count_increments` | `event_count()` increments on each evaluate |
| `reset_clears_event_count` | `engine.reset()` zeroes event count |
| `rate_limit_allows_within_budget` | 3 events within limit → all allowed |
| `rate_limit_denies_over_budget` | 4th event → deny + `constraint_violations` populated |
| `rate_limit_does_not_fire_for_other_event_types` | Rate limiter scoped to target event type |
| `always_sm_allows_compliant_sequence` | 5 clean events → all allowed, no violations |
| `always_sm_denies_on_violation` | `always(tool != "exec")` tripped by exec event |
| `state_machine_remains_violated_after_first_violation` | Violated absorbing state denies all subsequent events |
| `into_value_conversions_work` | `From` impls: `&str`, `String`, `i64`, `f64`, `bool` |
| `async_engine_allows_and_denies` | `AsyncPolicyEngine` allow + deny (async) |
| `async_engine_is_cloneable_and_concurrent` | Two clones evaluate concurrently via `tokio::join!` |
| `async_engine_event_count` | Shared `event_count()` across async evaluations |
| `async_engine_policy_name` | `policy_name()` on async engine |

The last four async tests run only with `--features async`.

#### Bug discovered during SDK integration testing

The `state_machine_remains_violated_after_first_violation` test exposed a bug in
`aegis-runtime/src/engine.rs`: state machines in a terminal violated state were
accumulating `Violation` entries but **not** setting the `Deny` verdict on
subsequent events. The absorbing-state branch pushed to `violations` but never
updated `verdict`. Fixed by adding:

```rust
if verdict != Verdict::Deny {
    verdict = Verdict::Deny;
    reason = Some(format!("Invariant violation: {} ({})", ...));
}
```

inside the non-active `is_violated()` branch of `engine.evaluate()`.

#### Supporting changes required by the SDK

- **`aegis-compiler/src/bytecode.rs`**: Added missing `impl std::error::Error for BytecodeError` so `thiserror`'s `#[from]` derive works in the SDK's `Error::Load` variant.
- **`aegis-runtime/src/event.rs`**: Added `From` impls for `Value` (`&str`, `String`, `i64`, `f64`, `bool`) to the crate that owns the type, avoiding the orphan rule.

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

## Summary

| Crate | Tests |
|-------|-------|
| `aegis-compiler` | 569 |
| `aegis-ffi` | 14 |
| `aegis-runtime` | 234 |
| `automaguard-mcp-proxy` | 31 |
| `automaguard-rs` | 23 |
| `automaguard-python` | 91 |
| **Total** | **962** |

---

## End-to-end — 15 tests (aegis-runtime/tests/e2e_tests.rs)

The `e2e_tests.rs` file covers the full Rust pipeline: `.aegis` source → parser →
type checker → lowering → `CompiledPolicy` → bytecode round-trip → `PolicyEngine::evaluate` → verdict.
All 15 tests pass.

### Still needed

1. **Python SDK round-trip**: Load the bytecode via the Python SDK, feed synthetic
   agent events over the pyo3 boundary, assert verdict/reason/triggered_rules survive.
2. **CLI compile → runtime**: Run `aegisc compile` in a subprocess, load the
   produced `.aegisc` file via `PolicyEngine`, assert verdicts.  Currently the
   e2e tests use the compiler API directly, not the CLI binary.

---

## Critical gaps (priority order)

1. **Python SDK round-trip tests** — requires the compiled native extension; verify the pyo3 boundary preserves verdict, reason, triggered_rules, and eval_time_us.
2. **`proxy.rs` async integration test** — start a real echo MCP subprocess over its stdio pipes, feed JSON-RPC `tools/call` messages, assert the proxy blocks denied tools (returns `-32001`) and forwards allowed ones. `extract_tool_call` is now unit-tested; the async intercept/relay/writer paths remain untested.
3. **`src/error.rs` Display output** — `Display` for each `Error` variant is unverified.
4. **Python SDK OpenAI client wrapper** — mock `openai.OpenAI` client, assert tool calls are intercepted and verdicts applied.
5. **Framework edge cases** — Unicode in tool arguments, deeply nested JSON payloads, missing required fields, very large payloads.
