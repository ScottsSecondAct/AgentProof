# Future Language Implementation

This document records features described in the Aegis Language Reference that are **not yet fully implemented** in the current codebase. Each entry cites the relevant source location so the implementation gap is easy to find.

---

## 1. Import Resolution (`import` / `from`)

**Reference:** Section 17 — Imports

**Status:** Grammar parses it; type checker accepts it structurally; no module system exists.

The type checker contains an explicit comment:

> `aegis-compiler/src/checker/mod.rs:134`
> ```rust
> Declaration::Import(_) => {
>     // Import resolution is a separate pass (module system).
>     // For now we just accept imports structurally.
> }
> ```

Writing `import automaguard.stdlib.pii as pii` will compile without error, but the imported names are not bound and any call like `pii.contains_pii(arg)` resolves to a null-returning built-in fallback at runtime. All examples in the reference that use `import` depend on this unimplemented subsystem.

---

## 2. Full Regex Support for the `matches` Predicate

**Reference:** Section 7 — Expressions (String Predicates), Section 6 — Regex Literals

**Status:** Parsed and stored; runtime uses glob-style matching only.

The `Value::matches_pattern` method in `aegis-runtime/src/event.rs:112` contains:

```rust
// Simple glob-style matching for v1.
// Full regex support via the `regex` crate in v2.
```

The patterns currently supported by `matches` are limited to:
- `^...$` — exact match
- `prefix.*` — prefix match
- `.*suffix` — suffix match
- anything else — substring containment

Regex literals (`/pattern/flags`) parse correctly and the flags field is captured by the grammar (`aegis-compiler/src/aegis.pest:131`), but flags are not applied — the regex is stored as a plain string and passed through `matches_pattern` as-is. Complex patterns such as `/\d{3}-\d{4}/` or `/^https?:\/\//i` will not behave as documented.

---

## 3. `eval` CLI Subcommand

**Reference:** Section 24 — The Compiler CLI (`eval` subcommand)

**Status:** Documented in the CLI help string; not implemented.

The `aegis-compiler/src/cli.rs` `print_usage()` function lists `eval` in the usage text, and the reference documents it as:

```sh
aegisc eval guard.aegisc tool_call tool_name=exec
aegisc eval --json guard.aegisc data_access classification=PII
```

However, there is no `"eval"` arm in the `cli_main` match and no `cmd_eval` function. Invoking `aegisc eval ...` returns `error: unknown command 'eval'`.

---

## 4. List Patterns in `match`

**Reference:** Section 19 — Pattern Matching (List Patterns)

**Status:** Parsed; lowered as wildcard default.

The lowering pass at `aegis-compiler/src/lower.rs:1103`:

```rust
Pattern::List(_) => {
    // List patterns — complex, deferred to v2
    default = Some(Box::new(body));
}
```

A `match` arm using a list pattern such as `[first, second, _]` silently becomes the catch-all default. The elements of the list pattern are not inspected.

---

## 5. Binding Patterns in `match`

**Reference:** Section 19 — Pattern Matching (Binding Patterns)

**Status:** Parsed; binding is discarded, treated as wildcard.

From `aegis-compiler/src/lower.rs:1066`:

```rust
Pattern::Binding(_ident) => {
    // Binding pattern — acts as a default that also binds
    // the value. For v1, treat as default.
    default = Some(Box::new(body));
}
```

The name `level` in `match event.classification { level -> audit with "Access at level: " + level }` is accepted by the parser and type checker but `level` is not bound at runtime — it evaluates as null.

---

## 6. Destructuring Patterns: Field Sub-Patterns Ignored

**Reference:** Section 19 — Pattern Matching (Destructuring Patterns)

**Status:** Constructor name is checked; field sub-patterns are silently dropped.

In `aegis-compiler/src/lower.rs:1072`:

```rust
Pattern::Destructure { name, fields: _ } => {
    cases.push(DecisionCase {
        test: CaseTest::Constructor(name.to_string().into()),
        body,
    });
}
```

A pattern like `ToolCall { tool: "exec", params: p }` will match any value whose `type` field equals `"ToolCall"`. The inner `tool: "exec"` and `params: p` sub-patterns are ignored at both compile and runtime. The binding `p` is not created.

---

## 7. Object Literals as Runtime Maps

**Reference:** Section 6 — Literals (Object Literals), used in Type Declarations examples

**Status:** Parsed; lowered to an empty list placeholder.

From `aegis-compiler/src/lower.rs:944`:

```rust
Expr::Object(_fields) => {
    // Object literals in the IR become runtime-constructed maps.
    // For now, lower to an empty list placeholder — the runtime
    // handles object construction.
    IRExpr::List(vec![])
}
```

Writing `{"Authorization": "Bearer xyz"}` or `{tool: "write_file", path: "/tmp/out.txt"}` in a policy expression compiles without error but evaluates to an empty list at runtime.

---

## 8. `Set<T>` Type at Runtime

**Reference:** Section 5 — Types (Collection Types)

**Status:** Parsed in grammar and AST; no corresponding runtime `Value` variant.

The grammar defines `set_ty` and the AST has `Type::Set(Box<Spanned<Type>>)`. However, the runtime `Value` enum in `aegis-runtime/src/event.rs` has no `Set` variant — only `List`, `Map`, `Bool`, `Int`, `Float`, `String`, `Duration`, and `Null`. A `Set<T>` annotation on a `let` binding type-checks but the runtime would represent the underlying value as a `List`. Uniqueness is not enforced.

---

## 9. Annotations: Only Single String Arguments Preserved

**Reference:** Section 18 — Annotations

**Status:** Multi-argument annotations and list-valued annotations are silently dropped in compiled metadata.

`aegis-compiler/src/lower.rs:329`:

```rust
let annotations = policy
    .annotations
    .iter()
    .filter_map(|ann| {
        if ann.args.len() == 1 {
            if let AnnotationArg::Positional(AnnotationValue::Literal(Literal::String(s))) =
                &ann.args[0]
            {
                return Some((ann.name.node.clone(), s.clone()));
            }
        }
        None
    })
    .collect();
```

Only annotations with exactly one positional string argument are stored. Examples from the reference such as:

```aegis
@tags(["pii", "gdpr", "critical"])    // list argument — dropped
@reviewed(true)                         // bool argument — dropped
@version("2.1.0")                       // single string — preserved
```

`@tags` and `@reviewed` parse correctly but produce no entry in `PolicyMetadata::annotations`.

---

## 10. Non-Temporal Invariant Conditions

**Reference:** Section 14 — Proofs and Invariants (multiple conditions per invariant)

**Status:** Non-temporal expressions inside `invariant` blocks are silently discarded.

From `aegis-compiler/src/lower.rs:732`:

```rust
// Non-temporal expression in a proof — treat as a static check.
// The runtime evaluates it once at policy load time.
_ => None,
```

The `None` return means no state machine is created. An invariant body such as:

```aegis
invariant StrictDataPolicy {
    never(event.tool == "drop_table");
    always(event.classification != "restricted");   // temporal — compiled
    event.approved == true;                          // static — silently dropped
}
```

The third condition `event.approved == true` is parsed and type-checked but never evaluated at runtime.

---

## 11. Generic Type Parameter Bounds

**Reference:** Section 16 — Type Declarations (Generic Types), Section 5 — Types

**Status:** Syntax parsed; bounds not enforced by type checker.

The grammar supports `<T extends string>`. The `GenericParam` AST node has a `bound: Option<Spanned<Type>>` field. However, the type checker's `register_declaration` function stores generic parameters as empty type params:

`aegis-compiler/src/checker/mod.rs:100`:
```rust
let ty = Ty::Struct(crate::types::StructType {
    name: td.name.node.clone(),
    fields,
    type_params: vec![],  // generic params not yet threaded through
});
```

Bounds on generic parameters are parsed but not type-checked. `<T extends string>` accepts any `T` at the call site.

---

## 12. `scope` Target Validation

**Reference:** Section 8 — Policies (`scope` keyword)

**Status:** Accepted structurally; no validation against known event types.

From `aegis-compiler/src/checker/mod.rs:196`:

```rust
PolicyMember::Scope(_targets) => {
    // Future: validate scope targets against known event types
}
```

`scope foo_bar_baz` compiles without warning even if `foo_bar_baz` is not a valid event type. The scope list is recorded in compiled metadata and used by the runtime for filtering, but a typo is silent.

---

## 13. Named Function Call Arguments

**Reference:** Section 7 — Expressions (Function Calls), Section 15 — Bindings and Functions

**Status:** Grammar parses `fn(key = value)` syntax; lowering strips names to positional only.

The grammar (`aegis.pest:274`) supports named arguments: `argument = { (ident ~ "=" ~ !">" ~ expression) | expression }`. In lowering, named arguments are resolved by extracting just the value: `args.iter().map(|a| self.lower_expr(&a.value.node))`. The name is discarded. The type checker only validates positional argument count and types for known function signatures. Named argument call sites that pass arguments out of declaration order will silently produce wrong results.

---

## 14. Policy-Level `let` Binding Values at Runtime

**Reference:** Section 15 — Bindings and Functions (`let`)

**Status:** Bindings are slot-tracked at compile time; complex expression values are not pre-evaluated.

From `aegis-compiler/src/lower.rs:308`:

```rust
PolicyMember::Binding(b) => {
    let _slot = self.locals.bind(b.name.node.clone());
    // Bindings at policy level become constants available
    // to rules and proofs. The runtime pre-evaluates them.
}
```

The comment says the runtime pre-evaluates them, but no pre-evaluation code exists in `aegis-runtime/src/engine.rs`. Simple literal bindings (`let max_retry = 5`) work because the literal is inlined at the reference site during lowering. Bindings whose value involves computed expressions (`let domains = load_domains()`) will fail to resolve at runtime — the slot will evaluate to `Value::Null`.

---

## Summary Table

| Feature | Grammar | Type check | Lowering | Runtime |
|---|---|---|---|---|
| Import resolution | Yes | Structural only | N/A | No |
| Full regex (`matches`) | Yes | Yes | Yes | No (glob only) |
| `eval` CLI command | N/A | N/A | N/A | No |
| List patterns in `match` | Yes | Partial | Dropped → default | N/A |
| Binding patterns in `match` | Yes | Partial | Dropped → default | N/A |
| Destructure field sub-patterns | Yes | Partial | Ignored | N/A |
| Object literals as Maps | Yes | Yes | Stub (empty list) | No |
| `Set<T>` runtime type | Yes | Yes | Yes | No (no Value::Set) |
| Multi-arg annotations | Yes | Yes | Filtered out | N/A |
| Non-temporal invariant conditions | Yes | Yes | Dropped (→ None) | N/A |
| Generic type bounds | Yes | No | No | N/A |
| `scope` target validation | Yes | No (future) | N/A | N/A |
| Named call arguments | Yes | Partial | Stripped | N/A |
| Complex policy `let` pre-eval | Yes | Yes | Slot only | No |

---

## Implementation Priority

Ranked by **failure mode severity** — the governing principle for an enforcement engine is that a silent policy bypass is categorically worse than a missing feature. Items are grouped into four tiers.

### Tier 1 — Silent Policy Bypass (Fix First)

These gaps allow a policy to compile, load, and appear active while silently failing to enforce its stated constraint. For a safety tool this is the worst possible outcome.

| # | Item | Why it's a bypass |
|---|---|---|
| **1** | **Destructure field sub-patterns ignored** | `ToolCall { tool: "exec" }` matches *every* ToolCall, not just exec. A `deny` rule targeting a specific tool silently fires on the wrong events or, if the wrong match triggers an `allow`, lets the targeted event through. |
| **2** | **`scope` target validation** | A one-character typo in a scope declaration (`tol_call` instead of `tool_call`) means every rule in the policy is permanently dead. No warning is emitted. |
| **3** | **Non-temporal invariant conditions silently dropped** | A static boolean condition inside an `invariant` block (e.g. `event.approved == true`) is parsed, type-checked, and then discarded by the lowering pass. The invariant produces no state machine and is never evaluated. |
| **4** | **Import resolution missing** | Any policy that imports `automaguard.stdlib.pii` and uses `pii.contains_pii()` to gate a `redact` or `deny` will silently receive `null` (falsy) from every call. PII detection via the stdlib is completely inoperative. This affects the most important real-world use cases. |

**Implementation notes for Tier 1:**

- **#1** requires completing the decision tree compiler in `lower.rs:lower_match_to_decision_tree` to recurse into `fields` on `Pattern::Destructure` and emit nested guard conditions.
- **#2** is a small checker addition: maintain a set of canonical event type names (or derive them from scope targets seen across the policy file) and emit a `DiagnosticCode::W` warning on unknown targets.
- **#3** requires the lowering pass to handle the `_ => None` case in `lower_temporal_to_sm`: non-temporal conditions should be lowered to a `StateMachine` with `TemporalKind::Always` and the condition as the predicate — semantically identical to `always(condition)`.
- **#4** is the largest item: requires a module resolver, a stdlib crate defining built-in modules (`pii`, `network`, `compliance`), and name injection into the type environment and lowering scope.

---

### Tier 2 — Documented Behavior Differs from Actual Behavior (Fix Before Stable)

These compile and run without error, but produce results that differ from what the language reference documents. A policy author who tests their policy will likely observe the discrepancy, but only if they test the specific feature.

| # | Item | Actual behavior |
|---|---|---|
| **5** | **Full regex for `matches`** | Only glob-style patterns work (`^...$`, `prefix.*`, `.*suffix`). A policy using `/^\d{3}-\d{4}$/` to validate a phone format will silently match nothing or match incorrectly. |
| **6** | **Policy-level `let` with computed values** | Literal-value bindings (`let n = 5`) work. Any binding whose right-hand side is an expression other than a literal evaluates to `null` at runtime because the runtime never pre-evaluates policy-level slots. |
| **7** | **Object literals lower to empty list** | `{"key": value}` compiles to `IRExpr::List(vec![])`. Any policy expression that constructs an object and then reads from it receives an empty list. |
| **8** | **Binding patterns in `match`** | `match x { n -> use n }` evaluates `n` as `null` instead of the matched value. Rules that compute a verdict message or action argument from the matched value silently lose the value. |

**Implementation notes for Tier 2:**

- **#5** is straightforward: add the `regex` crate, store compiled `Regex` objects alongside the `IRExpr::Literal(Literal::Regex(...))`, and call `regex.is_match()` in `eval_predicate`. Regex flags (`/pattern/i`) map directly to `regex::RegexBuilder` options.
- **#6** requires the engine to walk policy-level `BindingDecl` nodes at load time, evaluate their expressions into `Value`, and store them in the `policy` map that `EvalContext` already exposes via `RefRoot::Policy`.
- **#7** requires a new `IRExpr::Object(Vec<(SmolStr, IRExpr)>)` variant (or lowering object literals to a series of `Map::insert` IR calls) and a corresponding `Value::Map` construction path in `eval.rs`.
- **#8** requires the lowering pass to assign the matched subject value to the binding's local slot and emit an `IRExpr::Ref(RefRoot::Local(slot))` for references to the binding name in the arm body.

---

### Tier 3 — Missing Functionality (Fix for Completeness)

These features are absent rather than broken. A policy author who needs them cannot use them; a policy author who doesn't use them is unaffected.

| # | Item | Notes |
|---|---|---|
| **9** | **List patterns in `match`** | Currently falls through to the default arm. Requires pattern list compilation in the decision tree — emit a sequence of element-position guards. |
| **10** | **`aegisc eval` CLI subcommand** | Critical for interactive policy development and CI smoke tests. Requires instantiating a `PolicyEngine`, constructing an `Event` from `k=v` args, calling `engine.evaluate()`, and printing the `PolicyResult`. Self-contained addition to `cli.rs`. |
| **11** | **Named call arguments** | Currently stripped to positional. Requires the type checker to match named args by parameter name and the lowering pass to reorder them to the declared signature order before emitting `IRExpr::Call`. |

---

### Tier 4 — Type System Completeness (Defer)

These are correctness gaps in the type system or metadata layer with no runtime safety impact. A policy that compiles today is not made more dangerous by their absence.

| # | Item | Notes |
|---|---|---|
| **12** | **`Set<T>` runtime type** | Add `Value::Set(HashSet<Value>)` to the runtime, wire `Set<T>` type annotations to it, and enforce uniqueness. Low safety impact; `List` silently substitutes today. |
| **13** | **Multi-argument annotations** | Extend `PolicyMetadata::annotations` to `Vec<(SmolStr, AnnotationValue)>` and update the lowering filter. Metadata only; no enforcement impact. |
| **14** | **Generic type parameter bounds** | Thread `type_params` through `Ty::Struct` and add bound-checking in `check_call`. Improves type soundness for library authors; no impact on policy enforcement semantics. |

---

### Recommended Sequence

```
Sprint 1  ── Tier 1 items #1 #2 #3
Sprint 2  ── Tier 1 item  #4  (import resolution — larger, needs stdlib crate)
Sprint 3  ── Tier 2 items #5 #6 #7 #8
Sprint 4  ── Tier 3 items #9 #10 #11
Backlog   ── Tier 4 items #12 #13 #14
```

Item #10 (`aegisc eval`) could be pulled into Sprint 1 as a low-cost force-multiplier: it makes all other fixes immediately testable from the command line without writing a Rust test for each one.

---

## Appropriate Complexity: What the Language Needs vs. What It Has

This section assesses whether the Aegis language is over-specified relative to its mission. The short answer: the core is tight and purposeful; the overdesign is real but concentrated in three identifiable clusters.

---

### The Tight Core — Everything Here Earns Its Place

These features are all load-bearing. Remove any one of them and the language cannot do its job.

**Enforcement skeleton:** `policy`, `on`, `when`, `allow`, `deny`, `audit`, `redact`, `with`, `scope`, `severity`

**The formal verification moat — temporal operators:** `always`, `never`, `eventually`, `until`, `next`, `before`, `after`, `within`, `proof`, `invariant`

**Operational constraints:** `rate_limit`, `quota`, `per`

**Side effects:** `log`, `notify`, `escalate`, `block`, `tag`

**Abstraction:** `let`, `def`, `import`, `from`, `as`, `extends`

**Collection reasoning:** `all`, `any`, `none`, `exists`, `count`, lambda (`=>`)

**String matching:** `contains`, `starts_with`, `ends_with`, `matches`, `in`

**Logic:** `and`, `or`, `not`, `implies`, comparison operators, duration literals

This is roughly **75% of the keyword surface**. It is coherent, purposeful, and maps directly to the problem domain.

---

### The Overdesign — Three Clusters

#### Cluster 1: The Type System Is More Ambitious Than the Runtime Supports

`type` declarations, generic parameters (`<T extends string>`), and union types (`string | int`) exist in the grammar and type checker, but the runtime is fully dynamic — the `Value` enum has no generic type tracking. The type checker treats `event` and `context` as open dynamic structs that accept any field access. In practice, every policy accesses event fields by name, never by declared struct type.

`type Endpoint { url: string, method: string }` compiles but provides zero runtime enforcement. The only payoff is static type checking of user-defined function signatures — a narrow benefit.

The type system overreaches relative to what the verifier can actually enforce. The useful subset is: primitives (`int`, `float`, `bool`, `string`, `duration`), `List<T>`, and `Map<K, V>` for function signatures only. Generic bounds and union types are dead weight for v1.

#### Cluster 2: `match` Duplicates `on`/`when` at High Compiler Cost

Every `match` example in the reference is directly expressible as multiple `on` blocks:

```aegis
// match form
match event.classification {
    "restricted"  -> deny  with "Restricted access prohibited",
    "confidential" -> audit with "Confidential access logged",
    _ -> allow
}

// on/when form — identical behavior, zero extra compiler machinery
on data_access { when event.classification == "restricted"   deny  with "Restricted access prohibited" }
on data_access { when event.classification == "confidential" audit with "Confidential access logged" }
on data_access { allow }
```

`match` bought significant implementation complexity: the decision tree lowering pass, five pattern variants (three of which are unimplemented — see items 4, 5, and 6 above), a `MatchResult` type distinct from `BlockStatement`, and the grammar weight of `pattern`, `or_pattern`, `guarded_pattern`, `base_pattern`, and `pattern_field`.

The one case where `match` adds genuine value — returning a computed value from inside an expression — does not arise in practice because policies issue verdicts; they do not compose them as values.

#### Cluster 3: Syntactic Sugar That Does Not Change Expressiveness

| Feature | Assessment |
|---|---|
| **Object literals** `{k: v}` | Not implemented at runtime; no clear policy use case. Policies read from events and context — they do not construct new data structures. |
| **Raw strings** `r"..."` | Narrow value. Useful for regex patterns containing backslashes. Does not justify a dedicated grammar production. |
| **Scientific notation floats** `1.0e-3` | Policies count events and measure durations in whole numbers. This literal form will not appear in production policy. |
| **Named call arguments** `fn(key = val)` | Adds parser and checker complexity. Policy functions are short (1–3 parameters). Positional arguments are sufficient. |
| **Annotations** `@author("x")` | Metadata. This belongs in comments or a sidecar manifest, not in language syntax. The current implementation preserves only single-string arguments (see item 9 above), which is not useful enough to justify the grammar surface. |
| **Phantom keywords** `during`, `assert`, `rule`, `where` | Reserved in the `keyword` production but appear in no grammar rule anywhere in `aegis.pest`. They block their use as identifiers for zero current benefit. Either implement them or remove them from the reserved list. |

---

### Summary Verdict

The language is not bloated in the "throw everything in" sense. The core is purposeful and well-designed. The overdesign is concentrated and explainable: the original design had a coherent vision of a general-purpose policy language with a full type system and pattern matching, and partially implemented it. The features that survived from that larger vision — `type` declarations, generics, union types, `match`, object literals — add grammar and compiler surface area without adding enforcement power for the specific problem of AI agent safety.

**If starting from scratch,** the right cut is to keep the core temporal enforcement skeleton and remove: `type` declarations, generic bounds, union types, `match`, object literals, scientific notation floats, raw strings, named function arguments, annotations as syntax, and the four phantom keywords.

**Given existing investment,** the pragmatic path is narrower:

1. Finish `match` patterns to the level documented (the decision tree is already there; patterns 4, 5, and 6 in the implementation gap list are the remaining work). `match` is present in real policy examples and removing it now would be a breaking change.
2. Keep `type` declarations but document them as compiler-only type hints for function signatures, not runtime-enforced contracts. Remove generics and union types from the stable surface.
3. Remove the four phantom keywords (`during`, `assert`, `rule`, `where`) from the reserved list — they create error messages for valid identifiers while serving no purpose.
4. Deprecate annotations as syntax in favor of a policy-level comment convention or a sidecar `.toml` manifest. Annotations will never be rich enough to be useful at their current implementation depth.
