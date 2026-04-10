# The Aegis Policy Language
## A Programmer's Reference

---

> *"Policies compile to state machines. The runtime does not parse or evaluate policy source at request time."*
> — AutomaGuard design principle

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Getting Started](#2-getting-started)
3. [Program Structure](#3-program-structure)
4. [Lexical Conventions](#4-lexical-conventions)
5. [Types](#5-types)
6. [Literals](#6-literals)
7. [Expressions](#7-expressions)
8. [Policies](#8-policies)
9. [Rules](#9-rules)
10. [Verdicts](#10-verdicts)
11. [Actions](#11-actions)
12. [Rate Limits and Quotas](#12-rate-limits-and-quotas)
13. [Temporal Operators](#13-temporal-operators)
14. [Proofs and Invariants](#14-proofs-and-invariants)
15. [Bindings and Functions](#15-bindings-and-functions)
16. [Type Declarations](#16-type-declarations)
17. [Imports](#17-imports)
18. [Annotations](#18-annotations)
19. [Pattern Matching](#19-pattern-matching)
20. [Quantifiers and Collection Operations](#20-quantifiers-and-collection-operations)
21. [Event and Context References](#21-event-and-context-references)
22. [Severity Levels](#22-severity-levels)
23. [Policy Inheritance](#23-policy-inheritance)
24. [The Compiler CLI](#24-the-compiler-cli)
25. [Complete Examples](#25-complete-examples)
26. [Keyword Reference](#26-keyword-reference)

---

## 1. Introduction

Aegis is a domain-specific language for expressing behavioral constraints on AI agents. Unlike configuration-based approaches that interpret rules at runtime, Aegis **compiles** policies to state machines. The verifier loads pre-compiled bytecode and evaluates events against it — no parsing happens on the hot path. This is what makes sub-10ms latency possible.

### What Aegis Is For

An AI agent exercises tool calls: it reads files, sends email, makes HTTP requests, queries databases. Aegis lets you write precise, mathematically verifiable rules about what sequences of tool calls are and are not allowed.

A single-event check ("is this URL in the approved list?") is a predicate. That is easy. Aegis is distinguished by **temporal invariants**: "after the agent reads any file classified as PII, it must never send an external HTTP request." That constraint spans an unbounded sequence of events. It compiles to a state machine. No regex or validator approach can express it.

### Design Philosophy

- **Compiled, not interpreted.** Policies compile to `.aegisc` bytecode containing explicit state machines and decision trees. The runtime loads and evaluates bytecode.
- **Temporal logic is the moat.** `always`, `eventually`, `until`, `never`, `before`, `after`, and `next` compile to Büchi-like automata. They provide mathematical guarantees about event sequences, not just individual events.
- **The verifier is the product.** Optimize for runtime correctness and latency above compiler elegance.
- **Append-only audit.** Every verdict is logged. Nothing is mutable after the fact.

### A Taste of the Language

```aegis
policy FileGuard {
    rate_limit write_file: 10 per 1m

    on tool_call {
        when event.tool == "write_file"
          and !(event.params.path starts_with "/tmp/safe/")
        deny with "Write outside /tmp/safe/ is prohibited"
    }

    proof NoExfiltration {
        invariant NoPIILeak {
            after(
                !(event.tool == "send_email"),
                event.classification == "PII"
            )
        }
    }
}
```

This policy: (1) rate-limits file writes, (2) denies writes outside a safe directory, and (3) mathematically guarantees that no email is ever sent after a PII-classified data access.

---

## 2. Getting Started

### Installation

Build the compiler from the `aegis-compiler` crate:

```sh
cd aegis-compiler
cargo build --release
# Binary is at target/release/aegisc
```

### Your First Policy

Create `hello.aegis`:

```aegis
policy HelloGuard {
    on tool_call {
        when event.tool == "exec"
        deny with "Shell execution is not permitted"
    }
}
```

Compile it:

```sh
aegisc compile hello.aegis -o hello.aegisc
```

Type-check without compiling:

```sh
aegisc check hello.aegis
```

Inspect the compiled bytecode:

```sh
aegisc inspect hello.aegisc
```

Dump the compiled IR as JSON:

```sh
aegisc dump hello.aegis | jq '.rules'
```

---

## 3. Program Structure

An Aegis source file (`.aegis`) is a sequence of top-level declarations. Order does not matter; forward references are resolved.

```
program ::= declaration*

declaration ::=
    import_decl
  | policy_decl
  | proof_decl
  | type_decl
  | binding_decl
  | function_decl
```

**Top-level declarations:**

| Declaration | Keyword | Purpose |
|---|---|---|
| Import | `import` / `from` | Bring external modules or names into scope |
| Policy | `policy` | The primary safety construct; contains rules |
| Proof | `proof` | Temporal invariant group (can live outside a policy) |
| Type | `type` | Declare a named record type |
| Binding | `let` | Top-level constant binding |
| Function | `def` | Reusable helper function |

---

## 4. Lexical Conventions

### Comments

Aegis supports C-style comments:

```aegis
// Single-line comment

/*
   Multi-line comment.
   Spans multiple lines.
*/
```

### Identifiers

An identifier begins with a letter or underscore, followed by any combination of letters, digits, and underscores. Identifiers cannot be keywords.

```
ident = id_start id_continue*
id_start    = [A-Za-z_]
id_continue = [A-Za-z0-9_]
```

Valid identifiers: `tool_call`, `_private`, `MyPolicy`, `x1`

Invalid: `1start`, `rate_limit` (keyword), `my-var` (hyphens not allowed)

### Qualified Names

A qualified name is a sequence of identifiers joined by dots. Used for module paths, field access chains in type positions, and structured identifiers.

```aegis
automaguard.stdlib.pii    // import path
event.params.path         // field access expression
```

### Whitespace

Whitespace (spaces, tabs, newlines) is insignificant between tokens. Statements do not require semicolons; they are optional and ignored.

---

## 5. Types

Aegis has a static type system used by the compiler. At runtime, event field values are dynamically typed (the `Value` type in the runtime engine).

### Primitive Types

| Keyword | Description | Example value |
|---|---|---|
| `int` | 64-bit signed integer | `42`, `-7` |
| `float` | 64-bit floating point | `3.14`, `1.0e-3` |
| `bool` | Boolean | `true`, `false` |
| `string` | UTF-8 string | `"hello"` |
| `duration` | Time span | `5m`, `100ms`, `24h` |

### Collection Types

| Syntax | Description |
|---|---|
| `List<T>` | Ordered sequence of elements of type `T` |
| `Map<K, V>` | Key-value map from type `K` to type `V` |
| `Set<T>` | Unordered collection of unique elements of type `T` |

```aegis
let urls: List<string> = ["https://api.example.com", "https://cdn.example.com"]
let headers: Map<string, string> = {"Authorization": "Bearer xyz"}
```

### Union Types

Union types express that a value may be one of several types. Primarily used in pattern matching:

```aegis
type StringOrInt = string | int
```

### User-Defined Types

Custom record types are declared with `type` (see [Section 16](#16-type-declarations)).

### Generic Types

Type declarations can be parameterized:

```aegis
type Container<T extends string> {
    value: T,
    label: string
}
```

---

## 6. Literals

### Boolean Literals

```aegis
true
false
```

### Integer Literals

Sequences of decimal digits. No hex or binary notation in v1.

```aegis
0
42
1000000
```

### Float Literals

Decimal notation with a mandatory fractional part. Optional scientific notation.

```aegis
3.14
1.0
2.5e6
1.0e-3
```

### String Literals

Double-quoted strings with backslash escapes:

```aegis
"hello, world"
"path/to/file"
"line one\nline two"
"tab\there"
```

**Raw strings** suppress escape processing (prefix `r"`):

```aegis
r"C:\Users\agent\data"    // backslash is literal
r"no \n escape here"
```

### Duration Literals

A duration is an integer followed immediately by a unit suffix (no space):

| Suffix | Unit |
|---|---|
| `ms` | milliseconds |
| `s` | seconds |
| `m` | minutes |
| `h` | hours |
| `d` | days |

```aegis
100ms      // 100 milliseconds
30s        // 30 seconds
5m         // 5 minutes
2h         // 2 hours
1d         // 1 day
```

Duration is the type used for `rate_limit` and `quota` windows, and for `within` clauses on temporal operators.

**Note:** `ms` must come before `m` in parsing. `5ms` is 5 milliseconds; `5m` is 5 minutes. Always include the full suffix.

### Regex Literals

A regex literal is delimited by forward slashes with optional flags:

```aegis
/^https?:\/\//         // matches http:// or https://
/\d{3}-\d{4}/i        // phone number pattern, case-insensitive flag
```

Regex literals are used with the `matches` predicate.

### List Literals

```aegis
["read_file", "write_file", "exec"]
[1, 2, 3]
[]   // empty list
```

### Object Literals

```aegis
{tool: "write_file", path: "/tmp/out.txt"}
{"Content-Type": "application/json", "X-Api-Key": key}
```

Object field keys may be bare identifiers or string literals.

---

## 7. Expressions

### Operator Precedence

From lowest to highest binding:

| Level | Operators | Associativity |
|---|---|---|
| 1 (lowest) | `implies` | right |
| 2 | `\|\|`, `or` | left |
| 3 | `&&`, `and` | left |
| 4 | `==`, `!=` | left |
| 5 | `<`, `<=`, `>`, `>=`, `in` | left |
| 6 | Temporal: `always`, `eventually`, `never`, `next`, `before`, `after`, `until` | — |
| 7 | `+`, `-` | left |
| 8 | `*`, `/`, `%` | left |
| 9 | `!` (not), `-` (negation) | right (unary) |
| 10 (highest) | `.field`, `[index]`, `(call)`, predicates | left |

### Logical Operators

```aegis
// AND: both conditions must hold
event.tool == "write_file" and event.params.path contains ".."
event.tool == "write_file" && event.params.path contains ".."   // equivalent

// OR: at least one condition must hold
event.classification == "restricted" or event.classification == "confidential"
event.classification == "restricted" || event.classification == "confidential"

// NOT: negation
!event.approved
!(event.tool == "exec")

// IMPLIES: logical implication — "if A then B" (equivalent to !A || B)
event.classification == "PII" implies event.approved_by != ""
```

### Comparison Operators

```aegis
event.count == 5          // equal
event.count != 0          // not equal
event.count > 10          // greater than
event.count >= 10         // greater than or equal
event.count < 100         // less than
event.count <= 100        // less than or equal
```

### Membership: `in`

Tests whether a value is a member of a list or set:

```aegis
event.tool in ["read_file", "write_file", "list_files"]
event.recipient in approved_recipients
!(event.domain in blocked_domains)
```

### Arithmetic

```aegis
event.count + 1
event.size * 2
event.offset % page_size
event.total - event.used
event.bytes / 1024
```

### String Predicates

String predicates are **postfix** — they appear after the subject expression:

```aegis
// contains: substring test
event.params.path contains ".."
event.params.query contains "password"

// starts_with: prefix test
event.params.url starts_with "https://"
event.params.path starts_with "/tmp/safe/"

// ends_with: suffix test
event.params.filename ends_with ".exe"
event.params.filename ends_with ".sh"

// matches: regex test
event.params.email matches /^[a-z]+@example\.com$/
event.params.url matches /^https?:\/\//i
```

**Precedence caution:** `starts_with` and related predicates bind greedily. When the argument involves `or` or `and`, use parentheses:

```aegis
// Wrong: starts_with consumes the entire right side
url starts_with "https://api." || url starts_with "https://10."

// Correct: parentheses force the intended grouping
(url starts_with "https://api.") || (url starts_with "https://10.")
```

### Field Access

Access nested fields using dot notation:

```aegis
event.tool               // top-level field
event.params.path        // nested field
event.endpoint.url       // nested field on a sub-object
```

### Index Access

Access list elements by zero-based index, or map values by key:

```aegis
event.args[0]            // first element of args list
headers["Authorization"] // value for key "Authorization"
```

### Function Calls

Call user-defined or built-in functions:

```aegis
is_internal(event.endpoint.url)
pii.contains_pii(event.arguments)
```

### Method Calls

Call a method on an object using dot syntax followed by a call:

```aegis
event.params.path.len()
```

### Grouped Expressions

Parentheses override precedence:

```aegis
(event.count > 5) and (event.size < 1000)
```

### Lambda Expressions

Lambdas are anonymous functions used as arguments to quantifiers and collection operations. They appear as `param => body` or `(param1, param2) => body`.

```aegis
// Single parameter
tool => tool == "exec"
kw => event.params.query contains kw

// Typed single parameter
(url: string) => url starts_with "https://"

// Multiple parameters
(k, v) => k == "Authorization"
```

### Block Expressions

A block is a sequence of statements enclosed in braces. Used in `match` arms:

```aegis
{
    let reason = "Violation: " + event.tool
    deny with reason
    log level: "error"
}
```

---

## 8. Policies

A **policy** is the primary top-level construct. It groups rules, rate limits, proofs, functions, and bindings that enforce a coherent safety property.

### Syntax

```
policy <Name> [extends <ParentName>] {
    [severity <level>]
    [scope <event-type>, ...]
    [rate_limit <target>: <limit> per <window>]
    [quota <target>: <limit> per <window>]
    [let <name> [: <type>] = <expr>]
    [def <name>(<params>) -> <type> = <expr>]
    [on <event-type> { ... }]
    [proof <Name> { ... }]
}
```

### Minimal Policy

```aegis
policy EmptyGuard {
    // No rules: every event passes through
}
```

### A Complete Policy

```aegis
policy ApiGuard {
    severity high
    scope tool_call, external_request

    // Constant binding
    let max_body_size = 1048576  // 1 MB

    // Helper function
    def is_safe_domain(url: string) -> bool =
        (url starts_with "https://api.internal.") || (url starts_with "https://10.")

    // Rate limits
    rate_limit tool_call: 100 per 1m
    rate_limit external_request: 20 per 5m

    // Rules
    on external_request {
        when !is_safe_domain(event.endpoint.url)
        deny with "External request to unapproved domain"
        severity critical
    }

    on tool_call {
        when event.body_size > max_body_size
        deny with "Request body too large"
    }
}
```

### Policy Members

Inside a policy body, the following members are allowed in any order:

| Member | Description |
|---|---|
| `severity <level>` | Default severity for this policy |
| `scope <targets>` | Event types this policy applies to |
| `rate_limit <target>: <n> per <window>` | Rate limit constraint |
| `quota <target>: <n> per <window>` | Total quota constraint |
| `let <name> = <expr>` | Local constant binding |
| `def <name>(<params>) -> <type> = <expr>` | Helper function |
| `on <event-type> { ... }` | Rule block |
| `proof <Name> { ... }` | Temporal invariant group |

---

## 9. Rules

A rule is an **event-triggered check**. It fires when an event matches the `on` clause, evaluates the `when` condition, and issues a verdict.

### Syntax

```
on <event-type> [, <event-type> ...] {
    [when <condition>]
    <verdict> [with <message>]
    [<action> ...]
    [severity <level>]
}
```

### The `on` Clause

Specifies which event type(s) this rule applies to. The event type is a bare identifier or a string literal:

```aegis
on tool_call { ... }
on data_access { ... }
on external_request { ... }
on "custom_event_type" { ... }

// Multiple event types in one rule
on tool_call, data_access { ... }
```

The event type is matched against the `event_type` field of incoming events. Common event types:

| Event Type | When it fires |
|---|---|
| `tool_call` | Agent invokes a tool or function |
| `data_access` | Agent reads from a data source |
| `external_request` | Agent makes an outbound HTTP/network request |

### The `when` Clause

A boolean condition. The rule's verdict is only issued when the condition evaluates to `true`. If absent, the rule fires unconditionally.

```aegis
on tool_call {
    when event.tool == "exec"
    deny with "Shell execution is prohibited"
}

// No when: fires on every tool_call
on tool_call {
    audit
    log level: "info"
}
```

The `when` expression can reference `event.*` fields, `context.*` fields, local bindings, and policy-level functions.

### Annotations on Rules

Rules may carry annotations:

```aegis
@deprecated("Use exec_guard policy instead")
on tool_call {
    when event.tool == "exec"
    deny
}
```

---

## 10. Verdicts

A verdict is the decision the runtime returns for an event. Each rule produces exactly one verdict. If a rule has multiple verdict clauses, they are evaluated in order and the first applicable one wins.

### `allow`

Permit the event. The agent's tool call proceeds normally.

```aegis
on data_access {
    when event.classification == "public"
    allow
}
```

### `deny`

Block the event. The agent's tool call is rejected. An optional message explains why.

```aegis
on tool_call {
    when event.tool == "drop_table"
    deny with "DDL operations are prohibited"
}

// Without a message
on tool_call {
    when event.tool == "exec"
    deny
}
```

The message can be any string expression, including string concatenation:

```aegis
deny with "Blocked tool: " + event.tool
```

### `audit`

Allow the event but log it for compliance review. The agent proceeds, but the event is recorded in the audit trail with full details.

```aegis
on data_access {
    when event.classification == "PII"
    audit with "PII record accessed"
    tag "pii_accessed"
}
```

`audit` is often combined with `allow` to make the intent explicit:

```aegis
on data_access {
    when event.classification == "confidential" && event.jurisdiction == "EU"
    audit with "GDPR-regulated data access"
    allow
}
```

### `redact`

Allow the event but strip or mask sensitive fields before the agent receives the response. Used to prevent PII or credentials from flowing into agent memory or output.

```aegis
on tool_call {
    when any(event.arguments, arg => pii.contains_pii(arg))
    redact with "PII detected in tool arguments"
    tag "pii-redacted"
    audit
}
```

### Verdict Summary

| Verdict | Agent proceeds? | Logged? | Output modified? |
|---|---|---|---|
| `allow` | Yes | No (unless `audit` also present) | No |
| `deny` | No | Yes | — |
| `audit` | Yes | Yes (full detail) | No |
| `redact` | Yes | Yes | Yes (fields sanitized) |

---

## 11. Actions

Actions are side effects that accompany a verdict. They appear inside rule bodies after a verdict clause.

### `log`

Emit a structured log entry. Named arguments specify log fields:

```aegis
log level: "error", destination: event.endpoint.url
log level: "warn", message: "Suspicious access pattern"
log                  // bare log with no extra fields
```

Common log keys: `level`, `message`, `destination`, `reason`

### `notify`

Send a notification to a channel or team:

```aegis
notify channel: "security-alerts"
notify channel: "data-governance", message: "GDPR access detected"
```

### `escalate`

Escalate the event to a human review queue:

```aegis
escalate to: "data-governance"
escalate to: "security-team", priority: "high"
```

### `block`

Block all further events for a duration (circuit breaker):

```aegis
block 30m             // block for 30 minutes
block 1h              // block for 1 hour
```

When `block` fires, subsequent events from the same session are denied automatically until the window expires.

### `tag`

Attach a label to the event for downstream filtering and reporting:

```aegis
tag "pii_accessed"
tag "high-volume-user"
```

### Using Actions Together

Actions are cumulative — all listed actions fire when the rule matches:

```aegis
on data_access {
    when event.classification == "restricted"
    deny with "Access to restricted data requires explicit approval"
    escalate to: "data-governance"
    log level: "error", classification: event.classification
    notify channel: "security-alerts"
    severity critical
}
```

---

## 12. Rate Limits and Quotas

Rate limits and quotas are **declarative constraints** that the runtime enforces using sliding windows. They operate independently of rule conditions.

### `rate_limit`

Limits the **rate** (events per time window). Uses a sliding window — not a fixed bucket — to prevent burst-at-boundary exploits.

```
rate_limit <target>: <count> per <duration>
```

```aegis
rate_limit tool_call: 100 per 1m       // max 100 tool calls per minute
rate_limit send_email: 3 per 300s      // max 3 emails per 5 minutes
rate_limit web_search: 10 per 60s      // max 10 searches per minute
rate_limit external_request: 20 per 5m
```

When the limit is exceeded, the runtime automatically issues a `deny` verdict with an appropriate message. No rule is needed.

### `quota`

Limits the **total count** within a window. Semantically similar to `rate_limit` but emphasizes a cumulative budget rather than a per-second rate:

```aegis
quota data_access: 10000 per 1h   // at most 10,000 reads per hour
quota api_calls: 500 per 1d       // at most 500 API calls per day
```

### Placement

Rate limits and quotas can appear:

- At **policy level**: apply to all matching events in the policy's scope
- Inside a **rule body**: apply specifically to events that pass the rule's `when` condition

```aegis
policy MyPolicy {
    // Policy-level: applies to every tool_call event
    rate_limit tool_call: 60 per 1m

    on tool_call {
        when event.tool == "send_email"
        // Rule-level: only applies when this when-clause matches
        rate_limit send_email: 5 per 1m
        audit with "Email sent"
    }
}
```

---

## 13. Temporal Operators

Temporal operators are the distinguishing feature of Aegis. They express constraints about **sequences of events** across time. Each temporal operator compiles to a state machine that the runtime advances on every event.

Unlike per-event checks, temporal operators can detect violations that only emerge from a pattern of otherwise individually-acceptable actions.

### Linear Temporal Logic Background

Aegis temporal operators correspond to standard LTL (Linear Temporal Logic) operators:

| Aegis | LTL | Meaning |
|---|---|---|
| `always(φ)` | □φ | φ holds at every future state |
| `eventually(φ)` | ◇φ | φ holds at some future state |
| `never(φ)` | □¬φ | φ never holds |
| `φ until ψ` | φ U ψ | φ holds until ψ becomes true |
| `next(φ)` | Xφ | φ holds in the immediately next state |

`before` and `after` are derived forms for common temporal patterns.

Temporal operators may only appear inside `invariant` blocks within `proof` declarations.

---

### `always`

```
always(<condition>) [within <duration>]
```

`φ` must hold at **every** future event. Compiles to a 2-state machine (Satisfied → Violated). Once violated, the invariant stays violated.

```aegis
invariant AllRequestsApproved {
    always(event.approved == true)
}

invariant NoShellExecution {
    always(event.tool != "exec")
}
```

The optional `within` clause sets a time bound:

```aegis
invariant MustRespondQuickly {
    always(event.response_time < 100ms) within 5m
}
```

**State machine:** 2 states.
- State 0 (Satisfied): evaluate condition on each event. Condition holds → stay. Condition fails → transition to State 1.
- State 1 (Violated): absorbing. Invariant permanently broken.

---

### `eventually`

```
eventually(<condition>) [within <duration>]
```

`φ` must hold **at some future event**. Used to require that something eventually happens. Compiles to a 3-state machine.

```aegis
invariant MustAuthenticate {
    eventually(event.tool == "authenticate") within 30s
}

invariant WorkMustComplete {
    eventually(event.status == "complete") within 5m
}
```

Without `within`, `eventually` means "at some point before the session ends" — the window is the session lifetime.

**State machine:** 3 states.
- State 0 (Waiting): condition not yet seen. On each event: if condition holds → State 1. If timer expires → State 2.
- State 1 (Satisfied): absorbing. Invariant holds.
- State 2 (Timed Out / Violated): absorbing. Invariant broken.

---

### `never`

```
never(<condition>)
```

`φ` must **never** hold. Equivalent to `always(!φ)` but more readable for prohibition constraints.

```aegis
invariant NoDropTable {
    never(event.tool == "drop_table")
}

invariant NoCleartextPasswords {
    never(event.params.query contains "password=")
}
```

**State machine:** 2 states (same structure as `always`).

---

### `until`

```
<hold-condition> until <release-condition>
```

The `hold-condition` must remain true at every event **until** the `release-condition` becomes true. Once the release condition fires, the hold condition is no longer required.

This is the φ U ψ operator: φ must hold up to and including the moment ψ becomes true.

```aegis
invariant SandboxedUntilVerified {
    (event.tool != "external_request") until event.tool == "verify_identity"
}

invariant ReadOnlyUntilApproved {
    (event.action == "read") until event.approval_granted == true
}
```

**State machine:** 3 states.
- State 0 (Hold): hold-condition must be true. Check hold on each event: if hold fails and release hasn't fired → State 2 (Violated). If release fires → State 1.
- State 1 (Released): absorbing. Invariant satisfied.
- State 2 (Violated): absorbing. Hold condition broke before release.

---

### `next`

```
next(<condition>)
```

`φ` must hold on the **immediately next event** after this invariant is evaluated. This is the Xφ operator.

```aegis
invariant ConfirmationFollowsDeletion {
    next(event.tool == "confirm_delete")
}
```

`next` is typically used inside compound expressions to express ordering between adjacent events.

---

### `before`

```
before(<first-condition>, <second-condition>)
```

The first condition must become true **before** the second condition becomes true. If the second condition fires before the first, the invariant is violated.

```aegis
// Human approval must happen before any deletion
invariant ApprovalBeforeDelete {
    before(
        event.tool == "human_approved",
        event.tool == "delete_record"
    )
}

// Authentication must precede any data access
invariant AuthBeforeAccess {
    before(
        event.tool == "authenticate",
        event.event_type == "data_access"
    )
}
```

---

### `after`

```
after(<condition>, <trigger>)
```

Once the trigger fires, the condition must hold for all subsequent events. This is the pattern "after X happens, Y must always be true."

```aegis
// After any PII access, no external requests are allowed
invariant NoPIIExfiltration {
    after(
        !(event.event_type == "external_request"),
        event.event_type == "data_access" && event.classification == "PII"
    )
}

// After writing to /etc/, no email is permitted
invariant NoSensitiveFileExfiltration {
    after(
        !(event.tool == "send_email"),
        event.tool == "write_file" && event.params.path starts_with "/etc/"
    )
}
```

**Reading `after`:** `after(condition, trigger)` means: once `trigger` has been observed, `condition` must hold for every subsequent event.

---

### Temporal Operators Inside Proofs

Temporal operators only appear inside `invariant` blocks inside `proof` declarations. The compiler will reject temporal operators placed directly in rule `when` clauses:

```aegis
// WRONG: temporal operators only inside invariant blocks
on tool_call {
    when always(event.tool != "exec")   // compile error
    deny
}

// CORRECT:
proof NoExec {
    invariant NoShellCalls {
        always(event.tool != "exec")
    }
}
```

---

## 14. Proofs and Invariants

A **proof** is a named group of **invariants**. Invariants contain temporal logic expressions that compile to state machines.

### `proof`

```
proof <Name> {
    invariant <Name> { ... }
    invariant <Name> { ... }
    ...
}
```

A proof groups related invariants. All invariants in a proof are active simultaneously — the runtime tracks state machines for each one independently.

```aegis
proof ExfiltrationGuard {
    invariant NoPIILeak {
        after(
            !(event.tool == "send_data"),
            event.classification == "PII"
        )
    }

    invariant NoShellAfterNetworkAccess {
        after(
            !(event.tool == "exec"),
            event.event_type == "external_request"
        )
    }
}
```

### `invariant`

```
invariant <Name> {
    <temporal-expression>
    [; <temporal-expression>]
    ...
}
```

An invariant contains one or more temporal expressions. Multiple expressions within an invariant are implicitly conjoined (all must hold):

```aegis
invariant StrictDataPolicy {
    never(event.tool == "drop_table");
    always(event.classification != "restricted");
}
```

### Proof as a Policy Member

Proofs can appear directly inside a policy:

```aegis
policy DataGuard {
    // ... rules and rate limits ...

    proof SafetyProperties {
        invariant NoExternalWrite {
            always(
                event.event_type != "external_request"
                    || event.method == "GET"
            )
        }
    }
}
```

Or at the top level of a file (outside any policy):

```aegis
// Top-level proof applies globally
proof GlobalInvariants {
    invariant NoExec {
        never(event.tool == "exec")
    }
}
```

---

## 15. Bindings and Functions

### `let` — Value Bindings

`let` binds a name to a value or expression. Bindings are immutable. They can appear at the top level, inside a policy, or inside a rule body (block context).

```
let <name> [: <type>] = <expression>
```

```aegis
// Top-level binding
let max_retry = 5

// Policy-level binding
policy MyPolicy {
    let approved_domains = [
        "api.internal.corp",
        "reports.internal.corp"
    ]

    let allowed_prefix = "/tmp/safe/"

    on tool_call {
        when event.tool == "write_file"
          and !(event.params.path starts_with allowed_prefix)
        deny with "Write outside safe directory"
    }
}
```

With an explicit type annotation:

```aegis
let max_body_size: int = 1048576
let timeout: duration = 30s
let domains: List<string> = ["a.com", "b.com"]
```

### `def` — Functions

`def` declares a named function with typed parameters and a return type:

```
def <name>(<param>: <type>, ...) -> <return-type> = <expression>
```

```aegis
def is_internal(url: string) -> bool =
    (url starts_with "https://api.internal.") || (url starts_with "https://10.")

def is_pii_tool(tool: string) -> bool =
    tool in ["query_pii_db", "export_records", "generate_report"]

def is_safe_path(path: string) -> bool =
    (path starts_with "/tmp/") && !(path contains "..")
```

Functions can reference policy-level bindings:

```aegis
policy ApiGuard {
    let approved_endpoints = ["https://api.corp.com", "https://cdn.corp.com"]

    def is_approved(url: string) -> bool =
        url in approved_endpoints

    on external_request {
        when !is_approved(event.endpoint.url)
        deny with "Unapproved external endpoint"
    }
}
```

**Note:** Functions that reference `context.*` (runtime state) must be declared inside a policy, where context is in scope.

---

## 16. Type Declarations

`type` declares a named record type with named fields. These types can be used in function signatures and let bindings.

```
type <Name> [<GenericParams>] {
    <field>: <type>,
    ...
}
```

```aegis
type Endpoint {
    url: string,
    method: string,
    headers: Map<string, string>
}

type DataClassification {
    level: string,
    categories: List<string>,
    jurisdiction: string
}
```

### Generic Type Parameters

```aegis
type Container<T> {
    value: T,
    label: string
}

// With a bound
type BoundedContainer<T extends string> {
    value: T,
    count: int
}
```

### Using Custom Types

```aegis
type Endpoint {
    url: string,
    method: string
}

def is_safe(ep: Endpoint) -> bool =
    ep.method == "GET" && is_internal(ep.url)
```

---

## 17. Imports

Imports bring external module definitions — types, functions, constants — into scope.

### `import` — Module Import

```
import <module.path> [as <alias>]
```

Import an entire module under an alias:

```aegis
import automaguard.stdlib.pii as pii

// Use with the alias prefix
on tool_call {
    when any(event.arguments, arg => pii.contains_pii(arg))
    redact with "PII detected"
}
```

Without an alias, the last segment of the path becomes the module name:

```aegis
import automaguard.stdlib.network
// Use as: network.is_routable(...)
```

### `from` — Named Import

```
from <module.path> import <name> [as <alias>] [, <name> ...]
from <module.path> import *
```

Import specific names from a module:

```aegis
from automaguard.stdlib import network, compliance

// Import with alias
from automaguard.stdlib.pii import contains_pii as has_pii

// Glob import — brings everything into scope
from automaguard.stdlib import *
```

### Import Paths

Import paths are dot-separated module paths. The resolution strategy depends on the runtime configuration, but `automaguard.stdlib.*` refers to the AutomaGuard standard library.

---

## 18. Annotations

Annotations attach metadata to policies and rules. They do not affect runtime behavior but are preserved in the compiled bytecode for tooling and documentation purposes.

### Syntax

```
@<name>
@<name>(<value>, ...)
@<name>(<key>: <value>, ...)
```

```aegis
@author("security-team")
@version("2.1.0")
@deprecated("Use DataGuardV3 instead")
policy DataExfiltrationGuard {
    ...
}

@environment("development")
policy DevModeRelaxed extends DataExfiltrationGuard {
    ...
}
```

Annotation values can be literals or lists of literals:

```aegis
@tags(["pii", "gdpr", "critical"])
@since("2025-01-01")
@reviewed(true)
```

---

## 19. Pattern Matching

`match` evaluates an expression against a series of patterns and produces a result (a verdict, expression, or block) for the first matching arm.

### Syntax

```
match <scrutinee> {
    <pattern> -> <result>,
    <pattern> -> <result>,
    ...
}
```

### Patterns

#### Wildcard

Matches anything. Used as a catch-all default:

```aegis
match event.classification {
    "restricted" -> deny with "Restricted data access prohibited",
    "confidential" -> audit with "Confidential access logged",
    _ -> allow
}
```

#### Literal Patterns

Match exact values:

```aegis
match event.tool {
    "exec" -> deny with "Shell execution blocked",
    "drop_table" -> deny with "DDL blocked",
    "send_email" -> audit with "Email logged",
    _ -> allow
}
```

#### Or Patterns

Match any of several alternatives using `|`:

```aegis
match event.tool {
    "drop_table" | "truncate_table" | "delete_database" ->
        deny with "Destructive DDL is prohibited",
    _ -> allow
}
```

#### Binding Patterns

Bind the matched value to a name for use in the result:

```aegis
match event.classification {
    level -> audit with "Access at level: " + level
}
```

#### Destructuring Patterns

Match a structured value by its fields:

```aegis
match event {
    ToolCall { tool: "exec", params: p } -> deny with "exec blocked",
    ToolCall { tool: t } -> audit with "Tool: " + t,
    _ -> allow
}
```

#### List Patterns

Match a list by element patterns:

```aegis
match event.args {
    [first, second, _] -> audit with "Three-arg call",
    [] -> allow,
    _ -> audit
}
```

#### Guard Patterns

A pattern with an additional `when` condition:

```aegis
match event.count {
    n when n > 1000 -> deny with "Count too high",
    n when n > 100  -> audit with "Count elevated",
    _               -> allow
}
```

### Match Results

A match arm result can be:

1. **An expression** — the value of the match
2. **A verdict clause** — `deny`, `allow`, `audit`, or `redact`
3. **A block** — `{ let ...; deny ...; log ... }`

---

## 20. Quantifiers and Collection Operations

### `all`

`all(collection, predicate)` — true if the predicate holds for every element:

```aegis
// All arguments must be non-empty
all(event.arguments, arg => arg != "")

// Every domain must be in the approved list
all(event.domains, d => d in approved_domains)
```

### `any`

`any(collection, predicate)` — true if the predicate holds for at least one element:

```aegis
// At least one argument contains PII
any(event.arguments, arg => pii.contains_pii(arg))

// Any keyword matches
any(["password", "secret", "token"], kw => event.params.query contains kw)
```

### `none`

`none(collection, predicate)` — true if the predicate holds for no element (equivalent to `!any(...)`):

```aegis
// No argument contains shell metacharacters
none(event.arguments, arg => arg contains ";")

// None of the URLs are external
none(event.urls, url => url starts_with "http://")
```

### `exists`

`exists(collection, predicate)` — synonym for `any`. Preferred stylistically when expressing that something must be present:

```aegis
exists(event.approvers, a => a.role == "admin")
```

### `count`

`count(collection)` or `count(collection, predicate)` — returns the number of elements (optionally filtered):

```aegis
// More than 5 web searches in the context window
count(context.web_search_events) > 5

// More than 50 recent reads
count(context.recent_reads) > 50

// Count writes to /etc/
count(context.write_events, e => e.path starts_with "/etc/") > 0
```

`count` returns an integer usable in arithmetic and comparisons.

### Quantifier Syntax

```
all(collection, lambda)
any(collection, lambda)
none(collection, lambda)
exists(collection, lambda)
count(collection [, lambda])
```

The lambda binds the collection element to a name:

```aegis
any(event.arguments, arg => arg contains "password")
//                   ^^^   ^^^^^^^^^^^^^^^^^^^^^^^^
//                   param  body
```

---

## 21. Event and Context References

### The `event` Object

Inside rule `when` clauses, `event` refers to the current intercepted event. It has dynamic fields accessed via dot notation.

**Standard fields available on all events:**

| Field | Type | Description |
|---|---|---|
| `event.event_type` | `string` | The event type string (`"tool_call"`, `"data_access"`, etc.) |
| `event.timestamp` | `duration` | Event timestamp in milliseconds since epoch |

**Tool call event fields (convention):**

| Field | Type | Description |
|---|---|---|
| `event.tool` | `string` | Tool name |
| `event.params` | `Map<string, string>` | Tool parameters |
| `event.arguments` | `List<string>` | Positional arguments |
| `event.tool_name` | `string` | Alternative tool name field (framework-dependent) |

**Data access event fields (convention):**

| Field | Type | Description |
|---|---|---|
| `event.classification` | `string` | Data classification (`"PII"`, `"restricted"`, `"public"`, etc.) |
| `event.jurisdiction` | `string` | Legal jurisdiction (`"EU"`, `"US"`, etc.) |

**External request event fields (convention):**

| Field | Type | Description |
|---|---|---|
| `event.endpoint.url` | `string` | Full URL |
| `event.endpoint.method` | `string` | HTTP method |
| `event.domain` | `string` | Hostname |

The exact fields available depend on what the SDK populates. Accessing a missing field returns a null value; the condition evaluates to false rather than erroring.

### The `context` Object

`context` provides **session-level state** maintained by the runtime — not the current event, but aggregated history. Accessed as `context.<name>`.

```aegis
// Number of web searches in the recent sliding window
count(context.web_search_events) > 5

// Approved endpoints from runtime configuration
event.endpoint.url in context.config.approved_endpoints

// Recent read events
count(context.recent_reads) > 50
```

Context fields are populated by the runtime engine and SDK, not by the policy author. Available context fields depend on which framework integrations are active:

| Context field | Description |
|---|---|
| `context.web_search_events` | Recent web search events (sliding window) |
| `context.recent_reads` | Recent data read events |
| `context.write_events` | Recent file write events |
| `context.external_requests` | Recent outbound requests |
| `context.config.*` | Runtime configuration values |

**Note:** `context.*` is only meaningful inside `proof`/`invariant` blocks and rule `when` clauses. Functions referencing `context` must be declared inside a policy.

---

## 22. Severity Levels

Severity labels classify the urgency of a policy or rule violation. They propagate to the audit log and can drive alerting thresholds.

### Levels (highest to lowest)

| Keyword | Description |
|---|---|
| `critical` | Immediate threat; block and page on-call |
| `high` | Significant risk; alert immediately |
| `medium` | Notable anomaly; review promptly |
| `low` | Minor deviation; log for analysis |
| `info` | Informational; no action required |

### Policy-Level Severity

Sets the default severity for all rules in the policy:

```aegis
policy DataExfiltrationGuard {
    severity critical
    ...
}
```

### Rule-Level Severity

Overrides the policy default for a specific rule:

```aegis
on data_access {
    when event.classification == "restricted"
    deny with "Access to restricted data requires explicit approval"
    severity critical
}

on data_access {
    when event.classification == "internal"
    audit with "Internal data access"
    severity low
}
```

---

## 23. Policy Inheritance

A policy can extend another policy, inheriting all its rules, rate limits, proofs, and bindings. The child policy can add new members or override inherited behavior.

```
policy <Child> extends <Parent> {
    ...
}
```

### Example

```aegis
@author("security-team")
@version("2.1.0")
policy DataExfiltrationGuard {
    severity critical
    rate_limit tool_call: 100 per 1m
    rate_limit external_request: 20 per 5m

    on external_request {
        when !is_approved_destination(event.endpoint.url)
        deny with "External request to unapproved destination"
    }
}

// Development relaxation: inherits all rules but widens limits
@environment("development")
policy DevModeRelaxed extends DataExfiltrationGuard {
    severity low

    // Override: allow localhost (not allowed in parent)
    on external_request {
        when event.endpoint.url starts_with "http://localhost"
        allow
    }

    // Override rate limits
    rate_limit tool_call: 1000 per 1m
    rate_limit external_request: 200 per 5m
}
```

Inheritance is resolved at compile time. The compiled bytecode for `DevModeRelaxed` contains all parent rules inlined, with child-added rules merged in.

**Override semantics:** Child rules are evaluated first. If a child rule issues a verdict, parent rules for the same event type are skipped.

---

## 24. The Compiler CLI

The compiler binary is `aegisc`. It provides five subcommands.

### `compile`

Compile a `.aegis` source file to `.aegisc` bytecode:

```sh
aegisc compile policy.aegis
aegisc compile policy.aegis -o output.aegisc
```

If the source contains multiple policy declarations, each compiles to a separate output file suffixed with the policy name.

Output reports the number of rules and state machines compiled:

```
  Compiling policies/guard.aegis...
  Wrote guard.aegisc (4812 bytes, 7 rules, 3 state machines)
  Done.
```

### `check`

Type-check a source file without producing output:

```sh
aegisc check policy.aegis
aegisc check -                        # read from stdin
aegisc check --json policy.aegis      # machine-readable JSON
```

Success output:

```
  Checking policies/guard.aegis...
  OK: 1 policies, 7 rules, 3 invariants verified
```

JSON output (for CI integration):

```json
{
  "ok": true,
  "file": "policies/guard.aegis",
  "policies": [{"name": "DataGuard", "rules": 7, "invariants": 3, "constraints": 2}],
  "errors": [],
  "warnings": []
}
```

### `dump`

Dump the compiled IR as JSON. Useful for debugging and inspecting what the compiler produced:

```sh
aegisc dump policy.aegis
aegisc dump policy.aegis | jq '.state_machines'
aegisc dump policy.aegis | jq '.rules[].condition'
```

### `inspect`

Inspect the header of a compiled `.aegisc` file:

```sh
aegisc inspect guard.aegisc
```

```
File: guard.aegisc
  Magic:   0xAE915C01
  Version: 1
  Policy:  DataExfiltrationGuard
  Severity: Critical
  Scopes:  tool_call, data_access, external_request
  Rules:   7
  Constraints: 3
  State machines: 2
    - NoDataLeaks_InternalOnly (Always, 2 states, 2 transitions)
    - NoDataLeaks_NoPIIExfiltration (After, 3 states, 4 transitions)
```

### `eval` (planned)

Simulate an event against a compiled policy:

```sh
aegisc eval guard.aegisc tool_call tool_name=exec
aegisc eval --json guard.aegisc data_access classification=PII
```

### `.aegisc` Bytecode Format

The compiled bytecode format:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 bytes | Magic: `0xAE915C01` |
| 4 | 2 bytes | Format version |
| 6 | 2 bytes | Flags |
| 8 | 4 bytes | Payload length |
| 12 | N bytes | JSON-serialized `CompiledPolicy` |

The JSON payload means policies can also be distributed over HTTP and loaded by the runtime without disk I/O.

---

## 25. Complete Examples

### Example 1: File Write Guard

Prevents path traversal and restricts writes to a safe directory. Demonstrates `let` bindings, `starts_with`, `contains`, and rate limits.

```aegis
// file_write_guard.aegis
//
// Prevents AI agents from writing files outside a designated
// safe directory and blocks path traversal attacks.

policy FileWriteGuard {
    severity high

    let safe_prefix = "/tmp/research/"

    // Max 10 writes per minute to prevent bulk exfiltration
    rate_limit write_file: 10 per 1m

    // Block path traversal
    on tool_call {
        when event.tool == "write_file" and event.params.path contains ".."
        deny with "Write blocked: path traversal detected"
        log level: "warn", path: event.params.path
        severity critical
    }

    // Block writes outside the safe directory
    on tool_call {
        when event.tool == "write_file"
          and !(event.params.path starts_with safe_prefix)
        deny with "Write blocked: path must be under /tmp/research/"
        log level: "error", path: event.params.path
    }
}
```

### Example 2: Email Allowlist with Sequence Detection

Demonstrates `let` with a list, `in` membership test, rate limits, and `proof` / `invariant` with `always` and `after`.

```aegis
// research_guard.aegis
//
// Controls email sending and detects bulk search → email exfiltration.

policy ResearchGuard {

    let approved_recipients = [
        "analyst@corp.com",
        "team@corp.com"
    ]

    rate_limit send_email: 3 per 300s
    rate_limit web_search: 10 per 60s

    // Block email to unapproved recipients
    on tool_call {
        when event.tool == "send_email"
          and !(event.params.recipient in approved_recipients)
        deny with "Email blocked: recipient not in approved list"
        severity critical
    }

    proof SequenceGuards {

        // Detect bulk search → email pattern
        // A single email after 5+ searches is suspicious
        invariant NoBulkSearchThenEmail {
            always(
                !(count(context.web_search_events) > 5
                  and event.tool == "send_email")
            )
        }

        // After writing to /etc/, disallow email
        invariant NoSensitiveFileExfiltration {
            after(
                !(event.tool == "send_email"),
                event.tool == "write_file"
                    and event.params.path starts_with "/etc/"
            )
        }

        // After a PII-related search, disallow external email
        invariant NoPIIResearchExfiltration {
            after(
                !(event.tool == "send_email"
                  and !(event.params.recipient in approved_recipients)),
                event.tool == "web_search"
                and any(
                    ["personal information", "email address", "home address"],
                    kw => event.params.query contains kw
                )
            )
        }
    }
}
```

### Example 3: Data Classification Routing

Demonstrates `match`-style per-rule routing, multiple `on` blocks for the same event type, `escalate`, and GDPR-aware handling.

```aegis
// data_guard.aegis
//
// Routes data access events by classification level.
// Enforces GDPR requirements for EU-jurisdiction data.

policy CustomerDataGuard {

    rate_limit data_access: 20 per 1m
    rate_limit tool_calls:  60 per 1m

    // Block destructive DDL
    on tool_call {
        when event.tool_name in ["drop_table", "truncate_table",
                                  "delete_database", "alter_table"]
        deny with "DDL operations are prohibited"
        severity critical
    }

    // Restricted data: deny and escalate
    on data_access {
        when event.classification == "restricted"
        deny with "Access to restricted data requires explicit approval"
        escalate to: "data-governance"
        severity critical
    }

    // Confidential EU data: GDPR audit
    on data_access {
        when event.classification == "confidential" && event.jurisdiction == "EU"
        audit with "GDPR-regulated data access"
        allow
    }

    // PII data: audit and tag
    on data_access {
        when event.classification == "PII"
        audit with "PII record accessed"
        tag "pii_accessed"
        severity high
    }

    // Internal data: permit
    on data_access {
        when event.classification == "internal"
        allow
    }

    // Bulk extraction: block
    on data_access {
        when count(context.recent_reads) > 50
        deny with "Bulk data extraction pattern detected"
        block 30m
        notify channel: "security-alerts"
    }

    // PII must never be followed by an external request
    proof ExfiltrationGuard {
        invariant NoPIIExfiltration {
            after(
                !(event.event_type == "external_request"),
                event.event_type == "data_access"
                    && event.classification == "PII"
            )
        }
    }

    // Deletion requires prior human approval
    proof DeletionGate {
        invariant ApprovalBeforeDelete {
            before(
                event.event_type == "tool_call"
                    && event.tool_name == "human_approved",
                event.event_type == "tool_call"
                    && event.tool_name == "delete_record"
            )
        }
    }
}
```

### Example 4: Full-Featured Policy with Inheritance

Demonstrates `import`, custom types, `def` functions, annotations, and `extends`.

```aegis
// api_guard.aegis
//
// Full API safety policy with a development relaxation override.

import automaguard.stdlib.pii as pii
from automaguard.stdlib import network

type Endpoint {
    url: string,
    method: string,
    headers: Map<string, string>
}

def is_internal(url: string) -> bool =
    (url starts_with "https://api.internal.") || (url starts_with "https://10.")

@author("security-team")
@version("3.0.0")
policy ApiGuard {
    severity critical
    scope tool_call, data_access, external_request

    rate_limit tool_call: 100 per 1m
    rate_limit external_request: 20 per 5m
    quota data_access: 10000 per 1h

    def is_approved_destination(url: string) -> bool =
        url in context.config.approved_endpoints

    // Block unapproved external requests
    on external_request {
        when !is_approved_destination(event.endpoint.url)
          && !is_internal(event.endpoint.url)
        deny with "External request to unapproved destination"
        log level: "error", destination: event.endpoint.url
        notify channel: "security-alerts"
        severity critical
    }

    // Redact PII in tool call arguments
    on tool_call {
        when any(event.arguments, arg => pii.contains_pii(arg))
        redact with "PII detected in tool arguments"
        tag "pii-redacted"
        audit
    }

    // Bulk extraction protection
    on data_access {
        when count(context.recent_reads) > 50
        deny with "Bulk data extraction pattern detected"
        block 30m
        notify channel: "security-alerts"
    }

    proof NoDataLeaks {
        invariant InternalOnly {
            always(
                event.event_type != "external_request"
                    || is_approved_destination(event.endpoint.url)
                    || is_internal(event.endpoint.url)
            )
        }

        invariant NoPIIExfiltration {
            after(
                !(event.tool == "send_data"
                  && any(event.arguments, arg => pii.contains_pii(arg))),
                event.classification == "PII"
            )
        }
    }
}

// Development override: relaxed limits, allow localhost
@environment("development")
policy ApiGuardDev extends ApiGuard {
    severity low

    on external_request {
        when event.endpoint.url starts_with "http://localhost"
        allow
    }

    rate_limit tool_call: 1000 per 1m
    rate_limit external_request: 200 per 5m
}
```

---

## 26. Keyword Reference

Complete alphabetical list of all reserved keywords. These cannot be used as identifiers.

| Keyword | Category | Description |
|---|---|---|
| `after` | Temporal | φ must hold after trigger fires |
| `all` | Quantifier | True if predicate holds for all elements |
| `allow` | Verdict | Permit the event |
| `always` | Temporal | φ must hold at every future state (□φ) |
| `and` | Logical | Logical conjunction (`&&`) |
| `any` | Quantifier | True if predicate holds for at least one element |
| `as` | Import | Alias in import declarations |
| `assert` | Reserved | Reserved for future use |
| `audit` | Verdict | Allow event and log for compliance |
| `before` | Temporal | φ must occur before ψ |
| `block` | Action | Block all events for a duration |
| `bool` | Type | Boolean primitive type |
| `context` | Access | Runtime session state |
| `contains` | Predicate | Substring or list membership test |
| `count` | Collection | Count elements (optionally filtered) |
| `critical` | Severity | Highest severity level |
| `def` | Declaration | Function definition |
| `deny` | Verdict | Block the event |
| `duration` | Type | Time span primitive type |
| `during` | Reserved | Reserved for future use |
| `ends_with` | Predicate | String suffix test |
| `escalate` | Action | Escalate to human review |
| `eventually` | Temporal | φ must hold at some future state (◇φ) |
| `exists` | Quantifier | Synonym for `any` |
| `extends` | Policy | Policy inheritance |
| `false` | Literal | Boolean false |
| `float` | Type | Floating point primitive type |
| `from` | Import | Named import source |
| `high` | Severity | High severity level |
| `implies` | Logical | Logical implication (→) |
| `import` | Import | Module import |
| `in` | Membership | Collection membership test |
| `info` | Severity | Informational severity level |
| `int` | Type | Integer primitive type |
| `invariant` | Proof | Named temporal property inside a proof |
| `let` | Binding | Immutable value binding |
| `List` | Type | Ordered collection type constructor |
| `log` | Action | Emit a log entry |
| `low` | Severity | Low severity level |
| `Map` | Type | Key-value map type constructor |
| `match` | Expression | Pattern-matching expression |
| `matches` | Predicate | Regex match test |
| `medium` | Severity | Medium severity level |
| `never` | Temporal | φ must never hold (□¬φ) |
| `next` | Temporal | φ must hold in the immediately next state (Xφ) |
| `none` | Quantifier | True if predicate holds for no element |
| `notify` | Action | Send notification to a channel |
| `on` | Rule | Event type trigger for a rule |
| `or` | Logical | Logical disjunction (`\|\|`) |
| `per` | Constraint | Window separator in rate limits |
| `policy` | Declaration | Primary policy construct |
| `proof` | Declaration | Named group of temporal invariants |
| `quota` | Constraint | Total count constraint |
| `rate_limit` | Constraint | Rate limiting constraint |
| `redact` | Verdict | Allow event but sanitize sensitive fields |
| `rule` | Reserved | Reserved for future use |
| `scope` | Policy | Declares applicable event types |
| `Set` | Type | Unordered unique collection type constructor |
| `severity` | Policy/Rule | Severity classification |
| `starts_with` | Predicate | String prefix test |
| `string` | Type | String primitive type |
| `tag` | Action | Attach a label to an event |
| `true` | Literal | Boolean true |
| `type` | Declaration | Custom record type declaration |
| `until` | Temporal | φ must hold until ψ (φ U ψ) |
| `when` | Rule | Conditional guard on a rule |
| `with` | Verdict/Action | Message argument for verdicts and actions |
| `within` | Temporal | Time bound on `always` or `eventually` |

---

## Quick Reference Card

### Policy Skeleton

```aegis
policy MyPolicy [extends Parent] {
    severity <critical|high|medium|low|info>
    scope tool_call, data_access, external_request

    let name = value
    def fn(param: type) -> type = expr

    rate_limit target: N per duration
    quota target: N per duration

    on event_type {
        when <condition>
        deny | allow | audit | redact [with "message"]
        log | notify | escalate | block | tag
        severity <level>
    }

    proof ProofName {
        invariant InvariantName {
            always(condition)
            | never(condition)
            | eventually(condition) [within duration]
            | condition until condition
            | next(condition)
            | before(condition, condition)
            | after(condition, trigger)
        }
    }
}
```

### Verdict Decision Flow

```
Event arrives
    │
    ▼
Rate limit exceeded? ──── YES ──→ deny (auto)
    │ NO
    ▼
Match on event type
    │
    ▼
Evaluate when clause
    │
    ├── false ──→ (next rule)
    │
    └── true ───→ issue verdict:
                     allow   → proceed
                     deny    → block + log
                     audit   → proceed + log
                     redact  → proceed + sanitize + log
```

### Temporal Operator Cheat Sheet

```
always(φ)              — φ holds forever (□φ)
never(φ)               — φ never holds (□¬φ)
eventually(φ) within T — φ holds before T expires (◇φ within T)
φ until ψ             — φ holds until ψ fires (φ U ψ)
next(φ)               — φ holds on next event (Xφ)
before(φ, ψ)          — φ fires before ψ
after(cond, trigger)  — once trigger fires, cond holds always
```

### String Predicates

```
s contains "substr"      — substring test
s starts_with "prefix"   — prefix test
s ends_with "suffix"     — suffix test
s matches /pattern/      — regex test
```

### Duration Suffixes

```
100ms    5s    10m    2h    1d
```
