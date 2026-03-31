# Temporal Logic for Agent Safety: A Practical Guide

## Why You Need More Than Allow/Deny Lists

Most agent safety tools work like bouncers at a door: they check each action in isolation. "Is this tool call allowed? Yes or no." That catches simple violations, but it misses the dangerous ones — the ones that emerge from *sequences* of individually innocent actions.

Consider a customer support agent with access to a CRM and an email tool. Each of these actions is fine on its own:

1. Look up a customer record
2. Read the customer's purchase history
3. Send an email

But this *sequence* is a data breach:

1. Look up every customer record in the database
2. Compile all email addresses
3. Send them to an external endpoint

No single action is unauthorized. The violation is in the pattern. A bouncer checking IDs at the door would wave each one through. What you need is a detective who watches the whole story unfold and intervenes when the plot goes wrong.

That detective is temporal logic.

---

## What Is Temporal Logic?

Temporal logic is a formal system for reasoning about *sequences of events over time*. It was developed in the 1970s by computer scientist Amir Pnueli for verifying that programs behave correctly — not just on one input, but across all possible executions.

The core insight: some properties can only be expressed as statements about what happens *across time*, not at a single moment.

- "The system never deadlocks" — a property of all future states.
- "Every request eventually gets a response" — a property that spans from now into the future.
- "The mutex is held until the critical section completes" — a relationship between two future events.

These are temporal properties. You can't express them as input validation. You need a formalism that talks about *before*, *after*, *always*, and *eventually*.

Linear Temporal Logic (LTL) is the most widely used variant. "Linear" means it reasons about a single sequence of events unfolding over time — a trace, a timeline, a log. This maps directly to what an AI agent does: it takes a sequence of actions, one after another, and LTL lets you write down exactly which sequences are safe and which aren't.

### Notation at a Glance

LTL has two common notations. The symbolic notation (□, ◇) appears in academic papers and textbooks. The letter notation (G, F, U, X) is what most model-checking tools use (SPIN, NuSMV, TLA+). Aegis uses English keywords because the target audience is engineers writing policies, not logicians writing proofs — but the semantics are identical.

| Aegis | LTL Symbol | LTL Letter | Full Name | English |
|---|---|---|---|---|
| `always(φ)` | □φ | Gφ | Box / Globally | "φ holds at every step, forever" |
| `eventually(φ)` | ◇φ | Fφ | Diamond / Finally | "φ becomes true at some future step" |
| `never(φ)` | □¬φ | G¬φ | Negated globally | "φ is false at every step, forever" |
| `until(φ, ψ)` | φ U ψ | φ U ψ | Until | "φ holds at every step until ψ occurs" |
| `next(φ)` | Xφ | Xφ | Next | "φ holds at the immediately next step" |

If you're cross-referencing with academic material or other verification tools, this table is your Rosetta Stone. The rest of this tutorial uses the Aegis keywords and the symbolic notation side by side.

---

## The Five Core Operators

LTL has five operators. Each one makes a different kind of claim about the future. In the formal notation, φ (phi) and ψ (psi) represent properties — things that are either true or false at any given moment.

### 1. `always(φ)` — "This must be true forever"

**Formal notation:** □φ

**Meaning:** At every point in time, now and in the future, property φ must hold. If it ever becomes false, even once, the invariant is violated.

**When to use it:** Safety properties. Things that must *never go wrong*. "The agent must always stay within its authorized scope." "Every external request must always target an approved endpoint." "The running total must always stay under the budget."

**Example in Aegis:**

```
proof BudgetSafety {
    invariant SpendLimit {
        always(context.total_spend <= context.config.max_budget)
    }
}
```

This compiles to a 2-state machine:

```
┌────────────┐   spend ≤ budget   ┌────────────┐
│ Satisfied  │ ──────────────────→ │ Satisfied  │
│ (state 0)  │ ←──────────────────│ (state 0)  │
└────────────┘                    └────────────┘
      │
      │ spend > budget
      ▼
┌────────────┐
│ Violated   │  ← absorbing state (no way back)
│ (state 1)  │
└────────────┘
```

The machine starts in state 0 (satisfied). On every event, the runtime checks the predicate. If the predicate holds, the machine stays in state 0. The moment the predicate fails — even once — the machine transitions to state 1 (violated) and stays there permanently. There is no recovery from an `always` violation.

This permanence is a feature, not a limitation. If your policy says the budget must *always* stay under the limit, and the agent blows past it, the system has entered an unsafe state. The violation is recorded, and no future good behavior can undo it.

**Common mistake:** Using `always` when you mean "usually" or "on average." If there is any legitimate scenario where the property might temporarily be false, `always` is the wrong operator.

### 2. `eventually(φ)` — "This must become true at some point"

**Formal notation:** ◇φ

**Meaning:** At some point in the future (including right now), property φ must become true. It doesn't have to stay true — it just has to happen at least once.

**When to use it:** Liveness properties. Things that must *eventually happen*. "Every denied request must eventually be reviewed." "The agent must eventually release any resource it acquires." "A human must eventually approve the queued transactions."

Bare `eventually` without a deadline is a weak guarantee — "at some point before the heat death of the universe." In practice, you almost always pair it with `within` to set a time bound.

**Example in Aegis:**

```
proof ReviewCompliance {
    invariant TimelyReview {
        always(
            context.denied_requests.all(req =>
                eventually(req.reviewed == true) within 24h
            )
        )
    }
}
```

Read this inside-out: "For every denied request, it must eventually be true that the request has been reviewed, and that must happen within 24 hours. And this must *always* be the case (for every denied request, at every point in time)."

The nested `always(... eventually(...))` is the canonical liveness-under-safety pattern: "it is *always* the case that something *eventually* happens."

**The `within` clause compiles to a 3-state machine:**

```
┌────────────┐   φ becomes true   ┌────────────┐
│  Waiting   │ ──────────────────→│ Satisfied  │
│ (state 0)  │                    │ (state 1)  │
└────────────┘                    └────────────┘
      │
      │ deadline expires (φ still false)
      ▼
┌────────────┐
│  Violated  │
│ (state 2)  │
└────────────┘
```

The machine starts waiting. If the property becomes true before the deadline, it moves to satisfied. If the deadline expires without the property becoming true, it moves to violated. Without `within`, state 2 doesn't exist — the machine waits indefinitely.

**Common mistake:** Forgetting that `eventually` without `within` provides no practical guarantee. If you care about *when* something happens, add a deadline.

### 3. `never(φ)` — "This must never be true"

**Formal notation:** □¬φ

**Meaning:** At no point in time, now or in the future, may property φ become true. This is logically equivalent to `always(!φ)`, but reads more naturally for prohibitions.

**When to use it:** Blacklist properties. Hard prohibitions. "PII must never appear in outbound requests." "The agent must never call the delete endpoint." "Credentials must never be logged."

**Example in Aegis:**

```
proof DataSafety {
    invariant NoPIILeakage {
        never(
            any(context.tool_calls, call =>
                any(call.arguments, arg => pii.contains_pii(arg))
            )
        )
    }
}
```

This reads: "It must never be the case that any tool call contains any argument with PII." Mechanically identical to the `always` machine — 2 states, one absorbing violation state — but the intent is clearer. Use `never` when you're expressing a prohibition. Use `always` when you're expressing an obligation.

**Common mistake:** Using `never` for things that are only *sometimes* prohibited. If the same action is forbidden in one context but allowed in another, you need conditional logic inside your invariant, not a blanket `never`.

### 4. `until(φ, ψ)` — "Hold this until that happens"

**Formal notation:** φ U ψ

**Meaning:** Property φ must hold at every step *until* property ψ becomes true. Once ψ becomes true, the obligation on φ is released. Crucially, ψ *must* eventually become true — `until` is not "hold this, and maybe that happens someday." It guarantees both that φ holds in the interim and that ψ eventually occurs.

**When to use it:** Ordering constraints. Resource management. "The agent must operate in read-only mode until a human approves write access." "All actions must be logged to the staging audit trail until production deployment is confirmed." "The rate limit must stay at the lower threshold until the warmup period completes."

**Example in Aegis:**

```
proof DeploymentSafety {
    invariant ReadOnlyUntilApproval {
        until(
            none(context.tool_calls, c => c.mutates == true),
            context.human_approval_received == true
        )
    }
}
```

This says: "There must be no mutating tool calls (φ holds) *until* human approval is received (ψ becomes true)." The `until` operator guarantees three things simultaneously:

1. While waiting for approval, no mutations happen.
2. Approval *must* eventually arrive.
3. After approval, mutations are permitted.

**3-state machine:**

```
┌────────────┐   ψ becomes true    ┌────────────┐
│  Holding   │ ───────────────────→│  Released  │
│ (state 0)  │  (approval given)   │ (state 1)  │
└────────────┘                     └────────────┘
      │
      │ φ fails (mutation without approval)
      ▼
┌────────────┐
│  Violated  │
│ (state 2)  │
└────────────┘
```

While in state 0, every event is checked against φ (no mutations). If a mutation occurs before approval, the machine enters state 2 (violated). If approval arrives, it enters state 1 (released), and φ is no longer checked.

**Common mistake:** Confusing `until` with `always ... unless`. The `until` operator *requires* that the release condition eventually become true. If you want "hold this indefinitely, but stop holding it if that happens," you want a conditional `always`, not `until`.

### 5. `next(φ)` — "This must be true on the very next step"

**Formal notation:** Xφ

**Meaning:** On the immediately next event (not now, not eventually, but the very next one), property φ must be true.

**When to use it:** Sequencing constraints. "After a login attempt, the next action must be a verification step." "After acquiring a lock, the next operation must be within the critical section."

**Example in Aegis:**

```
proof AuthSequence {
    invariant VerifyAfterLogin {
        always(
            context.last_event.type == "login_attempt" implies
                next(event.type == "mfa_verify" or event.type == "login_failed")
        )
    }
}
```

This reads: "Whenever a login attempt occurs, the very next event must be either an MFA verification or a login failure." No other action can intervene between the attempt and the verification.

**2-state machine with a twist — it has a transient checking state:**

```
                                         any event
┌────────────┐   login_attempt   ┌──────────────┐
│  Idle      │ ─────────────────→│  Must-verify │
│ (state 0)  │ ←─────────────── │  (state 1)   │
└────────────┘  φ holds on next  └──────────────┘
                                       │
                                       │ φ fails on next
                                       ▼
                                 ┌────────────┐
                                 │  Violated  │
                                 │ (state 2)  │
                                 └────────────┘
```

The machine is usually idle. When the trigger fires (login attempt), it transitions to state 1 and waits for exactly one event. If that event satisfies φ, back to idle. If not, violated.

**Common mistake:** Using `next` when you mean `eventually`. `next` is extremely strict — it means the *immediate* next event with no intervening events allowed. If other benign actions might occur between trigger and response, use `eventually ... within` instead.

---

## Composing Operators

The real power of LTL emerges when you combine operators. Each combination expresses a different class of property.

### `always(... implies eventually(...))` — Response Pattern

"Whenever X happens, Y must follow."

```
proof CustomerService {
    invariant EscalationResponse {
        always(
            event.type == "escalation_created" implies
                eventually(event.type == "escalation_acknowledged") within 15m
        )
    }
}
```

Every escalation must be acknowledged within 15 minutes. The `always` ensures this holds for *every* escalation, not just the first one.

### `always(... implies never(...))` — Exclusion Pattern

"Whenever X is true, Y must not happen."

```
proof ComplianceMode {
    invariant NoExternalInAudit {
        always(
            context.audit_mode_active == true implies
                never(event.type == "external_request")
        )
    }
}
```

While audit mode is active, external requests are absolutely forbidden.

### `until(always(...), ...)` — Graduated Permissions

"Strict rules apply permanently until a condition enables relaxation."

```
proof GraduatedAccess {
    invariant WarmupPeriod {
        until(
            always(context.request_count_per_minute <= 10),
            context.warmup_complete == true
        )
    }
}
```

During warmup, the strict rate limit of 10/minute is enforced as an `always` property. Once warmup completes, the strict limit is released.

---

## From Logic to Machines: How Compilation Works

When the Aegis compiler encounters a temporal invariant, it doesn't store the formula for runtime interpretation. It compiles it into a deterministic state machine — a finite automaton with explicit states, transitions, and guards.

This is the performance secret. At runtime, the verifier doesn't evaluate logical formulas. It advances a state machine by one transition per event. That's a table lookup, not a computation. It's why AgentProof can verify policies in under 10 milliseconds.

The compilation follows a systematic pattern:

| Operator | States | Transitions |
|---|---|---|
| `always(φ)` | 2 (satisfied, violated) | Stay on φ, violate on ¬φ |
| `eventually(φ)` | 2-3 (waiting, satisfied, violated*) | Satisfy on φ, violate on timeout* |
| `never(φ)` | 2 (satisfied, violated) | Stay on ¬φ, violate on φ |
| `until(φ, ψ)` | 3 (holding, released, violated) | Release on ψ, violate on ¬φ |
| `next(φ)` | 3 (idle, checking, violated) | Check on trigger, violate on ¬φ |

*`eventually` only has a violated state when used with `within`

Each active invariant in a policy creates one state machine instance at runtime. If a policy has four temporal invariants, the runtime maintains four state machines, each advancing independently on every event. The overall verdict is the conjunction: if *any* machine enters a violated state, the policy is violated.

---

## Practical Patterns for Agent Policies

### Pattern 1: Budget Guardrails

Prevent cost overruns across a session, not just per-action.

```
policy CostControl {
    severity high
    scope tool_call

    proof SpendingSafety {
        invariant SessionBudget {
            always(context.session_spend <= context.config.session_limit)
        }

        invariant DailyBudget {
            always(context.daily_spend <= context.config.daily_limit)
        }

        invariant NoSingleLargeSpend {
            always(event.estimated_cost <= context.config.max_single_action)
        }
    }
}
```

Three `always` invariants running in parallel. The agent can't exceed session limits, daily limits, or single-action limits. All three are checked on every event, and all three must be satisfied.

### Pattern 2: Least-Privilege Escalation

Start with minimal permissions and expand only on explicit approval.

```
policy LeastPrivilege {
    severity critical
    scope tool_call

    proof PrivilegeControl {
        invariant ReadOnlyDefault {
            until(
                none(context.tool_calls, c => c.mutates == true),
                context.write_permission_granted == true
            )
        }

        invariant NoDeleteEver {
            never(event.tool == "delete_record")
        }

        invariant EscalationRequired {
            always(
                event.requires_elevation == true implies
                    context.elevation_approved == true
            )
        }
    }
}
```

The agent starts read-only (`until` releases on write permission). Delete is permanently forbidden (`never`). Elevated actions require prior approval (`always ... implies`).

### Pattern 3: Data Pipeline Safety

Prevent an agent from exfiltrating data through a sequence of innocent-looking reads followed by an external write.

```
policy PipelineSafety {
    severity critical
    scope tool_call, data_access

    proof NoExfiltration {
        invariant BoundedReads {
            always(
                count(context.recent_reads, r => r.timestamp within 5m) <= 50
            )
        }

        invariant WriteAfterReadRestriction {
            always(
                count(context.recent_reads, r => r.timestamp within 1m) > 10
                    implies never(event.type == "external_request")
            )
        }

        invariant ApprovedDestinationsOnly {
            always(
                event.type == "external_request" implies
                    event.url in context.config.approved_endpoints
            )
        }
    }
}
```

Three invariants working together: cap read velocity, block external writes after bursts of reads, and restrict all external requests to approved destinations. No single rule catches exfiltration — the combination does.

### Pattern 4: Compliance Session Lifecycle

Enforce that a compliance workflow follows the correct order.

```
policy ComplianceWorkflow {
    severity critical
    scope tool_call, system_event

    proof OrderedWorkflow {
        invariant AuditBeforeAction {
            until(
                event.type != "modify_record",
                event.type == "audit_session_started"
            )
        }

        invariant CloseoutRequired {
            always(
                event.type == "audit_session_started" implies
                    eventually(event.type == "audit_session_closed") within 8h
            )
        }
    }
}
```

No record modifications until an audit session starts (`until`). Once started, the session must close within 8 hours (`eventually ... within`).

---

## What LTL Cannot Do

LTL is powerful, but it has boundaries. Understanding them prevents misuse.

**LTL cannot express probabilities.** "The agent should usually respond within 5 seconds" is not an LTL property. LTL deals in absolutes: always, never, eventually. If you need statistical guarantees, you need a different formalism (or rate-limit-based approximations).

**LTL cannot count across unbounded history efficiently.** "The agent has made exactly 17 API calls total" requires tracking a counter over the entire trace. AgentProof handles this through rate limits and quotas (separate from the temporal engine) rather than encoding it as pure LTL.

**LTL cannot branch.** LTL reasons about a single linear trace of events. It cannot express "in all possible futures" (that's CTL — Computation Tree Logic). For agent safety, this is rarely a limitation because agents act sequentially: there is one trace, not a branching tree.

**LTL formulas can be expensive to monitor if deeply nested.** AgentProof restricts nesting depth in v1 — `always(eventually(always(φ)))` is rejected by the type checker with a suggestion to decompose into separate invariants. This keeps state machines small and runtime performance predictable.

---

## Summary

| Operator | Symbol | English | Machine States |
|---|---|---|---|
| `always(φ)` | □φ | "φ holds at every step, forever" | 2 |
| `eventually(φ)` | ◇φ | "φ becomes true at some future step" | 2-3 |
| `never(φ)` | □¬φ | "φ is false at every step, forever" | 2 |
| `until(φ, ψ)` | φ U ψ | "φ holds at every step until ψ occurs" | 3 |
| `next(φ)` | Xφ | "φ holds at the immediately next step" | 3 |

The key idea: temporal properties are compiled to state machines at build time and evaluated as table lookups at runtime. No interpretation. No regex. No ambiguity. Mathematical guarantees that the constraint holds, or a precise report of where and when it was violated.

This is what separates AgentProof from guardrail tools that check individual outputs. Those tools are spell-checkers. AgentProof is a type system — it reasons about the *structure* of behavior, not just the surface of individual actions.