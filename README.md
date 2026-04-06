# AutomaGuard

[![Open Source](https://img.shields.io/badge/Open%20Source-Yes-green.svg)](https://github.com/ScottsSecondAct/some) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) ![AI Assisted](https://img.shields.io/badge/AI%20Assisted-Claude-blue?logo=anthropic) [![CI](https://github.com/ScottsSecondAct/AutomaGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/ScottsSecondAct/AutomaGuard/actions/workflows/ci.yml) [![Staging](https://github.com/ScottsSecondAct/AutomaGuard/actions/workflows/staging.yml/badge.svg)](https://github.com/ScottsSecondAct/AutomaGuard/actions/workflows/staging.yml) [![Release](https://github.com/ScottsSecondAct/AutomaGuard/actions/workflows/release.yml/badge.svg)](https://github.com/ScottsSecondAct/AutomaGuard/actions/workflows/release.yml)

**Formally verified policy enforcement for AI agents.**

Current guardrails check what agents *say*. AutomaGuard checks what agents *do* — and blocks unauthorized actions before they execute, with mathematical proofs that the constraints hold.

## The Problem

AI agents are taking real actions: calling APIs, moving money, accessing data, sending messages. Every agent framework gives agents *capability*. None of them give you *guarantees* about what agents won't do.

A permissions system asks: "Is this single action allowed right now?"

AutomaGuard asks: "Given every action this agent has taken and might take, can I *prove* that no combination of allowed actions leads to a forbidden state?"

That's the difference between a spell-checker and a type system.

## Quick Start

```bash
pip install aegis-enforce
```

Write a policy in the Aegis Policy Language:

```
policy DataGuard {
    severity high
    scope tool_call, data_access

    on tool_call {
        when event.tool contains "http"
        deny with "External HTTP calls blocked"
    }

    proof NoDataLeaks {
        invariant InternalOnly {
            always(
                none(context.tool_calls, c =>
                    c.url starts_with "http://external"
                )
            )
        }
    }
}
```

Compile it:

```bash
aegisc compile guard.aegis -o guard.aegisc
```

Enforce it — one line:

```python
from aegis_enforce import enforce
import openai

client = openai.OpenAI()
safe_client = enforce(client, policy="guard.aegisc")

# Use exactly as before — AutomaGuard intercepts every tool call
response = safe_client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Check the weather"}],
    tools=[...],
)
```

If the agent tries something unauthorized:

```
aegis_enforce.EnforcementError: AutomaGuard: External HTTP calls are not permitted
```

## How It Works

AutomaGuard sits between your agent and its tools. Every action is evaluated against your compiled policy in <10ms:

1. **Agent decides** to call a tool
2. **AutomaGuard intercepts** the call and builds an event
3. **Policy engine evaluates** the event against compiled rules and temporal invariants
4. **Verdict is returned**: allow, deny, audit, or redact
5. **Action is taken**: proceed, block, log, or sanitize

The policy engine runs compiled state machines — not regex, not string matching, not validators. When your policy says "the agent must never access external URLs," AutomaGuard provides a mathematical guarantee, not a best-effort check.

## Why Formal Verification

Most guardrail tools validate individual outputs. AutomaGuard verifies *sequences* of actions against temporal logic specifications (LTL).

- `always(φ)` — property φ must hold on every action, forever
- `eventually(φ) within 5m` — property φ must become true within 5 minutes
- `never(φ)` — property φ must never hold
- `until(φ, ψ)` — property φ must hold until ψ becomes true

These compile to deterministic state machines at build time. At runtime, the verifier advances the automata on each event. No ambiguity, no false negatives, no "usually catches it."

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  .aegis source                                      │
│    → pest PEG parse                                 │
│    → Type check                                     │
│    → Compile temporal invariants to state machines   │
│    → Serialize to .aegisc bytecode                   │
└──────────────────────┬──────────────────────────────┘
                       │ compiled policy
┌──────────────────────▼──────────────────────────────┐
│  Runtime Verifier (Rust, <10ms)                     │
│    → Load .aegisc                                   │
│    → Evaluate rules against events                  │
│    → Advance state machines                         │
│    → Enforce rate limits                            │
│    → Return verdict + log to audit trail            │
└──────────────────────┬──────────────────────────────┘
                       │ pyo3 bindings
┌──────────────────────▼──────────────────────────────┐
│  Python SDK                                         │
│    → enforce(client, policy="...")                   │
│    → LangChain callback handler                     │
│    → Direct engine API                              │
└─────────────────────────────────────────────────────┘
```

## Integration Options

| Method | Code changes | Best for |
|--------|-------------|----------|
| **Python SDK** | One line (`enforce()`) | OpenAI, LangChain, CrewAI agents |
| **MCP Proxy** | Zero (sidecar) | MCP-based agents, zero-touch deployment |
| **Direct Engine** | Minimal | Custom frameworks, advanced use cases |

## Quick Start — Rust

```toml
# Cargo.toml
[dependencies]
automaguard = { path = "automaguard-rs" }
```

```rust
use automaguard::{PolicyEngine, EnforcementError};

let mut engine = PolicyEngine::from_file("guard.aegisc")?;

let result = engine
    .event("tool_call")
    .field("tool_name", "send_email")
    .field("to", "user@external.com")
    .evaluate()?;

if result.is_denied() {
    return Err(EnforcementError::new(result).into());
}
```

With the `async` feature, a `spawn_blocking`-backed `AsyncPolicyEngine` lets
the engine be shared across tokio tasks:

```rust
use automaguard::AsyncPolicyEngine;

let engine = AsyncPolicyEngine::from_file("guard.aegisc")?;
let result = engine.evaluate("tool_call", fields).await?;
```

## Project Structure

```
AutomaGuard/
├── aegis-compiler/      # Rust — parser, type checker, IR lowering, bytecode
│   └── src/aegis.pest   # pest PEG grammar
├── aegis-runtime/       # Rust — event evaluation, state machines, rate limits
├── aegis-ffi/           # Rust — C ABI layer (cdylib/staticlib + aegis.h)
├── automaguard-rs/      # Rust SDK — ergonomic wrapper + async engine
├── automaguard-python/  # Rust (pyo3) + Python — SDK and framework integrations
└── examples/            # Example .aegis policy files
```

## Integration Options

| Method | Language | Code changes | Best for |
|--------|----------|-------------|----------|
| **Python SDK** | Python | One line (`enforce()`) | OpenAI, LangChain, CrewAI agents |
| **Rust SDK** | Rust | One line (`PolicyEngine::from_file`) | Native Rust agents, tokio services |
| **C FFI** | Any | Link `libaegis` + include `aegis.h` | TypeScript (napi-rs), C#, Java, Go SDKs |
| **MCP Proxy** | Zero (sidecar) | Zero (sidecar) | MCP-based agents, zero-touch deployment |

## Building from Source

### Prerequisites

- Rust (stable toolchain)
- Python 3.9+
- [maturin](https://github.com/PyO3/maturin) (`pip install maturin`)

### Build

```bash
# Compiler + runtime + FFI layer + Rust SDK
cargo build --release

# Rust SDK with async support
cargo build --release --features async -p automaguard

# Python SDK (development mode)
cd automaguard-python
maturin develop

# Run all Rust tests
cargo test --workspace

# Run Python tests
cd automaguard-python && pytest
```

### CLI

```bash
# Compile a policy
aegisc compile policy.aegis -o policy.aegisc

# Type-check only (no output)
aegisc check policy.aegis

# Inspect a compiled policy
aegisc inspect policy.aegisc

# Dump compiled IR as JSON
aegisc dump policy.aegisc | jq .
```

## Comparison

| Capability | Platform Guardrails | Guardrails AI | AI Security Cos. | **AutomaGuard** |
|---|---|---|---|---|
| Text output validation | ✓ | ✓ | ✓ | ✓ |
| PII / toxicity filtering | ✓ | ✓ | ✓ | ✓ |
| Action-level verification | ✗ | ✗ | Partial | **✓** |
| Formal safety guarantees | ✗ | ✗ | ✗ | **✓** |
| Policy-as-code DSL | ✗ | Partial | ✗ | **✓** |
| Model-agnostic | ✗ | ✓ | Varies | **✓** |
| Immutable audit trail | Partial | ✗ | ✓ | **✓** |

## License

Apache 2.0