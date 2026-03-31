# AgentProof

[![Open Source](https://img.shields.io/badge/Open%20Source-Yes-green.svg)](https://github.com/ScottsSecondAct/some) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT) ![AI Assisted](https://img.shields.io/badge/AI%20Assisted-Claude-blue?logo=anthropic) [![Release](https://github.com/ScottsSecondAct/AgentProof/actions/workflows/release.yml/badge.svg)](https://github.com/ScottsSecondAct/AgentProof/actions/workflows/release.yml)

**Formally verified policy enforcement for AI agents.**

Current guardrails check what agents *say*. AgentProof checks what agents *do* — and blocks unauthorized actions before they execute, with mathematical proofs that the constraints hold.

## The Problem

AI agents are taking real actions: calling APIs, moving money, accessing data, sending messages. Every agent framework gives agents *capability*. None of them give you *guarantees* about what agents won't do.

A permissions system asks: "Is this single action allowed right now?"

AgentProof asks: "Given every action this agent has taken and might take, can I *prove* that no combination of allowed actions leads to a forbidden state?"

That's the difference between a spell-checker and a type system.

## Quick Start

```bash
pip install agentproof
```

Write a policy in the Aegis language:

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
from agentproof import enforce
import openai

client = openai.OpenAI()
safe_client = enforce(client, policy="guard.aegisc")

# Use exactly as before — AgentProof intercepts every tool call
response = safe_client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Check the weather"}],
    tools=[...],
)
```

If the agent tries something unauthorized:

```
agentproof.EnforcementError: AgentProof: External HTTP calls are not permitted
```

## How It Works

AgentProof sits between your agent and its tools. Every action is evaluated against your compiled policy in <10ms:

1. **Agent decides** to call a tool
2. **AgentProof intercepts** the call and builds an event
3. **Policy engine evaluates** the event against compiled rules and temporal invariants
4. **Verdict is returned**: allow, deny, audit, or redact
5. **Action is taken**: proceed, block, log, or sanitize

The policy engine runs compiled state machines — not regex, not string matching, not validators. When your policy says "the agent must never access external URLs," AgentProof provides a mathematical guarantee, not a best-effort check.

## Why Formal Verification

Most guardrail tools validate individual outputs. AgentProof verifies *sequences* of actions against temporal logic specifications (LTL).

- `always(φ)` — property φ must hold on every action, forever
- `eventually(φ) within 5m` — property φ must become true within 5 minutes
- `never(φ)` — property φ must never hold
- `until(φ, ψ)` — property φ must hold until ψ becomes true

These compile to deterministic state machines at build time. At runtime, the verifier advances the automata on each event. No ambiguity, no false negatives, no "usually catches it."

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  .aegis source                                      │
│    → ANTLR4 parse                                   │
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

## Project Structure

```
agentproof/
├── aegis-compiler/      # Rust — parser, type checker, IR lowering, bytecode
├── aegis-runtime/       # Rust — event evaluation, state machines, rate limits
├── agentproof-python/   # Rust (pyo3) + Python — SDK and framework integrations
├── examples/            # Example .aegis policy files
├── AegisLexer.g4        # ANTLR4 lexer grammar
└── AegisParser.g4       # ANTLR4 parser grammar
```

## Building from Source

### Prerequisites

- Rust (stable toolchain)
- Python 3.9+
- [maturin](https://github.com/PyO3/maturin) (`pip install maturin`)

### Build

```bash
# Compiler + runtime
cargo build --release

# Python SDK (development mode)
cd agentproof-python
maturin develop

# Run tests
cargo test
cd agentproof-python && pytest
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

| Capability | Platform Guardrails | Guardrails AI | AI Security Cos. | **AgentProof** |
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