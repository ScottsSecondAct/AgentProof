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
- `next(φ)` — property φ must hold on the immediately following action

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
                       │ pyo3 / napi-rs / FFI bindings
┌──────────────────────▼──────────────────────────────┐
│  Language SDKs                                      │
│    Python · TypeScript · Rust · Go · Java · .NET    │
└──────────────────────┬──────────────────────────────┘
                       │ JSON Lines audit log
┌──────────────────────▼──────────────────────────────┐
│  Compliance Dashboard (Next.js)                     │
│    → Verdict breakdown · Latency charts             │
│    → Filterable audit log · Violation detail        │
└─────────────────────────────────────────────────────┘
```

## Integration Options

| Method | Code changes | Best for |
|--------|-------------|----------|
| **Python SDK** | One line (`enforce()`) | OpenAI, LangChain, CrewAI agents |
| **Rust SDK** | One line (`PolicyEngine::from_file`) | Native Rust agents, tokio services |
| **TypeScript SDK** | One line (`withGuard` / `enforce`) | LangChain.js, OpenAI Node, Vercel AI SDK |
| **.NET SDK** | One line (`AddAutomaGuard`) | Microsoft Semantic Kernel agents |
| **Go SDK** | One line (`NewEngine`) | Go-based agents and services |
| **Java SDK** | One line (Spring AI advisor) | JVM agents, LangChain4j |
| **MCP Proxy** | Zero (sidecar) | MCP-based agents, zero-touch deployment |

## Quick Start — TypeScript

```typescript
import { PolicyEngine, EnforcementError } from 'automaguard';

const engine = PolicyEngine.fromFile('guard.aegisc');

const result = engine.evaluate('tool_call', {
  tool_name: 'send_email',
  arguments: { to: 'user@external.com' },
});

if (result.verdict === 'deny') {
  throw new EnforcementError(result.reason);
}
```

Or with the Vercel AI SDK:

```typescript
import { withGuard } from 'automaguard/vercel-ai';

const model = withGuard(openai('gpt-4o'), { policy: 'guard.aegisc' });
```

## Quick Start — C# / .NET

```csharp
using AutomaGuard.SemanticKernel;
using Microsoft.SemanticKernel;

var kernel = Kernel.CreateBuilder()
    .AddOpenAIChatCompletion("gpt-4o", apiKey)
    .AddAutomaGuard("guard.aegisc")
    .Build();

// AutomaGuard intercepts every function call before it executes.
// EnforcementException is thrown on a Deny verdict.
```

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

## Quick Start — MCP Proxy

The MCP proxy requires **zero code changes**. Configure it in place of your
upstream MCP server and it automatically intercepts every `tools/call`:

```bash
# Build
cd automaguard-mcp-proxy && cargo build --release

# Run — drop in before your existing server command
automaguard-mcp-proxy --policy guard.aegisc -- npx -y @modelcontextprotocol/server-filesystem /workspace
```

In Claude Desktop's `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/path/to/automaguard-mcp-proxy",
      "args": [
        "--policy", "/path/to/guard.aegisc",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/workspace"
      ]
    }
  }
}
```

When a tool call violates your policy the proxy returns a JSON-RPC error
and the upstream server never sees the request:

```
[automaguard] tool=write_file verdict=Deny latency=142μs
AutomaGuard: External writes are not permitted
```

Add `--verbose` to trace every message through the proxy.

## Compliance Dashboard

AutomaGuard ships a Next.js compliance dashboard that reads the JSON Lines audit log
written by the MCP proxy or any SDK.

```bash
cd dashboard
cp .env.local.example .env.local
# Set AUDIT_LOG_PATH to your .jsonl file, or leave unset for demo mode
npm install && npm run dev
```

Open `http://localhost:3000` to see:

- **Verdict breakdown** — donut chart of allow / deny / audit / redact counts
- **Latency chart** — per-event evaluation time with a 10ms SLA reference line
- **Audit log table** — filterable by verdict, event type, and policy; searchable; click any row to expand violation detail

The dashboard runs in demo mode (synthetic data) when no log file is configured, making it safe to explore without a live agent.

## Editor Support — VS Code

The `aegis-language` VS Code extension provides first-class support for `.aegis` policy files:

- Syntax highlighting for keywords, identifiers, string literals, and comments
- `.aegisc` bytecode inspector — open any compiled policy file directly in VS Code for a human-readable view of the compiled rules, state machines, and rate limit constraints
- Code snippets for common policy patterns (`policy`, `proof`, `on`, `constraint`)
- Bracket matching and auto-closing pairs

**Install from VSIX:**

```bash
code --install-extension aegis-vscode/aegis-language-0.1.0.vsix
```

Once installed, `.aegis` source files get full language support and `.aegisc` compiled
policy files open in the bytecode inspector, showing the rules, state machines, and
rate limit constraints in a readable format — useful for verifying what a policy
actually compiled to before deploying it.

Or open `aegis-vscode/` in VS Code and press `F5` to launch the Extension Development Host.

## Project Structure

```
AutomaGuard/
├── aegis-compiler/        # Rust — parser, type checker, IR lowering, bytecode
│   └── src/aegis.pest     # pest PEG grammar
├── aegis-runtime/         # Rust — event evaluation, state machines, rate limits
├── aegis-ffi/             # Rust — C ABI layer (cdylib/staticlib + aegis.h)
├── aegis-vscode/          # VS Code extension — syntax highlighting, snippets, .aegisc inspector
├── automaguard-rs/        # Rust SDK — ergonomic wrapper + async engine
├── automaguard-ts/        # TypeScript SDK — napi-rs; LangChain.js, OpenAI, Vercel AI
├── automaguard-dotnet/    # C# SDK — P/Invoke + Semantic Kernel IFunctionInvocationFilter
├── automaguard-java/      # Java/Kotlin SDK — JNI; Spring AI advisor, LangChain4j filter
├── automaguard-go/        # Go SDK — cgo bindings to libaegis
├── automaguard-python/    # Python SDK — pyo3/maturin; LangChain, OpenAI integrations
├── automaguard-mcp-proxy/ # Rust — stdio MCP proxy sidecar (zero client-side changes)
├── dashboard/             # Next.js compliance dashboard — audit trail, verdict charts
└── examples/              # Per-SDK runnable examples
```

## SDK Status

| SDK | Language | Integration point | Status |
|-----|----------|-------------------|--------|
| **automaguard-python** | Python | `enforce(client, policy=...)` — wraps OpenAI/LangChain | Available |
| **automaguard-rs** | Rust | `PolicyEngine::from_file` / `AsyncPolicyEngine` | Available |
| **automaguard-ts** | TypeScript / Node.js | `AutomaGuardCallbackHandler`, `enforce()`, `withGuard()` | Available |
| **automaguard-dotnet** | C# / .NET 8+ | `AddAutomaGuard()` — Semantic Kernel `IFunctionInvocationFilter` | Available |
| **automaguard-java** | Java / Kotlin | Spring AI advisor, LangChain4j filter (JNI) | Available |
| **automaguard-go** | Go | `NewEngine` / `engine.Evaluate` (cgo) | Available |
| **MCP Proxy** | Any | Zero-code sidecar interceptor | Available |
| **Dashboard** | — | Next.js compliance UI | Available |
| **VS Code Extension** | — | Syntax highlighting, snippets, bytecode inspector | Available |

## Building from Source

### Prerequisites

- Rust (stable toolchain)
- Python 3.9+ and [maturin](https://github.com/PyO3/maturin) (`pip install maturin`) — for Python SDK
- Node.js 18+ and npm — for TypeScript SDK and dashboard
- .NET 8 SDK — for C# SDK

### Build

```bash
# Compiler + runtime + FFI layer + Rust SDK
cargo build --release

# Rust SDK with async support
cargo build --release --features async -p automaguard

# Python SDK (development mode)
cd automaguard-python && maturin develop

# TypeScript SDK
cd automaguard-ts && npm install && npm run build

# .NET SDK
cd automaguard-dotnet && dotnet build

# MCP proxy
cd automaguard-mcp-proxy && cargo build --release

# Compliance dashboard
cd dashboard && npm install && npm run build

# Run all Rust tests
cargo test --workspace

# Run Python tests
cd automaguard-python && pytest

# Run TypeScript tests
cd automaguard-ts && npm test

# Run .NET tests
cd automaguard-dotnet && dotnet test

# Go SDK (no cgo — pure type tests)
cd automaguard-go && CGO_ENABLED=0 go test ./...
```

### CLI

```bash
# Compile a policy
aegisc compile policy.aegis -o policy.aegisc

# Type-check only (no output)
aegisc check policy.aegis

# Inspect a compiled policy
aegisc inspect policy.aegis

# Dump compiled IR as JSON
aegisc dump policy.aegis | jq .
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
| Compliance dashboard | ✗ | ✗ | Varies | **✓** |
| Editor integration | ✗ | ✗ | ✗ | **✓** |

## License

Apache 2.0
