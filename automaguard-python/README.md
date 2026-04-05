# AutomaGuard

**Runtime policy enforcement for AI agents.** One line to protect your users.

AutomaGuard ensures your AI agents never take unauthorized actions. Write policies in the [Aegis language](https://github.com/ScottsSecondAct/AutomaGuard), compile them, and enforce them at runtime with <10ms latency.

## Install

```bash
pip install aegis-enforce
```

Requires Python 3.9+. The package includes a pre-compiled Rust native extension — no Rust toolchain needed for installation.

## Quick Start

### OpenAI

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

If the agent tries to call an unauthorized tool:

```
aegis_enforce.EnforcementError: AutomaGuard: External HTTP calls are not permitted
```

### LangChain

```python
from aegis_enforce import AutomaGuardCallbackHandler

handler = AutomaGuardCallbackHandler(policy="guard.aegisc")
agent = create_react_agent(llm, tools, callbacks=[handler])
```

### Direct Engine

For custom frameworks or advanced use cases:

```python
from aegis_enforce import PolicyEngine

engine = PolicyEngine.from_file("guard.aegisc")

result = engine.evaluate("tool_call", {
    "tool": "http_request",
    "url": "https://api.external.com/data",
    "method": "POST",
})

print(result.verdict)      # "deny"
print(result.reason)       # "External request to unapproved destination"
print(result.eval_time_us) # 42 (microseconds)
```

### Decorator

Wrap individual tool functions:

```python
from aegis_enforce import intercept_tool_call

engine = PolicyEngine.from_file("guard.aegisc")

@intercept_tool_call(engine)
def send_email(to: str, subject: str, body: str):
    ...
```

## Writing Policies

Policies are written in the Aegis language and compiled with the `aegisc` CLI:

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

```bash
aegisc compile guard.aegis -o guard.aegisc
```

The compiler transforms temporal invariants (`always`, `eventually`, `until`, `never`) into deterministic state machines. At runtime, the verifier advances these automata on every event — no regex, no string matching, no validators. Mathematical guarantees.

## How It Works

```
Agent → tool call → AutomaGuard intercepts → Policy engine evaluates → Verdict
                                                                        ↓
                                                              allow / deny / audit / redact
```

1. Your agent decides to call a tool
2. AutomaGuard intercepts the call and builds an event
3. The compiled policy is evaluated against the event (<10ms)
4. A verdict is returned: allow, deny (with reason), audit (log but allow), or redact (allow with sanitized fields)
5. The decision is logged to an immutable audit trail

## Enforcement Modes

The `enforce()` wrapper supports three modes:

```python
# Raise an exception on deny (default)
safe_client = enforce(client, policy="guard.aegisc", on_deny="raise")

# Block silently (same behavior, different semantics)
safe_client = enforce(client, policy="guard.aegisc", on_deny="block")

# Monitor mode — log denials but allow all actions
safe_client = enforce(client, policy="guard.aegisc", on_deny="log")
```

Monitor mode is useful for deploying AutomaGuard alongside an existing agent to see what *would* be blocked before turning on enforcement.

## Dependencies

The base package has **zero Python dependencies** beyond the compiled Rust extension. Framework integrations are optional:

```bash
pip install aegis-enforce[openai]     # adds openai>=1.0
pip install aegis-enforce[langchain]  # adds langchain-core>=0.1
```

## Fail-Closed Design

If the Rust engine returns an error or the pyo3 bridge fails for any reason, the default behavior is to **deny the action**, not allow it. This is a security product — silent failures must not become silent permissions.

## Building from Source

If you want to build the native extension yourself:

```bash
# Prerequisites: Rust stable toolchain + maturin
pip install maturin

# Build in development mode
cd automaguard-python
maturin develop

# Run tests
pytest
```

## Part of AutomaGuard

This SDK is the Python interface to AutomaGuard's [compiler](https://github.com/ScottsSecondAct/AutomaGuard/tree/main/aegis-compiler) and [runtime verifier](https://github.com/ScottsSecondAct/AutomaGuard/tree/main/aegis-runtime). The full project, including the Aegis language specification, is at [github.com/ScottsSecondAct/AutomaGuard](https://github.com/ScottsSecondAct/AutomaGuard).

## License

Apache 2.0