# agentproof-python

The Python SDK for AgentProof. A thin Python layer over a Rust native extension (pyo3). Provides drop-in enforcement for OpenAI, LangChain, and raw tool-calling agents.

## User-Facing API

The entire public API fits in three lines:

```python
from agentproof import enforce
safe_client = enforce(client, policy="guard.aegisc")
# Every tool call is now policy-enforced.
```

That simplicity is intentional and load-bearing. Don't complicate the surface API.

## Project Structure

```
agentproof-python/
├── Cargo.toml              # Rust crate config (pyo3 + maturin)
├── pyproject.toml           # Python package config (maturin build backend)
├── src/
│   └── lib.rs               # pyo3 native extension — Rust ↔ Python bridge
└── python/
    └── agentproof/
        ├── __init__.py       # Public API re-exports
        ├── engine.py         # PolicyEngine Python wrapper
        ├── integrations/
        │   ├── openai.py     # OpenAI client wrapper
        │   └── langchain.py  # LangChain callback/tool interceptor
        └── types.py          # Python-side type definitions (Verdict, Event, etc.)
```

## Design Principles

- **The Python layer is a skin, not a brain.** All policy evaluation, state machine advancement, and expression evaluation happen in Rust. Python code handles framework-specific interception (wrapping OpenAI's `client.chat.completions.create`, hooking LangChain callbacks) and converts framework objects to `Event` dicts that cross the pyo3 boundary.
- **No policy logic in Python.** If you're writing an `if` statement in Python that makes a policy decision, it belongs in Rust.
- **Framework integrations are adapters.** Each file in `integrations/` translates one framework's tool-calling convention into AgentProof `Event` objects. They should be small (<200 lines each) and framework-version-aware.
- **Fail closed.** If the Rust engine returns an error or the pyo3 bridge fails, the default behavior is to deny the action, not allow it. This is a security product.

## Build System

- **maturin** is the build backend. `pip install maturin && maturin develop` for local dev.
- The Rust extension compiles `aegis-runtime` and `aegis-compiler` as dependencies.
- `pyproject.toml` declares optional deps: `openai` and `langchain-core`. The base package has zero Python dependencies beyond the compiled extension.

## Working in This Crate

- **Rust side (`src/lib.rs`)**: Exposes `PolicyEngine`, `evaluate`, and `load_policy` as Python-callable functions via `#[pyfunction]` / `#[pyclass]`. Converts between Python dicts and Rust `Event`/`Value` types. Keep this file focused on marshaling — no business logic.
- **Python side**: When adding a new framework integration, follow the pattern in `openai.py`: intercept the tool-calling method, build an `Event` dict, call the engine, and handle the verdict. Add the integration to `__init__.py`'s public exports.
- **Testing the bridge**: Use `maturin develop` to build the extension in-place, then `pytest`. Tests should cover: basic allow/deny, each framework integration with mocked clients, pyo3 type conversion edge cases (None ↔ null, nested dicts ↔ nested maps, large payloads).

## Testing

- `pytest` for Python-side tests.
- Framework integration tests mock the LLM client and verify that tool calls are intercepted and verdicts are enforced.
- Round-trip tests: Python dict → Rust Event → evaluate → Verdict → Python result.
- Edge cases: Unicode in field values, deeply nested event payloads, events with missing expected fields (should fail closed, not panic).

## Versioning

- The Python package version tracks the Rust crate version.
- The compiled extension includes the runtime version in its metadata — `agentproof.__version__` and `agentproof.__runtime_version__` should both be accessible.
