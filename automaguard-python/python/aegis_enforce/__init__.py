"""
AutomaGuard — Runtime policy enforcement for AI agents, powered by Aegis policies.

Quick start:
    from aegis_enforce import enforce

    # Wrap an OpenAI client with policy enforcement
    client = enforce(openai_client, policy="guard.aegisc")

    # Use the client exactly as before — AutomaGuard intercepts tool calls
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[...],
        tools=[...],
    )

For LangChain:
    from aegis_enforce import AutomaGuardCallbackHandler

    handler = AutomaGuardCallbackHandler(policy="guard.aegisc")
    agent = create_react_agent(llm, tools, callbacks=[handler])

Direct engine usage:
    from aegis_enforce import PolicyEngine

    engine = PolicyEngine.from_file("guard.aegisc")
    result = engine.evaluate("tool_call", {"tool": "http_request", "url": "https://..."})
    if result["verdict"] == "deny":
        raise PermissionError(result["reason"])
"""

__version__ = "0.1.0"

from aegis_enforce._engine import PolicyEngine, PolicyResult
from aegis_enforce._enforce import enforce
from aegis_enforce._interceptors import (
    AutomaGuardCallbackHandler,
    intercept_openai,
    intercept_tool_call,
)

__all__ = [
    "PolicyEngine",
    "PolicyResult",
    "enforce",
    "AutomaGuardCallbackHandler",
    "intercept_openai",
    "intercept_tool_call",
]
