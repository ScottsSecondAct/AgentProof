"""
AgentProof — Runtime policy enforcement for AI agents.

Quick start:
    from agentproof import enforce

    # Wrap an OpenAI client with policy enforcement
    client = enforce(openai_client, policy="guard.aegisc")

    # Use the client exactly as before — AgentProof intercepts tool calls
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[...],
        tools=[...],
    )

For LangChain:
    from agentproof import AgentProofCallbackHandler

    handler = AgentProofCallbackHandler(policy="guard.aegisc")
    agent = create_react_agent(llm, tools, callbacks=[handler])

Direct engine usage:
    from agentproof import PolicyEngine

    engine = PolicyEngine.from_file("guard.aegisc")
    result = engine.evaluate("tool_call", {"tool": "http_request", "url": "https://..."})
    if result["verdict"] == "deny":
        raise PermissionError(result["reason"])
"""

__version__ = "0.1.0"

from aegis_enforce._engine import PolicyEngine, PolicyResult
from aegis_enforce._enforce import enforce
from aegis_enforce._interceptors import (
    AgentProofCallbackHandler,
    intercept_openai,
    intercept_tool_call,
)

__all__ = [
    "PolicyEngine",
    "PolicyResult",
    "enforce",
    "AgentProofCallbackHandler",
    "intercept_openai",
    "intercept_tool_call",
]
