"""
Framework-specific interceptors for AutomaGuard.

Provides ready-made integrations for:
- LangChain (via callback handler)
- OpenAI function calling (via client wrapper)
- Generic tool-call interception (via decorator)
"""

from __future__ import annotations

import functools
import logging
from pathlib import Path
from typing import Any, Callable, Optional, Union

from aegis_enforce._engine import PolicyEngine, PolicyResult
from aegis_enforce._enforce import EnforcementError

logger = logging.getLogger("automaguard")


# ═══════════════════════════════════════════════════════════════════════
#  LangChain callback handler
# ═══════════════════════════════════════════════════════════════════════


class AutomaGuardCallbackHandler:
    """
    LangChain callback handler that enforces Aegis policies via AutomaGuard.

    Usage:
        from aegis_enforce import AutomaGuardCallbackHandler

        handler = AutomaGuardCallbackHandler(policy="guard.aegisc")
        agent = create_react_agent(llm, tools, callbacks=[handler])

        # The agent now enforces the policy on every tool invocation.
    """

    def __init__(
        self,
        policy: Union[str, Path, PolicyEngine],
        on_deny: str = "raise",
    ):
        if isinstance(policy, (str, Path)):
            self.engine = PolicyEngine.from_file(policy)
        elif isinstance(policy, PolicyEngine):
            self.engine = policy
        else:
            raise TypeError(f"policy must be a path or PolicyEngine, got {type(policy)}")

        self.on_deny = on_deny
        self._results: list[PolicyResult] = []

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Called when a LangChain tool is about to execute."""
        tool_name = serialized.get("name", "unknown")

        fields = {
            "tool": tool_name,
            "arguments": input_str,
            "description": serialized.get("description", ""),
        }

        # Add any extra metadata
        if "metadata" in kwargs:
            fields["metadata"] = kwargs["metadata"]

        result = self.engine.evaluate("tool_call", fields)
        self._results.append(result)

        if result.denied:
            if self.on_deny == "raise":
                raise EnforcementError(result)
            elif self.on_deny == "log":
                logger.warning(
                    "AutomaGuard DENY: tool=%s reason=%s",
                    tool_name,
                    result.reason,
                )

        if result.verdict == "audit":
            logger.info(
                "AutomaGuard AUDIT: tool=%s reason=%s",
                tool_name,
                result.reason or "audited",
            )

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        """Called after a tool finishes execution."""
        pass  # Post-execution auditing can be added here

    def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        """Called when a tool execution fails."""
        logger.error("AutomaGuard: tool execution error: %s", error)

    @property
    def results(self) -> list[PolicyResult]:
        """All evaluation results from this handler's lifetime."""
        return list(self._results)

    @property
    def deny_count(self) -> int:
        """Number of actions denied."""
        return sum(1 for r in self._results if r.denied)

    @property
    def event_count(self) -> int:
        """Total number of events evaluated."""
        return len(self._results)


# ═══════════════════════════════════════════════════════════════════════
#  OpenAI function-call interceptor
# ═══════════════════════════════════════════════════════════════════════


def intercept_openai(
    client: Any,
    engine: PolicyEngine,
    on_deny: str = "raise",
) -> Any:
    """
    Intercept OpenAI tool calls at the function-execution stage.

    Unlike enforce() which intercepts after the LLM responds, this
    intercepts when your code is about to execute the tool call.

    Usage:
        from aegis_enforce import intercept_openai, PolicyEngine

        engine = PolicyEngine.from_file("guard.aegisc")
        safe_client = intercept_openai(client, engine)

        # When processing tool calls from the response:
        for tool_call in response.choices[0].message.tool_calls:
            # This will be checked against the policy before execution
            result = execute_tool(tool_call)
    """
    # This is an alias for enforce() with explicit engine
    from aegis_enforce._enforce import _wrap_openai
    return _wrap_openai(client, engine, on_deny, None, None)


# ═══════════════════════════════════════════════════════════════════════
#  Generic tool-call decorator
# ═══════════════════════════════════════════════════════════════════════


def intercept_tool_call(
    engine: PolicyEngine,
    tool_name: Optional[str] = None,
    on_deny: str = "raise",
) -> Callable:
    """
    Decorator that enforces an Aegis policy on a function used as a tool.

    Usage:
        engine = PolicyEngine.from_file("guard.aegisc")

        @intercept_tool_call(engine, tool_name="search_database")
        def search_database(query: str, limit: int = 10):
            return db.execute(query, limit=limit)

        # Now every call to search_database() is checked first:
        results = search_database("SELECT * FROM users")
        # → EnforcementError if the policy denies it
    """

    def decorator(fn: Callable) -> Callable:
        name = tool_name or fn.__name__

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            fields = {
                "tool": name,
                "arguments": str(kwargs) if kwargs else str(args),
            }
            if kwargs:
                fields["keyword_arguments"] = kwargs

            result = engine.evaluate("tool_call", fields)

            if result.denied:
                if on_deny == "raise":
                    raise EnforcementError(result)
                elif on_deny == "log":
                    logger.warning(
                        "AutomaGuard DENY: %s — %s",
                        name,
                        result.reason,
                    )
                    # In log mode, still execute
                    return fn(*args, **kwargs)
                else:
                    raise EnforcementError(result)

            if result.verdict == "audit":
                logger.info("AutomaGuard AUDIT: %s", name)

            return fn(*args, **kwargs)

        # Attach metadata for introspection
        wrapper._automaguard_engine = engine
        wrapper._automaguard_tool_name = name
        return wrapper

    return decorator
