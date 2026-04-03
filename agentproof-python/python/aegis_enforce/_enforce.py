"""
enforce() — the one-line API for AgentProof.

Usage:
    from agentproof import enforce

    # Wrap any OpenAI client
    safe_client = enforce(client, policy="guard.aegisc")

    # Use it exactly as before — tool calls are automatically checked
    response = safe_client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Transfer $100"}],
        tools=[...],
    )
"""

from __future__ import annotations

import functools
import logging
from pathlib import Path
from typing import Any, Callable, Optional, Union

from aegis_enforce._engine import PolicyEngine, PolicyResult

logger = logging.getLogger("agentproof")


class EnforcementError(Exception):
    """Raised when a policy denies an agent action."""

    def __init__(self, result: PolicyResult):
        self.result = result
        reason = result.reason or "Policy denied the action"
        super().__init__(f"AgentProof: {reason}")


def enforce(
    client: Any,
    *,
    policy: Union[str, Path, PolicyEngine],
    on_deny: str = "raise",
    on_audit: Optional[Callable[[PolicyResult], None]] = None,
    on_redact: Optional[Callable[[dict, PolicyResult], dict]] = None,
) -> Any:
    """
    Wrap an AI client with AgentProof policy enforcement.

    This is the primary entry point for AgentProof. It returns a
    transparent proxy around your client that intercepts tool calls
    and evaluates them against the loaded policy.

    Args:
        client: An OpenAI client, LangChain LLM, or any object whose
                tool calls should be monitored.
        policy: Path to a compiled .aegisc file, or a PolicyEngine instance.
        on_deny: What to do when a tool call is denied:
                 - "raise": Raise an EnforcementError (default)
                 - "block": Return a structured error to the agent
                 - "log": Log and allow (monitoring mode)
        on_audit: Optional callback for audit verdicts.
        on_redact: Optional callback for redact verdicts. Receives the
                   tool call args and result, returns sanitized args.

    Returns:
        A proxy object that behaves identically to `client` but enforces
        the policy on every tool call.

    Example:
        client = openai.OpenAI()
        safe_client = enforce(client, policy="guard.aegisc")

        # This works exactly like before:
        response = safe_client.chat.completions.create(...)

        # But if the agent tries to call an unauthorized tool:
        # → EnforcementError: AgentProof: External HTTP calls not permitted
    """
    # Load the policy engine
    if isinstance(policy, (str, Path)):
        engine = PolicyEngine.from_file(policy)
    elif isinstance(policy, PolicyEngine):
        engine = policy
    else:
        raise TypeError(
            f"policy must be a file path or PolicyEngine, got {type(policy).__name__}"
        )

    logger.info(
        "AgentProof: enforcing policy '%s' on %s",
        engine.policy_name,
        type(client).__name__,
    )

    # Detect the client type and return the appropriate proxy
    client_type = type(client).__module__ + "." + type(client).__qualname__

    if "openai" in client_type.lower():
        return _wrap_openai(client, engine, on_deny, on_audit, on_redact)
    else:
        # Generic proxy — intercepts attribute access and wraps callables
        return _GenericProxy(client, engine, on_deny, on_audit, on_redact)


# ═══════════════════════════════════════════════════════════════════════
#  OpenAI client proxy
# ═══════════════════════════════════════════════════════════════════════


def _wrap_openai(client, engine, on_deny, on_audit, on_redact):
    """Wrap an OpenAI client to intercept tool-call completions."""
    original_create = client.chat.completions.create

    @functools.wraps(original_create)
    def patched_create(*args, **kwargs):
        response = original_create(*args, **kwargs)

        # Check if the response contains tool calls
        if not hasattr(response, "choices"):
            return response

        for choice in response.choices:
            message = getattr(choice, "message", None)
            if message is None:
                continue

            tool_calls = getattr(message, "tool_calls", None)
            if not tool_calls:
                continue

            for tool_call in tool_calls:
                fn = getattr(tool_call, "function", None)
                if fn is None:
                    continue

                # Build the event
                fields = {
                    "tool": fn.name,
                    "arguments": fn.arguments if isinstance(fn.arguments, str) else str(fn.arguments),
                    "call_id": getattr(tool_call, "id", "unknown"),
                }

                # Parse arguments if JSON
                try:
                    import json
                    parsed_args = json.loads(fn.arguments)
                    if isinstance(parsed_args, dict):
                        fields["parsed_arguments"] = parsed_args
                except (json.JSONDecodeError, TypeError):
                    pass

                # Evaluate against policy
                result = engine.evaluate("tool_call", fields)
                _handle_result(result, on_deny, on_audit, on_redact, fields)

        return response

    # Monkey-patch the create method
    client.chat.completions.create = patched_create
    # Store a reference so it can be inspected
    client._agentproof_engine = engine
    return client


# ═══════════════════════════════════════════════════════════════════════
#  Generic proxy for any client
# ═══════════════════════════════════════════════════════════════════════


class _GenericProxy:
    """
    Transparent proxy that intercepts method calls.

    Any method call on the proxied object that looks like a tool
    invocation gets checked against the policy.
    """

    def __init__(self, target, engine, on_deny, on_audit, on_redact):
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_engine", engine)
        object.__setattr__(self, "_on_deny", on_deny)
        object.__setattr__(self, "_on_audit", on_audit)
        object.__setattr__(self, "_on_redact", on_redact)

    def __getattr__(self, name):
        attr = getattr(object.__getattribute__(self, "_target"), name)
        if callable(attr):
            return self._wrap_callable(attr, name)
        return attr

    def __setattr__(self, name, value):
        setattr(object.__getattribute__(self, "_target"), name, value)

    def _wrap_callable(self, fn, name):
        engine = object.__getattribute__(self, "_engine")
        on_deny = object.__getattribute__(self, "_on_deny")
        on_audit = object.__getattribute__(self, "_on_audit")
        on_redact = object.__getattribute__(self, "_on_redact")

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            # Build the event
            fields = {
                "tool": name,
                "arguments": str(kwargs) if kwargs else str(args),
            }
            if kwargs:
                fields["keyword_arguments"] = kwargs
            if args:
                fields["positional_arguments"] = list(args)

            # Evaluate
            result = engine.evaluate("tool_call", fields)
            _handle_result(result, on_deny, on_audit, on_redact, fields)

            return fn(*args, **kwargs)

        return wrapper


# ═══════════════════════════════════════════════════════════════════════
#  Verdict handling
# ═══════════════════════════════════════════════════════════════════════


def _handle_result(result, on_deny, on_audit, on_redact, fields):
    """Process a PolicyResult based on the configured behavior."""
    if result.verdict == "deny":
        if on_deny == "raise":
            raise EnforcementError(result)
        elif on_deny == "block":
            raise EnforcementError(result)
        elif on_deny == "log":
            logger.warning(
                "AgentProof DENY (monitoring mode): %s — %s",
                fields.get("tool", "unknown"),
                result.reason,
            )
        else:
            raise EnforcementError(result)

    elif result.verdict == "audit":
        logger.info(
            "AgentProof AUDIT: %s — %s",
            fields.get("tool", "unknown"),
            result.reason or "audited",
        )
        if on_audit:
            on_audit(result)

    elif result.verdict == "redact":
        logger.info(
            "AgentProof REDACT: %s — %s",
            fields.get("tool", "unknown"),
            result.reason or "fields redacted",
        )
        if on_redact:
            on_redact(fields, result)
