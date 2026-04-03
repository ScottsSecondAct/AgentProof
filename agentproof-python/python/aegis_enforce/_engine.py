"""
PolicyEngine — the core evaluation interface.

Wraps the native Rust engine with a Pythonic API. Falls back to a
pure-Python JSON-based evaluator if the native extension isn't built.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

try:
    from aegis_enforce._agentproof_core import PolicyEngine as _NativeEngine

    _NATIVE_AVAILABLE = True
except ImportError:
    _NATIVE_AVAILABLE = False
    _NativeEngine = None


@dataclass
class PolicyResult:
    """The result of evaluating an event against a policy."""

    verdict: str
    """'allow', 'deny', 'audit', or 'redact'"""

    reason: Optional[str] = None
    """Human-readable explanation for the verdict."""

    triggered_rules: list[int] = field(default_factory=list)
    """IDs of rules that matched the event."""

    actions: list[dict[str, Any]] = field(default_factory=list)
    """Actions to execute (log, notify, escalate, etc.)."""

    violations: list[dict[str, Any]] = field(default_factory=list)
    """Invariant violations detected."""

    constraint_violations: list[dict[str, Any]] = field(default_factory=list)
    """Rate limit / quota violations."""

    eval_time_us: int = 0
    """Evaluation latency in microseconds."""

    @property
    def allowed(self) -> bool:
        """True if the verdict permits the action."""
        return self.verdict in ("allow", "audit")

    @property
    def denied(self) -> bool:
        """True if the verdict blocks the action."""
        return self.verdict == "deny"

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PolicyResult:
        return cls(
            verdict=d.get("verdict", "allow"),
            reason=d.get("reason"),
            triggered_rules=d.get("triggered_rules", []),
            actions=d.get("actions", []),
            violations=d.get("violations", []),
            constraint_violations=d.get("constraint_violations", []),
            eval_time_us=d.get("eval_time_us", 0),
        )


class PolicyEngine:
    """
    The AgentProof policy engine.

    Loads a compiled .aegisc policy and evaluates agent events against it.
    Uses the native Rust engine when available, falls back to pure Python.

    Examples:
        # From a compiled file
        engine = PolicyEngine.from_file("guard.aegisc")

        # From raw bytes (e.g., loaded from S3, database, etc.)
        engine = PolicyEngine.from_bytes(policy_bytes)

        # Evaluate an event
        result = engine.evaluate("tool_call", {
            "tool": "http_request",
            "url": "https://api.external.com/data",
        })

        if result.denied:
            raise PermissionError(result.reason)
    """

    def __init__(self, native_engine=None, policy_name: str = "unknown"):
        self._engine = native_engine
        self._policy_name = policy_name
        self._event_count = 0

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> PolicyEngine:
        """Load a policy from a compiled .aegisc file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")

        if _NATIVE_AVAILABLE:
            engine = _NativeEngine.from_file(str(path))
            return cls(native_engine=engine, policy_name=engine.policy_name)
        else:
            # Pure Python fallback: read and parse the JSON payload
            return cls._from_file_pure_python(path)

    @classmethod
    def from_bytes(cls, data: bytes) -> PolicyEngine:
        """Load a policy from raw .aegisc bytes."""
        if _NATIVE_AVAILABLE:
            engine = _NativeEngine.from_bytes(data)
            return cls(native_engine=engine, policy_name=engine.policy_name)
        else:
            return cls._from_bytes_pure_python(data)

    @classmethod
    def from_json(cls, json_str: str) -> PolicyEngine:
        """Load a policy from a JSON string (debug format)."""
        if _NATIVE_AVAILABLE:
            engine = _NativeEngine.from_json(json_str)
            return cls(native_engine=engine, policy_name=engine.policy_name)
        else:
            policy = json.loads(json_str)
            return cls(policy_name=policy.get("name", "unknown"))

    def evaluate(
        self,
        event_type: str,
        fields: Optional[dict[str, Any]] = None,
    ) -> PolicyResult:
        """
        Evaluate an event against the loaded policy.

        Args:
            event_type: The event type (e.g., "tool_call", "data_access")
            fields: Event-specific fields as a dict

        Returns:
            A PolicyResult with the verdict and metadata.

        Raises:
            RuntimeError: If the engine is not properly initialized.
        """
        self._event_count += 1

        if self._engine is not None:
            raw = self._engine.evaluate(event_type, fields)
            return PolicyResult.from_dict(raw)
        else:
            # Pure Python fallback: allow everything (no enforcement)
            return PolicyResult(
                verdict="allow",
                reason="No native engine available (pure Python fallback)",
                eval_time_us=0,
            )

    def set_context(self, key: str, value: Any) -> None:
        """Set a persistent context value (survives across events)."""
        if self._engine is not None:
            self._engine.set_context(key, value)

    def set_config(self, key: str, value: Any) -> None:
        """Set a policy configuration value."""
        if self._engine is not None:
            self._engine.set_config(key, value)

    @property
    def policy_name(self) -> str:
        """The name of the loaded policy."""
        return self._policy_name

    @property
    def event_count(self) -> int:
        """Total number of events evaluated."""
        if self._engine is not None:
            return self._engine.event_count
        return self._event_count

    def reset(self) -> None:
        """Reset engine state (state machines, counters)."""
        if self._engine is not None:
            self._engine.reset()
        self._event_count = 0

    def status(self) -> str:
        """Get a human-readable status summary."""
        if self._engine is not None:
            return self._engine.status()
        return f"PolicyEngine(policy='{self._policy_name}', native=False)"

    def __repr__(self) -> str:
        native = "native" if self._engine is not None else "python"
        return f"<PolicyEngine policy='{self._policy_name}' engine={native}>"

    # ── Pure Python fallback (reads .aegisc without native code) ──────

    @classmethod
    def _from_file_pure_python(cls, path: Path) -> PolicyEngine:
        """Read .aegisc file format in pure Python."""
        with open(path, "rb") as f:
            magic = f.read(4)
            if magic != b"\xae\x91\x5c\x01":
                raise ValueError(f"Not a valid .aegisc file: {path}")
            _version = int.from_bytes(f.read(2), "little")
            _flags = int.from_bytes(f.read(2), "little")
            payload_len = int.from_bytes(f.read(4), "little")
            payload = f.read(payload_len)

        policy = json.loads(payload)
        return cls(policy_name=policy.get("name", "unknown"))

    @classmethod
    def _from_bytes_pure_python(cls, data: bytes) -> PolicyEngine:
        """Parse .aegisc bytes in pure Python."""
        if data[:4] != b"\xae\x91\x5c\x01":
            raise ValueError("Not valid .aegisc data")
        payload_len = int.from_bytes(data[8:12], "little")
        payload = data[12 : 12 + payload_len]
        policy = json.loads(payload)
        return cls(policy_name=policy.get("name", "unknown"))
