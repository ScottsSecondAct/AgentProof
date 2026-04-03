"""
Shared fixtures for agentproof-python tests.

All tests run against the pure-Python fallback (no native Rust extension
required).  Integration tests that require the compiled .aegisc format
create synthetic byte payloads using the documented file layout:

    [magic: 4B][version: 2B LE][flags: 2B LE][payload_len: 4B LE][payload: N bytes]
"""

import json
import struct
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from aegis_enforce._engine import PolicyEngine, PolicyResult


# ── .aegisc helpers ───────────────────────────────────────────────────────────

_MAGIC = b"\xae\x91\x5c\x01"


def make_aegisc_bytes(policy: dict[str, Any]) -> bytes:
    """Build a minimal valid .aegisc byte payload from a policy dict."""
    payload = json.dumps(policy).encode()
    header = _MAGIC + struct.pack("<HHI", 1, 0, len(payload))
    return header + payload


def make_aegisc_file(tmp_path: Path, policy: dict[str, Any]) -> Path:
    """Write a minimal valid .aegisc file and return its path."""
    p = tmp_path / "test.aegisc"
    p.write_bytes(make_aegisc_bytes(policy))
    return p


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def allow_engine() -> PolicyEngine:
    """A pure-Python engine that always returns 'allow'."""
    return PolicyEngine(policy_name="test-allow")


@pytest.fixture
def deny_result() -> PolicyResult:
    return PolicyResult(
        verdict="deny",
        reason="Test denial",
        triggered_rules=[1],
    )


@pytest.fixture
def allow_result() -> PolicyResult:
    return PolicyResult(verdict="allow")


@pytest.fixture
def audit_result() -> PolicyResult:
    return PolicyResult(verdict="audit", reason="logged")


@pytest.fixture
def redact_result() -> PolicyResult:
    return PolicyResult(verdict="redact", reason="sanitised")


def make_mock_engine(verdict: str = "allow", reason: str | None = None) -> MagicMock:
    """Return a PolicyEngine whose evaluate() returns a fixed verdict."""
    engine = MagicMock(spec=PolicyEngine)
    engine.policy_name = "mock-policy"
    engine.evaluate.return_value = PolicyResult(verdict=verdict, reason=reason)
    return engine
