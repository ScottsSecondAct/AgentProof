"""Tests for the PolicyEngine class (pure-Python path)."""

import json
import struct
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from aegis_enforce._engine import PolicyEngine, PolicyResult
from tests.conftest import (
    NATIVE_AVAILABLE,
    make_aegisc_bytes,
    make_aegisc_file,
    minimal_policy_dict,
)


# ── Construction ──────────────────────────────────────────────────────────────


class TestPolicyEngineFromFile:
    def test_raises_for_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            PolicyEngine.from_file(tmp_path / "nonexistent.aegisc")

    def test_raises_for_bad_magic(self, tmp_path):
        bad = tmp_path / "bad.aegisc"
        bad.write_bytes(b"\x00\x01\x02\x03" + b"\x00" * 8)
        with pytest.raises((ValueError, RuntimeError)):
            PolicyEngine.from_file(bad)

    def test_loads_policy_name_from_valid_file(self, tmp_path):
        p = make_aegisc_file(tmp_path, minimal_policy_dict("my-policy"))
        engine = PolicyEngine.from_file(p)
        assert engine.policy_name == "my-policy"

    def test_accepts_pathlib_path(self, tmp_path):
        p = make_aegisc_file(tmp_path, minimal_policy_dict("path-test"))
        engine = PolicyEngine.from_file(Path(p))
        assert engine.policy_name == "path-test"

    def test_accepts_string_path(self, tmp_path):
        p = make_aegisc_file(tmp_path, minimal_policy_dict("str-test"))
        engine = PolicyEngine.from_file(str(p))
        assert engine.policy_name == "str-test"

    @pytest.mark.skipif(NATIVE_AVAILABLE, reason="tests pure-Python fallback only")
    def test_missing_name_key_defaults_to_unknown(self, tmp_path):
        p = make_aegisc_file(tmp_path, {})
        engine = PolicyEngine.from_file(p)
        assert engine.policy_name == "unknown"


class TestPolicyEngineFromBytes:
    def test_loads_policy_name(self):
        data = make_aegisc_bytes(minimal_policy_dict("bytes-policy"))
        engine = PolicyEngine.from_bytes(data)
        assert engine.policy_name == "bytes-policy"

    def test_raises_for_bad_magic(self):
        bad_data = b"\x00\x01\x02\x03" + b"\x00" * 12
        with pytest.raises((ValueError, RuntimeError)):
            PolicyEngine.from_bytes(bad_data)

    @pytest.mark.skipif(NATIVE_AVAILABLE, reason="tests pure-Python fallback only")
    def test_empty_policy_dict(self):
        data = make_aegisc_bytes({})
        engine = PolicyEngine.from_bytes(data)
        assert engine.policy_name == "unknown"


class TestPolicyEngineFromJson:
    def test_loads_policy_name(self):
        engine = PolicyEngine.from_json(json.dumps(minimal_policy_dict("json-policy")))
        assert engine.policy_name == "json-policy"

    @pytest.mark.skipif(NATIVE_AVAILABLE, reason="tests pure-Python fallback only")
    def test_missing_name_defaults_unknown(self):
        engine = PolicyEngine.from_json(json.dumps({}))
        assert engine.policy_name == "unknown"


# ── Evaluation (pure-Python fallback) ────────────────────────────────────────


class TestPolicyEngineEvaluate:
    def test_fallback_always_allows(self):
        engine = PolicyEngine(policy_name="fallback")
        result = engine.evaluate("tool_call", {"tool": "search"})
        assert result.verdict == "allow"
        assert result.allowed is True

    def test_fallback_no_fields(self):
        engine = PolicyEngine(policy_name="fallback")
        result = engine.evaluate("tool_call")
        assert result.verdict == "allow"

    def test_fallback_reason_mentions_no_native(self):
        engine = PolicyEngine(policy_name="fallback")
        result = engine.evaluate("tool_call", {})
        assert result.reason is not None
        assert "native" in result.reason.lower() or "python" in result.reason.lower()

    def test_evaluate_with_native_engine_proxied(self):
        native = MagicMock()
        native.evaluate.return_value = {
            "verdict": "deny",
            "reason": "blocked",
            "triggered_rules": [3],
            "actions": [],
            "violations": [],
            "constraint_violations": [],
            "eval_time_us": 500,
        }
        engine = PolicyEngine(native_engine=native, policy_name="native-test")
        result = engine.evaluate("tool_call", {"tool": "exec"})
        assert result.verdict == "deny"
        assert result.reason == "blocked"
        assert result.triggered_rules == [3]
        native.evaluate.assert_called_once_with("tool_call", {"tool": "exec"})


# ── Event count ───────────────────────────────────────────────────────────────


class TestEventCount:
    def test_increments_on_each_evaluate(self):
        engine = PolicyEngine(policy_name="counter")
        assert engine.event_count == 0
        engine.evaluate("tool_call", {})
        assert engine.event_count == 1
        engine.evaluate("data_access", {})
        assert engine.event_count == 2

    def test_reset_clears_counter(self):
        engine = PolicyEngine(policy_name="counter")
        engine.evaluate("tool_call", {})
        engine.evaluate("tool_call", {})
        engine.reset()
        assert engine.event_count == 0

    def test_native_event_count_delegates(self):
        native = MagicMock()
        native.event_count = 42
        native.evaluate.return_value = {
            "verdict": "allow",
            "reason": None,
            "triggered_rules": [],
            "actions": [],
            "violations": [],
            "constraint_violations": [],
            "eval_time_us": 0,
        }
        engine = PolicyEngine(native_engine=native, policy_name="n")
        assert engine.event_count == 42


# ── Status and repr ───────────────────────────────────────────────────────────


class TestEngineStatus:
    def test_status_without_native(self):
        engine = PolicyEngine(policy_name="test-policy")
        s = engine.status()
        assert "test-policy" in s
        assert "False" in s or "python" in s.lower()

    def test_repr_without_native(self):
        engine = PolicyEngine(policy_name="p")
        assert "PolicyEngine" in repr(engine)
        assert "python" in repr(engine)
        assert "'p'" in repr(engine)

    def test_repr_with_native(self):
        native = MagicMock()
        engine = PolicyEngine(native_engine=native, policy_name="q")
        assert "native" in repr(engine)


# ── Context and config passthrough ───────────────────────────────────────────


class TestContextConfig:
    def test_set_context_no_native_is_noop(self):
        engine = PolicyEngine(policy_name="p")
        engine.set_context("user_id", "u123")  # must not raise

    def test_set_config_no_native_is_noop(self):
        engine = PolicyEngine(policy_name="p")
        engine.set_config("max_rate", 100)  # must not raise

    def test_set_context_delegates_to_native(self):
        native = MagicMock()
        engine = PolicyEngine(native_engine=native, policy_name="p")
        engine.set_context("k", "v")
        native.set_context.assert_called_once_with("k", "v")

    def test_set_config_delegates_to_native(self):
        native = MagicMock()
        engine = PolicyEngine(native_engine=native, policy_name="p")
        engine.set_config("k", 1)
        native.set_config.assert_called_once_with("k", 1)
