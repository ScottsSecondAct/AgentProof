"""Tests for AutomaGuardCallbackHandler and intercept_tool_call."""

import logging
from typing import Any
from unittest.mock import MagicMock

import pytest

from aegis_enforce._engine import PolicyEngine, PolicyResult
from aegis_enforce._enforce import EnforcementError
from aegis_enforce._interceptors import (
    AutomaGuardCallbackHandler,
    intercept_tool_call,
)
from tests.conftest import make_mock_engine


# ── AutomaGuardCallbackHandler construction ────────────────────────────────────


class TestCallbackHandlerConstruction:
    def test_accepts_policy_engine(self):
        engine = make_mock_engine("allow")
        handler = AutomaGuardCallbackHandler(policy=engine)
        assert handler.engine is engine

    def test_raises_for_invalid_policy_type(self):
        with pytest.raises(TypeError):
            AutomaGuardCallbackHandler(policy=42)  # type: ignore[arg-type]

    def test_raises_for_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            AutomaGuardCallbackHandler(policy=tmp_path / "missing.aegisc")

    def test_default_on_deny_is_raise(self):
        engine = make_mock_engine("allow")
        handler = AutomaGuardCallbackHandler(policy=engine)
        assert handler.on_deny == "raise"

    def test_on_deny_configurable(self):
        engine = make_mock_engine("allow")
        handler = AutomaGuardCallbackHandler(policy=engine, on_deny="log")
        assert handler.on_deny == "log"


# ── on_tool_start: allow ──────────────────────────────────────────────────────


class TestCallbackHandlerOnToolStart:
    def test_allow_does_not_raise(self):
        engine = make_mock_engine("allow")
        handler = AutomaGuardCallbackHandler(policy=engine)
        handler.on_tool_start({"name": "search"}, '{"query": "hello"}')
        # Must not raise

    def test_allow_records_result(self):
        engine = make_mock_engine("allow")
        handler = AutomaGuardCallbackHandler(policy=engine)
        handler.on_tool_start({"name": "search"}, "q")
        assert handler.event_count == 1
        assert handler.deny_count == 0

    def test_evaluate_called_with_tool_name_and_args(self):
        engine = make_mock_engine("allow")
        handler = AutomaGuardCallbackHandler(policy=engine)
        handler.on_tool_start({"name": "db_query"}, '{"sql": "SELECT 1"}')
        fields = engine.evaluate.call_args[0][1]
        assert fields["tool_name"] == "db_query"
        assert fields["arguments"] == '{"sql": "SELECT 1"}'

    def test_description_included_in_fields(self):
        engine = make_mock_engine("allow")
        handler = AutomaGuardCallbackHandler(policy=engine)
        handler.on_tool_start(
            {"name": "tool", "description": "Does things"},
            "input",
        )
        fields = engine.evaluate.call_args[0][1]
        assert fields["description"] == "Does things"

    def test_unknown_tool_name(self):
        engine = make_mock_engine("allow")
        handler = AutomaGuardCallbackHandler(policy=engine)
        handler.on_tool_start({}, "input")
        fields = engine.evaluate.call_args[0][1]
        assert fields["tool_name"] == "unknown"


# ── on_tool_start: deny ───────────────────────────────────────────────────────


class TestCallbackHandlerDeny:
    def test_deny_raises_with_default_on_deny(self):
        engine = make_mock_engine("deny", reason="blocked")
        handler = AutomaGuardCallbackHandler(policy=engine)
        with pytest.raises(EnforcementError):
            handler.on_tool_start({"name": "exec"}, "cmd")

    def test_deny_log_does_not_raise(self, caplog):
        engine = make_mock_engine("deny", reason="blocked")
        handler = AutomaGuardCallbackHandler(policy=engine, on_deny="log")
        with caplog.at_level(logging.WARNING, logger="automaguard"):
            handler.on_tool_start({"name": "exec"}, "cmd")
        assert "DENY" in caplog.text

    def test_deny_increments_deny_count(self):
        engine = make_mock_engine("deny", reason="blocked")
        handler = AutomaGuardCallbackHandler(policy=engine, on_deny="log")
        handler.on_tool_start({"name": "exec"}, "cmd")
        assert handler.deny_count == 1

    def test_multiple_events_tracked(self):
        allow_engine = make_mock_engine("allow")
        handler = AutomaGuardCallbackHandler(policy=allow_engine)
        for _ in range(3):
            handler.on_tool_start({"name": "tool"}, "x")
        assert handler.event_count == 3
        assert handler.deny_count == 0


# ── on_tool_start: audit ──────────────────────────────────────────────────────


class TestCallbackHandlerAudit:
    def test_audit_does_not_raise(self, caplog):
        engine = make_mock_engine("audit", reason="logged")
        handler = AutomaGuardCallbackHandler(policy=engine)
        with caplog.at_level(logging.INFO, logger="automaguard"):
            handler.on_tool_start({"name": "search"}, "q")
        assert "AUDIT" in caplog.text

    def test_audit_not_counted_as_deny(self):
        engine = make_mock_engine("audit")
        handler = AutomaGuardCallbackHandler(policy=engine)
        handler.on_tool_start({"name": "search"}, "q")
        assert handler.deny_count == 0


# ── on_tool_end / on_tool_error ───────────────────────────────────────────────


class TestCallbackHandlerLifecycle:
    def test_on_tool_end_is_noop(self):
        engine = make_mock_engine("allow")
        handler = AutomaGuardCallbackHandler(policy=engine)
        handler.on_tool_end("result")  # must not raise

    def test_on_tool_error_logs(self, caplog):
        engine = make_mock_engine("allow")
        handler = AutomaGuardCallbackHandler(policy=engine)
        with caplog.at_level(logging.ERROR, logger="automaguard"):
            handler.on_tool_error(RuntimeError("boom"))
        assert "boom" in caplog.text

    def test_results_returns_copy(self):
        engine = make_mock_engine("allow")
        handler = AutomaGuardCallbackHandler(policy=engine)
        handler.on_tool_start({"name": "t"}, "x")
        results = handler.results
        results.clear()
        assert handler.event_count == 1  # internal list unaffected


# ── intercept_tool_call decorator ────────────────────────────────────────────


class TestInterceptToolCall:
    def test_allow_calls_through(self):
        engine = make_mock_engine("allow")

        @intercept_tool_call(engine)
        def my_tool(x: int) -> int:
            return x * 2

        assert my_tool(5) == 10

    def test_tool_name_defaults_to_function_name(self):
        engine = make_mock_engine("allow")

        @intercept_tool_call(engine)
        def my_tool():
            pass

        my_tool()
        fields = engine.evaluate.call_args[0][1]
        assert fields["tool_name"] == "my_tool"

    def test_explicit_tool_name_override(self):
        engine = make_mock_engine("allow")

        @intercept_tool_call(engine, tool_name="custom_name")
        def fn():
            pass

        fn()
        fields = engine.evaluate.call_args[0][1]
        assert fields["tool_name"] == "custom_name"

    def test_deny_raises_and_does_not_call_fn(self):
        engine = make_mock_engine("deny", reason="blocked")
        called = []

        @intercept_tool_call(engine)
        def dangerous():
            called.append(True)

        with pytest.raises(EnforcementError):
            dangerous()
        assert called == []

    def test_deny_log_mode_calls_through(self):
        engine = make_mock_engine("deny", reason="blocked")
        called = []

        @intercept_tool_call(engine, on_deny="log")
        def tool():
            called.append(True)

        tool()
        assert called == [True]

    def test_kwargs_included_in_fields(self):
        engine = make_mock_engine("allow")

        @intercept_tool_call(engine)
        def search(query: str, limit: int = 10):
            return []

        search(query="hello", limit=5)
        fields = engine.evaluate.call_args[0][1]
        assert "keyword_arguments" in fields
        assert fields["keyword_arguments"]["query"] == "hello"

    def test_metadata_attached_to_wrapper(self):
        engine = make_mock_engine("allow")

        @intercept_tool_call(engine, tool_name="my_fn")
        def my_fn():
            pass

        assert my_fn._automaguard_engine is engine
        assert my_fn._automaguard_tool_name == "my_fn"

    def test_wraps_preserves_function_name(self):
        engine = make_mock_engine("allow")

        @intercept_tool_call(engine)
        def named_function():
            pass

        assert named_function.__name__ == "named_function"

    def test_audit_calls_through(self, caplog):
        engine = make_mock_engine("audit")

        @intercept_tool_call(engine)
        def tool():
            return "result"

        with caplog.at_level(logging.INFO, logger="automaguard"):
            result = tool()
        assert result == "result"
        assert "AUDIT" in caplog.text
