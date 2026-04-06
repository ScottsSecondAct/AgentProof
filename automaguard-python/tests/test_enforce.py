"""Tests for enforce(), EnforcementError, and _GenericProxy."""

import logging
from unittest.mock import MagicMock, patch, call

import pytest

from aegis_enforce._engine import PolicyEngine, PolicyResult
from aegis_enforce._enforce import (
    EnforcementError,
    _GenericProxy,
    _handle_result,
    enforce,
)
from tests.conftest import make_mock_engine


# ── EnforcementError ──────────────────────────────────────────────────────────


class TestEnforcementError:
    def test_message_includes_reason(self):
        result = PolicyResult(verdict="deny", reason="External HTTP blocked")
        err = EnforcementError(result)
        assert "External HTTP blocked" in str(err)

    def test_message_uses_fallback_when_no_reason(self):
        result = PolicyResult(verdict="deny")
        err = EnforcementError(result)
        assert "Policy denied" in str(err) or "AutomaGuard" in str(err)

    def test_result_attribute_preserved(self):
        result = PolicyResult(verdict="deny", reason="blocked")
        err = EnforcementError(result)
        assert err.result is result

    def test_is_exception(self):
        result = PolicyResult(verdict="deny", reason="x")
        assert isinstance(EnforcementError(result), Exception)


# ── _handle_result ────────────────────────────────────────────────────────────


class TestHandleResult:
    def test_deny_raise_raises_enforcement_error(self):
        result = PolicyResult(verdict="deny", reason="blocked")
        with pytest.raises(EnforcementError):
            _handle_result(result, "raise", None, None, {"tool": "exec"})

    def test_deny_block_raises_enforcement_error(self):
        result = PolicyResult(verdict="deny", reason="blocked")
        with pytest.raises(EnforcementError):
            _handle_result(result, "block", None, None, {"tool": "exec"})

    def test_deny_log_does_not_raise(self, caplog):
        result = PolicyResult(verdict="deny", reason="blocked")
        with caplog.at_level(logging.WARNING, logger="automaguard"):
            _handle_result(result, "log", None, None, {"tool": "exec"})
        assert "DENY" in caplog.text

    def test_deny_unknown_mode_raises(self):
        result = PolicyResult(verdict="deny", reason="x")
        with pytest.raises(EnforcementError):
            _handle_result(result, "unknown_mode", None, None, {})

    def test_allow_does_nothing(self):
        result = PolicyResult(verdict="allow")
        _handle_result(result, "raise", None, None, {})  # must not raise

    def test_audit_calls_on_audit_callback(self, caplog):
        result = PolicyResult(verdict="audit", reason="logged")
        cb = MagicMock()
        with caplog.at_level(logging.INFO, logger="automaguard"):
            _handle_result(result, "raise", cb, None, {"tool": "search"})
        cb.assert_called_once_with(result)
        assert "AUDIT" in caplog.text

    def test_audit_no_callback_is_noop(self, caplog):
        result = PolicyResult(verdict="audit", reason="logged")
        with caplog.at_level(logging.INFO, logger="automaguard"):
            _handle_result(result, "raise", None, None, {"tool": "search"})
        assert "AUDIT" in caplog.text

    def test_redact_calls_on_redact_callback(self, caplog):
        result = PolicyResult(verdict="redact", reason="sanitised")
        fields = {"tool": "db_read", "data": "secret"}
        cb = MagicMock()
        with caplog.at_level(logging.INFO, logger="automaguard"):
            _handle_result(result, "raise", None, cb, fields)
        cb.assert_called_once_with(fields, result)
        assert "REDACT" in caplog.text


# ── enforce() ─────────────────────────────────────────────────────────────────


class TestEnforceFunction:
    def test_raises_for_invalid_policy_type(self):
        with pytest.raises(TypeError, match="policy must be a file path or PolicyEngine"):
            enforce(MagicMock(), policy=42)  # type: ignore[arg-type]

    def test_raises_for_missing_policy_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            enforce(MagicMock(), policy=tmp_path / "missing.aegisc")

    def test_accepts_policy_engine_directly(self):
        engine = make_mock_engine("allow")
        client = MagicMock()
        # Any non-openai client gets the generic proxy
        result = enforce(client, policy=engine)
        assert result is not None

    def test_non_openai_returns_generic_proxy(self):
        engine = make_mock_engine("allow")
        client = MagicMock(spec=object)
        type(client).__module__ = "mylib"
        type(client).__qualname__ = "MyClient"
        proxy = enforce(client, policy=engine)
        assert isinstance(proxy, _GenericProxy)


# ── _GenericProxy ─────────────────────────────────────────────────────────────


class TestGenericProxy:
    def _make_proxy(self, verdict="allow", target=None):
        engine = make_mock_engine(verdict)
        target = target or MagicMock()
        proxy = _GenericProxy(target, engine, "raise", None, None)
        return proxy, engine, target

    def test_non_callable_attrs_pass_through(self):
        target = MagicMock()
        target.value = 42
        proxy, _, _ = self._make_proxy(target=target)
        assert proxy.value == 42

    def test_callable_attrs_are_wrapped(self):
        target = MagicMock()
        target.run = MagicMock(return_value="ok")
        proxy, _, _ = self._make_proxy(target=target)
        result = proxy.run(x=1)
        assert result == "ok"

    def test_allow_verdict_calls_through(self):
        target = MagicMock()
        target.execute = MagicMock(return_value="executed")
        proxy, engine, _ = self._make_proxy(verdict="allow", target=target)
        result = proxy.execute(arg="value")
        assert result == "executed"
        engine.evaluate.assert_called_once()

    def test_deny_verdict_raises(self):
        target = MagicMock()
        target.execute = MagicMock(return_value="executed")
        proxy, _, _ = self._make_proxy(verdict="deny")
        with pytest.raises(EnforcementError):
            proxy.execute(arg="value")
        target.execute.assert_not_called()

    def test_deny_log_mode_still_calls_through(self):
        engine = make_mock_engine("deny", reason="blocked")
        target = MagicMock()
        target.execute = MagicMock(return_value="ok")
        proxy = _GenericProxy(target, engine, "log", None, None)
        result = proxy.execute(x=1)
        assert result == "ok"

    def test_setattr_delegates_to_target(self):
        target = MagicMock()
        proxy, _, _ = self._make_proxy(target=target)
        proxy.some_attr = "new_value"
        assert target.some_attr == "new_value"

    def test_evaluate_called_with_tool_name(self):
        target = MagicMock()
        target.my_tool = MagicMock(return_value=None)
        proxy, engine, _ = self._make_proxy(target=target)
        proxy.my_tool(key="val")
        args, kwargs = engine.evaluate.call_args
        assert args[0] == "tool_call"
        assert args[1]["tool_name"] == "my_tool"

    def test_evaluate_fields_include_kwargs(self):
        target = MagicMock()
        target.search = MagicMock(return_value=[])
        proxy, engine, _ = self._make_proxy(target=target)
        proxy.search(query="test", limit=5)
        fields = engine.evaluate.call_args[0][1]
        assert "keyword_arguments" in fields
        assert fields["keyword_arguments"]["query"] == "test"
