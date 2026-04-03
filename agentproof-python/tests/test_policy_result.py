"""Tests for PolicyResult dataclass."""

from aegis_enforce._engine import PolicyResult


class TestPolicyResultDefaults:
    def test_verdict_required(self):
        r = PolicyResult(verdict="allow")
        assert r.verdict == "allow"

    def test_optional_fields_default_empty(self):
        r = PolicyResult(verdict="allow")
        assert r.reason is None
        assert r.triggered_rules == []
        assert r.actions == []
        assert r.violations == []
        assert r.constraint_violations == []
        assert r.eval_time_us == 0

    def test_mutable_defaults_not_shared(self):
        a = PolicyResult(verdict="allow")
        b = PolicyResult(verdict="deny")
        a.triggered_rules.append(99)
        assert b.triggered_rules == []


class TestPolicyResultProperties:
    def test_allowed_allow(self):
        assert PolicyResult(verdict="allow").allowed is True

    def test_allowed_audit(self):
        assert PolicyResult(verdict="audit").allowed is True

    def test_allowed_deny(self):
        assert PolicyResult(verdict="deny").allowed is False

    def test_allowed_redact(self):
        assert PolicyResult(verdict="redact").allowed is False

    def test_denied_deny(self):
        assert PolicyResult(verdict="deny").denied is True

    def test_denied_allow(self):
        assert PolicyResult(verdict="allow").denied is False

    def test_denied_audit(self):
        assert PolicyResult(verdict="audit").denied is False


class TestPolicyResultFromDict:
    def test_full_dict(self):
        d = {
            "verdict": "deny",
            "reason": "Rate limit exceeded",
            "triggered_rules": [2, 5],
            "actions": [{"type": "log"}],
            "violations": [{"rule": "rate_limit"}],
            "constraint_violations": [{"kind": "quota"}],
            "eval_time_us": 1234,
        }
        r = PolicyResult.from_dict(d)
        assert r.verdict == "deny"
        assert r.reason == "Rate limit exceeded"
        assert r.triggered_rules == [2, 5]
        assert r.actions == [{"type": "log"}]
        assert r.violations == [{"rule": "rate_limit"}]
        assert r.constraint_violations == [{"kind": "quota"}]
        assert r.eval_time_us == 1234

    def test_empty_dict_defaults_to_allow(self):
        r = PolicyResult.from_dict({})
        assert r.verdict == "allow"
        assert r.reason is None
        assert r.triggered_rules == []
        assert r.eval_time_us == 0

    def test_missing_optional_fields_use_defaults(self):
        r = PolicyResult.from_dict({"verdict": "audit"})
        assert r.verdict == "audit"
        assert r.actions == []
        assert r.violations == []

    def test_unknown_extra_keys_are_ignored(self):
        r = PolicyResult.from_dict({"verdict": "allow", "future_field": "x"})
        assert r.verdict == "allow"
