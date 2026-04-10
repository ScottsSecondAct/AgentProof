"""
Native engine integration tests.

These tests exercise the full pipeline end-to-end using the compiled Rust
extension:

    .aegis source  →  aegisc compile  →  .aegisc file
                                              ↓
    Python dict  →  PolicyEngine.from_file/bytes/json  →  evaluate()  →  verdict

All tests in this file are skipped when the native extension is not installed.
Build it with:  maturin develop  (from automaguard-python/)
"""

import json
import subprocess
import tempfile
from pathlib import Path

import pytest

from aegis_enforce._engine import PolicyEngine, PolicyResult
from tests.conftest import NATIVE_AVAILABLE, make_aegisc_bytes, minimal_policy_dict

pytestmark = pytest.mark.skipif(
    not NATIVE_AVAILABLE, reason="native Rust extension not installed"
)

# Path to the aegisc compiler binary (built by cargo).
_AEGISC = (
    Path(__file__).parent.parent.parent / "aegis-compiler" / "target" / "debug" / "aegisc"
)


# ── Helpers ───────────────────────────────────────────────────────────────────


def compile_policy(source: str) -> bytes:
    """Compile Aegis source to .aegisc bytes via the aegisc CLI."""
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "policy.aegis"
        out = Path(td) / "policy.aegisc"
        src.write_text(source)
        result = subprocess.run(
            [str(_AEGISC), "compile", str(src), "-o", str(out)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"aegisc compile failed:\n{result.stderr}"
        return out.read_bytes()


def engine_from_source(source: str) -> PolicyEngine:
    """Compile Aegis source and return a live PolicyEngine."""
    return PolicyEngine.from_bytes(compile_policy(source))


# ── Construction ──────────────────────────────────────────────────────────────


class TestNativeConstruction:
    def test_from_bytes_loads_policy_name(self):
        data = make_aegisc_bytes(minimal_policy_dict("roundtrip"))
        engine = PolicyEngine.from_bytes(data)
        assert engine.policy_name == "roundtrip"

    def test_from_json_loads_policy_name(self):
        engine = PolicyEngine.from_json(json.dumps(minimal_policy_dict("json-native")))
        assert engine.policy_name == "json-native"

    def test_from_file_loads_policy_name(self, tmp_path):
        f = tmp_path / "p.aegisc"
        f.write_bytes(make_aegisc_bytes(minimal_policy_dict("file-native")))
        engine = PolicyEngine.from_file(f)
        assert engine.policy_name == "file-native"

    def test_from_compiled_source_preserves_policy_name(self):
        source = 'policy MyNamedPolicy { on tool_call { audit } }'
        engine = engine_from_source(source)
        assert engine.policy_name == "MyNamedPolicy"

    def test_event_count_starts_at_zero(self):
        data = make_aegisc_bytes(minimal_policy_dict())
        engine = PolicyEngine.from_bytes(data)
        assert engine.event_count == 0

    def test_event_count_increments(self):
        engine = engine_from_source('policy P { on tool_call { allow } }')
        engine.evaluate("tool_call", {})
        engine.evaluate("tool_call", {})
        assert engine.event_count == 2

    def test_reset_clears_event_count(self):
        engine = engine_from_source('policy P { on tool_call { allow } }')
        engine.evaluate("tool_call", {})
        engine.reset()
        assert engine.event_count == 0


# ── Verdict evaluation ────────────────────────────────────────────────────────


class TestNativeVerdicts:
    def test_allow_rule(self):
        engine = engine_from_source(
            'policy P { on tool_call { when event.tool_name == "search"\n allow } }'
        )
        result = engine.evaluate("tool_call", {"tool_name": "search"})
        assert result.verdict == "allow"
        assert result.allowed is True

    def test_deny_rule(self):
        engine = engine_from_source(
            'policy P { on tool_call { when event.tool_name == "exec"\n deny with "forbidden" } }'
        )
        result = engine.evaluate("tool_call", {"tool_name": "exec"})
        assert result.verdict == "deny"
        assert result.denied is True
        assert result.reason == "forbidden"

    def test_audit_rule(self):
        engine = engine_from_source(
            'policy P { on data_access { when event.classification == "PII"\n audit with "pii" } }'
        )
        result = engine.evaluate("data_access", {"classification": "PII"})
        assert result.verdict == "audit"
        assert result.allowed is True  # audit lets the action proceed

    def test_non_matching_event_type_defaults_to_allow(self):
        engine = engine_from_source(
            'policy P { on tool_call { deny } }'
        )
        result = engine.evaluate("data_access", {})
        assert result.verdict == "allow"

    def test_non_matching_condition_defaults_to_allow(self):
        engine = engine_from_source(
            'policy P { on tool_call { when event.tool_name == "exec"\n deny } }'
        )
        result = engine.evaluate("tool_call", {"tool_name": "search"})
        assert result.verdict == "allow"

    def test_deny_wins_over_audit(self):
        source = """
        policy P {
            on tool_call { audit }
            on tool_call { when event.tool_name == "exec"\n deny }
        }
        """
        engine = engine_from_source(source)
        result = engine.evaluate("tool_call", {"tool_name": "exec"})
        assert result.verdict == "deny"

    def test_triggered_rules_reported(self):
        engine = engine_from_source(
            'policy P { on tool_call { deny } }'
        )
        result = engine.evaluate("tool_call", {})
        assert len(result.triggered_rules) > 0

    def test_eval_time_us_is_positive(self):
        engine = engine_from_source('policy P { on tool_call { allow } }')
        result = engine.evaluate("tool_call", {})
        assert result.eval_time_us >= 0


# ── Field types through the pyo3 bridge ──────────────────────────────────────


class TestPyo3TypeConversion:
    """Verify Python → Rust → Python field-type round-trips."""

    def _engine(self) -> PolicyEngine:
        return engine_from_source('policy P { on tool_call { allow } }')

    def test_string_field(self):
        engine = self._engine()
        result = engine.evaluate("tool_call", {"key": "value"})
        assert result.verdict == "allow"

    def test_int_field(self):
        engine = self._engine()
        result = engine.evaluate("tool_call", {"count": 42})
        assert result.verdict == "allow"

    def test_float_field(self):
        engine = self._engine()
        result = engine.evaluate("tool_call", {"score": 0.95})
        assert result.verdict == "allow"

    def test_bool_field(self):
        engine = self._engine()
        result = engine.evaluate("tool_call", {"enabled": True})
        assert result.verdict == "allow"

    def test_none_field(self):
        engine = self._engine()
        result = engine.evaluate("tool_call", {"optional": None})
        assert result.verdict == "allow"

    def test_list_field(self):
        engine = self._engine()
        result = engine.evaluate("tool_call", {"tags": ["a", "b", "c"]})
        assert result.verdict == "allow"

    def test_nested_dict_field(self):
        engine = self._engine()
        result = engine.evaluate("tool_call", {"endpoint": {"host": "api.example.com", "port": 443}})
        assert result.verdict == "allow"

    def test_unicode_field_value(self):
        engine = self._engine()
        result = engine.evaluate("tool_call", {"name": "Ünïcödé"})
        assert result.verdict == "allow"

    def test_empty_fields_dict(self):
        engine = self._engine()
        result = engine.evaluate("tool_call", {})
        assert result.verdict == "allow"

    def test_no_fields_argument(self):
        engine = self._engine()
        result = engine.evaluate("tool_call")
        assert result.verdict == "allow"

    def test_large_payload(self):
        engine = self._engine()
        fields = {f"key_{i}": f"value_{i}" for i in range(100)}
        result = engine.evaluate("tool_call", fields)
        assert result.verdict == "allow"


# ── Temporal invariants ───────────────────────────────────────────────────────


class TestNativeTemporalInvariants:
    def test_never_invariant_allows_safe_events(self):
        engine = engine_from_source("""
        policy P {
            proof Safety {
                invariant NoExec { never(event.tool_name == "exec") }
            }
        }
        """)
        result = engine.evaluate("tool_call", {"tool_name": "search"})
        assert result.verdict == "allow"

    def test_never_invariant_denies_prohibited_event(self):
        engine = engine_from_source("""
        policy P {
            proof Safety {
                invariant NoExec { never(event.tool_name == "exec") }
            }
        }
        """)
        result = engine.evaluate("tool_call", {"tool_name": "exec"})
        assert result.verdict == "deny"
        assert len(result.violations) > 0

    def test_never_violation_persists_across_events(self):
        engine = engine_from_source("""
        policy P {
            proof Safety {
                invariant NoExec { never(event.tool_name == "exec") }
            }
        }
        """)
        engine.evaluate("tool_call", {"tool_name": "exec"})
        result = engine.evaluate("tool_call", {"tool_name": "search"})
        assert result.verdict == "deny"

    def test_before_invariant_allows_correct_order(self):
        engine = engine_from_source("""
        policy P {
            proof Gate {
                invariant ApproveFirst {
                    before(
                        event.tool_name == "approve",
                        event.tool_name == "delete"
                    )
                }
            }
        }
        """)
        engine.evaluate("tool_call", {"tool_name": "approve"})
        result = engine.evaluate("tool_call", {"tool_name": "delete"})
        assert result.verdict == "allow"

    def test_before_invariant_denies_wrong_order(self):
        engine = engine_from_source("""
        policy P {
            proof Gate {
                invariant ApproveFirst {
                    before(
                        event.tool_name == "approve",
                        event.tool_name == "delete"
                    )
                }
            }
        }
        """)
        result = engine.evaluate("tool_call", {"tool_name": "delete"})
        assert result.verdict == "deny"
        assert len(result.violations) > 0

    def test_after_invariant_denies_when_condition_fails(self):
        engine = engine_from_source("""
        policy P {
            proof Exfil {
                invariant NoPIILeak {
                    after(
                        !(event.event_type == "external_request"),
                        event.event_type == "data_access" && event.classification == "PII"
                    )
                }
            }
        }
        """)
        engine.evaluate("data_access", {"classification": "PII"})
        result = engine.evaluate("external_request", {})
        assert result.verdict == "deny"
        assert len(result.violations) > 0


# ── Rate limits ───────────────────────────────────────────────────────────────


class TestNativeRateLimits:
    def test_allows_within_limit(self):
        engine = engine_from_source("""
        policy P {
            rate_limit tool_call: 5 per 1m
        }
        """)
        for _ in range(5):
            result = engine.evaluate("tool_call", {})
            assert result.verdict == "allow"

    def test_denies_over_limit(self):
        engine = engine_from_source("""
        policy P {
            rate_limit tool_call: 2 per 1m
        }
        """)
        engine.evaluate("tool_call", {})
        engine.evaluate("tool_call", {})
        result = engine.evaluate("tool_call", {})
        assert result.verdict == "deny"
        assert len(result.constraint_violations) > 0

    def test_different_event_types_have_independent_limits(self):
        engine = engine_from_source("""
        policy P {
            rate_limit tool_call: 1 per 1m
        }
        """)
        engine.evaluate("tool_call", {})  # exhaust tool_call limit
        result = engine.evaluate("data_access", {})  # different type — not limited
        assert result.verdict == "allow"


# ── Reset ─────────────────────────────────────────────────────────────────────


class TestNativeReset:
    def test_reset_restores_clean_state(self):
        engine = engine_from_source("""
        policy P {
            proof Safety {
                invariant NoExec { never(event.tool_name == "exec") }
            }
        }
        """)
        engine.evaluate("tool_call", {"tool_name": "exec"})  # violate
        engine.reset()
        # After reset, the invariant monitor is back to its initial state.
        result = engine.evaluate("tool_call", {"tool_name": "search"})
        assert result.verdict == "allow"
