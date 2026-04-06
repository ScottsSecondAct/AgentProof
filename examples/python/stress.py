"""Stress / scenario tests for the CustomerDataGuard policy.

Exercises all scenarios without a live LLM using canned event sequences:

  - DDL denial: drop_table → immediate deny
  - PII access: data_access with classification=PII → audit
  - PII exfiltration: PII access followed by external_request → deny
  - Approved external request: reports.internal.corp → allow
  - Rate limiting: 21 data_access events in one minute → deny on 21st
  - Delete without approval: delete_record without human_approved → deny

Run without an OPENAI_API_KEY:
    python stress.py
"""

from __future__ import annotations

import sys
from pathlib import Path

from aegis_enforce import PolicyEngine

POLICY_PATH = Path(__file__).parent.parent / "customer_data_guard.aegisc"

if not POLICY_PATH.exists():
    print(
        f"Policy bytecode not found at {POLICY_PATH}. "
        "Run demo.sh first to compile it.",
        file=sys.stderr,
    )
    sys.exit(1)

engine = PolicyEngine.from_file(str(POLICY_PATH))

passed = 0
failed = 0


def check(label: str, event_type: str, fields: dict, expected: str) -> None:
    global passed, failed
    result = engine.evaluate(event_type, fields)
    if result.verdict == expected:
        print(f"  \u2713 {label} \u2192 {result.verdict}")
        passed += 1
    else:
        reason = f" ({result.reason})" if result.reason else ""
        print(
            f"  \u2717 {label}: expected {expected}, got {result.verdict}{reason}",
            file=sys.stderr,
        )
        failed += 1


# ── Scenario 1: DDL denial ────────────────────────────────────────────────────
print("\n[1] DDL denial")
engine.reset()
check("drop_table \u2192 deny", "tool_call", {"tool_name": "drop_table"}, "deny")
check("truncate_table \u2192 deny", "tool_call", {"tool_name": "truncate_table"}, "deny")
check("query_tickets \u2192 allow", "tool_call", {"tool_name": "query_tickets"}, "allow")

# ── Scenario 2: PII data access (audit) ──────────────────────────────────────
print("\n[2] PII data access")
engine.reset()
check(
    "data_access PII \u2192 audit",
    "data_access",
    {"classification": "PII", "record_id": "10042"},
    "audit",
)
check(
    "data_access aggregate \u2192 allow",
    "data_access",
    {"classification": "aggregate"},
    "allow",
)

# ── Scenario 3: PII exfiltration temporal invariant ────────────────────────────
print("\n[3] PII exfiltration (temporal invariant)")
engine.reset()
check(
    "data_access PII \u2192 audit",
    "data_access",
    {"classification": "PII", "record_id": "10042"},
    "audit",
)
check(
    "external_request unapproved domain \u2192 deny",
    "external_request",
    {"domain": "external-firm.com", "method": "POST"},
    "deny",
)

# ── Scenario 4: Approved external request ────────────────────────────────────
print("\n[4] Approved external request")
engine.reset()
check(
    "external_request reports.internal.corp \u2192 allow",
    "external_request",
    {"domain": "reports.internal.corp", "method": "POST"},
    "allow",
)

# ── Scenario 5: Rate limiting ─────────────────────────────────────────────────
print("\n[5] Rate limiting (20 allowed, 21st denied)")
engine.reset()
all_allowed = True
for i in range(1, 21):
    r = engine.evaluate("data_access", {"classification": "aggregate", "record_id": str(i)})
    if r.verdict != "allow":
        print(f"  \u2717 Event {i}: expected allow, got {r.verdict}", file=sys.stderr)
        failed += 1
        all_allowed = False
if all_allowed:
    print("  \u2713 events 1\u201320 \u2192 allow")
    passed += 20
check(
    "event 21 \u2192 deny (rate limit)",
    "data_access",
    {"classification": "aggregate", "record_id": "21"},
    "deny",
)

# ── Scenario 6: Delete without approval ──────────────────────────────────────
print("\n[6] Delete without prior human approval")
engine.reset()
check(
    "delete_record without approval \u2192 deny",
    "tool_call",
    {"tool_name": "delete_record", "account_id": "10042"},
    "deny",
)

# ── Summary ───────────────────────────────────────────────────────────────────
print(f"\n{'─' * 40}")
print(f"Stress test: {passed} passed, {failed} failed")
if failed > 0:
    sys.exit(1)
