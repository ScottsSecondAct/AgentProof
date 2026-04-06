"""Customer Data Assistant — AutomaGuard Python SDK example.

Demonstrates AutomaGuard policy enforcement on a LangChain agent.

Usage:
    python agent.py --safe    # Aggregate query, no PII accessed or sent externally
    python agent.py --unsafe  # Adversarial PII exfiltration attempt (blocked)
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from langchain.agents import AgentExecutor, create_openai_functions_agent
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_openai import ChatOpenAI

from aegis_enforce import AutomaGuardCallbackHandler, EnforcementError, PolicyEngine

from prompts import SAFE_PROMPT, UNSAFE_PROMPT
from tools import delete_record, get_customer_profile, human_approved, query_tickets, send_email

# ── Policy setup ──────────────────────────────────────────────────────────────

POLICY_PATH = Path(__file__).parent.parent / "customer_data_guard.aegisc"

if not POLICY_PATH.exists():
    print(
        f"Policy bytecode not found at {POLICY_PATH}.\n"
        "Compile it first:\n"
        "  aegisc compile examples/customer_data_guard.aegis "
        "-o examples/customer_data_guard.aegisc",
        file=sys.stderr,
    )
    sys.exit(1)


def on_audit(result, tool_name: str = "tool") -> None:
    print(
        f"  [audit] {tool_name}: {result.reason or 'no reason'} "
        f"(rules: {result.triggered_rules})"
    )


handler = AutomaGuardCallbackHandler(
    policy=str(POLICY_PATH),
    on_deny="raise",
)

# ── Agent setup ───────────────────────────────────────────────────────────────

tools = [get_customer_profile, query_tickets, send_email, delete_record, human_approved]

llm = ChatOpenAI(model="gpt-4o", temperature=0)

prompt = ChatPromptTemplate.from_messages(
    [
        ("system", "You are a helpful customer support analyst assistant."),
        ("human", "{input}"),
        MessagesPlaceholder(variable_name="agent_scratchpad"),
    ]
)

agent = create_openai_functions_agent(llm=llm, tools=tools, prompt=prompt)

executor = AgentExecutor(
    agent=agent,
    tools=tools,
    callbacks=[handler],
    verbose=False,
)

# ── Run ───────────────────────────────────────────────────────────────────────

mode = "safe" if "--safe" in sys.argv else "unsafe"
input_text = SAFE_PROMPT if mode == "safe" else UNSAFE_PROMPT

print(f"\n=== AutomaGuard Python Example ({mode} run) ===\n")
print(f"Prompt: {input_text}\n")

try:
    result = executor.invoke({"input": input_text})
    print(f"\nResult: {result['output']}")
except EnforcementError as e:
    print("\nBLOCKED by AutomaGuard policy:")
    print(f"  Reason:  {e.result.reason}")
    print(f"  Verdict: {e.result.verdict}")
    if e.result.triggered_rules:
        print(f"  Rules triggered: {e.result.triggered_rules}")
    if e.result.violations:
        print("  Invariant violations:")
        for v in e.result.violations:
            print(f"    - {v['proof']}/{v['invariant']}: {v['message']}")
    sys.exit(1)
except Exception as e:
    print(f"\nUnexpected error: {e}", file=sys.stderr)
    sys.exit(1)

status = handler.engine.status()
print(f"\n[engine] {handler.event_count} events evaluated")
