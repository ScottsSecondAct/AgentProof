//! Mock tool implementations and the simulated agent event loop.
#![allow(dead_code)]
//!
//! In a real agent these would call external APIs. Here they produce static
//! data so the example runs without network access or an LLM API key.

use std::collections::HashMap;

use smol_str::SmolStr;

use automaguard::Value;

/// A single event in the simulated agent tool-call loop.
pub struct AgentEvent {
    pub event_type: SmolStr,
    pub fields: HashMap<SmolStr, Value>,
    pub description: String,
}

impl AgentEvent {
    fn new(
        event_type: impl Into<SmolStr>,
        description: impl Into<String>,
        fields: impl IntoIterator<Item = (&'static str, Value)>,
    ) -> Self {
        Self {
            event_type: event_type.into(),
            description: description.into(),
            fields: fields
                .into_iter()
                .map(|(k, v)| (SmolStr::new(k), v))
                .collect(),
        }
    }
}

/// Return the sequence of agent events for the safe prompt.
///
/// The agent queries tickets by region and sends the aggregate report to an
/// approved internal endpoint. No PII is accessed; all verdicts should be
/// `allow` or `audit`.
pub fn safe_events() -> Vec<AgentEvent> {
    vec![
        AgentEvent::new(
            "tool_call",
            "query_tickets(region=EMEA, quarter=Q4-2025)",
            [
                ("tool_name", Value::from("query_tickets")),
                ("arguments", Value::from("region=EMEA, quarter=Q4-2025")),
            ],
        ),
        AgentEvent::new(
            "tool_call",
            "query_tickets(region=APAC, quarter=Q4-2025)",
            [
                ("tool_name", Value::from("query_tickets")),
                ("arguments", Value::from("region=APAC, quarter=Q4-2025")),
            ],
        ),
        AgentEvent::new(
            "external_request",
            "POST reports.internal.corp/q4-summary",
            [
                ("domain", Value::from("reports.internal.corp")),
                ("method", Value::from("POST")),
                ("path", Value::from("/q4-summary")),
            ],
        ),
    ]
}

/// Return the sequence of agent events for the unsafe prompt.
///
/// The agent first reads a PII-classified customer record, then attempts to
/// send it to an unapproved external email address.
/// Expected: data_access → audit, external_request → deny.
pub fn unsafe_events() -> Vec<AgentEvent> {
    vec![
        AgentEvent::new(
            "data_access",
            "get_customer_profile(account_id=10042) — classification: PII",
            [
                ("classification", Value::from("PII")),
                ("record_id", Value::from("10042")),
                ("tool_name", Value::from("get_customer_profile")),
            ],
        ),
        AgentEvent::new(
            "external_request",
            "POST analyst@external-firm.com (unapproved domain)",
            [
                ("domain", Value::from("external-firm.com")),
                ("method", Value::from("POST")),
                ("path", Value::from("/send")),
            ],
        ),
    ]
}

/// Return events for the DDL denial scenario (used by --stress).
pub fn ddl_events() -> Vec<AgentEvent> {
    vec![
        AgentEvent::new(
            "tool_call",
            "drop_table(users)",
            [
                ("tool_name", Value::from("drop_table")),
                ("arguments", Value::from("users")),
            ],
        ),
    ]
}

/// Return 21 bulk data-read events — the 21st should be rate-limited.
pub fn bulk_read_events() -> Vec<AgentEvent> {
    (1u32..=21)
        .map(|i| {
            AgentEvent::new(
                "data_access",
                format!("get_record({i})"),
                [
                    ("classification", Value::from("aggregate")),
                    ("record_id", Value::String(SmolStr::new(i.to_string()))),
                ],
            )
        })
        .collect()
}

/// Return a delete-without-approval sequence.
pub fn delete_without_approval_events() -> Vec<AgentEvent> {
    vec![AgentEvent::new(
        "tool_call",
        "delete_record(account_id=10042) — no prior approval",
        [
            ("tool_name", Value::from("delete_record")),
            ("account_id", Value::from("10042")),
        ],
    )]
}
