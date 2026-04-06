//! napi-rs native addon for the AutomaGuard TypeScript SDK.
//!
//! Exposes [`PolicyEngine`] and its supporting result types to Node.js via the
//! N-API interface. The evaluation path is identical to the Python SDK; only
//! the language bridge differs — napi-rs instead of pyo3.
//!
//! # Thread safety
//!
//! [`PolicyEngine`] wraps the Rust engine in a `Mutex` so that napi-rs can
//! share a single engine across concurrent JS calls (e.g. Promise chains).
//! JavaScript's event loop is single-threaded, but the `napi` runtime may
//! dispatch calls from a thread pool for async operations.
//!
//! # Fields parameter
//!
//! `evaluate()` accepts any JS object as `fields`. The `serde-json` napi
//! feature serialises it to `serde_json::Value` automatically, which is then
//! converted to the engine's native `Value` type.

#![allow(clippy::useless_conversion)] // napi macro expansions trigger this

use std::collections::HashMap;
use std::sync::Mutex;

use napi::bindgen_prelude::*;
use napi_derive::napi;
use smol_str::SmolStr;

use aegis_compiler::ast::Verdict;
use aegis_compiler::bytecode;
use aegis_runtime::engine::PolicyEngine as RustEngine;
use aegis_runtime::event::{Event, Value};

// ── Value conversion ──────────────────────────────────────────────────────────

/// Recursively convert a `serde_json::Value` to the engine's `Value` type.
fn json_to_value(v: serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i)
            } else if let Some(f) = n.as_f64() {
                Value::Float(f)
            } else {
                Value::Null
            }
        }
        serde_json::Value::String(s) => Value::String(SmolStr::new(&s)),
        serde_json::Value::Array(a) => {
            Value::List(a.into_iter().map(json_to_value).collect())
        }
        serde_json::Value::Object(o) => {
            let mut map = HashMap::with_capacity(o.len());
            for (k, v) in o {
                map.insert(SmolStr::new(&k), json_to_value(v));
            }
            Value::Map(map)
        }
    }
}

/// Convert the engine's `Value` back to `serde_json::Value` for JS serialisation.
fn value_to_json(v: Value) -> serde_json::Value {
    match v {
        Value::Null => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(b),
        Value::Int(i) => serde_json::Value::Number(i.into()),
        Value::Float(f) => serde_json::Number::from_f64(f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        Value::String(s) => serde_json::Value::String(s.to_string()),
        Value::Duration(ms) => serde_json::Value::Number(ms.into()),
        Value::List(items) => {
            serde_json::Value::Array(items.into_iter().map(value_to_json).collect())
        }
        Value::Map(map) => {
            let obj: serde_json::Map<String, serde_json::Value> = map
                .into_iter()
                .map(|(k, v)| (k.to_string(), value_to_json(v)))
                .collect();
            serde_json::Value::Object(obj)
        }
    }
}

// ── napi result object types ──────────────────────────────────────────────────

/// An invariant violation detected during event evaluation.
#[napi(object)]
pub struct Violation {
    /// Name of the proof block that owns this invariant.
    pub proof: String,
    /// Name of the invariant that was violated.
    pub invariant: String,
    /// Temporal operator kind (`Always`, `Eventually`, `Until`, `Never`).
    pub kind: String,
    /// Human-readable violation message.
    pub message: String,
}

/// A rate-limit or quota constraint violation.
#[napi(object)]
pub struct ConstraintViolation {
    /// Constraint kind (`RateLimit`, `Quota`).
    pub kind: String,
    /// The target event type this constraint applies to.
    pub target: String,
    /// Configured limit.
    pub limit: i64,
    /// Current count within the window.
    pub current: i64,
    /// Sliding window size in milliseconds.
    pub window_ms: i64,
}

/// An action emitted by a matched rule (e.g. `log`, `notify`, `escalate`).
#[napi(object)]
pub struct RuleAction {
    /// The action verb.
    pub verb: String,
    /// JSON-serialised action arguments. Call `JSON.parse(action.args_json)` to access them.
    pub args_json: String,
}

/// The result of evaluating one agent event against the loaded policy.
#[napi(object)]
pub struct PolicyResult {
    /// Final verdict: `"allow"`, `"deny"`, `"audit"`, or `"redact"`.
    pub verdict: String,
    /// Human-readable reason for the verdict, or `null` if none.
    pub reason: Option<String>,
    /// IDs of the rules that matched this event.
    pub triggered_rules: Vec<u32>,
    /// Invariant violations detected during evaluation.
    pub violations: Vec<Violation>,
    /// Rate-limit or quota violations.
    pub constraint_violations: Vec<ConstraintViolation>,
    /// Actions emitted by matched rules.
    pub actions: Vec<RuleAction>,
    /// Evaluation latency in microseconds.
    pub latency_us: i64,
}

/// A snapshot of the engine's current operational state.
#[napi(object)]
pub struct EngineStatus {
    pub policy_name: String,
    pub severity: String,
    pub total_rules: i64,
    pub total_state_machines: i64,
    pub active_state_machines: i64,
    pub violated_state_machines: i64,
    pub satisfied_state_machines: i64,
    pub total_constraints: i64,
    pub events_processed: i64,
}

// ── PolicyEngine ──────────────────────────────────────────────────────────────

/// AutomaGuard policy engine for Node.js.
///
/// Load a compiled `.aegisc` policy once at agent startup, then call
/// `evaluate()` on each agent event. Evaluation is synchronous and typically
/// completes in under 1 ms.
///
/// The engine is safe to use from multiple async tasks — the Mutex serialises
/// concurrent `evaluate()` calls.
///
/// @example
/// ```typescript
/// const engine = PolicyEngine.fromFile('guard.aegisc');
/// const result = engine.evaluate('tool_call', { tool_name: 'send_email' });
/// if (result.verdict === 'deny') throw new Error(result.reason ?? 'Denied');
/// ```
#[napi]
pub struct PolicyEngine {
    inner: Mutex<RustEngine>,
    name: String,
}

#[napi]
impl PolicyEngine {
    /// Load a policy engine from a compiled `.aegisc` file path.
    ///
    /// @param path - Absolute or relative path to the `.aegisc` file.
    /// @throws If the file does not exist or cannot be parsed as a compiled policy.
    #[napi(factory)]
    pub fn from_file(path: String) -> napi::Result<Self> {
        let policy = bytecode::read_file(std::path::Path::new(&path)).map_err(|e| {
            napi::Error::from_reason(format!("Failed to load policy from \"{path}\": {e}"))
        })?;
        let name = policy.name.to_string();
        Ok(Self {
            inner: Mutex::new(RustEngine::new(policy)),
            name,
        })
    }

    /// Load a policy engine from raw `.aegisc` bytes (e.g. from a bundled asset).
    ///
    /// @param data - A Node.js `Buffer` containing the compiled policy bytes.
    /// @throws If the buffer cannot be parsed as a compiled policy.
    #[napi(factory)]
    pub fn from_bytes(data: Buffer) -> napi::Result<Self> {
        let policy = bytecode::from_bytecode(&data).map_err(|e| {
            napi::Error::from_reason(format!("Failed to parse policy bytes: {e}"))
        })?;
        let name = policy.name.to_string();
        Ok(Self {
            inner: Mutex::new(RustEngine::new(policy)),
            name,
        })
    }

    /// Evaluate a single agent event against the loaded policy.
    ///
    /// @param event_type - Event type string (e.g. `"tool_call"`, `"data_access"`).
    /// @param fields     - Arbitrary event fields as a plain JS object. Pass `null`
    ///                     or omit for events with no fields.
    /// @returns A `PolicyResult` with the verdict, triggered rules, and any violations.
    #[napi]
    pub fn evaluate(
        &self,
        event_type: String,
        fields: Option<serde_json::Value>,
    ) -> napi::Result<PolicyResult> {
        let mut event = Event::new(&event_type);

        if let Some(serde_json::Value::Object(map)) = fields {
            for (k, v) in map {
                event.fields.insert(SmolStr::new(&k), json_to_value(v));
            }
        }

        let result = self
            .inner
            .lock()
            .map_err(|_| napi::Error::from_reason("PolicyEngine lock poisoned"))?
            .evaluate(&event);

        Ok(convert_result(result))
    }

    /// Set a persistent context value accessible in policy expressions as `context.<key>`.
    ///
    /// Context values accumulate across events for the lifetime of this engine instance.
    ///
    /// @param key   - Context key.
    /// @param value - Any JSON-serialisable value.
    #[napi]
    pub fn set_context(&self, key: String, value: serde_json::Value) -> napi::Result<()> {
        self.inner
            .lock()
            .map_err(|_| napi::Error::from_reason("PolicyEngine lock poisoned"))?
            .set_context(key, json_to_value(value));
        Ok(())
    }

    /// Set a policy configuration value accessible as `config.<key>`.
    ///
    /// @param key   - Config key.
    /// @param value - Any JSON-serialisable value.
    #[napi]
    pub fn set_config(&self, key: String, value: serde_json::Value) -> napi::Result<()> {
        self.inner
            .lock()
            .map_err(|_| napi::Error::from_reason("PolicyEngine lock poisoned"))?
            .set_config(key, json_to_value(value));
        Ok(())
    }

    /// The name declared in the loaded policy (from the `policy <Name> { }` header).
    #[napi(getter)]
    pub fn policy_name(&self) -> String {
        self.name.clone()
    }

    /// Total events evaluated since this engine was created or last `reset()`.
    #[napi(getter)]
    pub fn event_count(&self) -> napi::Result<i64> {
        let count = self
            .inner
            .lock()
            .map_err(|_| napi::Error::from_reason("PolicyEngine lock poisoned"))?
            .event_count();
        Ok(count as i64)
    }

    /// Reset all state machines and rate-limit counters to their initial states.
    ///
    /// Use this at the start of a new agent session to isolate per-session
    /// temporal invariants and rate limits.
    #[napi]
    pub fn reset(&self) -> napi::Result<()> {
        self.inner
            .lock()
            .map_err(|_| napi::Error::from_reason("PolicyEngine lock poisoned"))?
            .reset();
        Ok(())
    }

    /// Return a snapshot of the engine's current operational state.
    #[napi]
    pub fn status(&self) -> napi::Result<EngineStatus> {
        let s = self
            .inner
            .lock()
            .map_err(|_| napi::Error::from_reason("PolicyEngine lock poisoned"))?
            .status();
        Ok(EngineStatus {
            policy_name: s.policy_name.to_string(),
            severity: format!("{:?}", s.severity),
            total_rules: s.total_rules as i64,
            total_state_machines: s.total_state_machines as i64,
            active_state_machines: s.active_state_machines as i64,
            violated_state_machines: s.violated_state_machines as i64,
            satisfied_state_machines: s.satisfied_state_machines as i64,
            total_constraints: s.total_constraints as i64,
            events_processed: s.events_processed as i64,
        })
    }
}

// ── Conversion helpers ────────────────────────────────────────────────────────

fn convert_result(r: aegis_runtime::engine::PolicyResult) -> PolicyResult {
    let verdict = match r.verdict {
        Verdict::Allow => "allow",
        Verdict::Deny => "deny",
        Verdict::Audit => "audit",
        Verdict::Redact => "redact",
    };

    let violations = r
        .violations
        .into_iter()
        .map(|v| Violation {
            proof: v.proof_name.to_string(),
            invariant: v.invariant_name.to_string(),
            kind: format!("{:?}", v.kind),
            message: v.message,
        })
        .collect();

    let constraint_violations = r
        .constraint_violations
        .into_iter()
        .map(|cv| ConstraintViolation {
            kind: format!("{:?}", cv.kind),
            target: cv.target.to_string(),
            limit: cv.limit as i64,
            current: cv.current as i64,
            window_ms: cv.window_ms as i64,
        })
        .collect();

    let actions = r
        .actions
        .into_iter()
        .map(|a| {
            let args_obj: serde_json::Map<String, serde_json::Value> = a
                .args
                .into_iter()
                .map(|(k, v)| (k.to_string(), value_to_json(v)))
                .collect();
            RuleAction {
                verb: a.verb.to_string(),
                args_json: serde_json::to_string(&args_obj)
                    .unwrap_or_else(|_| "{}".to_string()),
            }
        })
        .collect();

    PolicyResult {
        verdict: verdict.to_string(),
        reason: r.reason,
        triggered_rules: r.triggered_rules,
        violations,
        constraint_violations,
        actions,
        latency_us: r.eval_time_us as i64,
    }
}
