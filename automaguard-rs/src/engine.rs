//! Synchronous policy engine — the primary entry point for the Rust SDK.

use std::collections::HashMap;
use std::path::Path;

use smol_str::SmolStr;

use aegis_compiler::ast::Verdict;
use aegis_compiler::bytecode;
use aegis_runtime::engine::{PolicyEngine as RuntimeEngine, PolicyResult as RuntimeResult};
use aegis_runtime::event::{Event, Value};

use crate::error::Error;

// ── PolicyResult ──────────────────────────────────────────────────────────────

/// The result of evaluating a single event against a loaded policy.
///
/// Wraps [`aegis_runtime::engine::PolicyResult`] with convenience methods.
/// Obtain one by calling [`PolicyEngine::evaluate`].
#[derive(Debug, Clone)]
pub struct PolicyResult(pub(crate) RuntimeResult);

impl PolicyResult {
    /// Returns `true` if the verdict is `Deny`.
    pub fn is_denied(&self) -> bool {
        self.0.verdict == Verdict::Deny
    }

    /// Returns `true` if the verdict is `Allow`.
    pub fn is_allowed(&self) -> bool {
        self.0.verdict == Verdict::Allow
    }

    /// Returns `true` if the verdict is `Audit` (log and allow).
    pub fn is_audit(&self) -> bool {
        self.0.verdict == Verdict::Audit
    }

    /// Returns `true` if the verdict is `Redact` (sanitise and allow).
    pub fn is_redact(&self) -> bool {
        self.0.verdict == Verdict::Redact
    }

    /// The human-readable reason accompanying the verdict, if any.
    pub fn reason(&self) -> Option<&str> {
        self.0.reason.as_deref()
    }

    /// The IDs of rules that fired for this event.
    pub fn triggered_rules(&self) -> &[u32] {
        &self.0.triggered_rules
    }

    /// Temporal invariant violations detected during this evaluation.
    pub fn violations(&self) -> &[aegis_runtime::engine::Violation] {
        &self.0.violations
    }

    /// Rate-limit or quota constraint violations detected during this evaluation.
    pub fn constraint_violations(&self) -> &[aegis_runtime::engine::ConstraintViolation] {
        &self.0.constraint_violations
    }

    /// How long the evaluation took, in microseconds.
    pub fn latency_us(&self) -> u64 {
        self.0.eval_time_us
    }

    /// The raw [`Verdict`] value.
    pub fn verdict(&self) -> Verdict {
        self.0.verdict
    }

    /// Borrow the underlying runtime result.
    pub fn inner(&self) -> &RuntimeResult {
        &self.0
    }
}

impl std::fmt::Display for PolicyResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0.verdict)?;
        if let Some(reason) = self.reason() {
            write!(f, ": {reason}")?;
        }
        Ok(())
    }
}

// ── PolicyEngine ──────────────────────────────────────────────────────────────

/// Synchronous AutomaGuard policy engine.
///
/// Loads a compiled `.aegisc` policy once at construction and evaluates agent
/// events against it at sub-microsecond latency.
///
/// # Example
///
/// ```ignore
/// use automaguard::{PolicyEngine, EnforcementError};
/// use std::collections::HashMap;
///
/// let mut engine = PolicyEngine::from_file("guard.aegisc")?;
///
/// let mut fields = HashMap::new();
/// fields.insert("tool_name".into(), "send_email".into());
///
/// let result = engine.evaluate("tool_call", fields)?;
/// if result.is_denied() {
///     return Err(EnforcementError::new(result).into());
/// }
/// ```
pub struct PolicyEngine {
    inner: RuntimeEngine,
}

impl std::fmt::Debug for PolicyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyEngine")
            .field("policy", &self.inner.policy_name())
            .field("events_processed", &self.inner.event_count())
            .finish()
    }
}

impl PolicyEngine {
    /// Load a compiled policy from a `.aegisc` file on disk.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, Error> {
        let policy = bytecode::read_file(path.as_ref())?;
        Ok(Self {
            inner: RuntimeEngine::new(policy),
        })
    }

    /// Load a compiled policy from an in-memory `.aegisc` byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let policy = bytecode::from_bytecode(bytes)?;
        Ok(Self {
            inner: RuntimeEngine::new(policy),
        })
    }

    /// Evaluate a single agent event against the loaded policy.
    ///
    /// - `event_type` — the event category (e.g. `"tool_call"`, `"data_access"`).
    /// - `fields`     — key-value map of event fields. Keys accept anything that
    ///   converts to [`SmolStr`]; values are [`Value`] instances.
    ///
    /// Returns a [`PolicyResult`] containing the verdict, triggered rules, and
    /// any invariant or rate-limit violations. The `?` operator is for
    /// infrastructure errors only (e.g. future async transport failures); in v1
    /// the synchronous path never returns `Err`.
    pub fn evaluate(
        &mut self,
        event_type: &str,
        fields: HashMap<SmolStr, Value>,
    ) -> Result<PolicyResult, Error> {
        let event = Event::new(event_type).with_fields(fields);
        Ok(PolicyResult(self.inner.evaluate(&event)))
    }

    /// Convenience builder for evaluating events with a fluent field API.
    ///
    /// ```ignore
    /// let result = engine.event("tool_call")
    ///     .field("tool_name", "search")
    ///     .field("query", "customer records")
    ///     .evaluate()?;
    /// ```
    pub fn event<'e>(&'e mut self, event_type: &str) -> EventBuilder<'e> {
        EventBuilder {
            engine: self,
            event_type: event_type.to_owned(),
            fields: HashMap::new(),
        }
    }

    /// Set a persistent context value that survives across evaluations.
    ///
    /// Context values are accessible from policy expressions via the `context`
    /// root (e.g. `context.user_role`).
    pub fn set_context(&mut self, key: impl Into<SmolStr>, value: Value) {
        self.inner.set_context(key, value);
    }

    /// The name of the loaded policy.
    pub fn policy_name(&self) -> &str {
        self.inner.policy_name()
    }

    /// Total number of events evaluated by this engine instance.
    pub fn event_count(&self) -> u64 {
        self.inner.event_count()
    }

    /// Reset all state machines and rate limiters to their initial state.
    ///
    /// Useful in tests or when starting a new agent session on a reused engine.
    pub fn reset(&mut self) {
        self.inner.reset();
    }
}

// ── EventBuilder ──────────────────────────────────────────────────────────────

/// Fluent builder for constructing and evaluating an event in one expression.
///
/// Obtain via [`PolicyEngine::event`].
pub struct EventBuilder<'e> {
    engine: &'e mut PolicyEngine,
    event_type: String,
    fields: HashMap<SmolStr, Value>,
}

impl<'e> EventBuilder<'e> {
    /// Add a field to the event.
    ///
    /// `key` accepts anything that converts to [`SmolStr`] (e.g. `&str`).
    /// `value` accepts anything that converts to [`Value`].
    pub fn field(mut self, key: impl Into<SmolStr>, value: impl Into<Value>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }

    /// Evaluate the event and return the policy result.
    pub fn evaluate(self) -> Result<PolicyResult, Error> {
        self.engine.evaluate(&self.event_type, self.fields)
    }
}

// Value From impls live in aegis-runtime/src/event.rs (where Value is defined).
