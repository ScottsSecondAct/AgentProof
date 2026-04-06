//! Async wrapper for the AutomaGuard policy engine.
//!
//! [`AsyncPolicyEngine`] wraps [`super::PolicyEngine`] in an
//! `Arc<Mutex<>>` so it can be shared across tasks and held across
//! `.await` points. The actual `evaluate()` call is dispatched to a
//! dedicated blocking thread via [`tokio::task::spawn_blocking`] so it
//! never blocks the async runtime's thread pool.
//!
//! Enable with the `async` Cargo feature:
//!
//! ```toml
//! automaguard = { version = "0.1", features = ["async"] }
//! ```

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use smol_str::SmolStr;

use aegis_runtime::event::Value;

use crate::engine::{PolicyEngine, PolicyResult};
use crate::error::Error;

/// Async AutomaGuard policy engine.
///
/// Wraps [`PolicyEngine`] for use in `async`/`await` contexts.
/// The engine is protected by an `Arc<Mutex<>>` so it can be cloned
/// and shared freely across tasks.
///
/// # Example
///
/// ```ignore
/// use automaguard::{AsyncPolicyEngine, EnforcementError};
///
/// let engine = AsyncPolicyEngine::from_file("guard.aegisc")?;
///
/// // Clone and move into tasks freely.
/// let engine2 = engine.clone();
/// tokio::spawn(async move {
///     let result = engine2.evaluate("tool_call", fields).await.unwrap();
///     assert!(result.is_allowed());
/// });
/// ```
#[derive(Clone)]
pub struct AsyncPolicyEngine {
    inner: Arc<Mutex<PolicyEngine>>,
}

impl AsyncPolicyEngine {
    /// Load a compiled policy from a `.aegisc` file on disk.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, Error> {
        let engine = PolicyEngine::from_file(path)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(engine)),
        })
    }

    /// Load a compiled policy from an in-memory `.aegisc` byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let engine = PolicyEngine::from_bytes(bytes)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(engine)),
        })
    }

    /// Evaluate a single agent event against the loaded policy.
    ///
    /// Dispatches to a blocking thread so the async executor thread pool
    /// is never blocked by evaluation work.
    pub async fn evaluate(
        &self,
        event_type: &str,
        fields: HashMap<SmolStr, Value>,
    ) -> Result<PolicyResult, Error> {
        let inner = Arc::clone(&self.inner);
        let event_type = event_type.to_owned();

        tokio::task::spawn_blocking(move || {
            inner
                .lock()
                .expect("policy engine mutex was poisoned")
                .evaluate(&event_type, fields)
        })
        .await
        .map_err(|e| Error::Runtime(e.to_string()))?
    }

    /// Convenience async builder for evaluating events with a fluent field API.
    ///
    /// ```ignore
    /// let result = engine.event("tool_call")
    ///     .field("tool_name", "search")
    ///     .evaluate()
    ///     .await?;
    /// ```
    pub fn event(&self, event_type: &str) -> AsyncEventBuilder<'_> {
        AsyncEventBuilder {
            engine: self,
            event_type: event_type.to_owned(),
            fields: HashMap::new(),
        }
    }

    /// The name of the loaded policy.
    pub fn policy_name(&self) -> String {
        self.inner
            .lock()
            .expect("policy engine mutex was poisoned")
            .policy_name()
            .to_owned()
    }

    /// Total number of events evaluated across all tasks sharing this engine.
    pub fn event_count(&self) -> u64 {
        self.inner
            .lock()
            .expect("policy engine mutex was poisoned")
            .event_count()
    }
}

// ── AsyncEventBuilder ─────────────────────────────────────────────────────────

/// Fluent async builder for constructing and evaluating an event.
///
/// Obtain via [`AsyncPolicyEngine::event`].
pub struct AsyncEventBuilder<'e> {
    engine: &'e AsyncPolicyEngine,
    event_type: String,
    fields: HashMap<SmolStr, Value>,
}

impl<'e> AsyncEventBuilder<'e> {
    /// Add a field to the event.
    pub fn field(mut self, key: impl Into<SmolStr>, value: impl Into<Value>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }

    /// Evaluate the event and return the policy result.
    pub async fn evaluate(self) -> Result<PolicyResult, Error> {
        self.engine.evaluate(&self.event_type, self.fields).await
    }
}
