//! Error types for the AutomaGuard Rust SDK.

use aegis_compiler::bytecode::BytecodeError;

use crate::PolicyResult;

/// All errors that can be returned by the AutomaGuard SDK.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The `.aegisc` policy file could not be loaded or parsed.
    #[error("failed to load policy: {0}")]
    Load(#[from] BytecodeError),

    /// An `EnforcementError` was promoted into this error.
    ///
    /// Boxed to keep the `Error` enum size manageable.
    #[error(transparent)]
    Enforcement(Box<EnforcementError>),

    /// The async task was cancelled or panicked.
    #[cfg(feature = "async")]
    #[error("async task failed: {0}")]
    Runtime(String),
}

/// Returned when a policy evaluation produces a `deny` verdict.
///
/// Wraps the full [`PolicyResult`] so callers can inspect the triggering rule,
/// violations, and reason before deciding how to handle the denial.
///
/// # Example
///
/// ```ignore
/// match engine.evaluate("tool_call", fields) {
///     Ok(result) if result.is_denied() => {
///         return Err(EnforcementError::new(result).into());
///     }
///     Ok(result) => { /* proceed */ }
///     Err(e) => return Err(e),
/// }
/// ```
#[derive(Debug)]
pub struct EnforcementError {
    /// The full result from the policy evaluation that produced the denial.
    pub result: PolicyResult,
}

impl EnforcementError {
    /// Wrap a [`PolicyResult`] in an enforcement error.
    ///
    /// Typically called after checking [`PolicyResult::is_denied`].
    pub fn new(result: PolicyResult) -> Self {
        Self { result }
    }
}

impl std::fmt::Display for EnforcementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "policy denied: {}",
            self.result.reason().unwrap_or("no reason given")
        )
    }
}

impl std::error::Error for EnforcementError {}

impl From<EnforcementError> for Error {
    fn from(e: EnforcementError) -> Self {
        Error::Enforcement(Box::new(e))
    }
}
