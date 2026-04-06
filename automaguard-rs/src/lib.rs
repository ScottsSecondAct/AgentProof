//! AutomaGuard Rust SDK.
//!
//! Compiled temporal policy enforcement for production AI agents.
//!
//! # Quick start
//!
//! ```ignore
//! use automaguard::{PolicyEngine, EnforcementError};
//!
//! // Load once at agent startup.
//! let mut engine = PolicyEngine::from_file("guard.aegisc")?;
//!
//! // Evaluate each agent action.
//! let result = engine
//!     .event("tool_call")
//!     .field("tool_name", "send_email")
//!     .field("to", "user@external.com")
//!     .evaluate()?;
//!
//! if result.is_denied() {
//!     return Err(EnforcementError::new(result).into());
//! }
//! ```
//!
//! # Async
//!
//! Enable the `async` feature and use [`AsyncPolicyEngine`]:
//!
//! ```ignore
//! use automaguard::AsyncPolicyEngine;
//!
//! let engine = AsyncPolicyEngine::from_file("guard.aegisc")?;
//! let result = engine.evaluate("tool_call", fields).await?;
//! ```
//!
//! # Re-exports
//!
//! The runtime value type ([`Value`]) and verdict type ([`Verdict`]) are
//! re-exported from the underlying crates so callers don't need to add
//! `aegis-runtime` or `aegis-compiler` as direct dependencies.

pub mod engine;
pub mod error;

#[cfg(feature = "async")]
pub mod async_engine;

// ── Public re-exports ─────────────────────────────────────────────────────────

pub use engine::{EventBuilder, PolicyEngine, PolicyResult};
pub use error::{EnforcementError, Error};

/// Re-export the runtime value type.
pub use aegis_runtime::event::Value;

/// Re-export the runtime violation type.
pub use aegis_runtime::engine::{ConstraintViolation, Violation};

/// Re-export the verdict enum so callers can match on it.
pub use aegis_compiler::ast::Verdict;

#[cfg(feature = "async")]
pub use async_engine::{AsyncEventBuilder, AsyncPolicyEngine};
