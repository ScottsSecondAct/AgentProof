pub mod audit;
pub mod engine;
pub mod eval;
pub mod event;

// Re-export the main types for convenience
pub use audit::AuditLog;
pub use engine::{PolicyEngine, PolicyResult};
pub use event::{Event, Value};
