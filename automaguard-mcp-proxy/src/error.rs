//! Error types for the AutomaGuard MCP proxy.

use aegis_compiler::bytecode::BytecodeError;

/// All errors that can occur while running the proxy.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The policy file could not be opened or read.
    #[error("cannot read policy file: {0}")]
    PolicyRead(#[source] std::io::Error),

    /// The policy file is not valid `.aegisc` bytecode.
    #[error("invalid policy file: {0}")]
    PolicyLoad(#[source] BytecodeError),

    /// The upstream MCP server process could not be spawned.
    #[error("failed to spawn upstream server: {0}")]
    Spawn(#[source] std::io::Error),

    /// A write to the upstream server's stdin failed.
    #[error("write to upstream failed: {0}")]
    UpstreamWrite(#[source] std::io::Error),

    /// Serializing a JSON-RPC response failed.
    #[error("JSON serialization failed: {0}")]
    Serialize(#[source] serde_json::Error),

    /// The output channel closed unexpectedly before the proxy finished.
    #[error("output channel closed unexpectedly")]
    OutputClosed,
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, Error>;
