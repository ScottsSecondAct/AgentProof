//! JSON-RPC 2.0 message types for the MCP protocol.
//!
//! MCP (Model Context Protocol) uses newline-delimited JSON-RPC 2.0 over stdio.
//! Each message is a single JSON object terminated by `\n`.
//!
//! Reference: <https://spec.modelcontextprotocol.io/specification/basic/transports/>

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JSON-RPC 2.0 error code for AutomaGuard policy violations.
///
/// Uses an application-defined code in the range reserved for
/// implementation-specific errors (-32099 to -32000).
pub const POLICY_VIOLATION_CODE: i32 = -32001;

/// A JSON-RPC 2.0 message.
///
/// Covers requests, responses, error responses, and notifications in a
/// single struct.  Fields absent in a given message variant are omitted
/// when serialized (`skip_serializing_if = "Option::is_none"`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Always `"2.0"`.
    pub jsonrpc: String,

    /// Present on requests and responses; absent on notifications.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,

    /// Present on requests and notifications; absent on responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// Present on requests and notifications that carry data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,

    /// Present on successful responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,

    /// Present on error responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorObject>,
}

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorObject {
    /// Numeric error code.
    pub code: i32,
    /// Human-readable error message.
    pub message: String,
    /// Optional additional data (structured or primitive).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl Message {
    /// Returns `true` if this is a request (has both `method` and `id`).
    pub fn is_request(&self) -> bool {
        self.method.is_some() && self.id.is_some()
    }

    /// Returns `true` if this is a notification (has `method` but no `id`).
    ///
    /// Not currently used by the proxy intercept path, but available for
    /// future extensions (e.g., filtering upstream notifications).
    #[allow(dead_code)]
    pub fn is_notification(&self) -> bool {
        self.method.is_some() && self.id.is_none()
    }

    /// Construct a JSON-RPC error response.
    pub fn error_response(
        id: Option<Value>,
        code: i32,
        message: impl Into<String>,
        data: Option<Value>,
    ) -> Self {
        Message {
            jsonrpc: "2.0".into(),
            id,
            method: None,
            params: None,
            result: None,
            error: Some(ErrorObject {
                code,
                message: message.into(),
                data,
            }),
        }
    }
}
