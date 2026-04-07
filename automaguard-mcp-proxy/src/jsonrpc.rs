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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request(id: i64, method: &str) -> Message {
        Message {
            jsonrpc: "2.0".into(),
            id: Some(json!(id)),
            method: Some(method.into()),
            params: None,
            result: None,
            error: None,
        }
    }

    fn notification(method: &str) -> Message {
        Message {
            jsonrpc: "2.0".into(),
            id: None,
            method: Some(method.into()),
            params: None,
            result: None,
            error: None,
        }
    }

    fn response(id: i64) -> Message {
        Message {
            jsonrpc: "2.0".into(),
            id: Some(json!(id)),
            method: None,
            params: None,
            result: Some(json!({"ok": true})),
            error: None,
        }
    }

    // ── is_request ───────────────────────────────────────────────────────

    #[test]
    fn is_request_true_when_method_and_id_present() {
        assert!(request(1, "tools/call").is_request());
    }

    #[test]
    fn is_request_false_for_notification() {
        assert!(!notification("tools/call").is_request());
    }

    #[test]
    fn is_request_false_for_response() {
        assert!(!response(1).is_request());
    }

    // ── is_notification ──────────────────────────────────────────────────

    #[test]
    fn is_notification_true_when_method_present_and_no_id() {
        assert!(notification("initialized").is_notification());
    }

    #[test]
    fn is_notification_false_for_request() {
        assert!(!request(1, "tools/call").is_notification());
    }

    #[test]
    fn is_notification_false_for_response() {
        assert!(!response(1).is_notification());
    }

    // ── error_response ───────────────────────────────────────────────────

    #[test]
    fn error_response_sets_jsonrpc_version() {
        let msg = Message::error_response(Some(json!(1)), POLICY_VIOLATION_CODE, "blocked", None);
        assert_eq!(msg.jsonrpc, "2.0");
    }

    #[test]
    fn error_response_sets_id() {
        let msg = Message::error_response(Some(json!(42)), POLICY_VIOLATION_CODE, "blocked", None);
        assert_eq!(msg.id, Some(json!(42)));
    }

    #[test]
    fn error_response_null_id_is_preserved() {
        let msg = Message::error_response(None, POLICY_VIOLATION_CODE, "blocked", None);
        assert!(msg.id.is_none());
    }

    #[test]
    fn error_response_sets_code() {
        let msg = Message::error_response(Some(json!(1)), POLICY_VIOLATION_CODE, "blocked", None);
        assert_eq!(msg.error.as_ref().unwrap().code, POLICY_VIOLATION_CODE);
    }

    #[test]
    fn error_response_sets_message() {
        let msg = Message::error_response(Some(json!(1)), POLICY_VIOLATION_CODE, "test msg", None);
        assert_eq!(msg.error.as_ref().unwrap().message, "test msg");
    }

    #[test]
    fn error_response_has_no_method_or_result() {
        let msg = Message::error_response(Some(json!(1)), POLICY_VIOLATION_CODE, "x", None);
        assert!(msg.method.is_none());
        assert!(msg.result.is_none());
    }

    #[test]
    fn error_response_with_data_field() {
        let data = json!({"tool": "http_get"});
        let msg = Message::error_response(
            Some(json!(1)),
            POLICY_VIOLATION_CODE,
            "blocked",
            Some(data.clone()),
        );
        assert_eq!(msg.error.as_ref().unwrap().data, Some(data));
    }

    #[test]
    fn policy_violation_code_is_minus_32001() {
        assert_eq!(POLICY_VIOLATION_CODE, -32001);
    }

    // ── Round-trip serialization ──────────────────────────────────────────

    #[test]
    fn request_serializes_without_null_fields() {
        let msg = request(1, "tools/call");
        let json = serde_json::to_string(&msg).unwrap();
        // Fields absent in a request should not appear as null.
        assert!(!json.contains("\"result\""));
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn request_round_trips_through_json() {
        let json_str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"http_get","arguments":{}}}"#;
        let msg: Message = serde_json::from_str(json_str).unwrap();
        assert!(msg.is_request());
        assert_eq!(msg.method.as_deref(), Some("tools/call"));
        assert_eq!(msg.id, Some(json!(1)));
        let params = msg.params.as_ref().unwrap();
        assert_eq!(params["name"], json!("http_get"));
    }

    #[test]
    fn error_response_round_trips_through_json() {
        let msg = Message::error_response(
            Some(json!(5)),
            POLICY_VIOLATION_CODE,
            "AutomaGuard: blocked",
            None,
        );
        let json_str = serde_json::to_string(&msg).unwrap();
        let restored: Message = serde_json::from_str(&json_str).unwrap();
        let err = restored.error.as_ref().unwrap();
        assert_eq!(err.code, POLICY_VIOLATION_CODE);
        assert_eq!(err.message, "AutomaGuard: blocked");
        assert_eq!(restored.id, Some(json!(5)));
    }

    #[test]
    fn notification_round_trips_through_json() {
        let json_str = r#"{"jsonrpc":"2.0","method":"initialized"}"#;
        let msg: Message = serde_json::from_str(json_str).unwrap();
        assert!(msg.is_notification());
        assert!(!msg.is_request());
        assert_eq!(msg.method.as_deref(), Some("initialized"));
    }
}
