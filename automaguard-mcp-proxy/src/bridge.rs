//! Converts MCP `tools/call` parameters into Aegis [`Event`]s.
//!
//! The bridge is the semantic boundary between the MCP protocol and the
//! AutomaGuard policy engine.  It maps MCP tool names and JSON arguments
//! to the `tool_call` event type that Aegis policies operate on.

use std::collections::HashMap;

use aegis_runtime::event::{Event, Value as AegisValue};
use serde_json::Value as JsonValue;
use smol_str::SmolStr;

/// Build an Aegis `tool_call` event from a `tools/call` message.
///
/// The produced event has:
/// - `event_type = "tool_call"`
/// - `tool_name` / `tool` → the MCP tool name (both aliases for policy convenience)
/// - Each argument key from `arguments` → its own top-level field
/// - `arguments` → the full argument object as a nested map
///
/// Policies can therefore match on `event.tool_name`, `event.tool`,
/// `event.arguments`, or individual argument fields directly
/// (e.g., `event.url`, `event.path`).
pub fn mcp_tool_call_to_event(tool_name: &str, arguments: &JsonValue) -> Event {
    let mut fields: HashMap<SmolStr, AegisValue> = HashMap::new();

    // Primary key used by most Aegis policy rules.
    fields.insert(SmolStr::new("tool_name"), AegisValue::String(SmolStr::new(tool_name)));
    // Short alias — matches the README quick-start example (`event.tool`).
    fields.insert(SmolStr::new("tool"), AegisValue::String(SmolStr::new(tool_name)));

    // Flatten individual arguments as top-level fields for ergonomic matching.
    if let JsonValue::Object(args) = arguments {
        for (key, val) in args {
            fields.insert(SmolStr::new(key), json_to_aegis(val));
        }
    }

    // Also store the full argument map under `arguments` for structured access.
    fields.insert(SmolStr::new("arguments"), json_to_aegis(arguments));

    Event::new("tool_call").with_fields(fields)
}

/// Recursively convert a `serde_json::Value` into an Aegis [`AegisValue`].
fn json_to_aegis(val: &JsonValue) -> AegisValue {
    match val {
        JsonValue::Null => AegisValue::Null,
        JsonValue::Bool(b) => AegisValue::Bool(*b),
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                AegisValue::Int(i)
            } else {
                AegisValue::Float(n.as_f64().unwrap_or(0.0))
            }
        }
        JsonValue::String(s) => AegisValue::String(SmolStr::new(s)),
        JsonValue::Array(arr) => AegisValue::List(arr.iter().map(json_to_aegis).collect()),
        JsonValue::Object(map) => AegisValue::Map(
            map.iter()
                .map(|(k, v)| (SmolStr::new(k), json_to_aegis(v)))
                .collect(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tool_name_is_set_as_both_aliases() {
        let event = mcp_tool_call_to_event("read_file", &json!({}));
        assert_eq!(
            event.fields.get("tool_name"),
            Some(&AegisValue::String(SmolStr::new("read_file")))
        );
        assert_eq!(
            event.fields.get("tool"),
            Some(&AegisValue::String(SmolStr::new("read_file")))
        );
    }

    #[test]
    fn event_type_is_tool_call() {
        let event = mcp_tool_call_to_event("read_file", &json!({}));
        assert_eq!(event.event_type.as_str(), "tool_call");
    }

    #[test]
    fn string_argument_becomes_top_level_field() {
        let event = mcp_tool_call_to_event("http_request", &json!({"url": "https://example.com"}));
        assert_eq!(
            event.fields.get("url"),
            Some(&AegisValue::String(SmolStr::new("https://example.com")))
        );
    }

    #[test]
    fn arguments_map_is_also_stored_nested() {
        let args = json!({"path": "/tmp/file.txt"});
        let event = mcp_tool_call_to_event("read_file", &args);
        assert!(matches!(event.fields.get("arguments"), Some(AegisValue::Map(_))));
    }

    #[test]
    fn bool_argument_converted() {
        let event = mcp_tool_call_to_event("tool", &json!({"flag": true}));
        assert_eq!(event.fields.get("flag"), Some(&AegisValue::Bool(true)));
    }

    #[test]
    fn integer_argument_converted() {
        let event = mcp_tool_call_to_event("tool", &json!({"count": 42}));
        assert_eq!(event.fields.get("count"), Some(&AegisValue::Int(42)));
    }

    #[test]
    fn null_arguments_object_produces_null_field() {
        let event = mcp_tool_call_to_event("tool", &JsonValue::Null);
        assert_eq!(event.fields.get("arguments"), Some(&AegisValue::Null));
    }
}
