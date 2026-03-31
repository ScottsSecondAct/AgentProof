//! Agent events — the input to the runtime verifier.
//!
//! An [`Event`] represents a single intercepted agent action: a tool call,
//! a data access, an external request, etc. The Python/TypeScript SDKs
//! construct Events from framework-specific interceptors and pass them
//! to the verifier.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

/// A runtime value — the dynamic type system for event fields.
///
/// Policies operate on these values at runtime. The IR expression
/// evaluator ([`crate::eval`]) produces and consumes `Value`s.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(SmolStr),
    Duration(u64), // milliseconds
    List(Vec<Value>),
    Map(HashMap<SmolStr, Value>),
}

impl Value {
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_float(&self) -> Option<f64> {
        match self {
            Value::Float(f) => Some(*f),
            Value::Int(n) => Some(*n as f64),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Value::List(l) => Some(l),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&HashMap<SmolStr, Value>> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }

    pub fn is_truthy(&self) -> bool {
        match self {
            Value::Null => false,
            Value::Bool(b) => *b,
            Value::Int(n) => *n != 0,
            Value::Float(f) => *f != 0.0,
            Value::String(s) => !s.is_empty(),
            Value::List(l) => !l.is_empty(),
            Value::Map(m) => !m.is_empty(),
            Value::Duration(d) => *d != 0,
        }
    }

    /// Navigate a dotted path into nested maps.
    /// `resolve_path(&["endpoint", "url"])` on a nested map returns the inner value.
    pub fn resolve_path(&self, fields: &[SmolStr]) -> Option<&Value> {
        let mut current = self;
        for field in fields {
            match current {
                Value::Map(m) => {
                    current = m.get(field)?;
                }
                _ => return None,
            }
        }
        Some(current)
    }

    /// Check if this value contains another value (for the `contains` predicate).
    pub fn contains(&self, needle: &Value) -> bool {
        match (self, needle) {
            (Value::String(haystack), Value::String(needle)) => haystack.contains(needle.as_str()),
            (Value::List(items), _) => items.iter().any(|item| item == needle),
            _ => false,
        }
    }

    /// Check regex match (for the `matches` predicate).
    pub fn matches_pattern(&self, pattern: &str) -> bool {
        match self {
            Value::String(s) => {
                // Simple glob-style matching for v1.
                // Full regex support via the `regex` crate in v2.
                if pattern.starts_with('^') && pattern.ends_with('$') {
                    s.as_str() == &pattern[1..pattern.len() - 1]
                } else if let Some(prefix) = pattern.strip_suffix(".*") {
                    s.starts_with(prefix)
                } else if let Some(suffix) = pattern.strip_prefix(".*") {
                    s.ends_with(suffix)
                } else {
                    s.contains(pattern)
                }
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Null => write!(f, "null"),
            Value::Bool(b) => write!(f, "{b}"),
            Value::Int(n) => write!(f, "{n}"),
            Value::Float(n) => write!(f, "{n}"),
            Value::String(s) => write!(f, "{s}"),
            Value::Duration(ms) => {
                if *ms >= 86_400_000 {
                    write!(f, "{}d", ms / 86_400_000)
                } else if *ms >= 3_600_000 {
                    write!(f, "{}h", ms / 3_600_000)
                } else if *ms >= 60_000 {
                    write!(f, "{}m", ms / 60_000)
                } else if *ms >= 1_000 {
                    write!(f, "{}s", ms / 1_000)
                } else {
                    write!(f, "{ms}ms")
                }
            }
            Value::List(items) => {
                write!(f, "[{} items]", items.len())
            }
            Value::Map(m) => {
                write!(f, "{{{} fields}}", m.len())
            }
        }
    }
}

/// An intercepted agent event.
///
/// The SDK constructs these from framework-specific hooks:
/// - OpenAI function calling → `tool_call` event
/// - LangChain tool invocation → `tool_call` event
/// - MCP protocol message → `external_request` event
/// - Database access → `data_access` event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Event type: "tool_call", "data_access", "external_request", etc.
    pub event_type: SmolStr,

    /// Timestamp (milliseconds since epoch)
    pub timestamp_ms: u64,

    /// Event-specific fields, accessed via `event.field` in policies
    pub fields: HashMap<SmolStr, Value>,
}

impl Event {
    pub fn new(event_type: impl Into<SmolStr>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            event_type: event_type.into(),
            timestamp_ms: now,
            fields: HashMap::new(),
        }
    }

    pub fn with_field(mut self, key: impl Into<SmolStr>, value: Value) -> Self {
        self.fields.insert(key.into(), value);
        self
    }

    pub fn with_fields(mut self, fields: HashMap<SmolStr, Value>) -> Self {
        self.fields.extend(fields);
        self
    }

    /// Resolve a field path on this event.
    pub fn get_field(&self, path: &[SmolStr]) -> Option<&Value> {
        if path.is_empty() {
            return None;
        }
        let first = self.fields.get(&path[0])?;
        if path.len() == 1 {
            Some(first)
        } else {
            first.resolve_path(&path[1..])
        }
    }

    /// Convert the entire event to a Value::Map for expression evaluation.
    pub fn to_value(&self) -> Value {
        let mut map = self.fields.clone();
        map.insert(SmolStr::new("type"), Value::String(self.event_type.clone()));
        map.insert(
            SmolStr::new("timestamp"),
            Value::Duration(self.timestamp_ms),
        );
        Value::Map(map)
    }
}
