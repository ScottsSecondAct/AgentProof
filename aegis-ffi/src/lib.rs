//! C ABI layer for AutomaGuard.
//!
//! This crate exposes the [`aegis_runtime`] policy engine through a stable
//! C interface so that non-Rust language SDKs (TypeScript via napi-rs,
//! C# via P/Invoke, Java via JNI, Go via cgo) can share a single
//! compiled engine without duplicating evaluation logic.
//!
//! # Memory contract
//!
//! - `AegisEngine*` is heap-allocated by the library and must be freed by
//!   calling [`aegis_engine_free`]. Do not free it any other way.
//! - Result strings returned by [`aegis_engine_evaluate`] are heap-allocated
//!   C strings; free them with [`aegis_result_free`]. Do not call `free()`
//!   on them directly.
//! - The error string returned by [`aegis_last_error`] is owned by the
//!   thread-local storage and remains valid until the next FFI call on the
//!   same thread. Do not free it.
//!
//! # Thread safety
//!
//! Each `AegisEngine` is **not** safe to share across threads without external
//! synchronisation. Create one engine per thread, or protect a shared engine
//! with a mutex in the calling language.
//!
//! # Result JSON schema
//!
//! [`aegis_engine_evaluate`] returns a UTF-8 JSON object:
//!
//! ```json
//! {
//!   "verdict":       "allow" | "deny" | "audit" | "redact",
//!   "reason":        "string or null",
//!   "triggered_rules": [/* u32 rule IDs */],
//!   "violations": [
//!     { "proof": "...", "invariant": "...", "message": "..." }
//!   ],
//!   "constraint_violations": [
//!     { "kind": "RateLimit", "target": "...", "limit": 100,
//!       "current": 101, "window_ms": 60000 }
//!   ],
//!   "latency_us": 2
//! }
//! ```

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uchar};
use std::path::Path;

use smol_str::SmolStr;

use aegis_compiler::ast::Verdict;
use aegis_compiler::bytecode;
use aegis_runtime::engine::PolicyEngine;
use aegis_runtime::event::{Event, Value};

// ── Thread-local error storage ────────────────────────────────────────────────

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn set_last_error(msg: impl std::fmt::Display) {
    let s = CString::new(msg.to_string()).unwrap_or_else(|_| {
        // Fallback if the message itself contains a null byte (shouldn't happen).
        CString::new("(error message contained a null byte)").unwrap()
    });
    LAST_ERROR.with(|cell| *cell.borrow_mut() = Some(s));
}

fn clear_last_error() {
    LAST_ERROR.with(|cell| *cell.borrow_mut() = None);
}

// ── Opaque engine handle ──────────────────────────────────────────────────────

/// Opaque handle to a loaded AutomaGuard policy engine.
///
/// Allocate with [`aegis_engine_from_file`] or [`aegis_engine_from_bytes`].
/// Free with [`aegis_engine_free`]. Must not be shared across threads without
/// external synchronisation.
pub struct AegisEngine {
    inner: PolicyEngine,
}

// ── Engine construction ───────────────────────────────────────────────────────

/// Load a compiled policy from a `.aegisc` file.
///
/// Returns a non-null `AegisEngine*` on success, or `NULL` on error.
/// On error call [`aegis_last_error`] for a description.
///
/// The caller is responsible for freeing the returned pointer with
/// [`aegis_engine_free`].
///
/// # Safety
///
/// `path` must be a valid, non-null, null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn aegis_engine_from_file(path: *const c_char) -> *mut AegisEngine {
    if path.is_null() {
        set_last_error("path must not be null");
        return std::ptr::null_mut();
    }

    let path_str = match CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(format!("invalid UTF-8 in path: {e}"));
            return std::ptr::null_mut();
        }
    };

    let policy = match bytecode::read_file(Path::new(path_str)) {
        Ok(p) => p,
        Err(e) => {
            set_last_error(format!("failed to load {path_str}: {e}"));
            return std::ptr::null_mut();
        }
    };

    clear_last_error();
    Box::into_raw(Box::new(AegisEngine {
        inner: PolicyEngine::new(policy),
    }))
}

/// Load a compiled policy from an in-memory `.aegisc` buffer.
///
/// Returns a non-null `AegisEngine*` on success, or `NULL` on error.
/// On error call [`aegis_last_error`] for a description.
///
/// The caller is responsible for freeing the returned pointer with
/// [`aegis_engine_free`].
///
/// # Safety
///
/// `data` must be a valid non-null pointer to at least `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn aegis_engine_from_bytes(
    data: *const c_uchar,
    len: usize,
) -> *mut AegisEngine {
    if data.is_null() {
        set_last_error("data must not be null");
        return std::ptr::null_mut();
    }

    let bytes = std::slice::from_raw_parts(data, len);

    let policy = match bytecode::from_bytecode(bytes) {
        Ok(p) => p,
        Err(e) => {
            set_last_error(format!("failed to load policy from bytes: {e}"));
            return std::ptr::null_mut();
        }
    };

    clear_last_error();
    Box::into_raw(Box::new(AegisEngine {
        inner: PolicyEngine::new(policy),
    }))
}

// ── Event evaluation ──────────────────────────────────────────────────────────

/// Evaluate a single agent event against the loaded policy.
///
/// - `engine`     — a non-null engine handle.
/// - `event_type` — null-terminated UTF-8 event type string (e.g. `"tool_call"`).
/// - `fields_json` — null-terminated UTF-8 JSON object of field name → value
///   pairs, or `NULL` for an empty field set.
///
/// Returns a heap-allocated, null-terminated UTF-8 JSON string containing the
/// `PolicyResult` (see crate-level documentation for the schema). The caller
/// must free this string with [`aegis_result_free`].
///
/// Returns `NULL` on error; call [`aegis_last_error`] for a description.
///
/// # Safety
///
/// All pointer arguments must satisfy the constraints described above.
#[no_mangle]
pub unsafe extern "C" fn aegis_engine_evaluate(
    engine: *mut AegisEngine,
    event_type: *const c_char,
    fields_json: *const c_char,
) -> *mut c_char {
    if engine.is_null() {
        set_last_error("engine must not be null");
        return std::ptr::null_mut();
    }
    if event_type.is_null() {
        set_last_error("event_type must not be null");
        return std::ptr::null_mut();
    }

    let event_type_str = match CStr::from_ptr(event_type).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(format!("invalid UTF-8 in event_type: {e}"));
            return std::ptr::null_mut();
        }
    };

    // Parse fields JSON (NULL → empty map).
    let fields: HashMap<SmolStr, Value> = if fields_json.is_null() {
        HashMap::new()
    } else {
        let json_str = match CStr::from_ptr(fields_json).to_str() {
            Ok(s) => s,
            Err(e) => {
                set_last_error(format!("invalid UTF-8 in fields_json: {e}"));
                return std::ptr::null_mut();
            }
        };
        match parse_fields_json(json_str) {
            Ok(f) => f,
            Err(e) => {
                set_last_error(format!("invalid fields_json: {e}"));
                return std::ptr::null_mut();
            }
        }
    };

    let event = Event::new(event_type_str).with_fields(fields);
    let result = (*engine).inner.evaluate(&event);

    let json = match serialize_result(&result) {
        Ok(s) => s,
        Err(e) => {
            set_last_error(format!("failed to serialize result: {e}"));
            return std::ptr::null_mut();
        }
    };

    match CString::new(json) {
        Ok(s) => {
            clear_last_error();
            s.into_raw()
        }
        Err(e) => {
            set_last_error(format!("serialized result contains a null byte: {e}"));
            std::ptr::null_mut()
        }
    }
}

// ── Memory management ─────────────────────────────────────────────────────────

/// Free a result string returned by [`aegis_engine_evaluate`].
///
/// Passing `NULL` is a no-op.
///
/// # Safety
///
/// `result` must have been returned by [`aegis_engine_evaluate`] and must not
/// have been freed before.
#[no_mangle]
pub unsafe extern "C" fn aegis_result_free(result: *mut c_char) {
    if !result.is_null() {
        drop(CString::from_raw(result));
    }
}

/// Free an engine handle returned by [`aegis_engine_from_file`] or
/// [`aegis_engine_from_bytes`].
///
/// Passing `NULL` is a no-op.
///
/// # Safety
///
/// `engine` must have been returned by one of the construction functions and
/// must not have been freed before.
#[no_mangle]
pub unsafe extern "C" fn aegis_engine_free(engine: *mut AegisEngine) {
    if !engine.is_null() {
        drop(Box::from_raw(engine));
    }
}

// ── Error reporting ───────────────────────────────────────────────────────────

/// Return the last error message on this thread, or `NULL` if the last call
/// succeeded.
///
/// The returned pointer is valid until the next FFI call on this thread.
/// Do not free it.
#[no_mangle]
pub extern "C" fn aegis_last_error() -> *const c_char {
    LAST_ERROR.with(|cell| match cell.borrow().as_ref() {
        Some(s) => s.as_ptr(),
        None => std::ptr::null(),
    })
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Parse a JSON object string into the engine's `HashMap<SmolStr, Value>` field map.
fn parse_fields_json(json_str: &str) -> Result<HashMap<SmolStr, Value>, String> {
    let parsed: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| e.to_string())?;

    match parsed {
        serde_json::Value::Object(map) => {
            let mut fields = HashMap::with_capacity(map.len());
            for (k, v) in map {
                fields.insert(SmolStr::new(&k), json_value_to_aegis(v));
            }
            Ok(fields)
        }
        _ => Err("fields_json must be a JSON object ({...})".to_string()),
    }
}

/// Recursively convert a `serde_json::Value` to an `aegis_runtime::Value`.
fn json_value_to_aegis(v: serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i)
            } else if let Some(f) = n.as_f64() {
                Value::Float(f)
            } else {
                // Number outside i64/f64 range — treat as null rather than panic.
                Value::Null
            }
        }
        serde_json::Value::String(s) => Value::String(SmolStr::new(&s)),
        serde_json::Value::Array(a) => {
            Value::List(a.into_iter().map(json_value_to_aegis).collect())
        }
        serde_json::Value::Object(o) => {
            let mut map = HashMap::with_capacity(o.len());
            for (k, v) in o {
                map.insert(SmolStr::new(&k), json_value_to_aegis(v));
            }
            Value::Map(map)
        }
    }
}

/// Serialize a `PolicyResult` to the canonical result JSON schema.
fn serialize_result(result: &aegis_runtime::engine::PolicyResult) -> Result<String, String> {
    let verdict = match result.verdict {
        Verdict::Allow => "allow",
        Verdict::Deny => "deny",
        Verdict::Audit => "audit",
        Verdict::Redact => "redact",
    };

    let violations: Vec<serde_json::Value> = result
        .violations
        .iter()
        .map(|v| {
            serde_json::json!({
                "proof":     v.proof_name.as_str(),
                "invariant": v.invariant_name.as_str(),
                "message":   v.message,
            })
        })
        .collect();

    let constraint_violations: Vec<serde_json::Value> = result
        .constraint_violations
        .iter()
        .map(|cv| {
            serde_json::json!({
                "kind":      format!("{:?}", cv.kind),
                "target":    cv.target.as_str(),
                "limit":     cv.limit,
                "current":   cv.current,
                "window_ms": cv.window_ms,
            })
        })
        .collect();

    let json = serde_json::json!({
        "verdict":               verdict,
        "reason":                result.reason,
        "triggered_rules":       result.triggered_rules,
        "violations":            violations,
        "constraint_violations": constraint_violations,
        "latency_us":            result.eval_time_us,
    });

    serde_json::to_string(&json).map_err(|e| e.to_string())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── json_value_to_aegis ───────────────────────────────────────────────

    #[test]
    fn converts_null() {
        assert_eq!(json_value_to_aegis(serde_json::Value::Null), Value::Null);
    }

    #[test]
    fn converts_bool() {
        assert_eq!(json_value_to_aegis(serde_json::json!(true)), Value::Bool(true));
        assert_eq!(json_value_to_aegis(serde_json::json!(false)), Value::Bool(false));
    }

    #[test]
    fn converts_integer() {
        assert_eq!(json_value_to_aegis(serde_json::json!(42)), Value::Int(42));
        assert_eq!(json_value_to_aegis(serde_json::json!(-7)), Value::Int(-7));
    }

    #[test]
    fn converts_float() {
        assert_eq!(
            json_value_to_aegis(serde_json::json!(3.14)),
            Value::Float(3.14)
        );
    }

    #[test]
    fn converts_string() {
        assert_eq!(
            json_value_to_aegis(serde_json::json!("hello")),
            Value::String(SmolStr::new("hello"))
        );
    }

    #[test]
    fn converts_array() {
        let v = json_value_to_aegis(serde_json::json!([1, 2, 3]));
        assert_eq!(
            v,
            Value::List(vec![Value::Int(1), Value::Int(2), Value::Int(3)])
        );
    }

    #[test]
    fn converts_nested_object() {
        let v = json_value_to_aegis(serde_json::json!({"a": 1, "b": "x"}));
        if let Value::Map(m) = v {
            assert_eq!(m.get("a"), Some(&Value::Int(1)));
            assert_eq!(m.get("b"), Some(&Value::String(SmolStr::new("x"))));
        } else {
            panic!("expected Map");
        }
    }

    // ── parse_fields_json ─────────────────────────────────────────────────

    #[test]
    fn parses_valid_object() {
        let fields =
            parse_fields_json(r#"{"tool_name": "search", "count": 3}"#).unwrap();
        assert_eq!(fields.get("tool_name"), Some(&Value::String(SmolStr::new("search"))));
        assert_eq!(fields.get("count"), Some(&Value::Int(3)));
    }

    #[test]
    fn rejects_non_object() {
        assert!(parse_fields_json(r#"[1, 2]"#).is_err());
        assert!(parse_fields_json(r#""string""#).is_err());
    }

    #[test]
    fn rejects_invalid_json() {
        assert!(parse_fields_json("{bad json}").is_err());
    }

    #[test]
    fn empty_object_yields_empty_map() {
        assert!(parse_fields_json("{}").unwrap().is_empty());
    }

    // ── round-trip through engine (in-process) ────────────────────────────

    /// Build a minimal compiled policy that denies tool_call events where
    /// tool_name == "exec", then evaluate two events and verify verdicts.
    #[test]
    fn engine_deny_roundtrip() {
        use aegis_compiler::ast::{Literal, SeverityLevel, Verdict as V};
        use aegis_compiler::ir::{
            CompiledPolicy, CompiledRule, IRExpr, IRVerdict, PolicyMetadata,
            RefPath, RefRoot,
        };
        use aegis_compiler::ast::BinaryOp;

        let deny_exec = CompiledRule {
            id: 0,
            on_events: vec![SmolStr::new("tool_call")],
            condition: Some(IRExpr::Binary {
                op: BinaryOp::Eq,
                left: Box::new(IRExpr::Ref(RefPath {
                    root: RefRoot::Event,
                    fields: vec![SmolStr::new("tool_name")],
                })),
                right: Box::new(IRExpr::Literal(Literal::String(SmolStr::new("exec")))),
            }),
            verdicts: vec![IRVerdict { verdict: V::Deny, message: None }],
            actions: vec![],
            severity: Some(SeverityLevel::Critical),
        };

        let policy = CompiledPolicy {
            name: SmolStr::new("test"),
            severity: SeverityLevel::High,
            scopes: vec![],
            rules: vec![deny_exec],
            constraints: vec![],
            state_machines: vec![],
            metadata: PolicyMetadata {
                annotations: vec![],
                source_hash: 0,
                compiler_version: SmolStr::new("test"),
            },
        };

        let mut engine = PolicyEngine::new(policy);

        // Allowed: tool_name = "search"
        let allow_event = Event::new("tool_call")
            .with_field("tool_name", Value::String(SmolStr::new("search")));
        let r = engine.evaluate(&allow_event);
        assert_eq!(r.verdict, V::Allow);

        // Denied: tool_name = "exec"
        let deny_event = Event::new("tool_call")
            .with_field("tool_name", Value::String(SmolStr::new("exec")));
        let r = engine.evaluate(&deny_event);
        assert_eq!(r.verdict, V::Deny);
    }

    // ── serialize_result ──────────────────────────────────────────────────

    #[test]
    fn serialized_result_has_required_keys() {
        use aegis_compiler::ast::Verdict as V;
        use aegis_runtime::engine::PolicyResult;

        let result = PolicyResult {
            verdict: V::Allow,
            reason: None,
            triggered_rules: vec![0, 1],
            actions: vec![],
            violations: vec![],
            constraint_violations: vec![],
            eval_time_us: 5,
        };

        let json_str = serialize_result(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["verdict"], "allow");
        assert!(parsed["reason"].is_null());
        assert_eq!(parsed["triggered_rules"], serde_json::json!([0, 1]));
        assert_eq!(parsed["latency_us"], 5);
        assert!(parsed["violations"].is_array());
        assert!(parsed["constraint_violations"].is_array());
    }

    // ── thread-local error storage ────────────────────────────────────────

    #[test]
    fn error_round_trip() {
        clear_last_error();
        assert!(aegis_last_error().is_null());

        set_last_error("something went wrong");
        let ptr = aegis_last_error();
        assert!(!ptr.is_null());
        let msg = unsafe { CStr::from_ptr(ptr).to_str().unwrap() };
        assert_eq!(msg, "something went wrong");

        clear_last_error();
        assert!(aegis_last_error().is_null());
    }
}
