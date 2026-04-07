//! JNI bridge for the AutomaGuard Java/Kotlin SDK.
//!
//! This crate wraps [`aegis_runtime`] with JNI-exported functions that the
//! Java [`io.automaguard.JniNativeBridge`] class calls via
//! [`System.load`](https://docs.oracle.com/en/java/docs/api/java.base/java/lang/System.html#load(java.lang.String)).
//!
//! # Memory contract
//!
//! Engine handles are heap-allocated Rust values cast to `jlong`. The Java
//! [`PolicyEngine`] holds the handle and calls [`free`] in its [`close()`]
//! method. Do not call [`free`] more than once for a given handle.
//!
//! The [`Mutex`] inside [`EngineHandle`] allows the engine to be safely shared
//! across Java threads without external synchronisation.
//!
//! # Result JSON schema
//!
//! [`evaluate`] returns a UTF-8 JSON string with the shape:
//!
//! ```json
//! {
//!   "verdict":               "allow" | "deny" | "audit" | "redact",
//!   "reason":                "string or null",
//!   "triggered_rules":       [0, 2],
//!   "violations":            [{ "proof": "…", "invariant": "…", "message": "…" }],
//!   "constraint_violations": [{ "kind": "…", "target": "…", "limit": 20,
//!                               "current": 21, "window_ms": 60000 }],
//!   "latency_us":            5
//! }
//! ```

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jlong, jstring};
use jni::JNIEnv;

use smol_str::SmolStr;

use aegis_compiler::ast::Verdict;
use aegis_compiler::bytecode;
use aegis_runtime::engine::PolicyEngine;
use aegis_runtime::event::{Event, Value};

// ── Engine handle ─────────────────────────────────────────────────────────────

/// Heap-allocated wrapper around a `PolicyEngine` that the Java side holds as
/// a `long` handle.  The `Mutex` makes the handle safe to share across threads.
struct EngineHandle {
    engine: Mutex<PolicyEngine>,
    policy_name: String,
}

// ── Error helpers ─────────────────────────────────────────────────────────────

fn throw_runtime(env: &mut JNIEnv, msg: &str) {
    let _ = env.throw_new("java/lang/RuntimeException", msg);
}

fn throw_io(env: &mut JNIEnv, msg: &str) {
    let _ = env.throw_new("java/io/IOException", msg);
}

// ── Factory functions ─────────────────────────────────────────────────────────

/// Load a compiled `.aegisc` policy from a file path.
///
/// Returns a non-zero `jlong` handle on success, or `0` if an exception was
/// thrown.  The caller is responsible for calling [`free`] when done.
///
/// # JNI signature
/// `static native long nativeFromFile(String path)`
#[no_mangle]
pub extern "system" fn Java_io_automaguard_JniNativeBridge_nativeFromFile(
    mut env: JNIEnv,
    _class: JClass,
    path: JString,
) -> jlong {
    let path_str: String = match env.get_string(&path) {
        Ok(s) => s.into(),
        Err(e) => {
            throw_runtime(&mut env, &format!("invalid path string: {e}"));
            return 0;
        }
    };

    let policy = match bytecode::read_file(Path::new(&path_str)) {
        Ok(p) => p,
        Err(e) => {
            throw_io(&mut env, &format!("failed to load policy from '{path_str}': {e}"));
            return 0;
        }
    };

    let name = policy.name.to_string();
    let handle = Box::new(EngineHandle {
        engine: Mutex::new(PolicyEngine::new(policy)),
        policy_name: name,
    });
    Box::into_raw(handle) as jlong
}

/// Load a compiled `.aegisc` policy from an in-memory byte array.
///
/// # JNI signature
/// `static native long nativeFromBytes(byte[] data)`
#[no_mangle]
pub extern "system" fn Java_io_automaguard_JniNativeBridge_nativeFromBytes(
    mut env: JNIEnv,
    _class: JClass,
    data: JByteArray,
) -> jlong {
    // jni-rs represents byte[] as signed i8; reinterpret as u8.
    let bytes: Vec<u8> = match env.convert_byte_array(&data) {
        Ok(b) => b.iter().map(|&x| x as u8).collect(),
        Err(e) => {
            throw_runtime(&mut env, &format!("failed to read byte array: {e}"));
            return 0;
        }
    };

    let policy = match bytecode::from_bytecode(&bytes) {
        Ok(p) => p,
        Err(e) => {
            throw_io(&mut env, &format!("failed to load policy from bytes: {e}"));
            return 0;
        }
    };

    let name = policy.name.to_string();
    let handle = Box::new(EngineHandle {
        engine: Mutex::new(PolicyEngine::new(policy)),
        policy_name: name,
    });
    Box::into_raw(handle) as jlong
}

// ── Event evaluation ──────────────────────────────────────────────────────────

/// Evaluate a single agent event against the loaded policy.
///
/// `fields_json` is a UTF-8 JSON object (`{key: value, …}`) or `null` for
/// an empty field set.  Returns a JSON string matching the schema above, or
/// `null` if an exception was thrown.
///
/// # JNI signature
/// `static native String nativeEvaluate(long handle, String eventType, String fieldsJson)`
#[no_mangle]
pub extern "system" fn Java_io_automaguard_JniNativeBridge_nativeEvaluate(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    event_type: JString,
    fields_json: JString,
) -> jstring {
    if handle == 0 {
        throw_runtime(&mut env, "engine handle is null");
        return std::ptr::null_mut();
    }

    // SAFETY: handle came from Box::into_raw in fromFile / fromBytes and has
    // not yet been freed (the Java AutoCloseable guarantees that).
    let handle_ref = unsafe { &*(handle as *const EngineHandle) };

    let event_type_str: String = match env.get_string(&event_type) {
        Ok(s) => s.into(),
        Err(e) => {
            throw_runtime(&mut env, &format!("invalid eventType string: {e}"));
            return std::ptr::null_mut();
        }
    };

    let fields: HashMap<SmolStr, Value> = if fields_json.is_null() {
        HashMap::new()
    } else {
        let json_str: String = match env.get_string(&fields_json) {
            Ok(s) => s.into(),
            Err(e) => {
                throw_runtime(&mut env, &format!("invalid fieldsJson string: {e}"));
                return std::ptr::null_mut();
            }
        };
        match parse_fields_json(&json_str) {
            Ok(f) => f,
            Err(e) => {
                throw_runtime(&mut env, &format!("invalid fieldsJson: {e}"));
                return std::ptr::null_mut();
            }
        }
    };

    let event = Event::new(&event_type_str).with_fields(fields);

    let result = match handle_ref.engine.lock() {
        Ok(mut engine) => engine.evaluate(&event),
        Err(e) => {
            throw_runtime(&mut env, &format!("engine mutex poisoned: {e}"));
            return std::ptr::null_mut();
        }
    };

    let json = match serialize_result(&result) {
        Ok(s) => s,
        Err(e) => {
            throw_runtime(&mut env, &format!("failed to serialize result: {e}"));
            return std::ptr::null_mut();
        }
    };

    match env.new_string(&json) {
        Ok(s) => s.into_raw(),
        Err(e) => {
            throw_runtime(&mut env, &format!("failed to create Java String: {e}"));
            std::ptr::null_mut()
        }
    }
}

// ── Metadata ──────────────────────────────────────────────────────────────────

/// Return the policy name declared in the `.aegisc` file.
///
/// # JNI signature
/// `static native String nativePolicyName(long handle)`
#[no_mangle]
pub extern "system" fn Java_io_automaguard_JniNativeBridge_nativePolicyName(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jstring {
    if handle == 0 {
        throw_runtime(&mut env, "engine handle is null");
        return std::ptr::null_mut();
    }
    let handle_ref = unsafe { &*(handle as *const EngineHandle) };
    match env.new_string(&handle_ref.policy_name) {
        Ok(s) => s.into_raw(),
        Err(e) => {
            throw_runtime(&mut env, &format!("failed to create Java String: {e}"));
            std::ptr::null_mut()
        }
    }
}

// ── State management ──────────────────────────────────────────────────────────

/// Reset all state machines and rate-limit counters to their initial states.
/// Call at the start of a new agent session to isolate per-session invariants.
///
/// # JNI signature
/// `static native void nativeReset(long handle)`
#[no_mangle]
pub extern "system" fn Java_io_automaguard_JniNativeBridge_nativeReset(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle == 0 {
        throw_runtime(&mut env, "engine handle is null");
        return;
    }
    let handle_ref = unsafe { &*(handle as *const EngineHandle) };
    match handle_ref.engine.lock() {
        Ok(mut engine) => engine.reset(),
        Err(e) => throw_runtime(&mut env, &format!("engine mutex poisoned: {e}")),
    }
}

// ── Memory management ─────────────────────────────────────────────────────────

/// Free an engine handle.  Must be called exactly once per handle.
///
/// # JNI signature
/// `static native void nativeFree(long handle)`
#[no_mangle]
pub extern "system" fn Java_io_automaguard_JniNativeBridge_nativeFree(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle != 0 {
        // SAFETY: handle came from Box::into_raw and the Java AutoCloseable
        // guarantees this is called at most once.
        unsafe { drop(Box::from_raw(handle as *mut EngineHandle)) };
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

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
        _ => Err("fieldsJson must be a JSON object ({…})".to_string()),
    }
}

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
