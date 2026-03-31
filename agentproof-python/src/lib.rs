use std::collections::HashMap;
use std::sync::Mutex;

use pyo3::exceptions::{PyFileNotFoundError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString};
use smol_str::SmolStr;

use aegis_compiler::bytecode;
use aegis_compiler::ir::CompiledPolicy;
use aegis_runtime::audit::AuditLog as RustAuditLog;
use aegis_runtime::engine::{PolicyEngine as RustEngine, PolicyResult as RustResult};
use aegis_runtime::event::{Event as RustEvent, Value};

// ═══════════════════════════════════════════════════════════════════════
//  Python ↔ Value conversion
// ═══════════════════════════════════════════════════════════════════════

fn py_to_value(obj: &Bound<'_, PyAny>) -> PyResult<Value> {
    if obj.is_none() {
        return Ok(Value::Null);
    }
    if let Ok(b) = obj.extract::<bool>() {
        return Ok(Value::Bool(b));
    }
    if let Ok(n) = obj.extract::<i64>() {
        return Ok(Value::Int(n));
    }
    if let Ok(f) = obj.extract::<f64>() {
        return Ok(Value::Float(f));
    }
    if let Ok(s) = obj.extract::<String>() {
        return Ok(Value::String(SmolStr::new(s)));
    }
    if let Ok(list) = obj.downcast::<PyList>() {
        let items: PyResult<Vec<Value>> = list.iter().map(|item| py_to_value(&item)).collect();
        return Ok(Value::List(items?));
    }
    if let Ok(dict) = obj.downcast::<PyDict>() {
        let mut map = HashMap::new();
        for (key, val) in dict.iter() {
            let k: String = key.extract()?;
            let v = py_to_value(&val)?;
            map.insert(SmolStr::new(k), v);
        }
        return Ok(Value::Map(map));
    }
    // Fallback: convert to string
    let s = obj.str()?.to_string();
    Ok(Value::String(SmolStr::new(s)))
}

fn value_to_py(py: Python<'_>, val: &Value) -> PyObject {
    match val {
        Value::Null => py.None(),
        Value::Bool(b) => b.into_py(py),
        Value::Int(n) => n.into_py(py),
        Value::Float(f) => f.into_py(py),
        Value::String(s) => s.as_str().into_py(py),
        Value::Duration(ms) => ms.into_py(py),
        Value::List(items) => {
            let list = PyList::new_bound(py, items.iter().map(|v| value_to_py(py, v)));
            list.into_py(py)
        }
        Value::Map(map) => {
            let dict = PyDict::new_bound(py);
            for (k, v) in map {
                dict.set_item(k.as_str(), value_to_py(py, v)).unwrap();
            }
            dict.into_py(py)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  PyPolicyEngine — the main Python-facing class
// ═══════════════════════════════════════════════════════════════════════

/// The AgentProof policy engine.
///
/// Load a compiled policy and evaluate agent events against it.
///
/// Example:
///     engine = PolicyEngine.from_file("guard.aegisc")
///     result = engine.evaluate("tool_call", {"tool": "http_request", "url": "https://..."})
///     if result["verdict"] == "deny":
///         raise PermissionError(result["reason"])
#[pyclass(name = "PolicyEngine")]
struct PyPolicyEngine {
    inner: Mutex<RustEngine>,
    policy_name: String,
}

#[pymethods]
impl PyPolicyEngine {
    /// Load a policy engine from a compiled .aegisc file.
    #[staticmethod]
    fn from_file(path: &str) -> PyResult<Self> {
        let p = std::path::Path::new(path);
        if !p.exists() {
            return Err(PyFileNotFoundError::new_err(format!(
                "Policy file not found: {path}"
            )));
        }
        let policy = bytecode::read_file(p)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to load policy: {e}")))?;
        let name = policy.name.to_string();
        let engine = RustEngine::new(policy);
        Ok(Self {
            inner: Mutex::new(engine),
            policy_name: name,
        })
    }

    /// Load a policy engine from raw .aegisc bytes.
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let policy = bytecode::from_bytecode(data)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to parse policy bytes: {e}")))?;
        let name = policy.name.to_string();
        let engine = RustEngine::new(policy);
        Ok(Self {
            inner: Mutex::new(engine),
            policy_name: name,
        })
    }

    /// Load a policy engine from a JSON string (debug format).
    #[staticmethod]
    fn from_json(json_str: &str) -> PyResult<Self> {
        let policy: CompiledPolicy = serde_json::from_str(json_str)
            .map_err(|e| PyValueError::new_err(format!("Invalid policy JSON: {e}")))?;
        let name = policy.name.to_string();
        let engine = RustEngine::new(policy);
        Ok(Self {
            inner: Mutex::new(engine),
            policy_name: name,
        })
    }

    /// Evaluate an event against the policy.
    ///
    /// Args:
    ///     event_type: The event type string (e.g., "tool_call", "data_access")
    ///     fields: A dict of event fields
    ///
    /// Returns:
    ///     A dict with keys: verdict, reason, triggered_rules, actions,
    ///     violations, constraint_violations, eval_time_us
    #[pyo3(signature = (event_type, fields=None))]
    fn evaluate(
        &self,
        py: Python<'_>,
        event_type: &str,
        fields: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<PyObject> {
        let mut event = RustEvent::new(event_type);

        if let Some(dict) = fields {
            for (key, val) in dict.iter() {
                let k: String = key.extract()?;
                let v = py_to_value(&val)?;
                event.fields.insert(SmolStr::new(k), v);
            }
        }

        let result = {
            let mut engine = self
                .inner
                .lock()
                .map_err(|_| PyRuntimeError::new_err("Engine lock poisoned"))?;
            engine.evaluate(&event)
        };

        Ok(result_to_py(py, &result))
    }

    /// Set a persistent context value.
    fn set_context(&self, key: &str, value: &Bound<'_, PyAny>) -> PyResult<()> {
        let v = py_to_value(value)?;
        let mut engine = self
            .inner
            .lock()
            .map_err(|_| PyRuntimeError::new_err("Engine lock poisoned"))?;
        engine.set_context(key, v);
        Ok(())
    }

    /// Set a policy configuration value.
    fn set_config(&self, key: &str, value: &Bound<'_, PyAny>) -> PyResult<()> {
        let v = py_to_value(value)?;
        let mut engine = self
            .inner
            .lock()
            .map_err(|_| PyRuntimeError::new_err("Engine lock poisoned"))?;
        engine.set_config(key, v);
        Ok(())
    }

    /// Get the policy name.
    #[getter]
    fn policy_name(&self) -> &str {
        &self.policy_name
    }

    /// Get the total number of events processed.
    #[getter]
    fn event_count(&self) -> PyResult<u64> {
        let engine = self
            .inner
            .lock()
            .map_err(|_| PyRuntimeError::new_err("Engine lock poisoned"))?;
        Ok(engine.event_count())
    }

    /// Reset the engine state (state machines, counters).
    fn reset(&self) -> PyResult<()> {
        let mut engine = self
            .inner
            .lock()
            .map_err(|_| PyRuntimeError::new_err("Engine lock poisoned"))?;
        engine.reset();
        Ok(())
    }

    /// Get engine status summary.
    fn status(&self) -> PyResult<String> {
        let engine = self
            .inner
            .lock()
            .map_err(|_| PyRuntimeError::new_err("Engine lock poisoned"))?;
        Ok(engine.status().to_string())
    }

    fn __repr__(&self) -> PyResult<String> {
        let engine = self
            .inner
            .lock()
            .map_err(|_| PyRuntimeError::new_err("Engine lock poisoned"))?;
        Ok(format!(
            "<PolicyEngine policy='{}' events={}>",
            self.policy_name,
            engine.event_count()
        ))
    }
}

fn result_to_py(py: Python<'_>, result: &RustResult) -> PyObject {
    let dict = PyDict::new_bound(py);

    dict.set_item("verdict", format!("{:?}", result.verdict).to_lowercase())
        .unwrap();
    dict.set_item("reason", result.reason.as_deref()).unwrap();
    dict.set_item("triggered_rules", &result.triggered_rules)
        .unwrap();
    dict.set_item("eval_time_us", result.eval_time_us).unwrap();

    // Actions
    let actions = PyList::new_bound(
        py,
        result.actions.iter().map(|a| {
            let d = PyDict::new_bound(py);
            d.set_item("verb", a.verb.as_str()).unwrap();
            let args = PyDict::new_bound(py);
            for (k, v) in &a.args {
                args.set_item(k.as_str(), value_to_py(py, v)).unwrap();
            }
            d.set_item("args", args).unwrap();
            d
        }),
    );
    dict.set_item("actions", actions).unwrap();

    // Violations
    let violations = PyList::new_bound(
        py,
        result.violations.iter().map(|v| {
            let d = PyDict::new_bound(py);
            d.set_item("proof", v.proof_name.as_str()).unwrap();
            d.set_item("invariant", v.invariant_name.as_str()).unwrap();
            d.set_item("kind", format!("{:?}", v.kind)).unwrap();
            d.set_item("message", &v.message).unwrap();
            d
        }),
    );
    dict.set_item("violations", violations).unwrap();

    // Constraint violations
    let cvs = PyList::new_bound(
        py,
        result.constraint_violations.iter().map(|cv| {
            let d = PyDict::new_bound(py);
            d.set_item("kind", format!("{:?}", cv.kind)).unwrap();
            d.set_item("target", cv.target.as_str()).unwrap();
            d.set_item("limit", cv.limit).unwrap();
            d.set_item("current", cv.current).unwrap();
            d.set_item("window_ms", cv.window_ms).unwrap();
            d
        }),
    );
    dict.set_item("constraint_violations", cvs).unwrap();

    dict.into_py(py)
}

// ═══════════════════════════════════════════════════════════════════════
//  Module initialization
// ═══════════════════════════════════════════════════════════════════════

/// AgentProof native core — Rust-powered policy verification.
#[pymodule]
fn _agentproof_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPolicyEngine>()?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
