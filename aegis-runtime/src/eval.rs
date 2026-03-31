//! IR expression evaluator — the hot path of the runtime verifier.
//!
//! Evaluates compiled [`IRExpr`] trees against a live [`EvalContext`]
//! containing the current event and accumulated policy state.
//!
//! # Performance
//!
//! This module is the latency-critical path. Design principles:
//! - No heap allocation in the common case (literal comparisons, field access)
//! - Short-circuit evaluation for `&&` and `||`
//! - Direct path resolution via `RefPath` (no string lookups)
//! - Quantifiers iterate without collecting intermediates

use std::collections::HashMap;

use smol_str::SmolStr;

use aegis_compiler::ast::{BinaryOp, DurationLit, Literal, PredicateKind, QuantifierKind, UnaryOp};
use aegis_compiler::ir::{CaseTest, DecisionNode, IRExpr, RefPath, RefRoot};

use crate::event::{Event, Value};

/// The evaluation context — everything an expression can reference.
///
/// Built fresh for each event evaluation. The `context` map persists
/// across events (it's the policy's running state).
pub struct EvalContext<'a> {
    /// The current event being evaluated
    pub event: &'a Event,
    /// Persistent policy state (counters, history, config)
    pub context: &'a HashMap<SmolStr, Value>,
    /// Policy configuration values
    pub policy: &'a HashMap<SmolStr, Value>,
    /// Local bindings (let-bound variables within rules)
    pub locals: HashMap<u32, Value>,
}

impl<'a> EvalContext<'a> {
    pub fn new(
        event: &'a Event,
        context: &'a HashMap<SmolStr, Value>,
        policy: &'a HashMap<SmolStr, Value>,
    ) -> Self {
        Self {
            event,
            context,
            policy,
            locals: HashMap::new(),
        }
    }
}

/// Evaluate an IR expression to a runtime Value.
pub fn eval(expr: &IRExpr, ctx: &EvalContext<'_>) -> Value {
    match expr {
        IRExpr::Literal(lit) => eval_literal(lit),

        IRExpr::Ref(path) => eval_ref(path, ctx),

        IRExpr::Binary { op, left, right } => {
            // Short-circuit for logical operators
            match op {
                BinaryOp::And => {
                    let lv = eval(left, ctx);
                    if !lv.is_truthy() {
                        return Value::Bool(false);
                    }
                    let rv = eval(right, ctx);
                    Value::Bool(rv.is_truthy())
                }
                BinaryOp::Or => {
                    let lv = eval(left, ctx);
                    if lv.is_truthy() {
                        return Value::Bool(true);
                    }
                    let rv = eval(right, ctx);
                    Value::Bool(rv.is_truthy())
                }
                BinaryOp::Implies => {
                    // p → q ≡ ¬p ∨ q
                    let lv = eval(left, ctx);
                    if !lv.is_truthy() {
                        return Value::Bool(true);
                    }
                    let rv = eval(right, ctx);
                    Value::Bool(rv.is_truthy())
                }
                _ => {
                    let lv = eval(left, ctx);
                    let rv = eval(right, ctx);
                    eval_binary(*op, &lv, &rv)
                }
            }
        }

        IRExpr::Unary { op, operand } => {
            let v = eval(operand, ctx);
            match op {
                UnaryOp::Not => Value::Bool(!v.is_truthy()),
                UnaryOp::Neg => match v {
                    Value::Int(n) => Value::Int(-n),
                    Value::Float(f) => Value::Float(-f),
                    _ => Value::Null,
                },
            }
        }

        IRExpr::Predicate {
            kind,
            subject,
            argument,
        } => {
            let subj = eval(subject, ctx);
            let arg = eval(argument, ctx);
            eval_predicate(*kind, &subj, &arg)
        }

        IRExpr::Quantifier {
            kind,
            collection,
            param,
            body,
        } => {
            let coll = eval(collection, ctx);
            eval_quantifier(*kind, &coll, param, body, ctx)
        }

        IRExpr::Count {
            collection,
            param,
            filter,
        } => {
            let coll = eval(collection, ctx);
            eval_count(&coll, param.as_ref(), filter.as_deref(), ctx)
        }

        IRExpr::Call { function, args } => {
            // Built-in function dispatch
            let arg_values: Vec<Value> = args.iter().map(|a| eval(a, ctx)).collect();
            eval_builtin_call(function, &arg_values)
        }

        IRExpr::MethodCall {
            object,
            method,
            args,
        } => {
            let obj = eval(object, ctx);
            let arg_values: Vec<Value> = args.iter().map(|a| eval(a, ctx)).collect();
            eval_method_call(&obj, method, &arg_values)
        }

        IRExpr::DecisionTree(node) => eval_decision_tree(node, ctx),

        IRExpr::List(items) => {
            let values: Vec<Value> = items.iter().map(|i| eval(i, ctx)).collect();
            Value::List(values)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Literal evaluation
// ═══════════════════════════════════════════════════════════════════════

fn eval_literal(lit: &Literal) -> Value {
    match lit {
        Literal::Bool(b) => Value::Bool(*b),
        Literal::Int(n) => Value::Int(*n),
        Literal::Float(f) => Value::Float(*f),
        Literal::String(s) => Value::String(s.clone()),
        Literal::Duration(d) => Value::Duration(d.to_millis()),
        Literal::Regex(r) => Value::String(r.clone()), // Pattern stored as string
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Reference resolution — the hot path for field access
// ═══════════════════════════════════════════════════════════════════════

fn eval_ref(path: &RefPath, ctx: &EvalContext<'_>) -> Value {
    match path.root {
        RefRoot::Event => {
            if path.fields.is_empty() {
                return ctx.event.to_value();
            }
            ctx.event
                .get_field(&path.fields)
                .cloned()
                .unwrap_or(Value::Null)
        }
        RefRoot::Context => {
            if path.fields.is_empty() {
                return Value::Map(ctx.context.clone());
            }
            let first = &path.fields[0];
            ctx.context
                .get(first)
                .and_then(|v| {
                    if path.fields.len() == 1 {
                        Some(v.clone())
                    } else {
                        v.resolve_path(&path.fields[1..]).cloned()
                    }
                })
                .unwrap_or(Value::Null)
        }
        RefRoot::Policy => {
            if path.fields.is_empty() {
                return Value::Map(ctx.policy.clone());
            }
            let first = &path.fields[0];
            ctx.policy
                .get(first)
                .and_then(|v| {
                    if path.fields.len() == 1 {
                        Some(v.clone())
                    } else {
                        v.resolve_path(&path.fields[1..]).cloned()
                    }
                })
                .unwrap_or(Value::Null)
        }
        RefRoot::Local(slot) => ctx
            .locals
            .get(&slot)
            .cloned()
            .unwrap_or(Value::Null),
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Binary operators
// ═══════════════════════════════════════════════════════════════════════

fn eval_binary(op: BinaryOp, left: &Value, right: &Value) -> Value {
    match op {
        // Arithmetic
        BinaryOp::Add => match (left, right) {
            (Value::Int(a), Value::Int(b)) => Value::Int(a + b),
            (Value::Float(a), Value::Float(b)) => Value::Float(a + b),
            (Value::Int(a), Value::Float(b)) => Value::Float(*a as f64 + b),
            (Value::Float(a), Value::Int(b)) => Value::Float(a + *b as f64),
            (Value::String(a), Value::String(b)) => {
                Value::String(SmolStr::new(format!("{a}{b}")))
            }
            _ => Value::Null,
        },
        BinaryOp::Sub => match (left, right) {
            (Value::Int(a), Value::Int(b)) => Value::Int(a - b),
            (Value::Float(a), Value::Float(b)) => Value::Float(a - b),
            (Value::Int(a), Value::Float(b)) => Value::Float(*a as f64 - b),
            (Value::Float(a), Value::Int(b)) => Value::Float(a - *b as f64),
            _ => Value::Null,
        },
        BinaryOp::Mul => match (left, right) {
            (Value::Int(a), Value::Int(b)) => Value::Int(a * b),
            (Value::Float(a), Value::Float(b)) => Value::Float(a * b),
            (Value::Int(a), Value::Float(b)) => Value::Float(*a as f64 * b),
            (Value::Float(a), Value::Int(b)) => Value::Float(a * *b as f64),
            _ => Value::Null,
        },
        BinaryOp::Div => match (left, right) {
            (Value::Int(a), Value::Int(b)) if *b != 0 => Value::Int(a / b),
            (Value::Float(a), Value::Float(b)) if *b != 0.0 => Value::Float(a / b),
            (Value::Int(a), Value::Float(b)) if *b != 0.0 => Value::Float(*a as f64 / b),
            (Value::Float(a), Value::Int(b)) if *b != 0 => Value::Float(a / *b as f64),
            _ => Value::Null,
        },
        BinaryOp::Mod => match (left, right) {
            (Value::Int(a), Value::Int(b)) if *b != 0 => Value::Int(a % b),
            _ => Value::Null,
        },

        // Comparison
        BinaryOp::Eq => Value::Bool(values_equal(left, right)),
        BinaryOp::Neq => Value::Bool(!values_equal(left, right)),
        BinaryOp::Lt => Value::Bool(values_compare(left, right) == Some(std::cmp::Ordering::Less)),
        BinaryOp::Le => Value::Bool(matches!(
            values_compare(left, right),
            Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
        )),
        BinaryOp::Gt => Value::Bool(values_compare(left, right) == Some(std::cmp::Ordering::Greater)),
        BinaryOp::Ge => Value::Bool(matches!(
            values_compare(left, right),
            Some(std::cmp::Ordering::Greater | std::cmp::Ordering::Equal)
        )),

        // Membership
        BinaryOp::In => match right {
            Value::List(items) => Value::Bool(items.iter().any(|item| values_equal(left, item))),
            Value::Map(m) => match left {
                Value::String(s) => Value::Bool(m.contains_key(s)),
                _ => Value::Bool(false),
            },
            _ => Value::Bool(false),
        },

        // Logical (non-short-circuit versions — shouldn't be reached due to
        // short-circuit handling in eval(), but included for completeness)
        BinaryOp::And => Value::Bool(left.is_truthy() && right.is_truthy()),
        BinaryOp::Or => Value::Bool(left.is_truthy() || right.is_truthy()),
        BinaryOp::Implies => Value::Bool(!left.is_truthy() || right.is_truthy()),
    }
}

fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Int(a), Value::Int(b)) => a == b,
        (Value::Float(a), Value::Float(b)) => (a - b).abs() < f64::EPSILON,
        (Value::Int(a), Value::Float(b)) | (Value::Float(b), Value::Int(a)) => {
            (*a as f64 - b).abs() < f64::EPSILON
        }
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Duration(a), Value::Duration(b)) => a == b,
        _ => false,
    }
}

fn values_compare(a: &Value, b: &Value) -> Option<std::cmp::Ordering> {
    match (a, b) {
        (Value::Int(a), Value::Int(b)) => Some(a.cmp(b)),
        (Value::Float(a), Value::Float(b)) => a.partial_cmp(b),
        (Value::Int(a), Value::Float(b)) => (*a as f64).partial_cmp(b),
        (Value::Float(a), Value::Int(b)) => a.partial_cmp(&(*b as f64)),
        (Value::String(a), Value::String(b)) => Some(a.cmp(b)),
        (Value::Duration(a), Value::Duration(b)) => Some(a.cmp(b)),
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Built-in predicates
// ═══════════════════════════════════════════════════════════════════════

fn eval_predicate(kind: PredicateKind, subject: &Value, argument: &Value) -> Value {
    match kind {
        PredicateKind::Contains => Value::Bool(subject.contains(argument)),
        PredicateKind::Matches => {
            let pattern = argument.as_str().unwrap_or("");
            Value::Bool(subject.matches_pattern(pattern))
        }
        PredicateKind::StartsWith => match (subject, argument) {
            (Value::String(s), Value::String(prefix)) => {
                Value::Bool(s.starts_with(prefix.as_str()))
            }
            _ => Value::Bool(false),
        },
        PredicateKind::EndsWith => match (subject, argument) {
            (Value::String(s), Value::String(suffix)) => {
                Value::Bool(s.ends_with(suffix.as_str()))
            }
            _ => Value::Bool(false),
        },
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Quantifiers — iterate without intermediate allocation
// ═══════════════════════════════════════════════════════════════════════

fn eval_quantifier(
    kind: QuantifierKind,
    collection: &Value,
    param: &SmolStr,
    body: &IRExpr,
    ctx: &EvalContext<'_>,
) -> Value {
    let items = match collection {
        Value::List(items) => items.as_slice(),
        _ => return Value::Bool(kind == QuantifierKind::None),
    };

    // We need to bind the parameter for each iteration.
    // Since EvalContext borrows immutably, we create a child context.
    // In the hot path, this is the main allocation cost.

    match kind {
        QuantifierKind::All => {
            for item in items {
                let mut child = EvalContext {
                    event: ctx.event,
                    context: ctx.context,
                    policy: ctx.policy,
                    locals: ctx.locals.clone(),
                };
                child.locals.insert(0, item.clone()); // param slot 0
                let result = eval(body, &child);
                if !result.is_truthy() {
                    return Value::Bool(false);
                }
            }
            Value::Bool(true)
        }
        QuantifierKind::Any | QuantifierKind::Exists => {
            for item in items {
                let mut child = EvalContext {
                    event: ctx.event,
                    context: ctx.context,
                    policy: ctx.policy,
                    locals: ctx.locals.clone(),
                };
                child.locals.insert(0, item.clone());
                let result = eval(body, &child);
                if result.is_truthy() {
                    return Value::Bool(true);
                }
            }
            Value::Bool(false)
        }
        QuantifierKind::None => {
            for item in items {
                let mut child = EvalContext {
                    event: ctx.event,
                    context: ctx.context,
                    policy: ctx.policy,
                    locals: ctx.locals.clone(),
                };
                child.locals.insert(0, item.clone());
                let result = eval(body, &child);
                if result.is_truthy() {
                    return Value::Bool(false);
                }
            }
            Value::Bool(true)
        }
    }
}

fn eval_count(
    collection: &Value,
    param: Option<&SmolStr>,
    filter: Option<&IRExpr>,
    ctx: &EvalContext<'_>,
) -> Value {
    let items = match collection {
        Value::List(items) => items,
        _ => return Value::Int(0),
    };

    match filter {
        Some(body) => {
            let mut count = 0i64;
            for item in items {
                let mut child = EvalContext {
                    event: ctx.event,
                    context: ctx.context,
                    policy: ctx.policy,
                    locals: ctx.locals.clone(),
                };
                child.locals.insert(0, item.clone());
                if eval(body, &child).is_truthy() {
                    count += 1;
                }
            }
            Value::Int(count)
        }
        None => Value::Int(items.len() as i64),
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Decision tree evaluation (compiled match expressions)
// ═══════════════════════════════════════════════════════════════════════

fn eval_decision_tree(node: &DecisionNode, ctx: &EvalContext<'_>) -> Value {
    match node {
        DecisionNode::Leaf(expr) => eval(expr, ctx),
        DecisionNode::VerdictLeaf(v) => {
            // Return the verdict as a string value for now.
            // The engine extracts verdicts separately.
            Value::String(SmolStr::new(format!("{:?}", v.verdict)))
        }
        DecisionNode::Switch {
            subject,
            cases,
            default,
        } => {
            let subject_val = eval(subject, ctx);
            for case in cases {
                let matches = match &case.test {
                    CaseTest::Literal(lit) => {
                        let lit_val = eval_literal(lit);
                        values_equal(&subject_val, &lit_val)
                    }
                    CaseTest::Constructor(name) => {
                        // Constructor matching: check if the value's "type" field matches
                        match &subject_val {
                            Value::Map(m) => m
                                .get("type")
                                .and_then(|v| v.as_str())
                                .map(|s| s == name.as_str())
                                .unwrap_or(false),
                            Value::String(s) => s.as_str() == name.as_str(),
                            _ => false,
                        }
                    }
                    CaseTest::Guard(guard_expr) => eval(guard_expr, ctx).is_truthy(),
                };
                if matches {
                    return eval_decision_tree(&case.body, ctx);
                }
            }
            // Default branch
            match default {
                Some(d) => eval_decision_tree(d, ctx),
                None => Value::Null,
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Built-in function and method dispatch
// ═══════════════════════════════════════════════════════════════════════

fn eval_builtin_call(name: &str, args: &[Value]) -> Value {
    match name {
        "len" | "length" => match args.first() {
            Some(Value::String(s)) => Value::Int(s.len() as i64),
            Some(Value::List(l)) => Value::Int(l.len() as i64),
            Some(Value::Map(m)) => Value::Int(m.len() as i64),
            _ => Value::Int(0),
        },
        "to_string" | "str" => match args.first() {
            Some(v) => Value::String(SmolStr::new(v.to_string())),
            None => Value::String(SmolStr::new("")),
        },
        "abs" => match args.first() {
            Some(Value::Int(n)) => Value::Int(n.abs()),
            Some(Value::Float(f)) => Value::Float(f.abs()),
            _ => Value::Null,
        },
        "min" => {
            if args.len() == 2 {
                match values_compare(&args[0], &args[1]) {
                    Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal) => {
                        args[0].clone()
                    }
                    Some(std::cmp::Ordering::Greater) => args[1].clone(),
                    None => Value::Null,
                }
            } else {
                Value::Null
            }
        }
        "max" => {
            if args.len() == 2 {
                match values_compare(&args[0], &args[1]) {
                    Some(std::cmp::Ordering::Greater | std::cmp::Ordering::Equal) => {
                        args[0].clone()
                    }
                    Some(std::cmp::Ordering::Less) => args[1].clone(),
                    None => Value::Null,
                }
            } else {
                Value::Null
            }
        }
        // Unknown function — return null (the type checker should have caught this)
        _ => Value::Null,
    }
}

fn eval_method_call(object: &Value, method: &str, args: &[Value]) -> Value {
    match (object, method) {
        (Value::String(s), "to_upper" | "to_uppercase") => {
            Value::String(SmolStr::new(s.to_uppercase()))
        }
        (Value::String(s), "to_lower" | "to_lowercase") => {
            Value::String(SmolStr::new(s.to_lowercase()))
        }
        (Value::String(s), "trim") => Value::String(SmolStr::new(s.trim())),
        (Value::String(s), "len" | "length") => Value::Int(s.len() as i64),
        (Value::String(s), "is_empty") => Value::Bool(s.is_empty()),
        (Value::String(s), "split") => {
            let sep = args.first().and_then(|a| a.as_str()).unwrap_or(",");
            Value::List(s.split(sep).map(|p| Value::String(SmolStr::new(p))).collect())
        }
        (Value::List(l), "len" | "length") => Value::Int(l.len() as i64),
        (Value::List(l), "is_empty") => Value::Bool(l.is_empty()),
        (Value::List(l), "first") => l.first().cloned().unwrap_or(Value::Null),
        (Value::List(l), "last") => l.last().cloned().unwrap_or(Value::Null),
        (Value::Map(m), "keys") => {
            Value::List(m.keys().map(|k| Value::String(k.clone())).collect())
        }
        (Value::Map(m), "values") => Value::List(m.values().cloned().collect()),
        (Value::Map(m), "len" | "length") => Value::Int(m.len() as i64),
        (Value::Map(m), "has_key" | "contains_key") => {
            let key = args.first().and_then(|a| a.as_str()).unwrap_or("");
            Value::Bool(m.contains_key(key))
        }
        // Field access fallback (for dynamic method resolution on open types)
        (Value::Map(m), field) => m.get(field).cloned().unwrap_or(Value::Null),
        _ => Value::Null,
    }
}
