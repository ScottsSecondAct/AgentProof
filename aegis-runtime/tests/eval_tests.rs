//! Expression evaluator tests.
//!
//! Each test constructs an `IRExpr` tree, evaluates it against a synthetic
//! `EvalContext`, and asserts on the resulting `Value`.  Tests are organised
//! by expression variant.

use std::collections::HashMap;

use aegis_compiler::ast::{
    BinaryOp, DurationLit, DurationUnit, Literal, PredicateKind, QuantifierKind, UnaryOp,
};
use aegis_compiler::ir::{
    CaseTest, DecisionCase, DecisionNode, IRExpr, IRVerdict, RefPath, RefRoot,
};
use aegis_compiler::ast::Verdict;
use smol_str::SmolStr;

use aegis_runtime::eval::{eval, EvalContext};
use aegis_runtime::event::{Event, Value};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn s(v: &str) -> SmolStr {
    SmolStr::new(v)
}

fn lit_bool(b: bool) -> IRExpr {
    IRExpr::Literal(Literal::Bool(b))
}

fn lit_int(n: i64) -> IRExpr {
    IRExpr::Literal(Literal::Int(n))
}

fn lit_float(f: f64) -> IRExpr {
    IRExpr::Literal(Literal::Float(f))
}

fn lit_str(v: &str) -> IRExpr {
    IRExpr::Literal(Literal::String(s(v)))
}

fn lit_dur(value: u64, unit: DurationUnit) -> IRExpr {
    IRExpr::Literal(Literal::Duration(DurationLit {
        value,
        unit,
    }))
}

fn event_ref(field: &str) -> IRExpr {
    IRExpr::Ref(RefPath {
        root: RefRoot::Event,
        fields: vec![s(field)],
    })
}

fn event_ref_path(fields: &[&str]) -> IRExpr {
    IRExpr::Ref(RefPath {
        root: RefRoot::Event,
        fields: fields.iter().map(|f| s(f)).collect(),
    })
}

fn context_ref(field: &str) -> IRExpr {
    IRExpr::Ref(RefPath {
        root: RefRoot::Context,
        fields: vec![s(field)],
    })
}

fn policy_ref(field: &str) -> IRExpr {
    IRExpr::Ref(RefPath {
        root: RefRoot::Policy,
        fields: vec![s(field)],
    })
}

fn local_ref(slot: u32) -> IRExpr {
    IRExpr::Ref(RefPath {
        root: RefRoot::Local(slot),
        fields: vec![],
    })
}

fn binary(op: BinaryOp, left: IRExpr, right: IRExpr) -> IRExpr {
    IRExpr::Binary {
        op,
        left: Box::new(left),
        right: Box::new(right),
    }
}

fn unary(op: UnaryOp, operand: IRExpr) -> IRExpr {
    IRExpr::Unary {
        op,
        operand: Box::new(operand),
    }
}

fn predicate(kind: PredicateKind, subject: IRExpr, argument: IRExpr) -> IRExpr {
    IRExpr::Predicate {
        kind,
        subject: Box::new(subject),
        argument: Box::new(argument),
    }
}

fn quantifier(kind: QuantifierKind, collection: IRExpr, body: IRExpr) -> IRExpr {
    IRExpr::Quantifier {
        kind,
        collection: Box::new(collection),
        param: s("item"),
        body: Box::new(body),
    }
}

fn count_expr(collection: IRExpr, filter: Option<IRExpr>) -> IRExpr {
    IRExpr::Count {
        collection: Box::new(collection),
        param: Some(s("x")),
        filter: filter.map(Box::new),
    }
}

fn call(function: &str, args: Vec<IRExpr>) -> IRExpr {
    IRExpr::Call {
        function: s(function),
        args,
    }
}

fn method_call(object: IRExpr, method: &str, args: Vec<IRExpr>) -> IRExpr {
    IRExpr::MethodCall {
        object: Box::new(object),
        method: s(method),
        args,
    }
}

/// Build a context with a single named event field.
fn event_with(field: &str, value: Value) -> Event {
    Event::new("tool_call").with_field(field, value)
}

fn eval_expr(expr: &IRExpr, event: &Event) -> Value {
    let empty1: HashMap<SmolStr, Value> = HashMap::new();
    let empty2: HashMap<SmolStr, Value> = HashMap::new();
    let ctx = EvalContext::new(event, &empty1, &empty2);
    eval(expr, &ctx)
}

fn eval_with_context(
    expr: &IRExpr,
    event: &Event,
    context: &HashMap<SmolStr, Value>,
    policy: &HashMap<SmolStr, Value>,
) -> Value {
    let ctx = EvalContext::new(event, context, policy);
    eval(expr, &ctx)
}

fn int(n: i64) -> Value {
    Value::Int(n)
}

fn float(f: f64) -> Value {
    Value::Float(f)
}

fn bool_val(b: bool) -> Value {
    Value::Bool(b)
}

fn str_val(s: &str) -> Value {
    Value::String(SmolStr::new(s))
}

fn list(items: Vec<Value>) -> Value {
    Value::List(items)
}

// ── Literal evaluation ────────────────────────────────────────────────────────

#[test]
fn literal_bool_true() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&lit_bool(true), &ev), bool_val(true));
}

#[test]
fn literal_bool_false() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&lit_bool(false), &ev), bool_val(false));
}

#[test]
fn literal_int() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&lit_int(42), &ev), int(42));
}

#[test]
fn literal_negative_int() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&lit_int(-7), &ev), int(-7));
}

#[test]
fn literal_float() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&lit_float(3.14), &ev), float(3.14));
}

#[test]
fn literal_string() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&lit_str("hello"), &ev), str_val("hello"));
}

#[test]
fn literal_duration_millis() {
    let ev = Event::new("x");
    assert_eq!(
        eval_expr(&lit_dur(5, DurationUnit::Seconds), &ev),
        Value::Duration(5_000)
    );
}

#[test]
fn literal_duration_minutes() {
    let ev = Event::new("x");
    assert_eq!(
        eval_expr(&lit_dur(2, DurationUnit::Minutes), &ev),
        Value::Duration(120_000)
    );
}

#[test]
fn literal_regex_stored_as_string() {
    let ev = Event::new("x");
    let expr = IRExpr::Literal(Literal::Regex(s("^https:")));
    assert_eq!(eval_expr(&expr, &ev), str_val("^https:"));
}

// ── Reference resolution ──────────────────────────────────────────────────────

#[test]
fn event_field_present() {
    let ev = event_with("tool_name", str_val("http_get"));
    assert_eq!(eval_expr(&event_ref("tool_name"), &ev), str_val("http_get"));
}

#[test]
fn event_field_missing_returns_null() {
    let ev = Event::new("tool_call");
    assert_eq!(eval_expr(&event_ref("missing"), &ev), Value::Null);
}

#[test]
fn event_field_nested_path() {
    let inner: HashMap<SmolStr, Value> = [(s("url"), str_val("https://example.com"))]
        .into_iter()
        .collect();
    let ev = event_with("endpoint", Value::Map(inner));
    assert_eq!(
        eval_expr(&event_ref_path(&["endpoint", "url"]), &ev),
        str_val("https://example.com")
    );
}

#[test]
fn event_ref_no_fields_returns_whole_event_as_map() {
    let ev = Event::new("tool_call");
    let expr = IRExpr::Ref(RefPath {
        root: RefRoot::Event,
        fields: vec![],
    });
    let result = eval_expr(&expr, &ev);
    assert!(matches!(result, Value::Map(_)));
}

#[test]
fn context_field_present() {
    let ev = Event::new("x");
    let mut ctx_map = HashMap::new();
    ctx_map.insert(s("budget"), int(100));
    let pol_map = HashMap::new();
    assert_eq!(
        eval_with_context(&context_ref("budget"), &ev, &ctx_map, &pol_map),
        int(100)
    );
}

#[test]
fn context_field_missing_returns_null() {
    let ev = Event::new("x");
    let ctx_map = HashMap::new();
    let pol_map = HashMap::new();
    assert_eq!(
        eval_with_context(&context_ref("missing"), &ev, &ctx_map, &pol_map),
        Value::Null
    );
}

#[test]
fn policy_field_present() {
    let ev = Event::new("x");
    let ctx_map = HashMap::new();
    let mut pol_map = HashMap::new();
    pol_map.insert(s("max_calls"), int(50));
    assert_eq!(
        eval_with_context(&policy_ref("max_calls"), &ev, &ctx_map, &pol_map),
        int(50)
    );
}

#[test]
fn local_slot_present() {
    let ev = Event::new("x");
    let ctx_map = HashMap::new();
    let pol_map = HashMap::new();
    let mut ctx = EvalContext::new(&ev, &ctx_map, &pol_map);
    ctx.locals.insert(0, str_val("local_value"));
    let expr = local_ref(0);
    assert_eq!(eval(&expr, &ctx), str_val("local_value"));
}

#[test]
fn local_slot_missing_returns_null() {
    let ev = Event::new("x");
    let ctx_map = HashMap::new();
    let pol_map = HashMap::new();
    let ctx = EvalContext::new(&ev, &ctx_map, &pol_map);
    assert_eq!(eval(&local_ref(99), &ctx), Value::Null);
}

// ── Binary operators: arithmetic ──────────────────────────────────────────────

#[test]
fn add_int_int() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&binary(BinaryOp::Add, lit_int(3), lit_int(4)), &ev), int(7));
}

#[test]
fn add_float_float() {
    let ev = Event::new("x");
    let result = eval_expr(&binary(BinaryOp::Add, lit_float(1.5), lit_float(2.5)), &ev);
    assert_eq!(result, float(4.0));
}

#[test]
fn add_int_float_widens() {
    let ev = Event::new("x");
    let result = eval_expr(&binary(BinaryOp::Add, lit_int(2), lit_float(0.5)), &ev);
    assert_eq!(result, float(2.5));
}

#[test]
fn add_string_concat() {
    let ev = Event::new("x");
    let result = eval_expr(&binary(BinaryOp::Add, lit_str("foo"), lit_str("bar")), &ev);
    assert_eq!(result, str_val("foobar"));
}

#[test]
fn add_type_mismatch_returns_null() {
    let ev = Event::new("x");
    let result = eval_expr(&binary(BinaryOp::Add, lit_int(1), lit_str("x")), &ev);
    assert_eq!(result, Value::Null);
}

#[test]
fn sub_int_int() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&binary(BinaryOp::Sub, lit_int(10), lit_int(3)), &ev), int(7));
}

#[test]
fn mul_int_int() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&binary(BinaryOp::Mul, lit_int(4), lit_int(5)), &ev), int(20));
}

#[test]
fn div_int_int() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&binary(BinaryOp::Div, lit_int(10), lit_int(2)), &ev), int(5));
}

#[test]
fn div_by_zero_returns_null() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&binary(BinaryOp::Div, lit_int(5), lit_int(0)), &ev), Value::Null);
}

#[test]
fn mod_int_int() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&binary(BinaryOp::Mod, lit_int(7), lit_int(3)), &ev), int(1));
}

#[test]
fn mod_by_zero_returns_null() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&binary(BinaryOp::Mod, lit_int(7), lit_int(0)), &ev), Value::Null);
}

// ── Binary operators: comparison ──────────────────────────────────────────────

#[test]
fn lt_int_true() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&binary(BinaryOp::Lt, lit_int(1), lit_int(2)), &ev), bool_val(true));
}

#[test]
fn lt_int_false() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&binary(BinaryOp::Lt, lit_int(2), lit_int(1)), &ev), bool_val(false));
}

#[test]
fn le_equal_is_true() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&binary(BinaryOp::Le, lit_int(3), lit_int(3)), &ev), bool_val(true));
}

#[test]
fn gt_float() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&binary(BinaryOp::Gt, lit_float(5.0), lit_float(3.0)), &ev), bool_val(true));
}

#[test]
fn ge_string_comparison() {
    let ev = Event::new("x");
    // "beta" >= "alpha" → true (lexicographic)
    assert_eq!(eval_expr(&binary(BinaryOp::Ge, lit_str("beta"), lit_str("alpha")), &ev), bool_val(true));
}

#[test]
fn compare_incompatible_types_returns_false() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&binary(BinaryOp::Lt, lit_int(1), lit_str("a")), &ev), bool_val(false));
}

// ── Binary operators: equality ────────────────────────────────────────────────

#[test]
fn eq_int_same_values() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&binary(BinaryOp::Eq, lit_int(7), lit_int(7)), &ev), bool_val(true));
}

#[test]
fn eq_int_different_values() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&binary(BinaryOp::Eq, lit_int(1), lit_int(2)), &ev), bool_val(false));
}

#[test]
fn eq_int_float_cross_type() {
    let ev = Event::new("x");
    // 1 == 1.0 → true (numeric widening equality)
    assert_eq!(eval_expr(&binary(BinaryOp::Eq, lit_int(1), lit_float(1.0)), &ev), bool_val(true));
}

#[test]
fn eq_null_null() {
    let ev = Event::new("x");
    let null = IRExpr::Ref(RefPath { root: RefRoot::Event, fields: vec![s("missing")] });
    let result = eval_expr(&binary(BinaryOp::Eq, null.clone(), null), &ev);
    assert_eq!(result, bool_val(true));
}

#[test]
fn neq_strings() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&binary(BinaryOp::Neq, lit_str("a"), lit_str("b")), &ev), bool_val(true));
}

// ── Binary operators: logical ─────────────────────────────────────────────────

#[test]
fn and_both_true() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&binary(BinaryOp::And, lit_bool(true), lit_bool(true)), &ev), bool_val(true));
}

#[test]
fn and_short_circuits_on_false() {
    // left = false, right = field access on missing field → null
    // Short-circuit means right is never evaluated → still false (not null)
    let ev = Event::new("x");
    let expr = binary(BinaryOp::And, lit_bool(false), event_ref("missing_field"));
    assert_eq!(eval_expr(&expr, &ev), bool_val(false));
}

#[test]
fn or_short_circuits_on_true() {
    let ev = Event::new("x");
    let expr = binary(BinaryOp::Or, lit_bool(true), event_ref("missing_field"));
    assert_eq!(eval_expr(&expr, &ev), bool_val(true));
}

#[test]
fn or_both_false() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&binary(BinaryOp::Or, lit_bool(false), lit_bool(false)), &ev), bool_val(false));
}

#[test]
fn implies_false_antecedent_is_true() {
    // false → anything ≡ true
    let ev = Event::new("x");
    assert_eq!(eval_expr(&binary(BinaryOp::Implies, lit_bool(false), lit_bool(false)), &ev), bool_val(true));
}

#[test]
fn implies_true_antecedent_true_consequent() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&binary(BinaryOp::Implies, lit_bool(true), lit_bool(true)), &ev), bool_val(true));
}

#[test]
fn implies_true_antecedent_false_consequent() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&binary(BinaryOp::Implies, lit_bool(true), lit_bool(false)), &ev), bool_val(false));
}

// ── Binary operators: membership ─────────────────────────────────────────────

#[test]
fn in_list_found() {
    let ev = Event::new("x");
    let list_expr = IRExpr::List(vec![lit_str("a"), lit_str("b"), lit_str("c")]);
    assert_eq!(eval_expr(&binary(BinaryOp::In, lit_str("b"), list_expr), &ev), bool_val(true));
}

#[test]
fn in_list_not_found() {
    let ev = Event::new("x");
    let list_expr = IRExpr::List(vec![lit_str("a"), lit_str("b")]);
    assert_eq!(eval_expr(&binary(BinaryOp::In, lit_str("z"), list_expr), &ev), bool_val(false));
}

#[test]
fn in_map_key_found() {
    let map: HashMap<SmolStr, Value> = [(s("key1"), int(1))].into_iter().collect();
    let ev2 = event_with("mymap", Value::Map(map));
    let map_ref = event_ref("mymap");
    let result = eval_expr(&binary(BinaryOp::In, lit_str("key1"), map_ref), &ev2);
    assert_eq!(result, bool_val(true));
}

#[test]
fn in_non_collection_returns_false() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&binary(BinaryOp::In, lit_int(1), lit_int(2)), &ev), bool_val(false));
}

// ── Unary operators ───────────────────────────────────────────────────────────

#[test]
fn not_true_gives_false() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&unary(UnaryOp::Not, lit_bool(true)), &ev), bool_val(false));
}

#[test]
fn not_falsy_null_gives_true() {
    let ev = Event::new("x");
    let null_ref = event_ref("missing");
    assert_eq!(eval_expr(&unary(UnaryOp::Not, null_ref), &ev), bool_val(true));
}

#[test]
fn neg_int() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&unary(UnaryOp::Neg, lit_int(5)), &ev), int(-5));
}

#[test]
fn neg_float() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&unary(UnaryOp::Neg, lit_float(2.5)), &ev), float(-2.5));
}

#[test]
fn neg_string_returns_null() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&unary(UnaryOp::Neg, lit_str("bad")), &ev), Value::Null);
}

// ── Predicates ────────────────────────────────────────────────────────────────

#[test]
fn contains_string_substring_found() {
    let ev = Event::new("x");
    assert_eq!(
        eval_expr(&predicate(PredicateKind::Contains, lit_str("hello world"), lit_str("world")), &ev),
        bool_val(true)
    );
}

#[test]
fn contains_string_not_found() {
    let ev = Event::new("x");
    assert_eq!(
        eval_expr(&predicate(PredicateKind::Contains, lit_str("hello"), lit_str("xyz")), &ev),
        bool_val(false)
    );
}

#[test]
fn contains_list_value_found() {
    let ev = event_with("items", list(vec![int(1), int(2), int(3)]));
    assert_eq!(
        eval_expr(&predicate(PredicateKind::Contains, event_ref("items"), lit_int(2)), &ev),
        bool_val(true)
    );
}

#[test]
fn contains_list_value_not_found() {
    let ev = event_with("items", list(vec![int(1), int(2)]));
    assert_eq!(
        eval_expr(&predicate(PredicateKind::Contains, event_ref("items"), lit_int(9)), &ev),
        bool_val(false)
    );
}

#[test]
fn matches_exact_pattern() {
    let ev = Event::new("x");
    // pattern "^hello$" = exact match for "hello"
    assert_eq!(
        eval_expr(&predicate(PredicateKind::Matches, lit_str("hello"), lit_str("^hello$")), &ev),
        bool_val(true)
    );
}

#[test]
fn matches_prefix_pattern() {
    let ev = Event::new("x");
    // "https://example.com" matches "https://.*"
    assert_eq!(
        eval_expr(
            &predicate(PredicateKind::Matches, lit_str("https://example.com"), lit_str("https://.*")),
            &ev
        ),
        bool_val(true)
    );
}

#[test]
fn matches_suffix_pattern() {
    let ev = Event::new("x");
    // "report.csv" matches ".*.csv"
    assert_eq!(
        eval_expr(
            &predicate(PredicateKind::Matches, lit_str("report.csv"), lit_str(".*.csv")),
            &ev
        ),
        bool_val(true)
    );
}

#[test]
fn matches_substring_pattern() {
    let ev = Event::new("x");
    // "foobar" matches "oba" (contains)
    assert_eq!(
        eval_expr(&predicate(PredicateKind::Matches, lit_str("foobar"), lit_str("oba")), &ev),
        bool_val(true)
    );
}

#[test]
fn starts_with_true() {
    let ev = Event::new("x");
    assert_eq!(
        eval_expr(
            &predicate(PredicateKind::StartsWith, lit_str("https://example.com"), lit_str("https://")),
            &ev
        ),
        bool_val(true)
    );
}

#[test]
fn starts_with_false() {
    let ev = Event::new("x");
    assert_eq!(
        eval_expr(
            &predicate(PredicateKind::StartsWith, lit_str("http://"), lit_str("https://")),
            &ev
        ),
        bool_val(false)
    );
}

#[test]
fn ends_with_true() {
    let ev = Event::new("x");
    assert_eq!(
        eval_expr(&predicate(PredicateKind::EndsWith, lit_str("report.csv"), lit_str(".csv")), &ev),
        bool_val(true)
    );
}

#[test]
fn ends_with_false() {
    let ev = Event::new("x");
    assert_eq!(
        eval_expr(&predicate(PredicateKind::EndsWith, lit_str("report.csv"), lit_str(".pdf")), &ev),
        bool_val(false)
    );
}

#[test]
fn predicate_non_string_subject_returns_false() {
    let ev = Event::new("x");
    assert_eq!(
        eval_expr(&predicate(PredicateKind::StartsWith, lit_int(42), lit_str("4")), &ev),
        bool_val(false)
    );
}

// ── Quantifiers ───────────────────────────────────────────────────────────────

#[test]
fn all_on_empty_list_is_true() {
    let ev = event_with("items", list(vec![]));
    let expr = quantifier(QuantifierKind::All, event_ref("items"), lit_bool(false));
    assert_eq!(eval_expr(&expr, &ev), bool_val(true));
}

#[test]
fn all_when_all_true() {
    let ev = event_with("items", list(vec![int(1), int(2), int(3)]));
    // body checks local slot 0 > 0
    let body = binary(BinaryOp::Gt, local_ref(0), lit_int(0));
    let expr = quantifier(QuantifierKind::All, event_ref("items"), body);
    assert_eq!(eval_expr(&expr, &ev), bool_val(true));
}

#[test]
fn all_when_one_false() {
    let ev = event_with("items", list(vec![int(1), int(-1), int(3)]));
    let body = binary(BinaryOp::Gt, local_ref(0), lit_int(0));
    let expr = quantifier(QuantifierKind::All, event_ref("items"), body);
    assert_eq!(eval_expr(&expr, &ev), bool_val(false));
}

#[test]
fn any_when_one_matches() {
    let ev = event_with("items", list(vec![int(0), int(5), int(0)]));
    let body = binary(BinaryOp::Gt, local_ref(0), lit_int(0));
    let expr = quantifier(QuantifierKind::Any, event_ref("items"), body);
    assert_eq!(eval_expr(&expr, &ev), bool_val(true));
}

#[test]
fn any_when_none_match() {
    let ev = event_with("items", list(vec![int(0), int(0)]));
    let body = binary(BinaryOp::Gt, local_ref(0), lit_int(0));
    let expr = quantifier(QuantifierKind::Any, event_ref("items"), body);
    assert_eq!(eval_expr(&expr, &ev), bool_val(false));
}

#[test]
fn any_on_empty_list_is_false() {
    let ev = event_with("items", list(vec![]));
    let expr = quantifier(QuantifierKind::Any, event_ref("items"), lit_bool(true));
    assert_eq!(eval_expr(&expr, &ev), bool_val(false));
}

#[test]
fn none_when_no_matches() {
    let ev = event_with("items", list(vec![int(0), int(0)]));
    let body = binary(BinaryOp::Gt, local_ref(0), lit_int(10));
    let expr = quantifier(QuantifierKind::None, event_ref("items"), body);
    assert_eq!(eval_expr(&expr, &ev), bool_val(true));
}

#[test]
fn none_when_one_matches() {
    let ev = event_with("items", list(vec![int(0), int(99)]));
    let body = binary(BinaryOp::Gt, local_ref(0), lit_int(10));
    let expr = quantifier(QuantifierKind::None, event_ref("items"), body);
    assert_eq!(eval_expr(&expr, &ev), bool_val(false));
}

#[test]
fn none_on_empty_list_is_true() {
    let ev = event_with("items", list(vec![]));
    let expr = quantifier(QuantifierKind::None, event_ref("items"), lit_bool(true));
    assert_eq!(eval_expr(&expr, &ev), bool_val(true));
}

#[test]
fn exists_is_alias_for_any() {
    let ev = event_with("items", list(vec![int(5)]));
    let body = binary(BinaryOp::Gt, local_ref(0), lit_int(0));
    let expr = quantifier(QuantifierKind::Exists, event_ref("items"), body);
    assert_eq!(eval_expr(&expr, &ev), bool_val(true));
}

#[test]
fn quantifier_on_non_list_returns_none_semantics() {
    // Non-list collection → None quantifier returns true, All/Any/Exists returns false
    let ev = Event::new("x");
    let expr = IRExpr::Quantifier {
        kind: QuantifierKind::None,
        collection: Box::new(lit_str("not_a_list")),
        param: s("x"),
        body: Box::new(lit_bool(true)),
    };
    assert_eq!(eval_expr(&expr, &ev), bool_val(true));
}

// ── Count ─────────────────────────────────────────────────────────────────────

#[test]
fn count_no_filter_returns_length() {
    let ev = event_with("items", list(vec![int(1), int(2), int(3)]));
    let expr = count_expr(event_ref("items"), None);
    assert_eq!(eval_expr(&expr, &ev), int(3));
}

#[test]
fn count_with_filter() {
    let ev = event_with("items", list(vec![int(1), int(10), int(2), int(20)]));
    let filter = binary(BinaryOp::Gt, local_ref(0), lit_int(5));
    let expr = count_expr(event_ref("items"), Some(filter));
    assert_eq!(eval_expr(&expr, &ev), int(2));
}

#[test]
fn count_on_non_list_returns_zero() {
    let ev = event_with("not_list", str_val("hello"));
    let expr = count_expr(event_ref("not_list"), None);
    assert_eq!(eval_expr(&expr, &ev), int(0));
}

#[test]
fn count_empty_list_returns_zero() {
    let ev = event_with("items", list(vec![]));
    let expr = count_expr(event_ref("items"), None);
    assert_eq!(eval_expr(&expr, &ev), int(0));
}

// ── List literal ──────────────────────────────────────────────────────────────

#[test]
fn list_literal_evaluates_elements() {
    let ev = Event::new("x");
    let expr = IRExpr::List(vec![lit_int(1), lit_int(2), lit_int(3)]);
    assert_eq!(eval_expr(&expr, &ev), list(vec![int(1), int(2), int(3)]));
}

#[test]
fn empty_list_literal() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&IRExpr::List(vec![]), &ev), list(vec![]));
}

// ── Built-in functions ────────────────────────────────────────────────────────

#[test]
fn builtin_len_string() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&call("len", vec![lit_str("hello")]), &ev), int(5));
}

#[test]
fn builtin_length_list() {
    let ev = event_with("items", list(vec![int(1), int(2)]));
    let expr = call("length", vec![event_ref("items")]);
    assert_eq!(eval_expr(&expr, &ev), int(2));
}

#[test]
fn builtin_len_no_args_returns_zero() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&call("len", vec![]), &ev), int(0));
}

#[test]
fn builtin_to_string_int() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&call("to_string", vec![lit_int(42)]), &ev), str_val("42"));
}

#[test]
fn builtin_str_bool() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&call("str", vec![lit_bool(true)]), &ev), str_val("true"));
}

#[test]
fn builtin_abs_negative_int() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&call("abs", vec![lit_int(-7)]), &ev), int(7));
}

#[test]
fn builtin_abs_float() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&call("abs", vec![lit_float(-3.5)]), &ev), float(3.5));
}

#[test]
fn builtin_min_two_ints() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&call("min", vec![lit_int(3), lit_int(7)]), &ev), int(3));
}

#[test]
fn builtin_max_two_ints() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&call("max", vec![lit_int(3), lit_int(7)]), &ev), int(7));
}

#[test]
fn builtin_unknown_returns_null() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&call("no_such_fn", vec![lit_int(1)]), &ev), Value::Null);
}

// ── Method calls ──────────────────────────────────────────────────────────────

#[test]
fn method_to_upper() {
    let ev = Event::new("x");
    assert_eq!(
        eval_expr(&method_call(lit_str("hello"), "to_upper", vec![]), &ev),
        str_val("HELLO")
    );
}

#[test]
fn method_to_lower() {
    let ev = Event::new("x");
    assert_eq!(
        eval_expr(&method_call(lit_str("HELLO"), "to_lowercase", vec![]), &ev),
        str_val("hello")
    );
}

#[test]
fn method_trim() {
    let ev = Event::new("x");
    assert_eq!(
        eval_expr(&method_call(lit_str("  hi  "), "trim", vec![]), &ev),
        str_val("hi")
    );
}

#[test]
fn method_string_len() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&method_call(lit_str("hello"), "len", vec![]), &ev), int(5));
}

#[test]
fn method_string_is_empty_false() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&method_call(lit_str("hi"), "is_empty", vec![]), &ev), bool_val(false));
}

#[test]
fn method_string_is_empty_true() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&method_call(lit_str(""), "is_empty", vec![]), &ev), bool_val(true));
}

#[test]
fn method_split() {
    let ev = Event::new("x");
    let result = eval_expr(&method_call(lit_str("a,b,c"), "split", vec![lit_str(",")]), &ev);
    assert_eq!(result, list(vec![str_val("a"), str_val("b"), str_val("c")]));
}

#[test]
fn method_list_first() {
    let ev = event_with("items", list(vec![int(10), int(20)]));
    assert_eq!(eval_expr(&method_call(event_ref("items"), "first", vec![]), &ev), int(10));
}

#[test]
fn method_list_last() {
    let ev = event_with("items", list(vec![int(10), int(20)]));
    assert_eq!(eval_expr(&method_call(event_ref("items"), "last", vec![]), &ev), int(20));
}

#[test]
fn method_list_first_on_empty_returns_null() {
    let ev = event_with("items", list(vec![]));
    assert_eq!(eval_expr(&method_call(event_ref("items"), "first", vec![]), &ev), Value::Null);
}

#[test]
fn method_list_len() {
    let ev = event_with("items", list(vec![int(1), int(2), int(3)]));
    assert_eq!(eval_expr(&method_call(event_ref("items"), "length", vec![]), &ev), int(3));
}

#[test]
fn method_list_is_empty() {
    let ev = event_with("items", list(vec![]));
    assert_eq!(eval_expr(&method_call(event_ref("items"), "is_empty", vec![]), &ev), bool_val(true));
}

#[test]
fn method_map_len() {
    let map: HashMap<SmolStr, Value> = [(s("a"), int(1)), (s("b"), int(2))].into_iter().collect();
    let ev = event_with("mymap", Value::Map(map));
    assert_eq!(eval_expr(&method_call(event_ref("mymap"), "len", vec![]), &ev), int(2));
}

#[test]
fn method_map_has_key_true() {
    let map: HashMap<SmolStr, Value> = [(s("secret"), str_val("x"))].into_iter().collect();
    let ev = event_with("mymap", Value::Map(map));
    let expr = method_call(event_ref("mymap"), "has_key", vec![lit_str("secret")]);
    assert_eq!(eval_expr(&expr, &ev), bool_val(true));
}

#[test]
fn method_map_has_key_false() {
    let map: HashMap<SmolStr, Value> = [(s("a"), int(1))].into_iter().collect();
    let ev = event_with("mymap", Value::Map(map));
    let expr = method_call(event_ref("mymap"), "contains_key", vec![lit_str("missing")]);
    assert_eq!(eval_expr(&expr, &ev), bool_val(false));
}

#[test]
fn method_unknown_returns_null() {
    let ev = Event::new("x");
    assert_eq!(eval_expr(&method_call(lit_int(5), "nonexistent", vec![]), &ev), Value::Null);
}

// ── Decision trees ────────────────────────────────────────────────────────────

#[test]
fn decision_tree_leaf_evaluates_expr() {
    let ev = Event::new("x");
    let node = DecisionNode::Leaf(Box::new(lit_int(42)));
    let expr = IRExpr::DecisionTree(Box::new(node));
    assert_eq!(eval_expr(&expr, &ev), int(42));
}

#[test]
fn decision_tree_verdict_leaf() {
    let ev = Event::new("x");
    let node = DecisionNode::VerdictLeaf(Box::new(IRVerdict {
        verdict: Verdict::Deny,
        message: None,
    }));
    let result = eval_expr(&IRExpr::DecisionTree(Box::new(node)), &ev);
    // Verdict is serialized as its debug representation
    assert_eq!(result, str_val("Deny"));
}

#[test]
fn decision_tree_switch_literal_match() {
    let ev = event_with("role", str_val("admin"));
    let node = DecisionNode::Switch {
        subject: Box::new(event_ref("role")),
        cases: vec![
            DecisionCase {
                test: CaseTest::Literal(Literal::String(s("admin"))),
                body: DecisionNode::Leaf(Box::new(lit_bool(true))),
            },
            DecisionCase {
                test: CaseTest::Literal(Literal::String(s("user"))),
                body: DecisionNode::Leaf(Box::new(lit_bool(false))),
            },
        ],
        default: None,
    };
    assert_eq!(eval_expr(&IRExpr::DecisionTree(Box::new(node)), &ev), bool_val(true));
}

#[test]
fn decision_tree_switch_falls_through_to_default() {
    let ev = event_with("role", str_val("unknown"));
    let node = DecisionNode::Switch {
        subject: Box::new(event_ref("role")),
        cases: vec![DecisionCase {
            test: CaseTest::Literal(Literal::String(s("admin"))),
            body: DecisionNode::Leaf(Box::new(lit_bool(true))),
        }],
        default: Some(Box::new(DecisionNode::Leaf(Box::new(lit_str("default"))))),
    };
    assert_eq!(eval_expr(&IRExpr::DecisionTree(Box::new(node)), &ev), str_val("default"));
}

#[test]
fn decision_tree_switch_no_match_no_default_returns_null() {
    let ev = event_with("role", str_val("unknown"));
    let node = DecisionNode::Switch {
        subject: Box::new(event_ref("role")),
        cases: vec![DecisionCase {
            test: CaseTest::Literal(Literal::String(s("admin"))),
            body: DecisionNode::Leaf(Box::new(lit_bool(true))),
        }],
        default: None,
    };
    assert_eq!(eval_expr(&IRExpr::DecisionTree(Box::new(node)), &ev), Value::Null);
}

#[test]
fn decision_tree_switch_guard_case() {
    let ev = event_with("score", int(95));
    let guard = binary(BinaryOp::Ge, event_ref("score"), lit_int(90));
    let node = DecisionNode::Switch {
        subject: Box::new(lit_bool(true)), // subject ignored for guard cases
        cases: vec![DecisionCase {
            test: CaseTest::Guard(guard),
            body: DecisionNode::Leaf(Box::new(lit_str("high"))),
        }],
        default: Some(Box::new(DecisionNode::Leaf(Box::new(lit_str("low"))))),
    };
    assert_eq!(eval_expr(&IRExpr::DecisionTree(Box::new(node)), &ev), str_val("high"));
}
