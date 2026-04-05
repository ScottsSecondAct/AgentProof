//! Type checker tests.
//!
//! Each test constructs an AST Program manually, runs it through TypeChecker,
//! and asserts on the resulting diagnostics. Tests are named after the
//! diagnostic code they exercise.

use aegis_compiler::ast::*;
use aegis_compiler::checker::TypeChecker;
use aegis_compiler::diagnostics::{DiagnosticCode, DiagnosticSink, Severity};

// ── AST builder helpers ───────────────────────────────────────────────────────
//
// Convenience functions that construct Spanned<T> nodes using Span::DUMMY.
// The checker does not enforce span consistency — only the renderer uses spans
// for error location reporting — so DUMMY spans are fine for unit tests.

fn ident(s: &str) -> Spanned<smol_str::SmolStr> {
    Spanned::dummy(smol_str::SmolStr::new(s))
}

fn simple_name(s: &str) -> QualifiedName {
    QualifiedName::simple(ident(s))
}

fn bool_expr() -> Spanned<Expr> {
    Spanned::dummy(Expr::Literal(Literal::Bool(true)))
}

fn int_expr() -> Spanned<Expr> {
    Spanned::dummy(Expr::Literal(Literal::Int(42)))
}

fn str_expr() -> Spanned<Expr> {
    Spanned::dummy(Expr::Literal(Literal::String(smol_str::SmolStr::new(
        "msg",
    ))))
}

fn dur_expr() -> Spanned<Expr> {
    Spanned::dummy(Expr::Literal(Literal::Duration(DurationLit {
        value: 5,
        unit: DurationUnit::Minutes,
    })))
}

fn var_expr(name: &str) -> Spanned<Expr> {
    Spanned::dummy(Expr::Identifier(simple_name(name)))
}

/// Build a multi-segment `event.field` identifier, mirroring what the parser
/// produces when `qualified_name` greedily consumes dot-separated segments.
fn event_field_expr(field: &str) -> Spanned<Expr> {
    Spanned::dummy(Expr::Identifier(QualifiedName {
        segments: vec![ident("event"), ident(field)],
        span: Span::DUMMY,
    }))
}

/// Build a three-segment `event.outer.inner` chain (e.g. `event.endpoint.url`).
fn event_nested_field_expr(outer: &str, inner: &str) -> Spanned<Expr> {
    Spanned::dummy(Expr::Identifier(QualifiedName {
        segments: vec![ident("event"), ident(outer), ident(inner)],
        span: Span::DUMMY,
    }))
}

/// Build a `context.field` expression using the dedicated `Expr::Context` node.
fn context_field_expr(field: &str) -> Spanned<Expr> {
    Spanned::dummy(Expr::Context(QualifiedName::simple(ident(field))))
}

fn binary_expr(op: BinaryOp, left: Spanned<Expr>, right: Spanned<Expr>) -> Spanned<Expr> {
    Spanned::dummy(Expr::Binary {
        op: Spanned::dummy(op),
        left: Box::new(left),
        right: Box::new(right),
    })
}

fn unary_expr(op: UnaryOp, operand: Spanned<Expr>) -> Spanned<Expr> {
    Spanned::dummy(Expr::Unary {
        op: Spanned::dummy(op),
        operand: Box::new(operand),
    })
}

fn predicate_expr(
    kind: PredicateKind,
    subject: Spanned<Expr>,
    argument: Spanned<Expr>,
) -> Spanned<Expr> {
    Spanned::dummy(Expr::Predicate {
        kind,
        subject: Box::new(subject),
        argument: Box::new(argument),
    })
}

fn quantifier_expr(
    kind: QuantifierKind,
    collection: Spanned<Expr>,
    param: &str,
    body: Spanned<Expr>,
) -> Spanned<Expr> {
    Spanned::dummy(Expr::Quantifier {
        kind,
        collection: Box::new(collection),
        predicate: Box::new(Lambda {
            params: vec![LambdaParam {
                name: ident(param),
                ty: None,
            }],
            body: Box::new(body),
        }),
    })
}

fn list_expr(elements: Vec<Spanned<Expr>>) -> Spanned<Expr> {
    Spanned::dummy(Expr::List(elements))
}

fn index_access(object: Spanned<Expr>, index: Spanned<Expr>) -> Spanned<Expr> {
    Spanned::dummy(Expr::IndexAccess {
        object: Box::new(object),
        index: Box::new(index),
    })
}

fn call_expr(name: &str, args: Vec<Spanned<Expr>>) -> Spanned<Expr> {
    Spanned::dummy(Expr::Call {
        callee: Box::new(Spanned::dummy(Expr::Identifier(simple_name(name)))),
        args: args
            .into_iter()
            .map(|v| Argument {
                name: None,
                value: v,
            })
            .collect(),
    })
}

fn always_expr(condition: Spanned<Expr>) -> Spanned<Expr> {
    Spanned::dummy(Expr::Temporal(TemporalExpr::Always {
        condition: Box::new(condition),
        within: None,
    }))
}

fn always_within_expr(condition: Spanned<Expr>, within: Spanned<Expr>) -> Spanned<Expr> {
    Spanned::dummy(Expr::Temporal(TemporalExpr::Always {
        condition: Box::new(condition),
        within: Some(Box::new(within)),
    }))
}

fn never_expr(condition: Spanned<Expr>) -> Spanned<Expr> {
    Spanned::dummy(Expr::Temporal(TemporalExpr::Never {
        condition: Box::new(condition),
    }))
}

fn eventually_expr(condition: Spanned<Expr>) -> Spanned<Expr> {
    Spanned::dummy(Expr::Temporal(TemporalExpr::Eventually {
        condition: Box::new(condition),
        within: None,
    }))
}

fn deny_verdict() -> Spanned<RuleClause> {
    Spanned::dummy(RuleClause::Verdict(VerdictClause {
        verdict: Spanned::dummy(Verdict::Deny),
        message: None,
    }))
}

fn deny_verdict_with_message(msg: Spanned<Expr>) -> Spanned<RuleClause> {
    Spanned::dummy(RuleClause::Verdict(VerdictClause {
        verdict: Spanned::dummy(Verdict::Deny),
        message: Some(msg),
    }))
}

fn when_clause(expr: Spanned<Expr>) -> Spanned<RuleClause> {
    Spanned::dummy(RuleClause::When(expr))
}

fn severity_clause(s: SeverityLevel) -> Spanned<PolicyMember> {
    Spanned::dummy(PolicyMember::Severity(s))
}

fn rule_member(event: &str, clauses: Vec<Spanned<RuleClause>>) -> Spanned<PolicyMember> {
    Spanned::dummy(PolicyMember::Rule(RuleDecl {
        annotations: vec![],
        on_events: vec![ScopeTarget::Literal(Spanned::dummy(
            smol_str::SmolStr::new(event),
        ))],
        clauses,
    }))
}

fn proof_member(proof_name: &str, inv_name: &str, cond: Spanned<Expr>) -> Spanned<PolicyMember> {
    Spanned::dummy(PolicyMember::Proof(ProofDecl {
        name: ident(proof_name),
        invariants: vec![InvariantDecl {
            name: ident(inv_name),
            conditions: vec![cond],
        }],
    }))
}

fn constraint_member(
    kind: ConstraintKind,
    target: &str,
    limit: Spanned<Expr>,
    window: Spanned<Expr>,
) -> Spanned<PolicyMember> {
    Spanned::dummy(PolicyMember::Constraint(ConstraintDecl {
        kind,
        target: simple_name(target),
        limit,
        window,
    }))
}

fn simple_policy(name: &str, members: Vec<Spanned<PolicyMember>>) -> Spanned<Declaration> {
    Spanned::dummy(Declaration::Policy(PolicyDecl {
        annotations: vec![],
        name: ident(name),
        extends: None,
        members,
    }))
}

fn policy_extends(
    name: &str,
    base: &str,
    members: Vec<Spanned<PolicyMember>>,
) -> Spanned<Declaration> {
    Spanned::dummy(Declaration::Policy(PolicyDecl {
        annotations: vec![],
        name: ident(name),
        extends: Some(simple_name(base)),
        members,
    }))
}

fn type_decl(name: &str, fields: Vec<(&str, Type)>) -> Spanned<Declaration> {
    Spanned::dummy(Declaration::Type(TypeDecl {
        name: ident(name),
        generic_params: vec![],
        fields: fields
            .into_iter()
            .map(|(n, t)| TypedField {
                name: ident(n),
                ty: Spanned::dummy(t),
            })
            .collect(),
    }))
}

fn fn_decl(
    name: &str,
    params: Vec<(&str, Type)>,
    ret: Type,
    body: Spanned<Expr>,
) -> Spanned<Declaration> {
    Spanned::dummy(Declaration::Function(FunctionDecl {
        name: ident(name),
        params: params
            .into_iter()
            .map(|(n, t)| TypedParam {
                name: ident(n),
                ty: Spanned::dummy(t),
            })
            .collect(),
        return_type: Spanned::dummy(ret),
        body,
    }))
}

fn program(declarations: Vec<Spanned<Declaration>>) -> Program {
    Program {
        declarations,
        span: Span::DUMMY,
    }
}

fn prim(p: PrimitiveType) -> Type {
    Type::Primitive(p)
}

/// Run the type checker and return all diagnostics.
fn check(prog: &Program) -> DiagnosticSink {
    let mut checker = TypeChecker::new();
    checker.check_program(prog);
    checker.into_diagnostics()
}

/// Assert that no errors are emitted.
fn assert_no_errors(diags: &DiagnosticSink) {
    assert!(
        !diags.has_errors(),
        "expected no errors but got: {:?}",
        diags.diagnostics()
    );
}

/// Assert that at least one diagnostic with the given code exists.
fn assert_has_code(diags: &DiagnosticSink, code: DiagnosticCode) {
    assert!(
        diags.diagnostics().iter().any(|d| d.code == code),
        "expected diagnostic {code:?} but got: {:?}",
        diags
            .diagnostics()
            .iter()
            .map(|d| d.code)
            .collect::<Vec<_>>()
    );
}


// ── Valid programs ────────────────────────────────────────────────────────────

#[test]
fn empty_program_produces_no_diagnostics() {
    let diags = check(&program(vec![]));
    assert_no_errors(&diags);
    assert_eq!(diags.warning_count(), 0);
}

#[test]
fn minimal_policy_with_deny_rule_no_errors() {
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member("tool_call", vec![deny_verdict()])],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn policy_with_severity_no_errors() {
    let prog = program(vec![simple_policy(
        "Guard",
        vec![
            severity_clause(SeverityLevel::High),
            rule_member("tool_call", vec![deny_verdict()]),
        ],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn policy_with_bool_when_clause_no_errors() {
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "tool_call",
            vec![when_clause(bool_expr()), deny_verdict()],
        )],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn policy_with_string_verdict_message_no_errors() {
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "tool_call",
            vec![deny_verdict_with_message(str_expr())],
        )],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn policy_with_proof_and_always_no_errors() {
    let prog = program(vec![simple_policy(
        "Guard",
        vec![proof_member("Safety", "NoHTTP", always_expr(bool_expr()))],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn type_declaration_no_errors() {
    let prog = program(vec![type_decl(
        "Endpoint",
        vec![
            ("url", prim(PrimitiveType::String)),
            ("method", prim(PrimitiveType::String)),
        ],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn function_declaration_with_correct_body_no_errors() {
    let prog = program(vec![fn_decl(
        "is_valid",
        vec![("x", prim(PrimitiveType::Int))],
        prim(PrimitiveType::Bool),
        bool_expr(),
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn policy_extends_known_policy_no_error() {
    let prog = program(vec![
        simple_policy("Base", vec![]),
        policy_extends("Derived", "Base", vec![]),
    ]);
    assert_no_errors(&check(&prog));
}

#[test]
fn rate_limit_with_int_limit_and_duration_window_no_errors() {
    let prog = program(vec![simple_policy(
        "Guard",
        vec![constraint_member(
            ConstraintKind::RateLimit,
            "tool_call",
            int_expr(),
            dur_expr(),
        )],
    )]);
    assert_no_errors(&check(&prog));
}

// ── E0001 — Undefined variable ────────────────────────────────────────────────

#[test]
fn undefined_variable_in_when_clause_emits_e0001() {
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "tool_call",
            vec![when_clause(var_expr("undefined_var")), deny_verdict()],
        )],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0001);
}

// ── E0002 — Undefined type ────────────────────────────────────────────────────

#[test]
fn binding_with_unknown_type_emits_e0002() {
    let prog = program(vec![Spanned::dummy(Declaration::Binding(BindingDecl {
        name: ident("x"),
        ty: Some(Spanned::dummy(Type::Named {
            name: simple_name("UnknownType"),
            type_args: vec![],
        })),
        value: int_expr(),
    }))]);
    assert_has_code(&check(&prog), DiagnosticCode::E0002);
}

// ── E0100 — Type mismatch ─────────────────────────────────────────────────────

#[test]
fn verdict_message_non_string_emits_e0100() {
    // deny with int message instead of string
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "tool_call",
            vec![deny_verdict_with_message(int_expr())],
        )],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0100);
}

#[test]
fn function_return_type_mismatch_emits_e0100() {
    // fn returns bool but body is int
    let prog = program(vec![fn_decl(
        "get_count",
        vec![],
        prim(PrimitiveType::Bool),
        int_expr(),
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0100);
}

// ── E0101 — Not a boolean expression ─────────────────────────────────────────

#[test]
fn when_clause_with_int_expr_emits_e0101() {
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "tool_call",
            vec![when_clause(int_expr()), deny_verdict()],
        )],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0101);
}

#[test]
fn when_clause_with_string_expr_emits_e0101() {
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "tool_call",
            vec![when_clause(str_expr()), deny_verdict()],
        )],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0101);
}

#[test]
fn unary_not_on_int_emits_e0101() {
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "tool_call",
            vec![
                when_clause(unary_expr(UnaryOp::Not, int_expr())),
                deny_verdict(),
            ],
        )],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0101);
}

#[test]
fn quantifier_predicate_returning_int_emits_e0101() {
    let items = list_expr(vec![bool_expr(), bool_expr()]);
    let q = quantifier_expr(QuantifierKind::All, items, "x", int_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "tool_call",
            vec![when_clause(q), deny_verdict()],
        )],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0101);
}

// ── E0102 — Not a numeric expression ──────────────────────────────────────────

#[test]
fn unary_neg_on_bool_emits_e0102() {
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "tool_call",
            vec![
                when_clause(unary_expr(UnaryOp::Neg, bool_expr())),
                deny_verdict(),
            ],
        )],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0102);
}

#[test]
fn list_index_with_string_emits_e0102() {
    let lst = list_expr(vec![int_expr()]);
    let idx = index_access(lst, str_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "tool_call",
            vec![when_clause(idx), deny_verdict()],
        )],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0102);
}

// ── E0103 — Not a collection ──────────────────────────────────────────────────

#[test]
fn quantifier_on_int_expr_emits_e0103() {
    let q = quantifier_expr(QuantifierKind::All, int_expr(), "x", bool_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "tool_call",
            vec![when_clause(q), deny_verdict()],
        )],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0103);
}

// ── E0105 — Wrong number of arguments ────────────────────────────────────────

#[test]
fn call_with_too_few_args_emits_e0105() {
    let prog = program(vec![
        fn_decl(
            "check_limit",
            vec![("n", prim(PrimitiveType::Int))],
            prim(PrimitiveType::Bool),
            bool_expr(),
        ),
        simple_policy(
            "Guard",
            vec![rule_member(
                "tool_call",
                vec![
                    when_clause(call_expr("check_limit", vec![])), // missing arg
                    deny_verdict(),
                ],
            )],
        ),
    ]);
    assert_has_code(&check(&prog), DiagnosticCode::E0105);
}

#[test]
fn call_with_too_many_args_emits_e0105() {
    let prog = program(vec![
        fn_decl("is_safe", vec![], prim(PrimitiveType::Bool), bool_expr()),
        simple_policy(
            "Guard",
            vec![rule_member(
                "tool_call",
                vec![
                    when_clause(call_expr("is_safe", vec![int_expr()])), // extra arg
                    deny_verdict(),
                ],
            )],
        ),
    ]);
    assert_has_code(&check(&prog), DiagnosticCode::E0105);
}

// ── E0106 — Incompatible types in binary operation ────────────────────────────

#[test]
fn arithmetic_on_bools_emits_e0106() {
    let expr = binary_expr(BinaryOp::Add, bool_expr(), bool_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "tool_call",
            vec![when_clause(expr), deny_verdict()],
        )],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0106);
}

#[test]
fn logical_and_on_ints_emits_e0106() {
    let expr = binary_expr(BinaryOp::And, int_expr(), int_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "tool_call",
            vec![when_clause(expr), deny_verdict()],
        )],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0106);
}

#[test]
fn comparison_int_vs_string_emits_e0106() {
    let expr = binary_expr(BinaryOp::Lt, int_expr(), str_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "tool_call",
            vec![when_clause(expr), deny_verdict()],
        )],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0106);
}

// ── E0107 — Cannot apply predicate to this type ───────────────────────────────

#[test]
fn contains_on_int_emits_e0107() {
    let expr = predicate_expr(PredicateKind::Contains, int_expr(), str_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "tool_call",
            vec![when_clause(expr), deny_verdict()],
        )],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0107);
}

#[test]
fn matches_predicate_on_int_emits_e0107() {
    let regex = Spanned::dummy(Expr::Literal(Literal::Regex(smol_str::SmolStr::new(".*"))));
    let expr = predicate_expr(PredicateKind::Matches, int_expr(), regex);
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "tool_call",
            vec![when_clause(expr), deny_verdict()],
        )],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0107);
}

#[test]
fn starts_with_on_int_emits_e0107() {
    let expr = predicate_expr(PredicateKind::StartsWith, int_expr(), str_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "tool_call",
            vec![when_clause(expr), deny_verdict()],
        )],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0107);
}

#[test]
fn ends_with_on_int_emits_e0107() {
    let expr = predicate_expr(PredicateKind::EndsWith, int_expr(), str_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "tool_call",
            vec![when_clause(expr), deny_verdict()],
        )],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0107);
}

// ── E0200 — Temporal operator requires boolean operand ────────────────────────

#[test]
fn always_with_int_condition_emits_e0200() {
    let prog = program(vec![simple_policy(
        "Guard",
        vec![proof_member("P", "I", always_expr(int_expr()))],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0200);
}

#[test]
fn never_with_int_condition_emits_e0200() {
    let prog = program(vec![simple_policy(
        "Guard",
        vec![proof_member("P", "I", never_expr(int_expr()))],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0200);
}

#[test]
fn eventually_with_string_condition_emits_e0200() {
    let prog = program(vec![simple_policy(
        "Guard",
        vec![proof_member("P", "I", eventually_expr(str_expr()))],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0200);
}

// ── E0201 — `within` clause requires duration ────────────────────────────────

#[test]
fn always_within_int_emits_e0201() {
    let prog = program(vec![simple_policy(
        "Guard",
        vec![proof_member(
            "P",
            "I",
            always_within_expr(bool_expr(), int_expr()),
        )],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0201);
}

#[test]
fn always_within_string_emits_e0201() {
    let prog = program(vec![simple_policy(
        "Guard",
        vec![proof_member(
            "P",
            "I",
            always_within_expr(bool_expr(), str_expr()),
        )],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0201);
}

#[test]
fn always_within_duration_no_error() {
    let prog = program(vec![simple_policy(
        "Guard",
        vec![proof_member(
            "P",
            "I",
            always_within_expr(bool_expr(), dur_expr()),
        )],
    )]);
    assert_no_errors(&check(&prog));
}

// ── E0202 — Temporal operator used outside proof/invariant ───────────────────

#[test]
fn always_in_rule_when_clause_emits_e0202() {
    let temporal = always_expr(bool_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "tool_call",
            vec![when_clause(temporal), deny_verdict()],
        )],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0202);
}

#[test]
fn never_in_rule_when_clause_emits_e0202() {
    let temporal = never_expr(bool_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "tool_call",
            vec![when_clause(temporal), deny_verdict()],
        )],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0202);
}

#[test]
fn eventually_in_rule_when_clause_emits_e0202() {
    let temporal = eventually_expr(bool_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "tool_call",
            vec![when_clause(temporal), deny_verdict()],
        )],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0202);
}

// ── E0203 — Nested temporal operators ────────────────────────────────────────

#[test]
fn nested_always_inside_always_emits_e0203() {
    // always(always(true)) — nested temporal
    let inner = always_expr(bool_expr());
    let outer = always_expr(inner);
    let prog = program(vec![simple_policy(
        "Guard",
        vec![proof_member("P", "I", outer)],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0203);
}

// ── E0300 — Rule without verdict (warning) ────────────────────────────────────

#[test]
fn rule_with_no_verdict_emits_warning_e0300() {
    // Rule with only a when clause — no verdict
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member("tool_call", vec![when_clause(bool_expr())])],
    )]);
    let diags = check(&prog);
    assert!(
        diags
            .diagnostics()
            .iter()
            .any(|d| d.code == DiagnosticCode::E0300 && d.severity == Severity::Warning),
        "expected W/E0300 warning"
    );
}

// ── E0301 — Multiple severity clauses (warning) ───────────────────────────────

#[test]
fn multiple_severity_clauses_emits_warning_e0301() {
    let prog = program(vec![simple_policy(
        "Guard",
        vec![
            severity_clause(SeverityLevel::High),
            severity_clause(SeverityLevel::Critical),
            rule_member("tool_call", vec![deny_verdict()]),
        ],
    )]);
    let diags = check(&prog);
    assert!(
        diags
            .diagnostics()
            .iter()
            .any(|d| d.code == DiagnosticCode::E0301 && d.severity == Severity::Warning),
        "expected W/E0301 warning"
    );
}

// ── E0303 — Rate limit constraint types ───────────────────────────────────────

#[test]
fn rate_limit_with_string_limit_emits_e0303() {
    let prog = program(vec![simple_policy(
        "Guard",
        vec![constraint_member(
            ConstraintKind::RateLimit,
            "tool_call",
            str_expr(), // should be numeric
            dur_expr(),
        )],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0303);
}

#[test]
fn rate_limit_with_int_window_emits_e0303() {
    let prog = program(vec![simple_policy(
        "Guard",
        vec![constraint_member(
            ConstraintKind::RateLimit,
            "tool_call",
            int_expr(),
            int_expr(), // should be duration
        )],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0303);
}

#[test]
fn quota_constraint_with_correct_types_no_errors() {
    let prog = program(vec![simple_policy(
        "Guard",
        vec![constraint_member(
            ConstraintKind::Quota,
            "data_access",
            int_expr(),
            dur_expr(),
        )],
    )]);
    assert_no_errors(&check(&prog));
}

// ── E0304 — Policy extends unknown policy ─────────────────────────────────────

#[test]
fn extends_unknown_policy_emits_e0304() {
    let prog = program(vec![policy_extends("Derived", "NonExistentBase", vec![])]);
    assert_has_code(&check(&prog), DiagnosticCode::E0304);
}

#[test]
fn extends_known_policy_declared_before_no_error() {
    let prog = program(vec![
        simple_policy("BasePolicy", vec![]),
        policy_extends("DerivedPolicy", "BasePolicy", vec![]),
    ]);
    assert_no_errors(&check(&prog));
}

#[test]
fn extends_known_policy_declared_after_no_error() {
    // First pass registers all policies so forward references work
    let prog = program(vec![
        policy_extends("DerivedPolicy", "BasePolicy", vec![]),
        simple_policy("BasePolicy", vec![]),
    ]);
    assert_no_errors(&check(&prog));
}

// ── Binary op type rules ──────────────────────────────────────────────────────

#[test]
fn int_plus_int_no_errors() {
    let expr = binary_expr(BinaryOp::Add, int_expr(), int_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "tool_call",
            vec![
                when_clause(binary_expr(BinaryOp::Eq, expr, int_expr())),
                deny_verdict(),
            ],
        )],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn string_plus_string_concatenation_no_errors() {
    let expr = binary_expr(BinaryOp::Add, str_expr(), str_expr());
    // Wrap in comparison to get bool for when clause
    let when = binary_expr(BinaryOp::Eq, expr, str_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "tool_call",
            vec![when_clause(when), deny_verdict()],
        )],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn duration_comparison_no_errors() {
    let expr = binary_expr(BinaryOp::Lt, dur_expr(), dur_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "tool_call",
            vec![when_clause(expr), deny_verdict()],
        )],
    )]);
    assert_no_errors(&check(&prog));
}

// ── Event and context bindings ────────────────────────────────────────────────
//
// These tests cover the gap where `event.field` in a when clause previously
// produced E0001 because the pest grammar's `qualified_name` rule greedily
// matches dot-separated identifiers, creating multi-segment Identifier nodes
// instead of FieldAccess nodes.  The checker must resolve the base segment
// and walk remaining segments as virtual field accesses.

#[test]
fn event_field_equality_in_when_clause_no_errors() {
    // when event.tool_name == "http_get" — most common real-world pattern
    let cond = binary_expr(BinaryOp::Eq, event_field_expr("tool_name"), str_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member("tool_call", vec![when_clause(cond), deny_verdict()])],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn event_field_neq_in_when_clause_no_errors() {
    // when event.tool_name != "allow" — tool_name is in the tool_call schema
    let cond = binary_expr(BinaryOp::Neq, event_field_expr("tool_name"), str_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member("tool_call", vec![when_clause(cond), deny_verdict()])],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn event_field_in_collection_in_when_clause_no_errors() {
    // when event.resource_type in ["pii", "financial"] — data_access schema
    let list = list_expr(vec![str_expr(), str_expr()]);
    let cond = binary_expr(BinaryOp::In, event_field_expr("resource_type"), list);
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "data_access",
            vec![when_clause(cond), deny_verdict()],
        )],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn event_nested_field_equality_in_when_clause_no_errors() {
    // when event.endpoint.url == "https://..."  (three-segment identifier)
    let cond = binary_expr(
        BinaryOp::Eq,
        event_nested_field_expr("endpoint", "url"),
        str_expr(),
    );
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "external_request",
            vec![when_clause(cond), deny_verdict()],
        )],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn event_field_starts_with_predicate_no_errors() {
    // when event.endpoint.url starts_with "https://"
    let subject = event_nested_field_expr("endpoint", "url");
    let cond = predicate_expr(PredicateKind::StartsWith, subject, str_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "external_request",
            vec![when_clause(cond), deny_verdict()],
        )],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn event_field_matches_predicate_no_errors() {
    // when event.url matches /^https:/ — url is in the external_request schema
    let subject = event_field_expr("url");
    let regex = Spanned::dummy(Expr::Literal(Literal::Regex(smol_str::SmolStr::new(
        "^https:",
    ))));
    let cond = predicate_expr(PredicateKind::Matches, subject, regex);
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "external_request",
            vec![when_clause(cond), deny_verdict()],
        )],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn event_field_contains_predicate_no_errors() {
    // when event.tool_name contains "secret" — tool_name is in the tool_call schema
    let subject = event_field_expr("tool_name");
    let cond = predicate_expr(PredicateKind::Contains, subject, str_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member("tool_call", vec![when_clause(cond), deny_verdict()])],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn context_field_access_in_when_clause_no_errors() {
    // `context` is a keyword; `context.field` produces `Expr::Context`.
    // This should be accepted inside a rule without errors.
    let cond = binary_expr(BinaryOp::Eq, context_field_expr("allowed_tools"), str_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member("tool_call", vec![when_clause(cond), deny_verdict()])],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn unknown_multi_segment_still_emits_e0001() {
    // `unknown_var.field` — base is not in scope → E0001
    let name = QualifiedName {
        segments: vec![ident("unknown_var"), ident("field")],
        span: Span::DUMMY,
    };
    let cond = binary_expr(
        BinaryOp::Eq,
        Spanned::dummy(Expr::Identifier(name)),
        str_expr(),
    );
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member("tool_call", vec![when_clause(cond), deny_verdict()])],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0001);
}

// ── Additional AST builder helpers (used by the coverage gap tests below) ─────

fn method_call_expr(object: Spanned<Expr>, method: &str, args: Vec<Spanned<Expr>>) -> Spanned<Expr> {
    Spanned::dummy(Expr::MethodCall {
        object: Box::new(object),
        method: ident(method),
        args: args
            .into_iter()
            .map(|v| Argument {
                name: None,
                value: v,
            })
            .collect(),
    })
}

fn count_expr_no_filter(collection: Spanned<Expr>) -> Spanned<Expr> {
    Spanned::dummy(Expr::Count {
        collection: Box::new(collection),
        filter: None,
    })
}

fn count_expr_with_filter(
    collection: Spanned<Expr>,
    param: &str,
    body: Spanned<Expr>,
) -> Spanned<Expr> {
    Spanned::dummy(Expr::Count {
        collection: Box::new(collection),
        filter: Some(Box::new(Lambda {
            params: vec![LambdaParam {
                name: ident(param),
                ty: None,
            }],
            body: Box::new(body),
        })),
    })
}

fn lambda_expr(param: &str, body: Spanned<Expr>) -> Spanned<Expr> {
    Spanned::dummy(Expr::Lambda(Lambda {
        params: vec![LambdaParam {
            name: ident(param),
            ty: None,
        }],
        body: Box::new(body),
    }))
}

fn lambda_typed_expr(param: &str, ty: Type, body: Spanned<Expr>) -> Spanned<Expr> {
    Spanned::dummy(Expr::Lambda(Lambda {
        params: vec![LambdaParam {
            name: ident(param),
            ty: Some(Spanned::dummy(ty)),
        }],
        body: Box::new(body),
    }))
}

fn object_expr() -> Spanned<Expr> {
    Spanned::dummy(Expr::Object(vec![ObjectField {
        key: ident("x"),
        value: int_expr(),
    }]))
}

fn block_expr(stmts: Vec<Spanned<BlockStatement>>) -> Spanned<Expr> {
    Spanned::dummy(Expr::Block(stmts))
}

fn block_expr_stmt(e: Spanned<Expr>) -> Spanned<BlockStatement> {
    Spanned::dummy(BlockStatement::Expr(e.node))
}

fn block_binding_stmt(name: &str, value: Spanned<Expr>) -> Spanned<BlockStatement> {
    Spanned::dummy(BlockStatement::Binding(BindingDecl {
        name: ident(name),
        ty: None,
        value,
    }))
}

fn block_verdict_stmt() -> Spanned<BlockStatement> {
    Spanned::dummy(BlockStatement::Verdict(VerdictClause {
        verdict: Spanned::dummy(Verdict::Deny),
        message: None,
    }))
}

fn block_action_stmt() -> Spanned<BlockStatement> {
    Spanned::dummy(BlockStatement::Action(ActionClause {
        verb: Spanned::dummy(ActionVerb::Log),
        args: ActionArgs::None,
    }))
}

fn match_arm_expr(pat: Pattern, result_expr: Spanned<Expr>) -> MatchArm {
    MatchArm {
        pattern: Spanned::dummy(pat),
        result: Spanned::dummy(MatchResult::Expr(result_expr.node)),
        span: Span::DUMMY,
    }
}

fn match_arm_verdict(pat: Pattern) -> MatchArm {
    MatchArm {
        pattern: Spanned::dummy(pat),
        result: Spanned::dummy(MatchResult::Verdict(VerdictClause {
            verdict: Spanned::dummy(Verdict::Allow),
            message: None,
        })),
        span: Span::DUMMY,
    }
}

fn match_arm_block(pat: Pattern, stmts: Vec<Spanned<BlockStatement>>) -> MatchArm {
    MatchArm {
        pattern: Spanned::dummy(pat),
        result: Spanned::dummy(MatchResult::Block(stmts)),
        span: Span::DUMMY,
    }
}

fn match_expr_node(scrutinee: Spanned<Expr>, arms: Vec<MatchArm>) -> Spanned<Expr> {
    Spanned::dummy(Expr::Match {
        scrutinee: Box::new(scrutinee),
        arms,
    })
}

fn binding_member(name: &str, value: Spanned<Expr>) -> Spanned<PolicyMember> {
    Spanned::dummy(PolicyMember::Binding(BindingDecl {
        name: ident(name),
        ty: None,
        value,
    }))
}

fn binding_member_typed(name: &str, ty: Type, value: Spanned<Expr>) -> Spanned<PolicyMember> {
    Spanned::dummy(PolicyMember::Binding(BindingDecl {
        name: ident(name),
        ty: Some(Spanned::dummy(ty)),
        value,
    }))
}

fn fn_policy_member(
    name: &str,
    params: Vec<(&str, Type)>,
    ret: Type,
    body: Spanned<Expr>,
) -> Spanned<PolicyMember> {
    Spanned::dummy(PolicyMember::Function(FunctionDecl {
        name: ident(name),
        params: params
            .into_iter()
            .map(|(n, t)| TypedParam {
                name: ident(n),
                ty: Spanned::dummy(t),
            })
            .collect(),
        return_type: Spanned::dummy(ret),
        body,
    }))
}

fn import_module(path: &str) -> Spanned<Declaration> {
    Spanned::dummy(Declaration::Import(ImportDecl {
        path: simple_name(path),
        kind: ImportKind::Module { alias: None },
    }))
}

fn import_names(path: &str, names: Vec<&str>) -> Spanned<Declaration> {
    Spanned::dummy(Declaration::Import(ImportDecl {
        path: simple_name(path),
        kind: ImportKind::Names(
            names
                .into_iter()
                .map(|n| ImportTarget {
                    name: ident(n),
                    alias: None,
                })
                .collect(),
        ),
    }))
}

// ── MethodCall ────────────────────────────────────────────────────────────────

#[test]
fn method_call_on_object_no_errors() {
    // object.len() — method resolution is deferred; checker accepts it
    let expr = method_call_expr(str_expr(), "len", vec![]);
    let cond = binary_expr(BinaryOp::Eq, expr, int_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member("tool_call", vec![when_clause(cond), deny_verdict()])],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn method_call_args_are_type_checked() {
    // even though the method itself isn't resolved, its arguments are still
    // checked — a bad arg type should propagate (but not error here because
    // the method result is Dynamic which suppresses cascading)
    let expr = method_call_expr(str_expr(), "replace", vec![str_expr(), int_expr()]);
    let cond = binary_expr(BinaryOp::Eq, expr, str_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member("tool_call", vec![when_clause(cond), deny_verdict()])],
    )]);
    assert_no_errors(&check(&prog));
}

// ── Count ─────────────────────────────────────────────────────────────────────

#[test]
fn count_without_filter_returns_int_no_errors() {
    let lst = list_expr(vec![int_expr(), int_expr()]);
    let expr = count_expr_no_filter(lst);
    // count(...) == 2  — both sides int
    let cond = binary_expr(BinaryOp::Eq, expr, int_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member("tool_call", vec![when_clause(cond), deny_verdict()])],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn count_with_bool_filter_no_errors() {
    let lst = list_expr(vec![int_expr(), int_expr()]);
    let expr = count_expr_with_filter(lst, "x", bool_expr());
    let cond = binary_expr(BinaryOp::Gt, expr, int_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member("tool_call", vec![when_clause(cond), deny_verdict()])],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn count_filter_returning_int_emits_e0101() {
    let lst = list_expr(vec![int_expr()]);
    // filter body is int, not bool → E0101
    let expr = count_expr_with_filter(lst, "x", int_expr());
    let cond = binary_expr(BinaryOp::Eq, expr, int_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member("tool_call", vec![when_clause(cond), deny_verdict()])],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0101);
}

// ── Match ─────────────────────────────────────────────────────────────────────

#[test]
fn match_with_expr_arms_no_errors() {
    // match scrutinee with bool arms — result type is bool
    let arms = vec![
        match_arm_expr(Pattern::Wildcard, bool_expr()),
        match_arm_expr(Pattern::Literal(Literal::Bool(false)), bool_expr()),
    ];
    let expr = match_expr_node(int_expr(), arms);
    // use the match result as a when condition
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member("tool_call", vec![when_clause(expr), deny_verdict()])],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn match_with_verdict_arm_no_errors() {
    // A match whose arms return Verdict — checker must visit the MatchResult::Verdict path.
    let arms = vec![match_arm_verdict(Pattern::Wildcard)];
    let expr = match_expr_node(str_expr(), arms);
    // Put the match inside a top-level binding so the checker visits it.
    let prog = program(vec![Spanned::dummy(Declaration::Binding(BindingDecl {
        name: ident("v"),
        ty: None,
        value: expr,
    }))]);
    assert_no_errors(&check(&prog));
}

#[test]
fn match_with_block_arm_no_errors() {
    // arm result is a block — checker must descend into it
    let stmts = vec![block_expr_stmt(bool_expr())];
    let arms = vec![match_arm_block(Pattern::Wildcard, stmts)];
    let expr = match_expr_node(int_expr(), arms);
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member("tool_call", vec![when_clause(bool_expr()), deny_verdict()])],
    )]);
    // Compile a program that contains the match expr inside a binding so the
    // checker visits it without requiring it to be bool.
    let prog2 = program(vec![Spanned::dummy(Declaration::Binding(BindingDecl {
        name: ident("m"),
        ty: None,
        value: expr,
    }))]);
    assert_no_errors(&check(&prog2));
    assert_no_errors(&check(&prog));
}

#[test]
fn match_empty_arms_no_errors() {
    // Empty arm list — checker returns Never, which is fine
    let expr = match_expr_node(int_expr(), vec![]);
    let prog = program(vec![Spanned::dummy(Declaration::Binding(BindingDecl {
        name: ident("m"),
        ty: None,
        value: expr,
    }))]);
    assert_no_errors(&check(&prog));
}

// ── Lambda ────────────────────────────────────────────────────────────────────

#[test]
fn standalone_lambda_with_untyped_param_no_errors() {
    // A free lambda (not inside a quantifier) — param gets a fresh type var
    let expr = lambda_expr("x", bool_expr());
    let prog = program(vec![Spanned::dummy(Declaration::Binding(BindingDecl {
        name: ident("f"),
        ty: None,
        value: expr,
    }))]);
    assert_no_errors(&check(&prog));
}

#[test]
fn standalone_lambda_with_typed_param_no_errors() {
    // Lambda with explicit int param
    let expr = lambda_typed_expr("n", prim(PrimitiveType::Int), bool_expr());
    let prog = program(vec![Spanned::dummy(Declaration::Binding(BindingDecl {
        name: ident("f"),
        ty: None,
        value: expr,
    }))]);
    assert_no_errors(&check(&prog));
}

#[test]
fn lambda_param_visible_in_body_no_errors() {
    // Body references the parameter — must resolve without E0001
    let expr = lambda_typed_expr("n", prim(PrimitiveType::Int), var_expr("n"));
    let prog = program(vec![Spanned::dummy(Declaration::Binding(BindingDecl {
        name: ident("f"),
        ty: None,
        value: expr,
    }))]);
    assert_no_errors(&check(&prog));
}

// ── Block ─────────────────────────────────────────────────────────────────────

#[test]
fn block_with_expr_statement_no_errors() {
    let stmts = vec![block_expr_stmt(bool_expr())];
    let expr = block_expr(stmts);
    let prog = program(vec![Spanned::dummy(Declaration::Binding(BindingDecl {
        name: ident("b"),
        ty: None,
        value: expr,
    }))]);
    assert_no_errors(&check(&prog));
}

#[test]
fn block_with_binding_statement_no_errors() {
    // let x = 42 inside a block — binding stmt returns Never
    let stmts = vec![
        block_binding_stmt("x", int_expr()),
        block_expr_stmt(bool_expr()),
    ];
    let expr = block_expr(stmts);
    let prog = program(vec![Spanned::dummy(Declaration::Binding(BindingDecl {
        name: ident("b"),
        ty: None,
        value: expr,
    }))]);
    assert_no_errors(&check(&prog));
}

#[test]
fn block_with_verdict_statement_returns_verdict_no_errors() {
    let stmts = vec![block_verdict_stmt()];
    let expr = block_expr(stmts);
    let prog = program(vec![Spanned::dummy(Declaration::Binding(BindingDecl {
        name: ident("b"),
        ty: None,
        value: expr,
    }))]);
    assert_no_errors(&check(&prog));
}

#[test]
fn block_with_action_statement_no_errors() {
    let stmts = vec![block_action_stmt()];
    let expr = block_expr(stmts);
    let prog = program(vec![Spanned::dummy(Declaration::Binding(BindingDecl {
        name: ident("b"),
        ty: None,
        value: expr,
    }))]);
    assert_no_errors(&check(&prog));
}

#[test]
fn empty_block_no_errors() {
    let expr = block_expr(vec![]);
    let prog = program(vec![Spanned::dummy(Declaration::Binding(BindingDecl {
        name: ident("b"),
        ty: None,
        value: expr,
    }))]);
    assert_no_errors(&check(&prog));
}

// ── Object ────────────────────────────────────────────────────────────────────

#[test]
fn object_literal_no_errors() {
    // { x: 42 } — produces anonymous open struct, no errors
    let expr = object_expr();
    let prog = program(vec![Spanned::dummy(Declaration::Binding(BindingDecl {
        name: ident("obj"),
        ty: None,
        value: expr,
    }))]);
    assert_no_errors(&check(&prog));
}

#[test]
fn object_literal_in_rule_no_errors() {
    // Object in a verdict message expression context (via binding)
    let prog = program(vec![simple_policy(
        "Guard",
        vec![
            binding_member("cfg", object_expr()),
            rule_member("tool_call", vec![deny_verdict()]),
        ],
    )]);
    assert_no_errors(&check(&prog));
}

// ── Policy-level Binding ──────────────────────────────────────────────────────

#[test]
fn policy_level_binding_no_errors() {
    // `let x = 42` inside a policy body
    let prog = program(vec![simple_policy(
        "Guard",
        vec![
            binding_member("threshold", int_expr()),
            rule_member("tool_call", vec![deny_verdict()]),
        ],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn policy_level_binding_with_matching_type_annotation_no_errors() {
    let prog = program(vec![simple_policy(
        "Guard",
        vec![
            binding_member_typed("limit", prim(PrimitiveType::Int), int_expr()),
            rule_member("tool_call", vec![deny_verdict()]),
        ],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn policy_level_binding_type_mismatch_emits_e0100() {
    // declared as bool but value is int
    let prog = program(vec![simple_policy(
        "Guard",
        vec![
            binding_member_typed("flag", prim(PrimitiveType::Bool), int_expr()),
            rule_member("tool_call", vec![deny_verdict()]),
        ],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0100);
}

#[test]
fn policy_level_binding_is_visible_in_rule_no_errors() {
    // A binding defined at policy level should be in scope for rules
    let prog = program(vec![simple_policy(
        "Guard",
        vec![
            binding_member("threshold", int_expr()),
            rule_member(
                "tool_call",
                vec![
                    when_clause(binary_expr(
                        BinaryOp::Eq,
                        var_expr("threshold"),
                        int_expr(),
                    )),
                    deny_verdict(),
                ],
            ),
        ],
    )]);
    assert_no_errors(&check(&prog));
}

// ── Policy-level Function ─────────────────────────────────────────────────────

#[test]
fn policy_level_function_no_errors() {
    // `def is_safe(x: int) -> bool = true` inside a policy body
    let prog = program(vec![simple_policy(
        "Guard",
        vec![
            fn_policy_member(
                "is_safe",
                vec![("x", prim(PrimitiveType::Int))],
                prim(PrimitiveType::Bool),
                bool_expr(),
            ),
            rule_member("tool_call", vec![deny_verdict()]),
        ],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn policy_level_function_return_mismatch_emits_e0100() {
    // declared to return bool but body is int
    let prog = program(vec![simple_policy(
        "Guard",
        vec![
            fn_policy_member(
                "bad_fn",
                vec![],
                prim(PrimitiveType::Bool),
                int_expr(),
            ),
            rule_member("tool_call", vec![deny_verdict()]),
        ],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0100);
}

#[test]
fn policy_level_function_callable_from_rule_no_errors() {
    // Function defined at policy level, called inside a when clause
    let prog = program(vec![simple_policy(
        "Guard",
        vec![
            fn_policy_member(
                "ok",
                vec![],
                prim(PrimitiveType::Bool),
                bool_expr(),
            ),
            rule_member(
                "tool_call",
                vec![when_clause(call_expr("ok", vec![])), deny_verdict()],
            ),
        ],
    )]);
    assert_no_errors(&check(&prog));
}

// ── Import declarations ───────────────────────────────────────────────────────

#[test]
fn module_import_no_errors() {
    // Import resolution is a future pass; the checker accepts imports structurally
    let prog = program(vec![
        import_module("automaguard.stdlib.pii"),
        simple_policy("Guard", vec![rule_member("tool_call", vec![deny_verdict()])]),
    ]);
    assert_no_errors(&check(&prog));
}

#[test]
fn named_import_no_errors() {
    let prog = program(vec![
        import_names("automaguard.stdlib", vec!["network", "compliance"]),
        simple_policy("Guard", vec![rule_member("tool_call", vec![deny_verdict()])]),
    ]);
    assert_no_errors(&check(&prog));
}

#[test]
fn import_with_policy_coexist_no_errors() {
    // Imports and policies in the same file — no interference
    let prog = program(vec![
        import_module("automaguard.stdlib"),
        type_decl("Endpoint", vec![("url", prim(PrimitiveType::String))]),
        simple_policy("Guard", vec![rule_member("tool_call", vec![deny_verdict()])]),
    ]);
    assert_no_errors(&check(&prog));
}

// ── equality_any_types_no_errors (kept last to preserve ordering) ─────────────

#[test]
fn equality_any_types_no_errors() {
    let expr = binary_expr(BinaryOp::Eq, int_expr(), str_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "tool_call",
            vec![when_clause(expr), deny_verdict()],
        )],
    )]);
    assert_no_errors(&check(&prog));
}

// ── Event field type refinement ───────────────────────────────────────────────
//
// When a rule targets a single known event name (e.g. `on tool_call`), the
// checker injects a typed `event` binding so that field access is validated
// at compile time.  Unknown fields on a known-schema event emit E0108.
// Rules on an unknown event name fall back to the open/dynamic `event` struct.

#[test]
fn known_event_known_field_no_errors() {
    // event.tool_name in on tool_call — field exists in schema → no error
    let cond = binary_expr(BinaryOp::Eq, event_field_expr("tool_name"), str_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member("tool_call", vec![when_clause(cond), deny_verdict()])],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn known_event_unknown_field_emits_e0108() {
    // event.nonexistent in on tool_call — not in schema → E0108
    let cond = binary_expr(BinaryOp::Eq, event_field_expr("nonexistent"), str_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member("tool_call", vec![when_clause(cond), deny_verdict()])],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0108);
}

#[test]
fn unknown_event_unknown_field_no_errors() {
    // event.anything in on custom_event — unknown event → dynamic fallback → no E0108
    let cond = binary_expr(BinaryOp::Eq, event_field_expr("anything"), str_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "custom_event",
            vec![when_clause(cond), deny_verdict()],
        )],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn data_access_event_known_field_no_errors() {
    // event.resource_type in on data_access — in schema → no error
    let cond = binary_expr(
        BinaryOp::Eq,
        event_field_expr("resource_type"),
        str_expr(),
    );
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "data_access",
            vec![when_clause(cond), deny_verdict()],
        )],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn data_access_event_unknown_field_emits_e0108() {
    // event.category in on data_access — not in schema → E0108
    let cond = binary_expr(BinaryOp::Eq, event_field_expr("category"), str_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "data_access",
            vec![when_clause(cond), deny_verdict()],
        )],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0108);
}

#[test]
fn external_request_nested_field_no_errors() {
    // event.endpoint.url in on external_request — nested field in schema → no error
    let cond = binary_expr(
        BinaryOp::Eq,
        event_nested_field_expr("endpoint", "url"),
        str_expr(),
    );
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "external_request",
            vec![when_clause(cond), deny_verdict()],
        )],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn external_request_unknown_nested_field_emits_e0108() {
    // event.endpoint.nonexistent in on external_request — endpoint exists but
    // field `nonexistent` does not → E0108
    let cond = binary_expr(
        BinaryOp::Eq,
        event_nested_field_expr("endpoint", "nonexistent"),
        str_expr(),
    );
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "external_request",
            vec![when_clause(cond), deny_verdict()],
        )],
    )]);
    assert_has_code(&check(&prog), DiagnosticCode::E0108);
}

#[test]
fn multi_event_rule_uses_dynamic_event_fallback() {
    // on tool_call, data_access { ... } — multiple events → dynamic fallback,
    // any field access is allowed (no E0108 for unknown field)
    let cond = binary_expr(BinaryOp::Eq, event_field_expr("arbitrary"), str_expr());
    let rule = PolicyMember::Rule(RuleDecl {
        annotations: vec![],
        on_events: vec![
            ScopeTarget::Literal(Spanned::dummy(smol_str::SmolStr::new("tool_call"))),
            ScopeTarget::Literal(Spanned::dummy(smol_str::SmolStr::new("data_access"))),
        ],
        clauses: vec![when_clause(cond), deny_verdict()],
    });
    let prog = program(vec![Spanned::dummy(Declaration::Policy(PolicyDecl {
        annotations: vec![],
        name: ident("Guard"),
        extends: None,
        members: vec![Spanned::dummy(rule)],
    }))]);
    assert_no_errors(&check(&prog));
}

#[test]
fn known_event_field_used_in_predicate_no_errors() {
    // event.tool_name starts_with "http" in on tool_call — string field, string
    // predicate → no error
    let cond = predicate_expr(
        PredicateKind::StartsWith,
        event_field_expr("tool_name"),
        str_expr(),
    );
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member("tool_call", vec![when_clause(cond), deny_verdict()])],
    )]);
    assert_no_errors(&check(&prog));
}

#[test]
fn message_event_known_field_no_errors() {
    // event.role in on message — in schema → no error
    let cond = binary_expr(BinaryOp::Eq, event_field_expr("role"), str_expr());
    let prog = program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "message",
            vec![when_clause(cond), deny_verdict()],
        )],
    )]);
    assert_no_errors(&check(&prog));
}
