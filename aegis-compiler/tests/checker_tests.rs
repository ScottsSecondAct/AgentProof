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
    Spanned::dummy(Expr::Literal(Literal::String(smol_str::SmolStr::new("msg"))))
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

fn field_access(object: Spanned<Expr>, field: &str) -> Spanned<Expr> {
    Spanned::dummy(Expr::FieldAccess {
        object: Box::new(object),
        field: ident(field),
    })
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
            .map(|v| Argument { name: None, value: v })
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

fn allow_verdict() -> Spanned<RuleClause> {
    Spanned::dummy(RuleClause::Verdict(VerdictClause {
        verdict: Spanned::dummy(Verdict::Allow),
        message: None,
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
        on_events: vec![ScopeTarget::Literal(Spanned::dummy(smol_str::SmolStr::new(
            event,
        )))],
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
        diags.diagnostics().iter().map(|d| d.code).collect::<Vec<_>>()
    );
}

/// Assert an exact error count.
fn assert_error_count(diags: &DiagnosticSink, n: usize) {
    assert_eq!(
        diags.error_count(),
        n,
        "expected {n} errors but got {}: {:?}",
        diags.error_count(),
        diags.diagnostics().iter().map(|d| &d.message).collect::<Vec<_>>()
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
        vec![rule_member("tool_call", vec![when_clause(q), deny_verdict()])],
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
        vec![rule_member("tool_call", vec![when_clause(q), deny_verdict()])],
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
        fn_decl(
            "is_safe",
            vec![],
            prim(PrimitiveType::Bool),
            bool_expr(),
        ),
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
        diags.diagnostics().iter().any(|d| d.code == DiagnosticCode::E0300
            && d.severity == Severity::Warning),
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
        diags.diagnostics().iter().any(|d| d.code == DiagnosticCode::E0301
            && d.severity == Severity::Warning),
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
    let prog = program(vec![policy_extends(
        "Derived",
        "NonExistentBase",
        vec![],
    )]);
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
            vec![when_clause(binary_expr(BinaryOp::Eq, expr, int_expr())), deny_verdict()],
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
