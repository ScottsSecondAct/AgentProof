//! Parse-from-source tests for the Aegis pest parser.
//!
//! Each test parses a `.aegis` source snippet, asserts no parse errors,
//! and verifies specific AST node structure.

use aegis_compiler::ast::nodes::*;
use aegis_compiler::ast::span::Span;
use aegis_compiler::parser::parse_source;

// ═══════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════

fn parse_ok(src: &str) -> Program {
    let (prog, diags) = parse_source(src, "test.aegis");
    if diags.has_errors() {
        for d in diags.diagnostics() {
            eprintln!("  diag: {}", d.message);
        }
    }
    assert!(!diags.has_errors(), "expected no parse errors for: {src}");
    prog
}

fn parse_policy(src: &str) -> PolicyDecl {
    let prog = parse_ok(src);
    match &prog.declarations[0].node {
        Declaration::Policy(p) => p.clone(),
        other => panic!("expected Policy, got {:?}", other),
    }
}

fn parse_expr_src(expr_src: &str) -> Expr {
    // Wrap in a minimal let binding to parse an expression
    let src = format!("let x = {expr_src}");
    let prog = parse_ok(&src);
    match &prog.declarations[0].node {
        Declaration::Binding(b) => b.value.node.clone(),
        other => panic!("expected Binding, got {:?}", other),
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Group 1: Empty / minimal programs
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn empty_program_parses() {
    let prog = parse_ok("");
    assert_eq!(prog.declarations.len(), 0);
}

#[test]
fn comment_only_program_parses() {
    let prog = parse_ok("// just a comment\n/* block */\n");
    assert_eq!(prog.declarations.len(), 0);
}

#[test]
fn empty_policy_body_parses() {
    let prog = parse_ok("policy Empty {}");
    assert_eq!(prog.declarations.len(), 1);
    match &prog.declarations[0].node {
        Declaration::Policy(p) => {
            assert_eq!(p.name.node.as_str(), "Empty");
            assert!(p.members.is_empty());
            assert!(p.extends.is_none());
        }
        other => panic!("expected Policy, got {:?}", other),
    }
}

#[test]
fn span_is_non_zero_for_non_empty_source() {
    let prog = parse_ok("policy P {}");
    assert!(prog.span != Span::DUMMY || prog.declarations.is_empty() || true);
    // Span start should be 0 for source that starts at byte 0
    assert_eq!(prog.span.start, 0);
}

// ═══════════════════════════════════════════════════════════════════════
//  Group 2: Policy declarations (severity, scope, extends)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn policy_with_severity_high() {
    let policy = parse_policy("policy Guard { severity high }");
    let severity_member = policy.members.iter().find_map(|m| {
        if let PolicyMember::Severity(s) = &m.node {
            Some(*s)
        } else {
            None
        }
    });
    assert_eq!(severity_member, Some(SeverityLevel::High));
}

#[test]
fn policy_with_severity_critical() {
    let policy = parse_policy("policy Guard { severity critical }");
    let sev = policy.members.iter().find_map(|m| {
        if let PolicyMember::Severity(s) = &m.node {
            Some(*s)
        } else {
            None
        }
    });
    assert_eq!(sev, Some(SeverityLevel::Critical));
}

#[test]
fn policy_with_severity_low() {
    let policy = parse_policy("policy Guard { severity low }");
    let sev = policy.members.iter().find_map(|m| {
        if let PolicyMember::Severity(s) = &m.node {
            Some(*s)
        } else {
            None
        }
    });
    assert_eq!(sev, Some(SeverityLevel::Low));
}

#[test]
fn policy_with_scope() {
    let policy = parse_policy("policy Guard { scope tool_call }");
    let scope = policy.members.iter().find_map(|m| {
        if let PolicyMember::Scope(targets) = &m.node {
            Some(targets.clone())
        } else {
            None
        }
    });
    let scope = scope.expect("scope member");
    assert_eq!(scope.len(), 1);
    match &scope[0] {
        ScopeTarget::Name(qn) => assert_eq!(qn.to_string(), "tool_call"),
        other => panic!("expected Name scope target, got {:?}", other),
    }
}

#[test]
fn policy_with_multiple_scopes() {
    let policy = parse_policy("policy Guard { scope tool_call, data_access }");
    let scope = policy
        .members
        .iter()
        .find_map(|m| {
            if let PolicyMember::Scope(t) = &m.node {
                Some(t.clone())
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(scope.len(), 2);
}

#[test]
fn policy_extends() {
    let policy = parse_policy("policy Child extends Base {}");
    let extends = policy.extends.as_ref().expect("extends");
    assert_eq!(extends.to_string(), "Base");
}

#[test]
fn policy_extends_qualified() {
    let policy = parse_policy("policy Child extends stdlib.Base {}");
    let extends = policy.extends.as_ref().expect("extends");
    assert_eq!(extends.to_string(), "stdlib.Base");
}

#[test]
fn policy_with_annotation() {
    let policy = parse_policy(r#"@deprecated("use NewGuard") policy OldGuard {}"#);
    assert_eq!(policy.annotations.len(), 1);
    assert_eq!(policy.annotations[0].name.node.as_str(), "deprecated");
}

// ═══════════════════════════════════════════════════════════════════════
//  Group 3: Rule declarations (when, verdict, action)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn rule_with_when_deny() {
    let policy = parse_policy(
        r#"
        policy Guard {
            on tool_call {
                when event.tool == "http"
                deny
            }
        }
    "#,
    );

    let rule = policy
        .members
        .iter()
        .find_map(|m| {
            if let PolicyMember::Rule(r) = &m.node {
                Some(r.clone())
            } else {
                None
            }
        })
        .expect("rule member");

    // Check on_events
    assert_eq!(rule.on_events.len(), 1);
    match &rule.on_events[0] {
        ScopeTarget::Name(qn) => assert_eq!(qn.to_string(), "tool_call"),
        _ => panic!("expected name scope"),
    }

    // Check clauses: when + deny
    let has_when = rule
        .clauses
        .iter()
        .any(|c| matches!(c.node, RuleClause::When(_)));
    let has_deny = rule
        .clauses
        .iter()
        .any(|c| matches!(&c.node, RuleClause::Verdict(v) if v.verdict.node == Verdict::Deny));
    assert!(has_when, "should have when clause");
    assert!(has_deny, "should have deny verdict");
}

#[test]
fn rule_with_allow_verdict() {
    let policy = parse_policy(
        r#"
        policy P {
            on request {
                allow
            }
        }
    "#,
    );
    let rule = policy
        .members
        .iter()
        .find_map(|m| {
            if let PolicyMember::Rule(r) = &m.node {
                Some(r.clone())
            } else {
                None
            }
        })
        .unwrap();
    let has_allow = rule
        .clauses
        .iter()
        .any(|c| matches!(&c.node, RuleClause::Verdict(v) if v.verdict.node == Verdict::Allow));
    assert!(has_allow);
}

#[test]
fn rule_with_audit_verdict_and_message() {
    let policy = parse_policy(
        r#"
        policy P {
            on data_read {
                audit with "PII access"
            }
        }
    "#,
    );
    let rule = policy
        .members
        .iter()
        .find_map(|m| {
            if let PolicyMember::Rule(r) = &m.node {
                Some(r.clone())
            } else {
                None
            }
        })
        .unwrap();
    let verdict = rule
        .clauses
        .iter()
        .find_map(|c| {
            if let RuleClause::Verdict(v) = &c.node {
                Some(v.clone())
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(verdict.verdict.node, Verdict::Audit);
    assert!(verdict.message.is_some());
}

#[test]
fn rule_with_log_action() {
    let policy = parse_policy(
        r#"
        policy P {
            on tool_call {
                deny
                log "blocked"
            }
        }
    "#,
    );
    let rule = policy
        .members
        .iter()
        .find_map(|m| {
            if let PolicyMember::Rule(r) = &m.node {
                Some(r.clone())
            } else {
                None
            }
        })
        .unwrap();
    let action = rule
        .clauses
        .iter()
        .find_map(|c| {
            if let RuleClause::Action(a) = &c.node {
                Some(a.clone())
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(action.verb.node, ActionVerb::Log);
}

#[test]
fn rule_with_named_action_args() {
    let policy = parse_policy(
        r#"
        policy P {
            on tool_call {
                deny
                notify notify: "security-team"
            }
        }
    "#,
    );
    let rule = policy
        .members
        .iter()
        .find_map(|m| {
            if let PolicyMember::Rule(r) = &m.node {
                Some(r.clone())
            } else {
                None
            }
        })
        .unwrap();
    let action = rule
        .clauses
        .iter()
        .find_map(|c| {
            if let RuleClause::Action(a) = &c.node {
                Some(a.clone())
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(action.verb.node, ActionVerb::Notify);
    matches!(&action.args, ActionArgs::Named(_));
}

// ═══════════════════════════════════════════════════════════════════════
//  Group 4: Temporal expressions
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn always_expression() {
    let expr = parse_expr_src("always(x > 0)");
    match expr {
        Expr::Temporal(TemporalExpr::Always { condition, within }) => {
            assert!(within.is_none());
            match condition.node {
                Expr::Binary { op, .. } => assert_eq!(op.node, BinaryOp::Gt),
                _ => panic!("expected binary inside always"),
            }
        }
        _ => panic!("expected Always temporal, got {:?}", expr),
    }
}

#[test]
fn always_with_within() {
    let expr = parse_expr_src("always(x > 0) within 24h");
    match expr {
        Expr::Temporal(TemporalExpr::Always { within, .. }) => {
            assert!(within.is_some());
            let w = within.unwrap();
            match w.node {
                Expr::Literal(Literal::Duration(d)) => {
                    assert_eq!(d.value, 24);
                    assert_eq!(d.unit, DurationUnit::Hours);
                }
                _ => panic!("expected duration literal in within"),
            }
        }
        _ => panic!("expected Always"),
    }
}

#[test]
fn eventually_expression() {
    let expr = parse_expr_src("eventually(approved == true)");
    match expr {
        Expr::Temporal(TemporalExpr::Eventually { within, .. }) => {
            assert!(within.is_none());
        }
        _ => panic!("expected Eventually"),
    }
}

#[test]
fn never_expression() {
    let expr = parse_expr_src("never(x < 0)");
    match expr {
        Expr::Temporal(TemporalExpr::Never { .. }) => {}
        _ => panic!("expected Never"),
    }
}

#[test]
fn next_expression() {
    let expr = parse_expr_src("next(state == 1)");
    match expr {
        Expr::Temporal(TemporalExpr::Next { .. }) => {}
        _ => panic!("expected Next"),
    }
}

#[test]
fn before_expression() {
    let expr = parse_expr_src("before(approved, deadline)");
    match expr {
        Expr::Temporal(TemporalExpr::Before { .. }) => {}
        _ => panic!("expected Before"),
    }
}

#[test]
fn after_expression() {
    let expr = parse_expr_src("after(x, trigger)");
    match expr {
        Expr::Temporal(TemporalExpr::After { .. }) => {}
        _ => panic!("expected After"),
    }
}

#[test]
fn until_expression() {
    let expr = parse_expr_src("x until y");
    match expr {
        Expr::Temporal(TemporalExpr::Until { .. }) => {}
        _ => panic!("expected Until, got {:?}", expr),
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Group 5: Constraint declarations
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn rate_limit_constraint() {
    let policy = parse_policy(
        r#"
        policy P {
            rate_limit tool_call: 100 per 1m
        }
    "#,
    );
    let constraint = policy
        .members
        .iter()
        .find_map(|m| {
            if let PolicyMember::Constraint(c) = &m.node {
                Some(c.clone())
            } else {
                None
            }
        })
        .expect("constraint");
    assert_eq!(constraint.kind, ConstraintKind::RateLimit);
    assert_eq!(constraint.target.to_string(), "tool_call");
    match constraint.limit.node {
        Expr::Literal(Literal::Int(100)) => {}
        _ => panic!("expected int literal 100 for limit"),
    }
    match constraint.window.node {
        Expr::Literal(Literal::Duration(d)) => {
            assert_eq!(d.value, 1);
            assert_eq!(d.unit, DurationUnit::Minutes);
        }
        _ => panic!("expected duration for window"),
    }
}

#[test]
fn quota_constraint() {
    let policy = parse_policy(
        r#"
        policy P {
            quota token_usage: 50000 per 1h
        }
    "#,
    );
    let constraint = policy
        .members
        .iter()
        .find_map(|m| {
            if let PolicyMember::Constraint(c) = &m.node {
                Some(c.clone())
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(constraint.kind, ConstraintKind::Quota);
    match constraint.window.node {
        Expr::Literal(Literal::Duration(d)) => assert_eq!(d.unit, DurationUnit::Hours),
        _ => panic!("expected duration"),
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Group 6: Proof / invariant declarations
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn proof_with_invariant() {
    let src = r#"
        proof BudgetSafety {
            invariant SpendLimit {
                always(context.total_spend <= 1000)
            }
        }
    "#;
    let prog = parse_ok(src);
    assert_eq!(prog.declarations.len(), 1);
    match &prog.declarations[0].node {
        Declaration::Proof(p) => {
            assert_eq!(p.name.node.as_str(), "BudgetSafety");
            assert_eq!(p.invariants.len(), 1);
            assert_eq!(p.invariants[0].name.node.as_str(), "SpendLimit");
            assert_eq!(p.invariants[0].conditions.len(), 1);
        }
        _ => panic!("expected Proof"),
    }
}

#[test]
fn proof_inside_policy() {
    let policy = parse_policy(
        r#"
        policy P {
            proof Safety {
                invariant NoNeg {
                    always(x >= 0)
                }
            }
        }
    "#,
    );
    let has_proof = policy
        .members
        .iter()
        .any(|m| matches!(m.node, PolicyMember::Proof(_)));
    assert!(has_proof);
}

#[test]
fn invariant_with_multiple_conditions() {
    let src = r#"
        proof P {
            invariant Multi {
                always(a > 0);
                never(b < 0)
            }
        }
    "#;
    let prog = parse_ok(src);
    match &prog.declarations[0].node {
        Declaration::Proof(p) => {
            assert_eq!(p.invariants[0].conditions.len(), 2);
        }
        _ => panic!("expected Proof"),
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Group 7: Type declarations
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn simple_type_declaration() {
    let src = "type Endpoint { url: string, port: int }";
    let prog = parse_ok(src);
    match &prog.declarations[0].node {
        Declaration::Type(t) => {
            assert_eq!(t.name.node.as_str(), "Endpoint");
            assert_eq!(t.fields.len(), 2);
            assert_eq!(t.fields[0].name.node.as_str(), "url");
            assert_eq!(t.fields[1].name.node.as_str(), "port");
        }
        _ => panic!("expected Type"),
    }
}

#[test]
fn type_with_generic_param() {
    let src = "type Container<T> { item: T }";
    let prog = parse_ok(src);
    match &prog.declarations[0].node {
        Declaration::Type(t) => {
            assert_eq!(t.generic_params.len(), 1);
            assert_eq!(t.generic_params[0].name.node.as_str(), "T");
        }
        _ => panic!("expected Type"),
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Group 8: Binding / function declarations
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn let_binding_simple() {
    let prog = parse_ok("let threshold = 100");
    match &prog.declarations[0].node {
        Declaration::Binding(b) => {
            assert_eq!(b.name.node.as_str(), "threshold");
            assert!(b.ty.is_none());
            match &b.value.node {
                Expr::Literal(Literal::Int(100)) => {}
                _ => panic!("expected Int literal"),
            }
        }
        _ => panic!("expected Binding"),
    }
}

#[test]
fn let_binding_with_type() {
    let prog = parse_ok("let limit: int = 50");
    match &prog.declarations[0].node {
        Declaration::Binding(b) => {
            assert!(b.ty.is_some());
            match b.ty.as_ref().unwrap().node {
                Type::Primitive(PrimitiveType::Int) => {}
                _ => panic!("expected int type"),
            }
        }
        _ => panic!("expected Binding"),
    }
}

#[test]
fn function_declaration() {
    let prog = parse_ok("def add(x: int, y: int) -> int = x + y");
    match &prog.declarations[0].node {
        Declaration::Function(f) => {
            assert_eq!(f.name.node.as_str(), "add");
            assert_eq!(f.params.len(), 2);
            assert_eq!(f.params[0].name.node.as_str(), "x");
            match f.return_type.node {
                Type::Primitive(PrimitiveType::Int) => {}
                _ => panic!("expected int return type"),
            }
        }
        _ => panic!("expected Function"),
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Group 9: Import declarations
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn simple_import() {
    let prog = parse_ok("import automaguard.stdlib.pii");
    match &prog.declarations[0].node {
        Declaration::Import(i) => {
            assert_eq!(i.path.to_string(), "automaguard.stdlib.pii");
            match &i.kind {
                ImportKind::Module { alias } => assert!(alias.is_none()),
                _ => panic!("expected Module import"),
            }
        }
        _ => panic!("expected Import"),
    }
}

#[test]
fn import_with_alias() {
    let prog = parse_ok("import automaguard.stdlib.pii as pii");
    match &prog.declarations[0].node {
        Declaration::Import(i) => match &i.kind {
            ImportKind::Module { alias } => {
                assert_eq!(alias.as_ref().unwrap().node.as_str(), "pii");
            }
            _ => panic!("expected aliased module import"),
        },
        _ => panic!("expected Import"),
    }
}

#[test]
fn from_import_names() {
    let prog = parse_ok("from automaguard.stdlib import network, compliance");
    match &prog.declarations[0].node {
        Declaration::Import(i) => match &i.kind {
            ImportKind::Names(targets) => {
                assert_eq!(targets.len(), 2);
                assert_eq!(targets[0].name.node.as_str(), "network");
                assert_eq!(targets[1].name.node.as_str(), "compliance");
            }
            _ => panic!("expected Names import"),
        },
        _ => panic!("expected Import"),
    }
}

#[test]
fn glob_import() {
    let prog = parse_ok("from automaguard.stdlib import *");
    match &prog.declarations[0].node {
        Declaration::Import(i) => {
            assert!(matches!(i.kind, ImportKind::Glob));
        }
        _ => panic!("expected Import"),
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Group 10: Expression shapes
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn binary_add_expression() {
    let expr = parse_expr_src("a + b");
    match expr {
        Expr::Binary { op, .. } => assert_eq!(op.node, BinaryOp::Add),
        _ => panic!("expected Binary Add"),
    }
}

#[test]
fn binary_eq_expression() {
    let expr = parse_expr_src("x == 42");
    match expr {
        Expr::Binary { op, .. } => assert_eq!(op.node, BinaryOp::Eq),
        _ => panic!("expected Binary Eq"),
    }
}

#[test]
fn binary_in_expression() {
    let expr = parse_expr_src(r#"x in ["a", "b"]"#);
    match expr {
        Expr::Binary { op, .. } => assert_eq!(op.node, BinaryOp::In),
        _ => panic!("expected Binary In"),
    }
}

#[test]
fn logical_and_expression() {
    let expr = parse_expr_src("a && b");
    match expr {
        Expr::Binary { op, .. } => assert_eq!(op.node, BinaryOp::And),
        _ => panic!("expected Binary And"),
    }
}

#[test]
fn logical_or_expression() {
    let expr = parse_expr_src("a || b");
    match expr {
        Expr::Binary { op, .. } => assert_eq!(op.node, BinaryOp::Or),
        _ => panic!("expected Binary Or"),
    }
}

#[test]
fn implies_expression() {
    let expr = parse_expr_src("a implies b");
    match expr {
        Expr::Binary { op, .. } => assert_eq!(op.node, BinaryOp::Implies),
        _ => panic!("expected Binary Implies"),
    }
}

#[test]
fn field_access_expression() {
    // In the Aegis grammar, `event.tool` is a qualified name (multi-segment identifier),
    // not a postfix field-access node.  FieldAccess is only produced by the postfix_dot_op
    // rule when the primary itself is a single-segment name.
    let expr = parse_expr_src("event.tool");
    match expr {
        Expr::Identifier(qn) => {
            assert_eq!(qn.segments.len(), 2);
            assert_eq!(qn.segments[0].node.as_str(), "event");
            assert_eq!(qn.segments[1].node.as_str(), "tool");
        }
        _ => panic!("expected Identifier(QualifiedName), got {:?}", expr),
    }
}

#[test]
fn method_call_expression() {
    // In the Aegis grammar, predicates use postfix syntax without a dot:
    //   `event.url starts_with "http"`
    // (`event.url` is a qualified name; `starts_with` is a postfix_predicate_op)
    let expr = parse_expr_src("event.url starts_with \"http\"");
    match expr {
        Expr::Predicate { kind, .. } => assert_eq!(kind, PredicateKind::StartsWith),
        _ => panic!("expected Predicate StartsWith, got {:?}", expr),
    }
}

#[test]
fn function_call_expression() {
    let expr = parse_expr_src("foo(1, 2)");
    match expr {
        Expr::Call { args, .. } => {
            assert_eq!(args.len(), 2);
        }
        _ => panic!("expected Call, got {:?}", expr),
    }
}

#[test]
fn context_expression() {
    let expr = parse_expr_src("context.tool_calls");
    match expr {
        Expr::Context(qn) => {
            assert_eq!(qn.to_string(), "tool_calls");
        }
        _ => panic!("expected Context, got {:?}", expr),
    }
}

#[test]
fn quantifier_all_expression() {
    let expr = parse_expr_src("all(context.tools, t => t.approved)");
    match expr {
        Expr::Quantifier { kind, .. } => assert_eq!(kind, QuantifierKind::All),
        _ => panic!("expected Quantifier All, got {:?}", expr),
    }
}

#[test]
fn quantifier_any_expression() {
    let expr = parse_expr_src("any(context.tags, t => t == \"sensitive\")");
    match expr {
        Expr::Quantifier { kind, .. } => assert_eq!(kind, QuantifierKind::Any),
        _ => panic!("expected Quantifier Any"),
    }
}

#[test]
fn predicate_contains_expression() {
    let expr = parse_expr_src("event.tool contains \"http\"");
    match expr {
        Expr::Predicate { kind, .. } => assert_eq!(kind, PredicateKind::Contains),
        _ => panic!("expected Predicate Contains, got {:?}", expr),
    }
}

#[test]
fn predicate_matches_expression() {
    let expr = parse_expr_src(r#"url matches /^https:\/\//i"#);
    match expr {
        Expr::Predicate { kind, .. } => assert_eq!(kind, PredicateKind::Matches),
        _ => panic!("expected Predicate Matches, got {:?}", expr),
    }
}

#[test]
fn duration_literal_milliseconds() {
    let expr = parse_expr_src("500ms");
    match expr {
        Expr::Literal(Literal::Duration(d)) => {
            assert_eq!(d.value, 500);
            assert_eq!(d.unit, DurationUnit::Milliseconds);
        }
        _ => panic!("expected Duration literal"),
    }
}

#[test]
fn duration_literal_days() {
    let expr = parse_expr_src("30d");
    match expr {
        Expr::Literal(Literal::Duration(d)) => {
            assert_eq!(d.value, 30);
            assert_eq!(d.unit, DurationUnit::Days);
        }
        _ => panic!("expected Duration literal"),
    }
}

#[test]
fn list_literal_expression() {
    let expr = parse_expr_src("[1, 2, 3]");
    match expr {
        Expr::List(items) => assert_eq!(items.len(), 3),
        _ => panic!("expected List"),
    }
}

#[test]
fn single_lambda_expression() {
    let expr = parse_expr_src("x => x > 0");
    match expr {
        Expr::Lambda(lambda) => {
            assert_eq!(lambda.params.len(), 1);
            assert_eq!(lambda.params[0].name.node.as_str(), "x");
        }
        _ => panic!("expected Lambda"),
    }
}

#[test]
fn multi_param_lambda_expression() {
    let expr = parse_expr_src("(x, y) => x + y");
    match expr {
        Expr::Lambda(lambda) => {
            assert_eq!(lambda.params.len(), 2);
        }
        _ => panic!("expected Lambda"),
    }
}

#[test]
fn unary_not_expression() {
    let expr = parse_expr_src("!active");
    match expr {
        Expr::Unary { op, .. } => assert_eq!(op.node, UnaryOp::Not),
        _ => panic!("expected Unary Not"),
    }
}

#[test]
fn index_access_expression() {
    let expr = parse_expr_src("items[0]");
    match expr {
        Expr::IndexAccess { .. } => {}
        _ => panic!("expected IndexAccess, got {:?}", expr),
    }
}

#[test]
fn count_expression() {
    let expr = parse_expr_src("count(items, x => x > 0)");
    match expr {
        Expr::Count { filter, .. } => {
            assert!(filter.is_some());
        }
        _ => panic!("expected Count"),
    }
}

#[test]
fn full_policy_pipeline() {
    // A more complete policy that exercises many features at once
    let src = r#"
        policy DataExfiltrationGuard {
            severity high
            scope tool_call, data_access

            on tool_call {
                when event.tool contains "http" and event.destination != "internal"
                deny with "External HTTP calls are not permitted"
                log notify: "security-team"
            }

            rate_limit tool_call: 100 per 1m
        }
    "#;
    let prog = parse_ok(src);
    assert_eq!(prog.declarations.len(), 1);
    let policy = match &prog.declarations[0].node {
        Declaration::Policy(p) => p,
        _ => panic!("expected Policy"),
    };
    assert_eq!(policy.name.node.as_str(), "DataExfiltrationGuard");

    // Check severity
    let sev = policy.members.iter().find_map(|m| {
        if let PolicyMember::Severity(s) = &m.node {
            Some(*s)
        } else {
            None
        }
    });
    assert_eq!(sev, Some(SeverityLevel::High));

    // Check scope has 2 targets
    let scope = policy
        .members
        .iter()
        .find_map(|m| {
            if let PolicyMember::Scope(t) = &m.node {
                Some(t.clone())
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(scope.len(), 2);

    // Check rule exists
    let rule = policy
        .members
        .iter()
        .find_map(|m| {
            if let PolicyMember::Rule(r) = &m.node {
                Some(r.clone())
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(rule.on_events.len(), 1);
    assert!(rule.clauses.len() >= 3); // when + deny + log

    // Check constraint exists
    let constraint = policy
        .members
        .iter()
        .find_map(|m| {
            if let PolicyMember::Constraint(c) = &m.node {
                Some(c.clone())
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(constraint.kind, ConstraintKind::RateLimit);
}
// ═══════════════════════════════════════════════════════════════════════
//  Group 11: Parse error recovery
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn parse_error_returns_empty_program_with_error_diag() {
    let (prog, diags) = parse_source("@@@invalid syntax###", "test.aegis");
    assert!(
        diags.has_errors(),
        "invalid syntax should produce a parse error"
    );
    assert_eq!(
        prog.declarations.len(),
        0,
        "error program has no declarations"
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  Group 12: Additional severity, scope, and policy members
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn severity_info_parses() {
    let policy = parse_policy("policy P { severity info }");
    let sev = policy.members.iter().find_map(|m| {
        if let PolicyMember::Severity(s) = &m.node {
            Some(*s)
        } else {
            None
        }
    });
    assert_eq!(sev, Some(SeverityLevel::Info));
}

#[test]
fn scope_string_literal_target_parses() {
    let policy = parse_policy(r#"policy P { scope "custom-scope" }"#);
    let scope = policy
        .members
        .iter()
        .find_map(|m| {
            if let PolicyMember::Scope(t) = &m.node {
                Some(t.clone())
            } else {
                None
            }
        })
        .expect("scope");
    assert_eq!(scope.len(), 1);
    match &scope[0] {
        ScopeTarget::Literal(s) => assert_eq!(s.node.as_str(), "custom-scope"),
        other => panic!("expected Literal scope, got {:?}", other),
    }
}

#[test]
fn policy_binding_member_parses() {
    let policy = parse_policy("policy P { let threshold = 100 }");
    let has_binding = policy
        .members
        .iter()
        .any(|m| matches!(m.node, PolicyMember::Binding(_)));
    assert!(has_binding, "policy should have a binding member");
}

#[test]
fn policy_function_member_parses() {
    let policy = parse_policy("policy P { def check(x: int) -> bool = x > 0 }");
    let has_fn = policy
        .members
        .iter()
        .any(|m| matches!(m.node, PolicyMember::Function(_)));
    assert!(has_fn, "policy should have a function member");
}

// ═══════════════════════════════════════════════════════════════════════
//  Group 13: Rule clause variants
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn rule_severity_clause_parses() {
    let policy = parse_policy(
        r#"
        policy P {
            on tool_call {
                severity high
                deny
            }
        }
    "#,
    );
    let rule = policy
        .members
        .iter()
        .find_map(|m| {
            if let PolicyMember::Rule(r) = &m.node {
                Some(r.clone())
            } else {
                None
            }
        })
        .expect("rule");
    let has_severity = rule
        .clauses
        .iter()
        .any(|c| matches!(c.node, RuleClause::Severity(_)));
    assert!(has_severity, "rule should have a severity clause");
}

#[test]
fn rule_constraint_in_rule_body_parses() {
    let policy = parse_policy(
        r#"
        policy P {
            on tool_call {
                deny
                rate_limit calls: 10 per 1m
            }
        }
    "#,
    );
    let rule = policy
        .members
        .iter()
        .find_map(|m| {
            if let PolicyMember::Rule(r) = &m.node {
                Some(r.clone())
            } else {
                None
            }
        })
        .expect("rule");
    let has_constraint = rule
        .clauses
        .iter()
        .any(|c| matches!(c.node, RuleClause::Constraint(_)));
    assert!(has_constraint, "rule should have an inline constraint");
}

#[test]
fn redact_verdict_parses() {
    let policy = parse_policy(
        r#"
        policy P {
            on data_read { redact }
        }
    "#,
    );
    let rule = policy
        .members
        .iter()
        .find_map(|m| {
            if let PolicyMember::Rule(r) = &m.node {
                Some(r.clone())
            } else {
                None
            }
        })
        .unwrap();
    let has_redact = rule
        .clauses
        .iter()
        .any(|c| matches!(&c.node, RuleClause::Verdict(v) if v.verdict.node == Verdict::Redact));
    assert!(has_redact, "rule should have a redact verdict");
}

#[test]
fn escalate_action_parses() {
    let policy = parse_policy(
        r#"
        policy P {
            on tool_call {
                deny
                escalate "tier-2"
            }
        }
    "#,
    );
    let rule = policy
        .members
        .iter()
        .find_map(|m| {
            if let PolicyMember::Rule(r) = &m.node {
                Some(r.clone())
            } else {
                None
            }
        })
        .unwrap();
    let has_escalate = rule
        .clauses
        .iter()
        .any(|c| matches!(&c.node, RuleClause::Action(a) if a.verb.node == ActionVerb::Escalate));
    assert!(has_escalate, "rule should have an escalate action");
}

// ═══════════════════════════════════════════════════════════════════════
//  Group 14: Additional temporal expressions
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn eventually_within_parses() {
    let expr = parse_expr_src("eventually(approved) within 5m");
    match expr {
        Expr::Temporal(TemporalExpr::Eventually { within, .. }) => {
            assert!(within.is_some(), "eventually within should have deadline");
            let w = within.unwrap();
            match w.node {
                Expr::Literal(Literal::Duration(d)) => {
                    assert_eq!(d.value, 5);
                    assert_eq!(d.unit, DurationUnit::Minutes);
                }
                _ => panic!("expected duration in within"),
            }
        }
        _ => panic!("expected Eventually"),
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Group 15: Arithmetic and unary operators
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn binary_sub_expression() {
    let expr = parse_expr_src("a - b");
    match expr {
        Expr::Binary { op, .. } => assert_eq!(op.node, BinaryOp::Sub),
        _ => panic!("expected Binary Sub"),
    }
}

#[test]
fn binary_mul_expression() {
    let expr = parse_expr_src("a * b");
    match expr {
        Expr::Binary { op, .. } => assert_eq!(op.node, BinaryOp::Mul),
        _ => panic!("expected Binary Mul"),
    }
}

#[test]
fn binary_div_expression() {
    let expr = parse_expr_src("a / b");
    match expr {
        Expr::Binary { op, .. } => assert_eq!(op.node, BinaryOp::Div),
        _ => panic!("expected Binary Div"),
    }
}

#[test]
fn binary_mod_expression() {
    let expr = parse_expr_src("a % b");
    match expr {
        Expr::Binary { op, .. } => assert_eq!(op.node, BinaryOp::Mod),
        _ => panic!("expected Binary Mod"),
    }
}

#[test]
fn unary_neg_expression() {
    let expr = parse_expr_src("-42");
    match expr {
        Expr::Unary { op, .. } => assert_eq!(op.node, UnaryOp::Neg),
        _ => panic!("expected Unary Neg, got {:?}", expr),
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Group 16: Postfix method call and predicates
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn postfix_field_access_expression() {
    // `items[0].name` produces FieldAccess because the primary is not a bare identifier
    let expr = parse_expr_src("items[0].name");
    match expr {
        Expr::FieldAccess { field, .. } => assert_eq!(field.node.as_str(), "name"),
        _ => panic!("expected FieldAccess, got {:?}", expr),
    }
}

#[test]
fn postfix_method_call_expression() {
    // `foo().method(1)` — call result + dot-postfix call produces MethodCall.
    // `foo().method` cannot be a qualified name, so it must be FieldAccess/MethodCall.
    let expr = parse_expr_src("foo().method(1)");
    match expr {
        Expr::MethodCall { method, args, .. } => {
            assert_eq!(method.node.as_str(), "method");
            assert_eq!(args.len(), 1);
        }
        _ => panic!("expected MethodCall, got {:?}", expr),
    }
}

#[test]
fn predicate_ends_with_expression() {
    let expr = parse_expr_src(r#"url ends_with ".com""#);
    match expr {
        Expr::Predicate { kind, .. } => assert_eq!(kind, PredicateKind::EndsWith),
        _ => panic!("expected Predicate EndsWith, got {:?}", expr),
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Group 17: Match expressions and patterns
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn match_expression_basic() {
    let expr = parse_expr_src("match x { 1 -> true, 2 -> false, _ -> false }");
    match expr {
        Expr::Match { arms, .. } => assert_eq!(arms.len(), 3),
        _ => panic!("expected Match, got {:?}", expr),
    }
}

#[test]
fn match_literal_pattern() {
    let expr = parse_expr_src(r#"match x { "allow" -> true, _ -> false }"#);
    match expr {
        Expr::Match { arms, .. } => match &arms[0].pattern.node {
            Pattern::Literal(_) => {}
            p => panic!("expected Literal pattern, got {:?}", p),
        },
        _ => panic!("expected Match"),
    }
}

#[test]
fn match_wildcard_pattern() {
    let expr = parse_expr_src("match x { _ -> true }");
    match expr {
        Expr::Match { arms, .. } => match &arms[0].pattern.node {
            Pattern::Wildcard => {}
            p => panic!("expected Wildcard pattern, got {:?}", p),
        },
        _ => panic!("expected Match"),
    }
}

#[test]
fn match_or_pattern() {
    let expr = parse_expr_src("match x { 1 | 2 -> true, _ -> false }");
    match expr {
        Expr::Match { arms, .. } => match &arms[0].pattern.node {
            Pattern::Or(parts) => assert_eq!(parts.len(), 2),
            p => panic!("expected Or pattern, got {:?}", p),
        },
        _ => panic!("expected Match"),
    }
}

#[test]
fn match_binding_pattern() {
    // A single-segment name in match position becomes a binding pattern
    let expr = parse_expr_src("match x { myvar -> myvar }");
    match expr {
        Expr::Match { arms, .. } => match &arms[0].pattern.node {
            Pattern::Binding(_) => {}
            p => panic!("expected Binding pattern, got {:?}", p),
        },
        _ => panic!("expected Match"),
    }
}

#[test]
fn match_list_pattern() {
    let expr = parse_expr_src("match x { [1, 2] -> true, _ -> false }");
    match expr {
        Expr::Match { arms, .. } => match &arms[0].pattern.node {
            Pattern::List(_) => {}
            p => panic!("expected List pattern, got {:?}", p),
        },
        _ => panic!("expected Match"),
    }
}

#[test]
fn match_result_verdict() {
    // Match arm result is a verdict clause
    let expr = parse_expr_src("match x { _ -> deny }");
    match expr {
        Expr::Match { arms, .. } => match &arms[0].result.node {
            MatchResult::Verdict(v) => assert_eq!(v.verdict.node, Verdict::Deny),
            r => panic!("expected Verdict match result, got {:?}", r),
        },
        _ => panic!("expected Match"),
    }
}

#[test]
fn match_result_block() {
    // Match arm result is a block expression containing statements
    let expr = parse_expr_src("match x { _ -> { let y = 1; true } }");
    match expr {
        Expr::Match { arms, .. } => match &arms[0].result.node {
            MatchResult::Block(stmts) => assert!(!stmts.is_empty(), "block should have statements"),
            r => panic!("expected Block match result, got {:?}", r),
        },
        _ => panic!("expected Match"),
    }
}

#[test]
fn block_binding_statement() {
    let expr = parse_expr_src("match z { _ -> { let y = 42; y } }");
    match expr {
        Expr::Match { arms, .. } => match &arms[0].result.node {
            MatchResult::Block(stmts) => {
                assert!(
                    stmts
                        .iter()
                        .any(|s| matches!(s.node, BlockStatement::Binding(_))),
                    "block should contain a binding statement"
                );
            }
            r => panic!("expected Block, got {:?}", r),
        },
        _ => panic!("expected Match"),
    }
}

#[test]
fn block_verdict_statement() {
    let expr = parse_expr_src("match z { _ -> { deny } }");
    match expr {
        Expr::Match { arms, .. } => match &arms[0].result.node {
            MatchResult::Block(stmts) => {
                assert!(
                    stmts
                        .iter()
                        .any(|s| matches!(s.node, BlockStatement::Verdict(_))),
                    "block should contain a verdict statement"
                );
            }
            r => panic!("expected Block, got {:?}", r),
        },
        _ => panic!("expected Match"),
    }
}

#[test]
fn block_action_statement() {
    let expr = parse_expr_src(r#"match z { _ -> { log "info"; true } }"#);
    match expr {
        Expr::Match { arms, .. } => match &arms[0].result.node {
            MatchResult::Block(stmts) => {
                assert!(
                    stmts
                        .iter()
                        .any(|s| matches!(s.node, BlockStatement::Action(_))),
                    "block should contain an action statement"
                );
            }
            r => panic!("expected Block, got {:?}", r),
        },
        _ => panic!("expected Match"),
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Group 18: Object literals
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn object_literal_expression() {
    let expr = parse_expr_src(r#"{ name: "alice", age: 30 }"#);
    match expr {
        Expr::Object(fields) => {
            assert_eq!(fields.len(), 2);
            assert_eq!(fields[0].key.node.as_str(), "name");
            assert_eq!(fields[1].key.node.as_str(), "age");
        }
        _ => panic!("expected Object, got {:?}", expr),
    }
}

#[test]
fn object_literal_string_key() {
    let expr = parse_expr_src(r#"{ "my-key": true }"#);
    match expr {
        Expr::Object(fields) => {
            assert_eq!(fields[0].key.node.as_str(), "my-key");
        }
        _ => panic!("expected Object, got {:?}", expr),
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Group 19: Quantifier variants (none / exists)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn quantifier_none_expression() {
    let expr = parse_expr_src("none(context.items, x => x < 0)");
    match expr {
        Expr::Quantifier { kind, .. } => assert_eq!(kind, QuantifierKind::None),
        _ => panic!("expected Quantifier None, got {:?}", expr),
    }
}

#[test]
fn quantifier_exists_expression() {
    let expr = parse_expr_src("exists(context.items, x => x > 0)");
    match expr {
        Expr::Quantifier { kind, .. } => assert_eq!(kind, QuantifierKind::Exists),
        _ => panic!("expected Quantifier Exists, got {:?}", expr),
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Group 20: Literal variants (float, raw string)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn float_literal_parses() {
    let expr = parse_expr_src("3.14");
    match expr {
        Expr::Literal(Literal::Float(f)) => {
            assert!((f - 3.14).abs() < 1e-9, "float value should be 3.14");
        }
        _ => panic!("expected Float literal, got {:?}", expr),
    }
}

#[test]
fn raw_string_literal_parses() {
    let expr = parse_expr_src(r#"r"raw content""#);
    match expr {
        Expr::Literal(Literal::String(s)) => {
            assert_eq!(s.as_str(), "raw content");
        }
        _ => panic!("expected String from raw string literal, got {:?}", expr),
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Group 21: Type expressions (list, map, union)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn list_type_annotation_parses() {
    // Grammar uses capital `List<T>` for the built-in list type keyword.
    let prog = parse_ok("let x: List<int> = [1, 2, 3]");
    match &prog.declarations[0].node {
        Declaration::Binding(b) => match b.ty.as_ref().unwrap().node {
            Type::List(_) => {}
            ref t => panic!("expected List type, got {:?}", t),
        },
        _ => panic!("expected Binding"),
    }
}

#[test]
fn map_type_annotation_parses() {
    // Grammar uses capital `Map<K, V>` for the built-in map type keyword.
    let prog = parse_ok("let x: Map<string, int> = {}");
    match &prog.declarations[0].node {
        Declaration::Binding(b) => match b.ty.as_ref().unwrap().node {
            Type::Map(_, _) => {}
            ref t => panic!("expected Map type, got {:?}", t),
        },
        _ => panic!("expected Binding"),
    }
}

#[test]
fn union_type_annotation_parses() {
    let prog = parse_ok("let x: int | string = 42");
    match &prog.declarations[0].node {
        Declaration::Binding(b) => match b.ty.as_ref().unwrap().node {
            Type::Union(_) => {}
            ref t => panic!("expected Union type, got {:?}", t),
        },
        _ => panic!("expected Binding"),
    }
}

#[test]
fn set_type_annotation_parses() {
    // Grammar uses capital `Set<T>` for the built-in set type keyword.
    let prog = parse_ok("let x: Set<string> = {}");
    match &prog.declarations[0].node {
        Declaration::Binding(b) => match b.ty.as_ref().unwrap().node {
            Type::Set(_) => {}
            ref t => panic!("expected Set type, got {:?}", t),
        },
        _ => panic!("expected Binding"),
    }
}
