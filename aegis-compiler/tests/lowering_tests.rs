//! Lowering pass tests.
//!
//! Constructs Programs from AST nodes, runs `lower::compile`, and asserts
//! on the resulting `CompiledPolicy` IR — rules, constraints, state machines.

use aegis_compiler::ast::*;
use aegis_compiler::ir::{TemporalKind, StateKind};
use aegis_compiler::lower;

// ── AST builder helpers ───────────────────────────────────────────────────────

fn ident(s: &str) -> Spanned<smol_str::SmolStr> {
    Spanned::dummy(smol_str::SmolStr::new(s))
}

fn simple_name(s: &str) -> QualifiedName {
    QualifiedName::simple(ident(s))
}

fn bool_expr() -> Spanned<Expr> {
    Spanned::dummy(Expr::Literal(Literal::Bool(true)))
}

fn int_lit_expr(n: i64) -> Spanned<Expr> {
    Spanned::dummy(Expr::Literal(Literal::Int(n)))
}

fn dur_lit_expr(value: u64, unit: DurationUnit) -> Spanned<Expr> {
    Spanned::dummy(Expr::Literal(Literal::Duration(DurationLit { value, unit })))
}

fn deny_verdict() -> Spanned<RuleClause> {
    Spanned::dummy(RuleClause::Verdict(VerdictClause {
        verdict: Spanned::dummy(Verdict::Deny),
        message: None,
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

fn rule_member(event: &str, clauses: Vec<Spanned<RuleClause>>) -> Spanned<PolicyMember> {
    Spanned::dummy(PolicyMember::Rule(RuleDecl {
        annotations: vec![],
        on_events: vec![ScopeTarget::Literal(Spanned::dummy(smol_str::SmolStr::new(event)))],
        clauses,
    }))
}

fn rule_on_events(events: Vec<&str>, clauses: Vec<Spanned<RuleClause>>) -> Spanned<PolicyMember> {
    Spanned::dummy(PolicyMember::Rule(RuleDecl {
        annotations: vec![],
        on_events: events
            .into_iter()
            .map(|e| ScopeTarget::Literal(Spanned::dummy(smol_str::SmolStr::new(e))))
            .collect(),
        clauses,
    }))
}

fn severity_member(s: SeverityLevel) -> Spanned<PolicyMember> {
    Spanned::dummy(PolicyMember::Severity(s))
}

fn scope_member(scopes: Vec<&str>) -> Spanned<PolicyMember> {
    Spanned::dummy(PolicyMember::Scope(
        scopes
            .into_iter()
            .map(|s| ScopeTarget::Literal(Spanned::dummy(smol_str::SmolStr::new(s))))
            .collect(),
    ))
}

fn constraint_member(
    kind: ConstraintKind,
    target: &str,
    limit_int: i64,
    dur_value: u64,
    dur_unit: DurationUnit,
) -> Spanned<PolicyMember> {
    Spanned::dummy(PolicyMember::Constraint(ConstraintDecl {
        kind,
        target: simple_name(target),
        limit: int_lit_expr(limit_int),
        window: dur_lit_expr(dur_value, dur_unit),
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

fn temporal_always(cond: Spanned<Expr>) -> Spanned<Expr> {
    Spanned::dummy(Expr::Temporal(TemporalExpr::Always {
        condition: Box::new(cond),
        within: None,
    }))
}

fn temporal_always_within(cond: Spanned<Expr>, within: Spanned<Expr>) -> Spanned<Expr> {
    Spanned::dummy(Expr::Temporal(TemporalExpr::Always {
        condition: Box::new(cond),
        within: Some(Box::new(within)),
    }))
}

fn temporal_eventually(cond: Spanned<Expr>) -> Spanned<Expr> {
    Spanned::dummy(Expr::Temporal(TemporalExpr::Eventually {
        condition: Box::new(cond),
        within: None,
    }))
}

fn temporal_eventually_within(cond: Spanned<Expr>, within: Spanned<Expr>) -> Spanned<Expr> {
    Spanned::dummy(Expr::Temporal(TemporalExpr::Eventually {
        condition: Box::new(cond),
        within: Some(Box::new(within)),
    }))
}

fn temporal_never(cond: Spanned<Expr>) -> Spanned<Expr> {
    Spanned::dummy(Expr::Temporal(TemporalExpr::Never {
        condition: Box::new(cond),
    }))
}

fn temporal_until(hold: Spanned<Expr>, release: Spanned<Expr>) -> Spanned<Expr> {
    Spanned::dummy(Expr::Temporal(TemporalExpr::Until {
        hold: Box::new(hold),
        release: Box::new(release),
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

fn annotated_policy(
    name: &str,
    annotations: Vec<(&str, &str)>,
    members: Vec<Spanned<PolicyMember>>,
) -> Spanned<Declaration> {
    Spanned::dummy(Declaration::Policy(PolicyDecl {
        annotations: annotations
            .into_iter()
            .map(|(k, v)| Annotation {
                name: ident(k),
                args: vec![AnnotationArg::Positional(AnnotationValue::Literal(
                    Literal::String(smol_str::SmolStr::new(v)),
                ))],
                span: Span::DUMMY,
            })
            .collect(),
        name: ident(name),
        extends: None,
        members,
    }))
}

fn program(declarations: Vec<Spanned<Declaration>>) -> Program {
    Program {
        declarations,
        span: Span::DUMMY,
    }
}

// ── Empty / minimal ───────────────────────────────────────────────────────────

#[test]
fn empty_program_produces_no_policies() {
    let (policies, diags) = lower::compile(&program(vec![]));
    assert!(policies.is_empty());
    assert!(!diags.has_errors());
}

#[test]
fn policy_with_no_members_compiles_with_defaults() {
    let (policies, _) = lower::compile(&program(vec![simple_policy("Empty", vec![])]));
    assert_eq!(policies.len(), 1);
    let p = &policies[0];
    assert_eq!(p.name.as_str(), "Empty");
    assert!(p.rules.is_empty());
    assert!(p.constraints.is_empty());
    assert!(p.state_machines.is_empty());
}

#[test]
fn default_severity_is_medium() {
    let (policies, _) = lower::compile(&program(vec![simple_policy("Guard", vec![])]));
    assert_eq!(policies[0].severity, SeverityLevel::Medium);
}

// ── Policy metadata ───────────────────────────────────────────────────────────

#[test]
fn policy_name_preserved_in_output() {
    let (policies, _) = lower::compile(&program(vec![simple_policy("MyPolicy", vec![])]));
    assert_eq!(policies[0].name.as_str(), "MyPolicy");
}

#[test]
fn severity_override_recorded() {
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![severity_member(SeverityLevel::Critical)],
    )]));
    assert_eq!(policies[0].severity, SeverityLevel::Critical);
}

#[test]
fn severity_last_one_wins() {
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![
            severity_member(SeverityLevel::Low),
            severity_member(SeverityLevel::High),
        ],
    )]));
    assert_eq!(policies[0].severity, SeverityLevel::High);
}

#[test]
fn scope_targets_recorded() {
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![scope_member(vec!["tool_call", "data_access"])],
    )]));
    let scopes = &policies[0].scopes;
    assert_eq!(scopes.len(), 2);
    assert!(scopes.iter().any(|s| s.as_str() == "tool_call"));
    assert!(scopes.iter().any(|s| s.as_str() == "data_access"));
}

#[test]
fn annotation_with_string_value_in_metadata() {
    let (policies, _) = lower::compile(&program(vec![annotated_policy(
        "Guard",
        vec![("author", "alice"), ("version", "1.0")],
        vec![],
    )]));
    let annotations = &policies[0].metadata.annotations;
    assert!(annotations.iter().any(|(k, v)| k.as_str() == "author" && v.as_str() == "alice"));
    assert!(annotations.iter().any(|(k, v)| k.as_str() == "version" && v.as_str() == "1.0"));
}

#[test]
fn source_hash_is_nonzero_for_nonempty_name() {
    let (policies, _) = lower::compile(&program(vec![simple_policy("MyPolicy", vec![])]));
    assert_ne!(policies[0].metadata.source_hash, 0);
}

#[test]
fn compiler_version_in_metadata() {
    let (policies, _) = lower::compile(&program(vec![simple_policy("Guard", vec![])]));
    assert!(!policies[0].metadata.compiler_version.is_empty());
}

// ── Multiple policies ─────────────────────────────────────────────────────────

#[test]
fn multiple_policies_all_compiled() {
    let prog = program(vec![
        simple_policy("A", vec![]),
        simple_policy("B", vec![]),
        simple_policy("C", vec![]),
    ]);
    let (policies, _) = lower::compile(&prog);
    assert_eq!(policies.len(), 3);
}

#[test]
fn multiple_policies_have_distinct_names() {
    let prog = program(vec![
        simple_policy("Alpha", vec![]),
        simple_policy("Beta", vec![]),
    ]);
    let (policies, _) = lower::compile(&prog);
    let names: Vec<&str> = policies.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"Alpha"));
    assert!(names.contains(&"Beta"));
}

#[test]
fn non_policy_declarations_not_included_in_output() {
    // A type declaration should not produce a policy
    let prog = program(vec![Spanned::dummy(Declaration::Type(TypeDecl {
        name: ident("MyType"),
        generic_params: vec![],
        fields: vec![],
    }))]);
    let (policies, _) = lower::compile(&prog);
    assert!(policies.is_empty());
}

// ── Rules ─────────────────────────────────────────────────────────────────────

#[test]
fn rule_with_deny_verdict_produces_one_rule() {
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![rule_member("tool_call", vec![deny_verdict()])],
    )]));
    assert_eq!(policies[0].rules.len(), 1);
}

#[test]
fn rule_records_on_event_name() {
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![rule_member("tool_call", vec![deny_verdict()])],
    )]));
    assert_eq!(policies[0].rules[0].on_events, vec!["tool_call"]);
}

#[test]
fn rule_with_multiple_events_records_all() {
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![rule_on_events(
            vec!["tool_call", "data_access"],
            vec![deny_verdict()],
        )],
    )]));
    let events = &policies[0].rules[0].on_events;
    assert_eq!(events.len(), 2);
    assert!(events.iter().any(|e| e.as_str() == "tool_call"));
    assert!(events.iter().any(|e| e.as_str() == "data_access"));
}

#[test]
fn rule_with_no_when_clause_has_no_condition() {
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![rule_member("tool_call", vec![deny_verdict()])],
    )]));
    assert!(policies[0].rules[0].condition.is_none());
}

#[test]
fn rule_with_when_clause_has_condition() {
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![rule_member(
            "tool_call",
            vec![when_clause(bool_expr()), deny_verdict()],
        )],
    )]));
    assert!(policies[0].rules[0].condition.is_some());
}

#[test]
fn rule_deny_verdict_is_deny() {
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![rule_member("tool_call", vec![deny_verdict()])],
    )]));
    assert_eq!(policies[0].rules[0].verdicts[0].verdict, Verdict::Deny);
}

#[test]
fn rule_allow_verdict_is_allow() {
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![rule_member("tool_call", vec![allow_verdict()])],
    )]));
    assert_eq!(policies[0].rules[0].verdicts[0].verdict, Verdict::Allow);
}

#[test]
fn rule_ids_are_sequential_across_rules() {
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![
            rule_member("tool_call", vec![deny_verdict()]),
            rule_member("data_access", vec![allow_verdict()]),
        ],
    )]));
    let ids: Vec<u32> = policies[0].rules.iter().map(|r| r.id).collect();
    assert_eq!(ids[0] + 1, ids[1]);
}

#[test]
fn two_policies_rule_ids_continue_incrementing() {
    let prog = program(vec![
        simple_policy("A", vec![rule_member("e", vec![deny_verdict()])]),
        simple_policy("B", vec![rule_member("e", vec![deny_verdict()])]),
    ]);
    let (policies, _) = lower::compile(&prog);
    let id_a = policies[0].rules[0].id;
    let id_b = policies[1].rules[0].id;
    assert_ne!(id_a, id_b);
}

// ── Constraints ───────────────────────────────────────────────────────────────

#[test]
fn rate_limit_constraint_compiles() {
    let (policies, diags) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![constraint_member(
            ConstraintKind::RateLimit,
            "tool_call",
            100,
            1,
            DurationUnit::Minutes,
        )],
    )]));
    assert!(!diags.has_errors());
    assert_eq!(policies[0].constraints.len(), 1);
}

#[test]
fn rate_limit_target_name_preserved() {
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![constraint_member(
            ConstraintKind::RateLimit,
            "tool_call",
            100,
            1,
            DurationUnit::Minutes,
        )],
    )]));
    assert_eq!(policies[0].constraints[0].target.as_str(), "tool_call");
}

#[test]
fn rate_limit_values_correct() {
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![constraint_member(
            ConstraintKind::RateLimit,
            "tool_call",
            50,
            5,
            DurationUnit::Minutes,
        )],
    )]));
    let c = &policies[0].constraints[0];
    assert_eq!(c.limit, 50);
    assert_eq!(c.window_millis, 5 * 60_000); // 5 minutes in ms
}

#[test]
fn quota_constraint_kind_is_quota() {
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![constraint_member(
            ConstraintKind::Quota,
            "data_access",
            1000,
            1,
            DurationUnit::Hours,
        )],
    )]));
    assert_eq!(policies[0].constraints[0].kind, ConstraintKind::Quota);
}

#[test]
fn constraint_with_duration_in_seconds_correct_millis() {
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![constraint_member(
            ConstraintKind::RateLimit,
            "tool_call",
            10,
            30,
            DurationUnit::Seconds,
        )],
    )]));
    assert_eq!(policies[0].constraints[0].window_millis, 30_000);
}

#[test]
fn non_constant_limit_produces_error_and_no_constraint() {
    // Constraints require compile-time int literals for limit
    let prog = program(vec![simple_policy(
        "Guard",
        vec![Spanned::dummy(PolicyMember::Constraint(ConstraintDecl {
            kind: ConstraintKind::RateLimit,
            target: simple_name("tool_call"),
            // bool is not a constant int
            limit: Spanned::dummy(Expr::Literal(Literal::Bool(true))),
            window: dur_lit_expr(1, DurationUnit::Minutes),
        }))],
    )]);
    let (policies, diags) = lower::compile(&prog);
    assert!(diags.has_errors());
    assert!(policies[0].constraints.is_empty());
}

// ── Proofs → state machines ───────────────────────────────────────────────────

#[test]
fn proof_with_always_produces_one_state_machine() {
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![proof_member("Safety", "NoHTTP", temporal_always(bool_expr()))],
    )]));
    assert_eq!(policies[0].state_machines.len(), 1);
}

#[test]
fn always_state_machine_kind_is_always() {
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![proof_member("Safety", "NoHTTP", temporal_always(bool_expr()))],
    )]));
    assert_eq!(policies[0].state_machines[0].kind, TemporalKind::Always);
}

#[test]
fn always_state_machine_name_matches_proof_name() {
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![proof_member("MySafety", "MyInvariant", temporal_always(bool_expr()))],
    )]));
    let sm = &policies[0].state_machines[0];
    assert_eq!(sm.name.as_str(), "MySafety");
    assert_eq!(sm.invariant_name.as_str(), "MyInvariant");
}

#[test]
fn always_state_machine_has_two_states() {
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![proof_member("P", "I", temporal_always(bool_expr()))],
    )]));
    assert_eq!(policies[0].state_machines[0].states.len(), 2);
}

#[test]
fn always_state_machine_violating_state_is_violated_kind() {
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![proof_member("P", "I", temporal_always(bool_expr()))],
    )]));
    let sm = &policies[0].state_machines[0];
    let violated_ids = &sm.violating_states;
    assert_eq!(violated_ids.len(), 1);
    let violated = sm.states.iter().find(|s| s.id == violated_ids[0]).unwrap();
    assert_eq!(violated.kind, StateKind::Violated);
}

#[test]
fn never_state_machine_kind_is_always() {
    // never(φ) compiles as always(!φ)
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![proof_member("P", "I", temporal_never(bool_expr()))],
    )]));
    assert_eq!(policies[0].state_machines[0].kind, TemporalKind::Always);
}

#[test]
fn eventually_state_machine_kind_is_eventually() {
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![proof_member("P", "I", temporal_eventually(bool_expr()))],
    )]));
    assert_eq!(policies[0].state_machines[0].kind, TemporalKind::Eventually);
}

#[test]
fn eventually_without_within_has_no_deadline() {
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![proof_member("P", "I", temporal_eventually(bool_expr()))],
    )]));
    assert!(policies[0].state_machines[0].deadline_millis.is_none());
}

#[test]
fn eventually_with_within_has_deadline() {
    let expr = temporal_eventually_within(
        bool_expr(),
        dur_lit_expr(24, DurationUnit::Hours),
    );
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![proof_member("P", "I", expr)],
    )]));
    assert_eq!(
        policies[0].state_machines[0].deadline_millis,
        Some(24 * 3_600_000)
    );
}

#[test]
fn eventually_with_within_has_three_states() {
    let expr = temporal_eventually_within(
        bool_expr(),
        dur_lit_expr(5, DurationUnit::Minutes),
    );
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![proof_member("P", "I", expr)],
    )]));
    assert_eq!(policies[0].state_machines[0].states.len(), 3);
}

#[test]
fn always_with_within_has_deadline() {
    let expr = temporal_always_within(
        bool_expr(),
        dur_lit_expr(10, DurationUnit::Seconds),
    );
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![proof_member("P", "I", expr)],
    )]));
    assert_eq!(
        policies[0].state_machines[0].deadline_millis,
        Some(10_000)
    );
}

#[test]
fn until_state_machine_kind_is_until() {
    let expr = temporal_until(bool_expr(), bool_expr());
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![proof_member("P", "I", expr)],
    )]));
    assert_eq!(policies[0].state_machines[0].kind, TemporalKind::Until);
}

#[test]
fn until_state_machine_has_three_states() {
    let expr = temporal_until(bool_expr(), bool_expr());
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![proof_member("P", "I", expr)],
    )]));
    assert_eq!(policies[0].state_machines[0].states.len(), 3);
}

#[test]
fn multiple_invariants_produce_multiple_state_machines() {
    let prog = program(vec![simple_policy(
        "Guard",
        vec![Spanned::dummy(PolicyMember::Proof(ProofDecl {
            name: ident("Safety"),
            invariants: vec![
                InvariantDecl {
                    name: ident("Inv1"),
                    conditions: vec![temporal_always(bool_expr())],
                },
                InvariantDecl {
                    name: ident("Inv2"),
                    conditions: vec![temporal_never(bool_expr())],
                },
            ],
        }))],
    )]);
    let (policies, _) = lower::compile(&prog);
    assert_eq!(policies[0].state_machines.len(), 2);
}

#[test]
fn state_machine_ids_are_unique_across_proofs() {
    let prog = program(vec![simple_policy(
        "Guard",
        vec![
            proof_member("P1", "I1", temporal_always(bool_expr())),
            proof_member("P2", "I2", temporal_eventually(bool_expr())),
        ],
    )]);
    let (policies, _) = lower::compile(&prog);
    let sm_ids: Vec<u32> = policies[0].state_machines.iter().map(|s| s.id).collect();
    let unique: std::collections::HashSet<_> = sm_ids.iter().collect();
    assert_eq!(unique.len(), sm_ids.len(), "state machine IDs should be unique");
}

#[test]
fn non_temporal_invariant_condition_produces_no_state_machine() {
    // A plain boolean literal in an invariant is not a temporal operator,
    // so it produces no state machine (it's treated as a static assertion).
    let prog = program(vec![simple_policy(
        "Guard",
        vec![proof_member("P", "I", bool_expr())], // not wrapped in temporal
    )]);
    let (policies, _) = lower::compile(&prog);
    assert!(policies[0].state_machines.is_empty());
}
