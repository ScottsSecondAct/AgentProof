//! Lowering pass tests.
//!
//! Constructs Programs from AST nodes, runs `lower::compile`, and asserts
//! on the resulting `CompiledPolicy` IR — rules, constraints, state machines.

use aegis_compiler::ast::*;
use aegis_compiler::ir::{StateKind, TemporalKind};
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
    Spanned::dummy(Expr::Literal(Literal::Duration(DurationLit {
        value,
        unit,
    })))
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
        on_events: vec![ScopeTarget::Literal(Spanned::dummy(
            smol_str::SmolStr::new(event),
        ))],
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
    assert!(annotations
        .iter()
        .any(|(k, v)| k.as_str() == "author" && v.as_str() == "alice"));
    assert!(annotations
        .iter()
        .any(|(k, v)| k.as_str() == "version" && v.as_str() == "1.0"));
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
        vec![proof_member(
            "Safety",
            "NoHTTP",
            temporal_always(bool_expr()),
        )],
    )]));
    assert_eq!(policies[0].state_machines.len(), 1);
}

#[test]
fn always_state_machine_kind_is_always() {
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![proof_member(
            "Safety",
            "NoHTTP",
            temporal_always(bool_expr()),
        )],
    )]));
    assert_eq!(policies[0].state_machines[0].kind, TemporalKind::Always);
}

#[test]
fn always_state_machine_name_matches_proof_name() {
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![proof_member(
            "MySafety",
            "MyInvariant",
            temporal_always(bool_expr()),
        )],
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
    let expr = temporal_eventually_within(bool_expr(), dur_lit_expr(24, DurationUnit::Hours));
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
    let expr = temporal_eventually_within(bool_expr(), dur_lit_expr(5, DurationUnit::Minutes));
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![proof_member("P", "I", expr)],
    )]));
    assert_eq!(policies[0].state_machines[0].states.len(), 3);
}

#[test]
fn always_with_within_has_deadline() {
    let expr = temporal_always_within(bool_expr(), dur_lit_expr(10, DurationUnit::Seconds));
    let (policies, _) = lower::compile(&program(vec![simple_policy(
        "Guard",
        vec![proof_member("P", "I", expr)],
    )]));
    assert_eq!(policies[0].state_machines[0].deadline_millis, Some(10_000));
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
    assert_eq!(
        unique.len(),
        sm_ids.len(),
        "state machine IDs should be unique"
    );
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

// ── Policy inheritance (`extends`) ────────────────────────────────────────────
//
// Current behavior: the lowering pass ignores `extends` — each policy compiles
// independently from its own members. These tests verify that presence of an
// `extends` clause does not panic or produce spurious errors, and document the
// boundary at which member-merging should eventually be tested once inheritance
// lowering is implemented.

fn policy_extends(
    name: &str,
    base: &str,
    members: Vec<Spanned<PolicyMember>>,
) -> Spanned<Declaration> {
    Spanned::dummy(Declaration::Policy(PolicyDecl {
        annotations: vec![],
        name: ident(name),
        extends: Some(QualifiedName::simple(ident(base))),
        members,
    }))
}

#[test]
fn derived_policy_extends_base_compiles_without_errors() {
    let prog = program(vec![
        simple_policy("Base", vec![severity_member(SeverityLevel::High)]),
        policy_extends("Derived", "Base", vec![]),
    ]);
    let (_, diags) = lower::compile(&prog);
    assert!(!diags.has_errors());
}

#[test]
fn derived_policy_with_extends_produces_a_compiled_policy() {
    let prog = program(vec![
        simple_policy("Base", vec![]),
        policy_extends("Derived", "Base", vec![]),
    ]);
    let (policies, _) = lower::compile(&prog);
    assert_eq!(policies.len(), 2);
    assert!(policies.iter().any(|p| p.name.as_str() == "Derived"));
}

#[test]
fn derived_policy_own_rules_are_present() {
    let prog = program(vec![
        simple_policy(
            "Base",
            vec![rule_member("base_event", vec![deny_verdict()])],
        ),
        policy_extends(
            "Derived",
            "Base",
            vec![rule_member("derived_event", vec![allow_verdict()])],
        ),
    ]);
    let (policies, _) = lower::compile(&prog);
    let derived = policies
        .iter()
        .find(|p| p.name.as_str() == "Derived")
        .unwrap();
    // The derived policy's own rule must be present.
    assert!(
        derived
            .rules
            .iter()
            .any(|r| r.on_events.iter().any(|e| e.as_str() == "derived_event")),
        "derived policy's own rules should be compiled"
    );
}

#[test]
fn base_policy_is_compiled_independently() {
    // Even when another policy extends it, the base compiles to its own output.
    let prog = program(vec![
        simple_policy(
            "Base",
            vec![rule_member("base_event", vec![deny_verdict()])],
        ),
        policy_extends("Derived", "Base", vec![]),
    ]);
    let (policies, _) = lower::compile(&prog);
    let base = policies.iter().find(|p| p.name.as_str() == "Base").unwrap();
    assert_eq!(base.rules.len(), 1);
}

#[test]
fn multilevel_chain_all_compile_without_errors() {
    // C extends B, B extends A — three levels deep.
    let prog = program(vec![
        simple_policy("A", vec![severity_member(SeverityLevel::Low)]),
        policy_extends("B", "A", vec![severity_member(SeverityLevel::Medium)]),
        policy_extends("C", "B", vec![severity_member(SeverityLevel::High)]),
    ]);
    let (policies, diags) = lower::compile(&prog);
    assert!(
        !diags.has_errors(),
        "multilevel chain should compile cleanly"
    );
    assert_eq!(policies.len(), 3);
}

#[test]
fn multilevel_chain_each_has_correct_name() {
    let prog = program(vec![
        simple_policy("Root", vec![]),
        policy_extends("Middle", "Root", vec![]),
        policy_extends("Leaf", "Middle", vec![]),
    ]);
    let (policies, _) = lower::compile(&prog);
    let names: Vec<&str> = policies.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"Root"));
    assert!(names.contains(&"Middle"));
    assert!(names.contains(&"Leaf"));
}

#[test]
fn multilevel_chain_leaf_has_own_rule() {
    let prog = program(vec![
        simple_policy(
            "Root",
            vec![rule_member("root_event", vec![deny_verdict()])],
        ),
        policy_extends(
            "Mid",
            "Root",
            vec![rule_member("mid_event", vec![deny_verdict()])],
        ),
        policy_extends(
            "Leaf",
            "Mid",
            vec![rule_member("leaf_event", vec![allow_verdict()])],
        ),
    ]);
    let (policies, _) = lower::compile(&prog);
    let leaf = policies.iter().find(|p| p.name.as_str() == "Leaf").unwrap();
    assert!(
        leaf.rules
            .iter()
            .any(|r| r.on_events.iter().any(|e| e.as_str() == "leaf_event")),
        "leaf policy should contain its own rule"
    );
}

// ── Diamond topology (closest expressible with single inheritance) ────────────
//
// Aegis supports single inheritance only: `extends` takes at most one base.
// The closest topology to a diamond is two sibling policies that share a
// common ancestor: D ← B ← A and D ← C.  "Resolving the diamond" means
// verifying that D's members appear exactly once in each derived policy's
// compiled output — no cross-chain duplication.
//
// Note on cross-policy output: the compiler intentionally inlines each
// policy's full ancestry into its own compiled output so that individual
// `.aegisc` files can be loaded without their base policies present.  When
// multiple policies extend the same base, the base's compiled members appear
// in each policy's bytecode independently.  This is by design (self-contained
// output), not a correctness defect.

#[test]
fn diamond_shape_compiles_without_errors() {
    // Two subtrees sharing D: D←B←A, D←C.
    let prog = program(vec![
        simple_policy("D", vec![severity_member(SeverityLevel::Low)]),
        policy_extends("B", "D", vec![]),
        policy_extends("C", "D", vec![]),
        policy_extends("A", "B", vec![]),
    ]);
    let (policies, diags) = lower::compile(&prog);
    assert!(
        !diags.has_errors(),
        "diamond-shaped hierarchy should compile cleanly"
    );
    assert_eq!(policies.len(), 4);
}

#[test]
fn diamond_shape_all_names_present() {
    let prog = program(vec![
        simple_policy("D", vec![]),
        policy_extends("B", "D", vec![]),
        policy_extends("C", "D", vec![]),
        policy_extends("A", "B", vec![]),
    ]);
    let (policies, _) = lower::compile(&prog);
    let names: std::collections::HashSet<&str> = policies.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains("A"));
    assert!(names.contains("B"));
    assert!(names.contains("C"));
    assert!(names.contains("D"));
}

#[test]
fn diamond_base_rule_appears_once_in_each_sibling() {
    // D has one rule.  B and C each extend D.
    // Each compiled sibling should contain D's rule exactly once.
    let prog = program(vec![
        simple_policy("D", vec![rule_member("d_ev", vec![deny_verdict()])]),
        policy_extends("B", "D", vec![]),
        policy_extends("C", "D", vec![]),
    ]);
    let (policies, _) = lower::compile(&prog);
    let b = policies.iter().find(|p| p.name.as_str() == "B").unwrap();
    let c = policies.iter().find(|p| p.name.as_str() == "C").unwrap();
    assert_eq!(b.rules.len(), 1, "B should have D's rule exactly once");
    assert_eq!(c.rules.len(), 1, "C should have D's rule exactly once");
}

#[test]
fn diamond_base_rule_appears_once_in_deep_child() {
    // D←B←A: A inherits through B, which inherits from D.
    // D's rule must appear exactly once in A — not duplicated.
    let prog = program(vec![
        simple_policy("D", vec![rule_member("d_ev", vec![deny_verdict()])]),
        policy_extends("B", "D", vec![rule_member("b_ev", vec![deny_verdict()])]),
        policy_extends("C", "D", vec![]),
        policy_extends("A", "B", vec![rule_member("a_ev", vec![allow_verdict()])]),
    ]);
    let (policies, _) = lower::compile(&prog);
    let a = policies.iter().find(|p| p.name.as_str() == "A").unwrap();
    // A inherits d_ev (via B←D) and b_ev (from B), plus its own a_ev.
    assert_eq!(
        a.rules.len(),
        3,
        "A should have d + b + own rule, each once"
    );
    // Count occurrences of d_ev specifically.
    let d_ev_count = a
        .rules
        .iter()
        .filter(|r| r.on_events.iter().any(|e| e.as_str() == "d_ev"))
        .count();
    assert_eq!(d_ev_count, 1, "d_ev must appear exactly once in A");
}

#[test]
fn diamond_base_state_machine_appears_once_in_each_sibling() {
    // D has one temporal invariant → one state machine.
    // B and C (both extending D) each inherit exactly one state machine.
    let prog = program(vec![
        simple_policy(
            "D",
            vec![proof_member("P", "I", temporal_always(bool_expr()))],
        ),
        policy_extends("B", "D", vec![]),
        policy_extends("C", "D", vec![]),
    ]);
    let (policies, _) = lower::compile(&prog);
    let b = policies.iter().find(|p| p.name.as_str() == "B").unwrap();
    let c = policies.iter().find(|p| p.name.as_str() == "C").unwrap();
    assert_eq!(
        b.state_machines.len(),
        1,
        "B should inherit D's SM exactly once"
    );
    assert_eq!(
        c.state_machines.len(),
        1,
        "C should inherit D's SM exactly once"
    );
}

#[test]
fn diamond_base_constraint_appears_once_in_each_sibling() {
    // D has one rate-limit constraint; B and C inherit it without duplication.
    let prog = program(vec![
        simple_policy(
            "D",
            vec![constraint_member(
                ConstraintKind::RateLimit,
                "calls",
                10,
                1,
                DurationUnit::Minutes,
            )],
        ),
        policy_extends("B", "D", vec![]),
        policy_extends("C", "D", vec![]),
    ]);
    let (policies, _) = lower::compile(&prog);
    let b = policies.iter().find(|p| p.name.as_str() == "B").unwrap();
    let c = policies.iter().find(|p| p.name.as_str() == "C").unwrap();
    assert_eq!(
        b.constraints.len(),
        1,
        "B should inherit D's constraint exactly once"
    );
    assert_eq!(
        c.constraints.len(),
        1,
        "C should inherit D's constraint exactly once"
    );
}

#[test]
fn diamond_severity_inherited_by_both_siblings() {
    // D sets severity Critical; B and C inherit it without override.
    let prog = program(vec![
        simple_policy("D", vec![severity_member(SeverityLevel::Critical)]),
        policy_extends("B", "D", vec![]),
        policy_extends("C", "D", vec![]),
    ]);
    let (policies, _) = lower::compile(&prog);
    let b = policies.iter().find(|p| p.name.as_str() == "B").unwrap();
    let c = policies.iter().find(|p| p.name.as_str() == "C").unwrap();
    assert_eq!(b.severity, SeverityLevel::Critical);
    assert_eq!(c.severity, SeverityLevel::Critical);
}

#[test]
fn forward_reference_extends_compiles_without_errors() {
    // Derived is declared before its base — forward reference.
    let prog = program(vec![
        policy_extends("Derived", "Base", vec![]),
        simple_policy("Base", vec![]),
    ]);
    let (_, diags) = lower::compile(&prog);
    assert!(
        !diags.has_errors(),
        "forward-reference extends should compile"
    );
}

// ── Inheritance member merging ────────────────────────────────────────────────
//
// These tests verify that rules, state machines, constraints, and severity set
// in a base policy are carried into derived policies by the lowering pass.

#[test]
fn derived_inherits_single_rule_from_base() {
    let prog = program(vec![
        simple_policy(
            "Base",
            vec![rule_member("base_event", vec![deny_verdict()])],
        ),
        policy_extends("Derived", "Base", vec![]),
    ]);
    let (policies, _) = lower::compile(&prog);
    let derived = policies
        .iter()
        .find(|p| p.name.as_str() == "Derived")
        .unwrap();
    assert_eq!(
        derived.rules.len(),
        1,
        "derived should inherit the base rule"
    );
    assert!(derived.rules[0]
        .on_events
        .iter()
        .any(|e| e.as_str() == "base_event"));
}

#[test]
fn derived_has_both_inherited_and_own_rules() {
    let prog = program(vec![
        simple_policy(
            "Base",
            vec![rule_member("base_event", vec![deny_verdict()])],
        ),
        policy_extends(
            "Derived",
            "Base",
            vec![rule_member("derived_event", vec![allow_verdict()])],
        ),
    ]);
    let (policies, _) = lower::compile(&prog);
    let derived = policies
        .iter()
        .find(|p| p.name.as_str() == "Derived")
        .unwrap();
    assert_eq!(
        derived.rules.len(),
        2,
        "derived should have base + own rule"
    );
    assert!(derived
        .rules
        .iter()
        .any(|r| r.on_events.iter().any(|e| e.as_str() == "base_event")));
    assert!(derived
        .rules
        .iter()
        .any(|r| r.on_events.iter().any(|e| e.as_str() == "derived_event")));
}

#[test]
fn derived_inherits_base_severity() {
    // Base is High; derived has no severity override → inherits High.
    let prog = program(vec![
        simple_policy("Base", vec![severity_member(SeverityLevel::High)]),
        policy_extends("Derived", "Base", vec![]),
    ]);
    let (policies, _) = lower::compile(&prog);
    let derived = policies
        .iter()
        .find(|p| p.name.as_str() == "Derived")
        .unwrap();
    assert_eq!(derived.severity, SeverityLevel::High);
}

#[test]
fn derived_severity_overrides_base() {
    // Base is Low; derived sets Critical → last-wins gives Critical.
    let prog = program(vec![
        simple_policy("Base", vec![severity_member(SeverityLevel::Low)]),
        policy_extends(
            "Derived",
            "Base",
            vec![severity_member(SeverityLevel::Critical)],
        ),
    ]);
    let (policies, _) = lower::compile(&prog);
    let derived = policies
        .iter()
        .find(|p| p.name.as_str() == "Derived")
        .unwrap();
    assert_eq!(derived.severity, SeverityLevel::Critical);
}

#[test]
fn derived_inherits_base_state_machine() {
    // Base has a temporal invariant; derived should get the compiled state machine.
    let prog = program(vec![
        simple_policy(
            "Base",
            vec![proof_member("P", "I", temporal_always(bool_expr()))],
        ),
        policy_extends("Derived", "Base", vec![]),
    ]);
    let (policies, _) = lower::compile(&prog);
    let derived = policies
        .iter()
        .find(|p| p.name.as_str() == "Derived")
        .unwrap();
    assert_eq!(
        derived.state_machines.len(),
        1,
        "derived should inherit base state machine"
    );
}

#[test]
fn derived_accumulates_state_machines_from_base_and_own() {
    let prog = program(vec![
        simple_policy(
            "Base",
            vec![proof_member("P1", "I1", temporal_always(bool_expr()))],
        ),
        policy_extends(
            "Derived",
            "Base",
            vec![proof_member("P2", "I2", temporal_never(bool_expr()))],
        ),
    ]);
    let (policies, _) = lower::compile(&prog);
    let derived = policies
        .iter()
        .find(|p| p.name.as_str() == "Derived")
        .unwrap();
    assert_eq!(derived.state_machines.len(), 2);
}

#[test]
fn derived_inherits_base_constraint() {
    let prog = program(vec![
        simple_policy(
            "Base",
            vec![constraint_member(
                ConstraintKind::RateLimit,
                "calls",
                10,
                1,
                DurationUnit::Minutes,
            )],
        ),
        policy_extends("Derived", "Base", vec![]),
    ]);
    let (policies, _) = lower::compile(&prog);
    let derived = policies
        .iter()
        .find(|p| p.name.as_str() == "Derived")
        .unwrap();
    assert_eq!(
        derived.constraints.len(),
        1,
        "derived should inherit the base constraint"
    );
}

#[test]
fn multilevel_leaf_inherits_all_ancestor_rules() {
    // Root → Mid → Leaf; each level contributes one rule.
    let prog = program(vec![
        simple_policy("Root", vec![rule_member("root_ev", vec![deny_verdict()])]),
        policy_extends(
            "Mid",
            "Root",
            vec![rule_member("mid_ev", vec![deny_verdict()])],
        ),
        policy_extends(
            "Leaf",
            "Mid",
            vec![rule_member("leaf_ev", vec![allow_verdict()])],
        ),
    ]);
    let (policies, _) = lower::compile(&prog);
    let leaf = policies.iter().find(|p| p.name.as_str() == "Leaf").unwrap();
    assert_eq!(
        leaf.rules.len(),
        3,
        "leaf should have root + mid + own rule"
    );
    assert!(leaf
        .rules
        .iter()
        .any(|r| r.on_events.iter().any(|e| e.as_str() == "root_ev")));
    assert!(leaf
        .rules
        .iter()
        .any(|r| r.on_events.iter().any(|e| e.as_str() == "mid_ev")));
    assert!(leaf
        .rules
        .iter()
        .any(|r| r.on_events.iter().any(|e| e.as_str() == "leaf_ev")));
}

#[test]
fn inheritance_cycle_guard_does_not_panic() {
    // Cycle: A extends B, B extends A. The lowering should not loop forever.
    // B is not in the program (unknown base), so only A is compiled. The
    // cycle guard is exercised when A is resolved and its base lookup finds
    // a policy that has already been visited.
    let prog = program(vec![
        policy_extends("A", "B", vec![rule_member("ev_a", vec![deny_verdict()])]),
        policy_extends("B", "A", vec![rule_member("ev_b", vec![deny_verdict()])]),
    ]);
    // Must complete without panicking.
    let (policies, _) = lower::compile(&prog);
    assert_eq!(policies.len(), 2);
}

#[test]
fn base_rules_are_not_duplicated_when_multiple_policies_extend_it() {
    // D extends Base; E extends Base. Base's rules must not multiply.
    let prog = program(vec![
        simple_policy("Base", vec![rule_member("shared", vec![deny_verdict()])]),
        policy_extends("D", "Base", vec![]),
        policy_extends("E", "Base", vec![]),
    ]);
    let (policies, _) = lower::compile(&prog);
    let d = policies.iter().find(|p| p.name.as_str() == "D").unwrap();
    let e = policies.iter().find(|p| p.name.as_str() == "E").unwrap();
    assert_eq!(d.rules.len(), 1);
    assert_eq!(e.rules.len(), 1);
}

// ── Additional temporal operators (Next / Before / After) ─────────────────────

fn temporal_next(cond: Spanned<Expr>) -> Spanned<Expr> {
    Spanned::dummy(Expr::Temporal(TemporalExpr::Next {
        condition: Box::new(cond),
    }))
}

fn temporal_before(first: Spanned<Expr>, second: Spanned<Expr>) -> Spanned<Expr> {
    Spanned::dummy(Expr::Temporal(TemporalExpr::Before {
        first: Box::new(first),
        second: Box::new(second),
    }))
}

fn temporal_after(condition: Spanned<Expr>, trigger: Spanned<Expr>) -> Spanned<Expr> {
    Spanned::dummy(Expr::Temporal(TemporalExpr::After {
        condition: Box::new(condition),
        trigger: Box::new(trigger),
    }))
}

#[test]
fn next_invariant_compiles_to_state_machine_with_kind_next() {
    let prog = program(vec![simple_policy(
        "P",
        vec![proof_member(
            "Proof",
            "MustNext",
            temporal_next(bool_expr()),
        )],
    )]);
    let (policies, diags) = lower::compile(&prog);
    assert!(!diags.has_errors());
    let policy = &policies[0];
    assert_eq!(policy.state_machines.len(), 1);
    assert_eq!(policy.state_machines[0].kind, TemporalKind::Next);
}

#[test]
fn next_state_machine_has_four_states() {
    // next(φ) → initial → checking → satisfied/violated (4 states)
    let prog = program(vec![simple_policy(
        "P",
        vec![proof_member(
            "Proof",
            "NextCheck",
            temporal_next(bool_expr()),
        )],
    )]);
    let (policies, _) = lower::compile(&prog);
    assert_eq!(policies[0].state_machines[0].states.len(), 4);
}

// ── always(next(ψ)) ───────────────────────────────────────────────────────────

fn always_next(cond: Spanned<Expr>) -> Spanned<Expr> {
    temporal_always(temporal_next(cond))
}

fn always_implies_next(trigger: Spanned<Expr>, response: Spanned<Expr>) -> Spanned<Expr> {
    temporal_always(Spanned::dummy(Expr::Binary {
        op: Spanned::dummy(BinaryOp::Implies),
        left: Box::new(trigger),
        right: Box::new(temporal_next(response)),
    }))
}

#[test]
fn always_next_compiles_without_errors() {
    let prog = program(vec![simple_policy(
        "P",
        vec![proof_member(
            "Proof",
            "AlwaysNext",
            always_next(bool_expr()),
        )],
    )]);
    let (_, diags) = lower::compile(&prog);
    assert!(!diags.has_errors());
}

#[test]
fn always_next_produces_kind_next() {
    let prog = program(vec![simple_policy(
        "P",
        vec![proof_member(
            "Proof",
            "AlwaysNext",
            always_next(bool_expr()),
        )],
    )]);
    let (policies, _) = lower::compile(&prog);
    assert_eq!(policies[0].state_machines[0].kind, TemporalKind::Next);
}

#[test]
fn always_next_has_three_states() {
    // initial → checking (loop/violated)
    let prog = program(vec![simple_policy(
        "P",
        vec![proof_member(
            "Proof",
            "AlwaysNext",
            always_next(bool_expr()),
        )],
    )]);
    let (policies, _) = lower::compile(&prog);
    assert_eq!(policies[0].state_machines[0].states.len(), 3);
}

#[test]
fn always_next_initial_state_is_active() {
    let prog = program(vec![simple_policy(
        "P",
        vec![proof_member("Proof", "AN", always_next(bool_expr()))],
    )]);
    let (policies, _) = lower::compile(&prog);
    let sm = &policies[0].state_machines[0];
    assert_eq!(sm.states[sm.initial_state as usize].kind, StateKind::Active);
}

#[test]
fn always_next_has_one_violating_state() {
    let prog = program(vec![simple_policy(
        "P",
        vec![proof_member("Proof", "AN", always_next(bool_expr()))],
    )]);
    let (policies, _) = lower::compile(&prog);
    assert_eq!(policies[0].state_machines[0].violating_states.len(), 1);
}

// ── always(trigger implies next(ψ)) ──────────────────────────────────────────

#[test]
fn always_implies_next_compiles_without_errors() {
    let prog = program(vec![simple_policy(
        "P",
        vec![proof_member(
            "Proof",
            "Seq",
            always_implies_next(bool_expr(), bool_expr()),
        )],
    )]);
    let (_, diags) = lower::compile(&prog);
    assert!(!diags.has_errors());
}

#[test]
fn always_implies_next_produces_kind_next() {
    let prog = program(vec![simple_policy(
        "P",
        vec![proof_member(
            "Proof",
            "Seq",
            always_implies_next(bool_expr(), bool_expr()),
        )],
    )]);
    let (policies, _) = lower::compile(&prog);
    assert_eq!(policies[0].state_machines[0].kind, TemporalKind::Next);
}

#[test]
fn always_implies_next_has_three_states() {
    // idle → armed → violated (reset arc from armed to idle)
    let prog = program(vec![simple_policy(
        "P",
        vec![proof_member(
            "Proof",
            "Seq",
            always_implies_next(bool_expr(), bool_expr()),
        )],
    )]);
    let (policies, _) = lower::compile(&prog);
    assert_eq!(policies[0].state_machines[0].states.len(), 3);
}

#[test]
fn always_implies_next_initial_state_is_idle() {
    let prog = program(vec![simple_policy(
        "P",
        vec![proof_member(
            "Proof",
            "Seq",
            always_implies_next(bool_expr(), bool_expr()),
        )],
    )]);
    let (policies, _) = lower::compile(&prog);
    let sm = &policies[0].state_machines[0];
    assert_eq!(sm.states[sm.initial_state as usize].label.as_str(), "idle");
}

#[test]
fn always_implies_next_has_four_transitions() {
    // idle→idle, idle→armed, armed→idle, armed→violated
    let prog = program(vec![simple_policy(
        "P",
        vec![proof_member(
            "Proof",
            "Seq",
            always_implies_next(bool_expr(), bool_expr()),
        )],
    )]);
    let (policies, _) = lower::compile(&prog);
    assert_eq!(policies[0].state_machines[0].transitions.len(), 4);
}

#[test]
fn always_implies_next_violating_state_is_state_2() {
    let prog = program(vec![simple_policy(
        "P",
        vec![proof_member(
            "Proof",
            "Seq",
            always_implies_next(bool_expr(), bool_expr()),
        )],
    )]);
    let (policies, _) = lower::compile(&prog);
    let sm = &policies[0].state_machines[0];
    assert_eq!(sm.violating_states, vec![2]);
    assert_eq!(sm.states[2].kind, StateKind::Violated);
}

#[test]
fn before_invariant_compiles_to_state_machine() {
    let prog = program(vec![simple_policy(
        "P",
        vec![proof_member(
            "Proof",
            "Order",
            temporal_before(bool_expr(), bool_expr()),
        )],
    )]);
    let (policies, diags) = lower::compile(&prog);
    assert!(!diags.has_errors());
    assert_eq!(policies[0].state_machines.len(), 1);
}

#[test]
fn before_state_machine_has_three_states() {
    let prog = program(vec![simple_policy(
        "P",
        vec![proof_member(
            "Proof",
            "BeforeOrder",
            temporal_before(bool_expr(), bool_expr()),
        )],
    )]);
    let (policies, _) = lower::compile(&prog);
    assert_eq!(policies[0].state_machines[0].states.len(), 3);
}

#[test]
fn after_invariant_compiles_to_state_machine() {
    let prog = program(vec![simple_policy(
        "P",
        vec![proof_member(
            "Proof",
            "Sequence",
            temporal_after(bool_expr(), bool_expr()),
        )],
    )]);
    let (policies, diags) = lower::compile(&prog);
    assert!(!diags.has_errors());
    assert_eq!(policies[0].state_machines.len(), 1);
}

// ── lower_expr variant coverage ───────────────────────────────────────────────

// Helper: build a policy whose single rule has the given `when` expression.
// Lowering the policy exercises lower_expr on that expression.
fn policy_with_when_expr(expr: Spanned<Expr>) -> aegis_compiler::ast::Program {
    program(vec![simple_policy(
        "P",
        vec![rule_member("ev", vec![when_clause(expr), deny_verdict()])],
    )])
}

#[test]
fn lower_expr_unary_not_does_not_panic() {
    let expr = Spanned::dummy(Expr::Unary {
        op: Spanned::dummy(UnaryOp::Not),
        operand: Box::new(bool_expr()),
    });
    let (policies, _) = lower::compile(&policy_with_when_expr(expr));
    assert_eq!(policies.len(), 1);
}

#[test]
fn lower_expr_context_ref_produces_ir() {
    let name = QualifiedName {
        segments: vec![ident("tool_calls")],
        span: Span::DUMMY,
    };
    let expr = Spanned::dummy(Expr::Context(name));
    let (policies, _) = lower::compile(&policy_with_when_expr(expr));
    assert_eq!(policies.len(), 1);
}

#[test]
fn lower_expr_identifier_event_root_resolves() {
    // Identifier starting with "event" → RefRoot::Event
    let name = QualifiedName {
        segments: vec![ident("event"), ident("tool")],
        span: Span::DUMMY,
    };
    let expr = Spanned::dummy(Expr::Identifier(name));
    let (policies, _) = lower::compile(&policy_with_when_expr(expr));
    assert_eq!(policies.len(), 1);
}

#[test]
fn lower_expr_identifier_context_root_resolves() {
    let name = QualifiedName {
        segments: vec![ident("context"), ident("budget")],
        span: Span::DUMMY,
    };
    let expr = Spanned::dummy(Expr::Identifier(name));
    let (policies, _) = lower::compile(&policy_with_when_expr(expr));
    assert_eq!(policies.len(), 1);
}

#[test]
fn lower_expr_identifier_policy_root_resolves() {
    let name = QualifiedName {
        segments: vec![ident("policy"), ident("version")],
        span: Span::DUMMY,
    };
    let expr = Spanned::dummy(Expr::Identifier(name));
    let (policies, _) = lower::compile(&policy_with_when_expr(expr));
    assert_eq!(policies.len(), 1);
}

#[test]
fn lower_expr_identifier_unresolved_single_segment() {
    // Unknown single-segment name → context ref for forward compat
    let name = QualifiedName {
        segments: vec![ident("unknown_var")],
        span: Span::DUMMY,
    };
    let expr = Spanned::dummy(Expr::Identifier(name));
    let (policies, _) = lower::compile(&policy_with_when_expr(expr));
    assert_eq!(policies.len(), 1);
}

#[test]
fn lower_expr_identifier_multi_segment_unknown() {
    // Multi-segment unknown → dotted context ref
    let name = QualifiedName {
        segments: vec![ident("module"), ident("sub"), ident("field")],
        span: Span::DUMMY,
    };
    let expr = Spanned::dummy(Expr::Identifier(name));
    let (policies, _) = lower::compile(&policy_with_when_expr(expr));
    assert_eq!(policies.len(), 1);
}

#[test]
fn lower_expr_field_access_does_not_panic() {
    let obj = Spanned::dummy(Expr::Context(QualifiedName {
        segments: vec![ident("data")],
        span: Span::DUMMY,
    }));
    let expr = Spanned::dummy(Expr::FieldAccess {
        object: Box::new(obj),
        field: ident("value"),
    });
    let (policies, _) = lower::compile(&policy_with_when_expr(expr));
    assert_eq!(policies.len(), 1);
}

#[test]
fn lower_expr_index_access_does_not_panic() {
    let obj = Spanned::dummy(Expr::Context(QualifiedName {
        segments: vec![ident("items")],
        span: Span::DUMMY,
    }));
    let expr = Spanned::dummy(Expr::IndexAccess {
        object: Box::new(obj),
        index: Box::new(int_lit_expr(0)),
    });
    let (policies, _) = lower::compile(&policy_with_when_expr(expr));
    assert_eq!(policies.len(), 1);
}

#[test]
fn lower_expr_call_known_identifier_does_not_panic() {
    let callee = Spanned::dummy(Expr::Identifier(QualifiedName {
        segments: vec![ident("my_func")],
        span: Span::DUMMY,
    }));
    let expr = Spanned::dummy(Expr::Call {
        callee: Box::new(callee),
        args: vec![],
    });
    let (policies, _) = lower::compile(&policy_with_when_expr(expr));
    assert_eq!(policies.len(), 1);
}

#[test]
fn lower_expr_call_field_access_callee() {
    // Call where callee is a FieldAccess → MethodCall in IR
    let obj = Spanned::dummy(Expr::Context(QualifiedName {
        segments: vec![ident("obj")],
        span: Span::DUMMY,
    }));
    let fa = Spanned::dummy(Expr::FieldAccess {
        object: Box::new(obj),
        field: ident("method"),
    });
    let expr = Spanned::dummy(Expr::Call {
        callee: Box::new(fa),
        args: vec![Argument {
            name: None,
            value: bool_expr(),
        }],
    });
    let (policies, _) = lower::compile(&policy_with_when_expr(expr));
    assert_eq!(policies.len(), 1);
}

#[test]
fn lower_expr_method_call_does_not_panic() {
    let obj = Spanned::dummy(Expr::Context(QualifiedName {
        segments: vec![ident("items")],
        span: Span::DUMMY,
    }));
    let expr = Spanned::dummy(Expr::MethodCall {
        object: Box::new(obj),
        method: ident("count"),
        args: vec![],
    });
    let (policies, _) = lower::compile(&policy_with_when_expr(expr));
    assert_eq!(policies.len(), 1);
}

#[test]
fn lower_expr_predicate_does_not_panic() {
    let subject = Spanned::dummy(Expr::Identifier(QualifiedName {
        segments: vec![ident("event"), ident("url")],
        span: Span::DUMMY,
    }));
    let expr = Spanned::dummy(Expr::Predicate {
        kind: PredicateKind::StartsWith,
        subject: Box::new(subject),
        argument: Box::new(Spanned::dummy(Expr::Literal(Literal::String(
            "https".into(),
        )))),
    });
    let (policies, _) = lower::compile(&policy_with_when_expr(expr));
    assert_eq!(policies.len(), 1);
}

#[test]
fn lower_expr_quantifier_all_does_not_panic() {
    let collection = Spanned::dummy(Expr::Context(QualifiedName {
        segments: vec![ident("tools")],
        span: Span::DUMMY,
    }));
    let lambda = Lambda {
        params: vec![LambdaParam {
            name: ident("t"),
            ty: None,
        }],
        body: Box::new(bool_expr()),
    };
    let expr = Spanned::dummy(Expr::Quantifier {
        kind: QuantifierKind::All,
        collection: Box::new(collection),
        predicate: Box::new(lambda),
    });
    let (policies, _) = lower::compile(&policy_with_when_expr(expr));
    assert_eq!(policies.len(), 1);
}

#[test]
fn lower_expr_count_with_filter_does_not_panic() {
    let collection = Spanned::dummy(Expr::Context(QualifiedName {
        segments: vec![ident("calls")],
        span: Span::DUMMY,
    }));
    let lambda = Lambda {
        params: vec![LambdaParam {
            name: ident("c"),
            ty: None,
        }],
        body: Box::new(bool_expr()),
    };
    let expr = Spanned::dummy(Expr::Count {
        collection: Box::new(collection),
        filter: Some(Box::new(lambda)),
    });
    let (policies, _) = lower::compile(&policy_with_when_expr(expr));
    assert_eq!(policies.len(), 1);
}

#[test]
fn lower_expr_count_without_filter_does_not_panic() {
    let collection = Spanned::dummy(Expr::Context(QualifiedName {
        segments: vec![ident("calls")],
        span: Span::DUMMY,
    }));
    let expr = Spanned::dummy(Expr::Count {
        collection: Box::new(collection),
        filter: None,
    });
    let (policies, _) = lower::compile(&policy_with_when_expr(expr));
    assert_eq!(policies.len(), 1);
}

#[test]
fn lower_expr_list_does_not_panic() {
    let expr = Spanned::dummy(Expr::List(vec![bool_expr(), bool_expr(), int_lit_expr(1)]));
    let (policies, _) = lower::compile(&policy_with_when_expr(expr));
    assert_eq!(policies.len(), 1);
}

#[test]
fn lower_expr_object_does_not_panic() {
    let expr = Spanned::dummy(Expr::Object(vec![ObjectField {
        key: ident("key"),
        value: bool_expr(),
    }]));
    let (policies, _) = lower::compile(&policy_with_when_expr(expr));
    assert_eq!(policies.len(), 1);
}

#[test]
fn lower_expr_lambda_does_not_panic() {
    let lambda = Lambda {
        params: vec![LambdaParam {
            name: ident("x"),
            ty: None,
        }],
        body: Box::new(bool_expr()),
    };
    let expr = Spanned::dummy(Expr::Lambda(lambda));
    let (policies, _) = lower::compile(&policy_with_when_expr(expr));
    assert_eq!(policies.len(), 1);
}

#[test]
fn lower_expr_match_wildcard_pattern_does_not_panic() {
    let arm = MatchArm {
        pattern: Spanned::dummy(Pattern::Wildcard),
        result: Spanned::dummy(MatchResult::Expr(Expr::Literal(Literal::Bool(true)))),
        span: Span::DUMMY,
    };
    let expr = Spanned::dummy(Expr::Match {
        scrutinee: Box::new(bool_expr()),
        arms: vec![arm],
    });
    let (policies, _) = lower::compile(&policy_with_when_expr(expr));
    assert_eq!(policies.len(), 1);
}

#[test]
fn lower_expr_match_literal_pattern_does_not_panic() {
    let arm = MatchArm {
        pattern: Spanned::dummy(Pattern::Literal(Literal::Bool(true))),
        result: Spanned::dummy(MatchResult::Expr(Expr::Literal(Literal::Bool(false)))),
        span: Span::DUMMY,
    };
    let expr = Spanned::dummy(Expr::Match {
        scrutinee: Box::new(bool_expr()),
        arms: vec![arm],
    });
    let (policies, _) = lower::compile(&policy_with_when_expr(expr));
    assert_eq!(policies.len(), 1);
}

#[test]
fn lower_expr_match_destructure_pattern_does_not_panic() {
    let arm = MatchArm {
        pattern: Spanned::dummy(Pattern::Destructure {
            name: simple_name("MyType"),
            fields: vec![],
        }),
        result: Spanned::dummy(MatchResult::Expr(Expr::Literal(Literal::Bool(true)))),
        span: Span::DUMMY,
    };
    let expr = Spanned::dummy(Expr::Match {
        scrutinee: Box::new(bool_expr()),
        arms: vec![arm],
    });
    let (policies, _) = lower::compile(&policy_with_when_expr(expr));
    assert_eq!(policies.len(), 1);
}

#[test]
fn lower_expr_match_or_pattern_does_not_panic() {
    let arm = MatchArm {
        pattern: Spanned::dummy(Pattern::Or(vec![
            Spanned::dummy(Pattern::Literal(Literal::Bool(true))),
            Spanned::dummy(Pattern::Literal(Literal::Bool(false))),
        ])),
        result: Spanned::dummy(MatchResult::Expr(Expr::Literal(Literal::Bool(true)))),
        span: Span::DUMMY,
    };
    let expr = Spanned::dummy(Expr::Match {
        scrutinee: Box::new(bool_expr()),
        arms: vec![arm],
    });
    let (policies, _) = lower::compile(&policy_with_when_expr(expr));
    assert_eq!(policies.len(), 1);
}

#[test]
fn lower_expr_match_guard_pattern_does_not_panic() {
    let arm = MatchArm {
        pattern: Spanned::dummy(Pattern::Guard {
            pattern: Box::new(Spanned::dummy(Pattern::Wildcard)),
            condition: Box::new(bool_expr()),
        }),
        result: Spanned::dummy(MatchResult::Expr(Expr::Literal(Literal::Bool(true)))),
        span: Span::DUMMY,
    };
    let expr = Spanned::dummy(Expr::Match {
        scrutinee: Box::new(bool_expr()),
        arms: vec![arm],
    });
    let (policies, _) = lower::compile(&policy_with_when_expr(expr));
    assert_eq!(policies.len(), 1);
}
