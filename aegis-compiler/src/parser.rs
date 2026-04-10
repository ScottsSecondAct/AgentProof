//! Pest-based parser for the Aegis policy language.
//!
//! Transforms `.aegis` source text into a typed [`Program`] AST.
//! All parse errors are emitted into a [`DiagnosticSink`] rather than
//! panicking so that callers can report multiple errors at once.
//!
//! # Entry point
//!
//! ```ignore
//! let (program, diags) = parse_source(source, "policy.aegis");
//! if diags.has_errors() {
//!     eprintln!("{}", diags.render(source, "policy.aegis"));
//! }
//! ```

use pest::iterators::Pair;
use pest::Parser as _;
use smol_str::SmolStr;

use crate::ast::nodes::*;
use crate::ast::span::{Span, Spanned};
use crate::diagnostics::{Diagnostic, DiagnosticCode, DiagnosticSink};

// ═══════════════════════════════════════════════════════════════════════
//  pest-derive Parser
// ═══════════════════════════════════════════════════════════════════════

#[derive(pest_derive::Parser)]
#[grammar = "aegis.pest"]
pub(crate) struct AegisParser;

// ═══════════════════════════════════════════════════════════════════════
//  Public entry point
// ═══════════════════════════════════════════════════════════════════════

/// Parse `source` text and return a [`Program`] AST plus any diagnostics.
///
/// On a fatal parse error the program will be empty (no declarations) but
/// the diagnostic sink will contain the error details.
pub fn parse_source(source: &str, _filename: &str) -> (Program, DiagnosticSink) {
    let mut diags = DiagnosticSink::new();

    let pairs = match AegisParser::parse(Rule::program, source) {
        Ok(p) => p,
        Err(e) => {
            let (start, end) = match e.location {
                pest::error::InputLocation::Pos(p) => (p as u32, p as u32),
                pest::error::InputLocation::Span((s, en)) => (s as u32, en as u32),
            };
            // Extract a clean message from the pest error variant without the
            // embedded `-->` location marker (our DiagnosticSink render adds it).
            let pest_msg = match &e.variant {
                pest::error::ErrorVariant::ParsingError { positives, negatives } => {
                    if !positives.is_empty() {
                        let names: Vec<String> = positives
                            .iter()
                            .map(|r| format!("{r:?}").to_lowercase().replace('_', " "))
                            .collect();
                        format!("unexpected token; expected {}", names.join(" or "))
                    } else if !negatives.is_empty() {
                        let names: Vec<String> = negatives
                            .iter()
                            .map(|r| format!("{r:?}").to_lowercase().replace('_', " "))
                            .collect();
                        format!("unexpected {}", names.join(" or "))
                    } else {
                        "unexpected token".to_string()
                    }
                }
                pest::error::ErrorVariant::CustomError { message } => message.clone(),
            };
            diags.emit(Diagnostic::error(
                Span::new(start, end),
                DiagnosticCode::E0001,
                format!("parse error: {pest_msg}"),
            ));
            return (
                Program {
                    declarations: vec![],
                    span: Span::DUMMY,
                },
                diags,
            );
        }
    };

    // grammar guarantees exactly one `program` pair at the top level
    let program_pair = pairs.into_iter().next().expect("grammar: program pair");
    let span = s(&program_pair);
    let mut declarations = Vec::new();

    for pair in program_pair.into_inner() {
        match pair.as_rule() {
            Rule::declaration => {
                let decl_span = s(&pair);
                // grammar: declaration has exactly one non-keyword inner rule
                let inner = non_kw_inner(pair)
                    .into_iter()
                    .next()
                    .expect("grammar: declaration inner");
                if let Some(decl) = build_declaration(inner, &mut diags) {
                    declarations.push(Spanned::new(decl, decl_span));
                }
            }
            Rule::EOI => {}
            r => unreachable!("unexpected rule in program: {:?}", r),
        }
    }

    (Program { declarations, span }, diags)
}

// ═══════════════════════════════════════════════════════════════════════
//  Span & keyword helpers
// ═══════════════════════════════════════════════════════════════════════

#[inline]
fn s(pair: &Pair<Rule>) -> Span {
    let ps = pair.as_span();
    Span::new(ps.start() as u32, ps.end() as u32)
}

/// Returns `true` if this rule is a keyword-token rule (kw_* or or_kw/and_kw).
/// These pairs carry text but no further AST structure.
fn is_kw(rule: Rule) -> bool {
    matches!(
        rule,
        Rule::kw_policy
            | Rule::kw_scope
            | Rule::kw_on
            | Rule::kw_when
            | Rule::kw_in
            | Rule::kw_allow
            | Rule::kw_deny
            | Rule::kw_audit
            | Rule::kw_redact
            | Rule::kw_proof
            | Rule::kw_invariant
            | Rule::kw_always
            | Rule::kw_eventually
            | Rule::kw_never
            | Rule::kw_until
            | Rule::kw_before
            | Rule::kw_after
            | Rule::kw_next
            | Rule::kw_within
            | Rule::kw_any
            | Rule::kw_all
            | Rule::kw_none
            | Rule::kw_exists
            | Rule::kw_import
            | Rule::kw_from
            | Rule::kw_as
            | Rule::kw_let
            | Rule::kw_def
            | Rule::kw_type
            | Rule::kw_extends
            | Rule::kw_match
            | Rule::kw_rate_limit
            | Rule::kw_quota
            | Rule::kw_severity
            | Rule::kw_context
            | Rule::kw_count
            | Rule::kw_per
            | Rule::kw_log
            | Rule::kw_notify
            | Rule::kw_escalate
            | Rule::kw_block
            | Rule::kw_tag
            | Rule::kw_contains
            | Rule::kw_matches
            | Rule::kw_starts_with
            | Rule::kw_ends_with
            | Rule::kw_implies
            | Rule::kw_with
            | Rule::kw_int_ty
            | Rule::kw_float_ty
            | Rule::kw_bool_ty
            | Rule::kw_string_ty
            | Rule::kw_duration_ty
            | Rule::kw_list_ty
            | Rule::kw_map_ty
            | Rule::kw_set_ty
            | Rule::kw_critical
            | Rule::kw_high
            | Rule::kw_medium
            | Rule::kw_low
            | Rule::kw_info
            | Rule::kw_true
            | Rule::kw_false
            | Rule::or_kw
            | Rule::and_kw
    )
}

/// Collect inner pairs of `pair`, filtering out keyword-token pairs.
/// Use when only semantic (non-keyword) children matter.
fn non_kw_inner(pair: Pair<Rule>) -> Vec<Pair<Rule>> {
    pair.into_inner().filter(|p| !is_kw(p.as_rule())).collect()
}

// ═══════════════════════════════════════════════════════════════════════
//  Declaration builders
// ═══════════════════════════════════════════════════════════════════════

fn build_declaration(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> Option<Declaration> {
    match pair.as_rule() {
        Rule::import_decl => Some(Declaration::Import(build_import_decl(pair))),
        Rule::policy_decl => Some(Declaration::Policy(build_policy_decl(pair, diags))),
        Rule::proof_decl => Some(Declaration::Proof(build_proof_decl(pair, diags))),
        Rule::type_decl => Some(Declaration::Type(build_type_decl(pair))),
        Rule::binding_decl => Some(Declaration::Binding(build_binding_decl(pair, diags))),
        Rule::function_decl => Some(Declaration::Function(build_function_decl(pair, diags))),
        r => {
            diags.emit(Diagnostic::error(
                s(&pair),
                DiagnosticCode::E0001,
                format!("unexpected declaration rule: {:?}", r),
            ));
            None
        }
    }
}

// ── Imports ─────────────────────────────────────────────────────────

fn build_import_decl(pair: Pair<Rule>) -> ImportDecl {
    // import_decl = { (kw_import ~ import_path ~ (kw_as ~ ident)?) |
    //                 (kw_from ~ import_path ~ kw_import ~ import_targets) }
    // Determine which form by looking at the first keyword pair
    let first_kw = pair
        .clone()
        .into_inner()
        .find(|p| is_kw(p.as_rule()))
        .map(|p| p.as_rule());

    let mut children = non_kw_inner(pair);
    let mut it = children.drain(..);

    if first_kw == Some(Rule::kw_import) {
        // import path (as alias)?
        let path_pair = it.next().expect("grammar: import_path");
        let path = build_import_path(path_pair);
        // Remaining: maybe an ident (alias)
        let alias = it
            .next()
            .map(|p| Spanned::new(SmolStr::new(p.as_str()), s(&p)));
        ImportDecl {
            path,
            kind: ImportKind::Module { alias },
        }
    } else {
        // from path import targets
        let path_pair = it.next().expect("grammar: from-import path");
        let path = build_import_path(path_pair);
        let targets_pair = it.next().expect("grammar: from-import targets");
        let kind = build_import_targets(targets_pair);
        ImportDecl { path, kind }
    }
}

fn build_import_path(pair: Pair<Rule>) -> QualifiedName {
    let span = s(&pair);
    let segments: Vec<Spanned<SmolStr>> = pair
        .into_inner()
        .map(|p| Spanned::new(SmolStr::new(p.as_str()), s(&p)))
        .collect();
    QualifiedName { segments, span }
}

fn build_import_targets(pair: Pair<Rule>) -> ImportKind {
    let text = pair.as_str().trim();
    if text == "*" {
        return ImportKind::Glob;
    }
    // import_targets = { "*" | import_target ~ ("," ~ import_target)* }
    // Each child is an import_target
    let targets: Vec<ImportTarget> = pair
        .into_inner()
        .filter(|p| p.as_rule() == Rule::import_target)
        .map(|p| {
            // import_target = { ident ~ (kw_as ~ ident)? }
            let children = non_kw_inner(p);
            let mut it = children.into_iter();
            let name_pair = it.next().expect("grammar: import_target name");
            let name = Spanned::new(SmolStr::new(name_pair.as_str()), s(&name_pair));
            let alias = it
                .next()
                .map(|a| Spanned::new(SmolStr::new(a.as_str()), s(&a)));
            ImportTarget { name, alias }
        })
        .collect();
    ImportKind::Names(targets)
}

// ── Policy ───────────────────────────────────────────────────────────

fn build_policy_decl(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> PolicyDecl {
    // policy_decl = { annotation* ~ kw_policy ~ ident ~ (kw_extends ~ qualified_name)? ~ "{" ~ policy_member* ~ "}" }
    // After filtering keywords, non-kw children are:
    //   annotation*, ident (name), qualified_name (if extends), policy_member*

    let all_inner: Vec<Pair<Rule>> = pair.into_inner().collect();
    let mut annotations = Vec::new();
    let mut name_opt: Option<Spanned<SmolStr>> = None;
    let mut extends: Option<QualifiedName> = None;
    let mut members = Vec::new();

    let mut saw_kw_policy = false;
    let mut saw_extends_kw = false;

    for p in all_inner {
        match p.as_rule() {
            Rule::annotation => annotations.push(build_annotation(p)),
            Rule::kw_policy => saw_kw_policy = true,
            Rule::ident if saw_kw_policy && name_opt.is_none() => {
                name_opt = Some(Spanned::new(SmolStr::new(p.as_str()), s(&p)));
            }
            Rule::kw_extends => saw_extends_kw = true,
            Rule::qualified_name if saw_extends_kw => {
                extends = Some(build_qualified_name(p));
            }
            Rule::policy_member => {
                let pm_span = s(&p);
                if let Some(pm) = build_policy_member(p, diags) {
                    members.push(Spanned::new(pm, pm_span));
                }
            }
            _ if is_kw(p.as_rule()) => {} // skip other keywords
            _ => {}
        }
    }

    PolicyDecl {
        annotations,
        name: name_opt.expect("grammar: policy name"),
        extends,
        members,
    }
}

fn build_policy_member(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> Option<PolicyMember> {
    // grammar: policy_member has exactly one non-keyword inner rule
    let inner = non_kw_inner(pair)
        .into_iter()
        .next()
        .expect("grammar: policy_member inner");
    match inner.as_rule() {
        Rule::severity_clause => Some(PolicyMember::Severity(build_severity_clause(inner))),
        Rule::scope_clause => Some(PolicyMember::Scope(build_scope_clause(inner))),
        Rule::rule_decl => Some(PolicyMember::Rule(build_rule_decl(inner, diags))),
        Rule::proof_decl => Some(PolicyMember::Proof(build_proof_decl(inner, diags))),
        Rule::constraint_decl => Some(PolicyMember::Constraint(build_constraint_decl(
            inner, diags,
        ))),
        Rule::binding_decl => Some(PolicyMember::Binding(build_binding_decl(inner, diags))),
        Rule::function_decl => Some(PolicyMember::Function(build_function_decl(inner, diags))),
        r => {
            diags.emit(Diagnostic::error(
                s(&inner),
                DiagnosticCode::E0001,
                format!("unexpected policy member: {:?}", r),
            ));
            None
        }
    }
}

fn build_severity_clause(pair: Pair<Rule>) -> SeverityLevel {
    // severity_clause = { kw_severity ~ severity_level ~ ";"? }
    let level_pair = non_kw_inner(pair)
        .into_iter()
        .next()
        .expect("grammar: severity_level");
    build_severity_level(level_pair)
}

fn build_severity_level(pair: Pair<Rule>) -> SeverityLevel {
    // severity_level = { kw_critical | kw_high | kw_medium | kw_low | kw_info }
    // The inner pair IS a kw_* — look at its text
    let inner = pair
        .into_inner()
        .next()
        .expect("grammar: severity kw inner");
    match inner.as_str() {
        "critical" => SeverityLevel::Critical,
        "high" => SeverityLevel::High,
        "medium" => SeverityLevel::Medium,
        "low" => SeverityLevel::Low,
        "info" => SeverityLevel::Info,
        other => unreachable!("unexpected severity level: {}", other),
    }
}

fn build_scope_clause(pair: Pair<Rule>) -> Vec<ScopeTarget> {
    // scope_clause = { kw_scope ~ scope_target ~ ("," ~ scope_target)* ~ ";"? }
    non_kw_inner(pair)
        .into_iter()
        .filter(|p| p.as_rule() == Rule::scope_target)
        .map(build_scope_target)
        .collect()
}

fn build_scope_target(pair: Pair<Rule>) -> ScopeTarget {
    // scope_target = { qualified_name | string_lit }
    let inner = pair
        .into_inner()
        .next()
        .expect("grammar: scope_target inner");
    match inner.as_rule() {
        Rule::qualified_name => ScopeTarget::Name(build_qualified_name(inner)),
        Rule::string_lit => {
            let sp = s(&inner);
            ScopeTarget::Literal(Spanned::new(
                SmolStr::new(strip_string_quotes(inner.as_str())),
                sp,
            ))
        }
        r => unreachable!("unexpected scope_target inner: {:?}", r),
    }
}

// ── Rules ────────────────────────────────────────────────────────────

fn build_rule_decl(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> RuleDecl {
    // rule_decl = { annotation* ~ kw_on ~ scope_target ~ ("," ~ scope_target)* ~ "{" ~ rule_body ~ "}" }
    let all_inner: Vec<Pair<Rule>> = pair.into_inner().collect();
    let mut annotations = Vec::new();
    let mut on_events = Vec::new();
    let mut clauses = Vec::new();
    let mut saw_on = false;

    for p in all_inner {
        match p.as_rule() {
            Rule::annotation => annotations.push(build_annotation(p)),
            Rule::kw_on => saw_on = true,
            Rule::scope_target if saw_on => on_events.push(build_scope_target(p)),
            Rule::rule_body => {
                for clause_pair in p.into_inner() {
                    let cl_span = s(&clause_pair);
                    if let Some(rc) = build_rule_clause(clause_pair, diags) {
                        clauses.push(Spanned::new(rc, cl_span));
                    }
                }
            }
            _ if is_kw(p.as_rule()) => {}
            _ => {}
        }
    }

    RuleDecl {
        annotations,
        on_events,
        clauses,
    }
}

fn build_rule_clause(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> Option<RuleClause> {
    // rule_clause = { when_clause | verdict_clause | action_clause | severity_clause | constraint_decl }
    let inner = non_kw_inner(pair)
        .into_iter()
        .next()
        .expect("grammar: rule_clause inner");
    match inner.as_rule() {
        Rule::when_clause => {
            // when_clause = { kw_when ~ expression ~ ";"? }
            let expr_pair = non_kw_inner(inner)
                .into_iter()
                .next()
                .expect("grammar: when_clause expr");
            let esp = s(&expr_pair);
            Some(RuleClause::When(Spanned::new(
                build_expression(expr_pair, diags),
                esp,
            )))
        }
        Rule::verdict_clause => Some(RuleClause::Verdict(build_verdict_clause(inner, diags))),
        Rule::action_clause => Some(RuleClause::Action(build_action_clause(inner, diags))),
        Rule::severity_clause => Some(RuleClause::Severity(build_severity_clause(inner))),
        Rule::constraint_decl => Some(RuleClause::Constraint(build_constraint_decl(inner, diags))),
        r => {
            diags.emit(Diagnostic::error(
                s(&inner),
                DiagnosticCode::E0001,
                format!("unexpected rule clause: {:?}", r),
            ));
            None
        }
    }
}

fn build_verdict_clause(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> VerdictClause {
    // verdict_clause = { verdict_kw ~ (kw_with ~ expression)? ~ ";"? }
    let children: Vec<Pair<Rule>> = pair.into_inner().collect();
    let mut verdict_opt: Option<(Verdict, Span)> = None;
    let mut message: Option<Spanned<Expr>> = None;
    let mut saw_with = false;

    for p in children {
        match p.as_rule() {
            Rule::verdict_kw => {
                // verdict_kw = { kw_allow | kw_deny | kw_audit | kw_redact }
                let vsp = s(&p);
                let kw = p.into_inner().next().expect("grammar: verdict_kw inner");
                let v = match kw.as_str() {
                    "allow" => Verdict::Allow,
                    "deny" => Verdict::Deny,
                    "audit" => Verdict::Audit,
                    "redact" => Verdict::Redact,
                    other => unreachable!("unexpected verdict: {}", other),
                };
                verdict_opt = Some((v, vsp));
            }
            Rule::kw_with => saw_with = true,
            Rule::expression if saw_with => {
                let msp = s(&p);
                message = Some(Spanned::new(build_expression(p, diags), msp));
            }
            _ if is_kw(p.as_rule()) => {}
            _ => {}
        }
    }

    let (verdict, vspan) = verdict_opt.expect("grammar: verdict");
    VerdictClause {
        verdict: Spanned::new(verdict, vspan),
        message,
    }
}

fn build_action_clause(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> ActionClause {
    // action_clause = { action_verb ~ action_args? ~ ";"? }
    let children: Vec<Pair<Rule>> = pair.into_inner().collect();
    let mut verb_opt: Option<(ActionVerb, Span)> = None;
    let mut args = ActionArgs::None;

    for p in children {
        match p.as_rule() {
            Rule::action_verb => {
                // action_verb = { kw_log | kw_notify | ... }
                let vsp = s(&p);
                let kw = p.into_inner().next().expect("grammar: action_verb kw");
                let v = match kw.as_str() {
                    "log" => ActionVerb::Log,
                    "notify" => ActionVerb::Notify,
                    "escalate" => ActionVerb::Escalate,
                    "block" => ActionVerb::Block,
                    "tag" => ActionVerb::Tag,
                    other => unreachable!("unexpected action verb: {}", other),
                };
                verb_opt = Some((v, vsp));
            }
            Rule::action_args => {
                args = build_action_args(p, diags);
            }
            _ if is_kw(p.as_rule()) => {}
            _ => {}
        }
    }

    let (verb, vspan) = verb_opt.expect("grammar: action_verb");
    ActionClause {
        verb: Spanned::new(verb, vspan),
        args,
    }
}

fn build_action_args(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> ActionArgs {
    // action_args = { named_action_args | expression }
    let inner = pair
        .into_inner()
        .next()
        .expect("grammar: action_args inner");
    match inner.as_rule() {
        Rule::named_action_args => {
            // named_action_args = { arg_key ~ ":" ~ expression ~ ("," ~ arg_key ~ ":" ~ expression)* }
            // arg_key = { kw_log | kw_notify | ... | ident } — wraps keyword or ident
            let mut pairs: Vec<(Ident, Spanned<Expr>)> = Vec::new();
            let children: Vec<Pair<Rule>> = inner.into_inner().collect();
            let mut i = 0;
            while i < children.len() {
                if children[i].as_rule() == Rule::arg_key {
                    let key_p = &children[i];
                    // arg_key contains one inner pair (ident or kw_*); use as_str() to get text
                    let key_text = key_p.as_str();
                    let key = Spanned::new(SmolStr::new(key_text), s(key_p));
                    // Next should be expression
                    i += 1;
                    if i < children.len() && children[i].as_rule() == Rule::expression {
                        let val_p = children[i].clone();
                        let vsp = s(&val_p);
                        pairs.push((key, Spanned::new(build_expression(val_p, diags), vsp)));
                    }
                }
                i += 1;
            }
            ActionArgs::Named(pairs)
        }
        Rule::expression => {
            let sp = s(&inner);
            ActionArgs::Positional(Spanned::new(build_expression(inner, diags), sp))
        }
        r => unreachable!("unexpected action_args inner: {:?}", r),
    }
}

// ── Constraints ──────────────────────────────────────────────────────

fn build_constraint_decl(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> ConstraintDecl {
    // constraint_decl = { constraint_kind ~ qualified_name ~ ":" ~ expression ~ kw_per ~ expression ~ ";"? }
    let children: Vec<Pair<Rule>> = pair.into_inner().collect();
    let mut kind_opt: Option<ConstraintKind> = None;
    let mut target_opt: Option<QualifiedName> = None;
    let mut exprs: Vec<Spanned<Expr>> = Vec::new();
    let mut saw_per = false;

    for p in children {
        match p.as_rule() {
            Rule::constraint_kind => {
                // constraint_kind = { kw_rate_limit | kw_quota }
                let kw = p.into_inner().next().expect("grammar: constraint_kind kw");
                kind_opt = Some(match kw.as_str() {
                    "rate_limit" => ConstraintKind::RateLimit,
                    "quota" => ConstraintKind::Quota,
                    other => unreachable!("unexpected constraint kind: {}", other),
                });
            }
            Rule::qualified_name if target_opt.is_none() => {
                target_opt = Some(build_qualified_name(p));
            }
            Rule::kw_per => saw_per = true,
            Rule::expression => {
                let sp = s(&p);
                exprs.push(Spanned::new(build_expression(p, diags), sp));
            }
            _ if is_kw(p.as_rule()) => {}
            _ => {}
        }
    }

    let _ = saw_per;
    let window = exprs.pop().expect("grammar: constraint window");
    let limit = exprs.pop().expect("grammar: constraint limit");
    ConstraintDecl {
        kind: kind_opt.expect("grammar: constraint kind"),
        target: target_opt.expect("grammar: constraint target"),
        limit,
        window,
    }
}

// ── Proofs ───────────────────────────────────────────────────────────

fn build_proof_decl(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> ProofDecl {
    // proof_decl = { kw_proof ~ ident ~ "{" ~ invariant_decl* ~ "}" }
    let children = non_kw_inner(pair);
    let mut it = children.into_iter();
    let name_pair = it.next().expect("grammar: proof name");
    let name = Spanned::new(SmolStr::new(name_pair.as_str()), s(&name_pair));
    let invariants: Vec<InvariantDecl> = it.map(|p| build_invariant_decl(p, diags)).collect();
    ProofDecl { name, invariants }
}

fn build_invariant_decl(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> InvariantDecl {
    // invariant_decl = { kw_invariant ~ ident ~ "{" ~ expression ~ (";" ~ expression)* ~ ";"? ~ "}" }
    let children = non_kw_inner(pair);
    let mut it = children.into_iter();
    let name_pair = it.next().expect("grammar: invariant name");
    let name = Spanned::new(SmolStr::new(name_pair.as_str()), s(&name_pair));
    let conditions: Vec<Spanned<Expr>> = it
        .map(|p| {
            let sp = s(&p);
            Spanned::new(build_expression(p, diags), sp)
        })
        .collect();
    InvariantDecl { name, conditions }
}

// ── Types ────────────────────────────────────────────────────────────

fn build_type_decl(pair: Pair<Rule>) -> TypeDecl {
    // type_decl = { kw_type ~ ident ~ generic_params? ~ "{" ~ typed_field_list ~ "}" }
    let children = non_kw_inner(pair);
    let mut it = children.into_iter();
    let name_pair = it.next().expect("grammar: type name");
    let name = Spanned::new(SmolStr::new(name_pair.as_str()), s(&name_pair));
    let mut generic_params = Vec::new();
    let mut fields = Vec::new();
    for p in it {
        match p.as_rule() {
            Rule::generic_params => generic_params = build_generic_params(p),
            Rule::typed_field_list => fields = build_typed_field_list(p),
            r => unreachable!("unexpected type_decl child: {:?}", r),
        }
    }
    TypeDecl {
        name,
        generic_params,
        fields,
    }
}

fn build_generic_params(pair: Pair<Rule>) -> Vec<GenericParam> {
    pair.into_inner()
        .filter(|p| p.as_rule() == Rule::generic_param)
        .map(build_generic_param)
        .collect()
}

fn build_generic_param(pair: Pair<Rule>) -> GenericParam {
    // generic_param = { ident ~ (kw_extends ~ ty)? }
    let children = non_kw_inner(pair);
    let mut it = children.into_iter();
    let name_pair = it.next().expect("grammar: generic_param name");
    let name = Spanned::new(SmolStr::new(name_pair.as_str()), s(&name_pair));
    let bound = it.next().map(|p| Spanned::new(build_ty(p.clone()), s(&p)));
    GenericParam { name, bound }
}

fn build_typed_field_list(pair: Pair<Rule>) -> Vec<TypedField> {
    pair.into_inner()
        .filter(|p| p.as_rule() == Rule::typed_field)
        .map(build_typed_field)
        .collect()
}

fn build_typed_field(pair: Pair<Rule>) -> TypedField {
    // typed_field = { ident ~ ":" ~ ty }
    let children: Vec<Pair<Rule>> = pair.into_inner().collect();
    let mut it = children.into_iter();
    let name_pair = it.next().expect("grammar: typed_field name");
    let name = Spanned::new(SmolStr::new(name_pair.as_str()), s(&name_pair));
    let ty_pair = it.next().expect("grammar: typed_field ty");
    TypedField {
        name,
        ty: Spanned::new(build_ty(ty_pair.clone()), s(&ty_pair)),
    }
}

fn build_ty(pair: Pair<Rule>) -> Type {
    // ty = { base_ty ~ ("|" ~ base_ty)* }
    let mut parts: Vec<Spanned<Type>> = pair
        .into_inner()
        .filter(|p| p.as_rule() == Rule::base_ty)
        .map(|p| Spanned::new(build_base_ty(p.clone()), s(&p)))
        .collect();
    if parts.len() == 1 {
        parts.remove(0).node
    } else {
        Type::Union(parts)
    }
}

fn build_base_ty(pair: Pair<Rule>) -> Type {
    // base_ty = { primitive_ty | list_ty | map_ty | set_ty | "(" ~ ty ~ ")" | user_ty }
    let inner = pair.into_inner().next().expect("grammar: base_ty inner");
    match inner.as_rule() {
        Rule::primitive_ty => build_primitive_ty(inner),
        Rule::list_ty => {
            // list_ty = { kw_list_ty ~ "<" ~ ty ~ ">" }
            let tp = non_kw_inner(inner)
                .into_iter()
                .next()
                .expect("grammar: list_ty ty");
            Type::List(Box::new(Spanned::new(build_ty(tp.clone()), s(&tp))))
        }
        Rule::map_ty => {
            let children = non_kw_inner(inner);
            let mut it = children.into_iter();
            let k = it.next().expect("grammar: map_ty key");
            let v = it.next().expect("grammar: map_ty value");
            Type::Map(
                Box::new(Spanned::new(build_ty(k.clone()), s(&k))),
                Box::new(Spanned::new(build_ty(v.clone()), s(&v))),
            )
        }
        Rule::set_ty => {
            let tp = non_kw_inner(inner)
                .into_iter()
                .next()
                .expect("grammar: set_ty ty");
            Type::Set(Box::new(Spanned::new(build_ty(tp.clone()), s(&tp))))
        }
        Rule::ty => build_ty(inner), // grouped: "(" ~ ty ~ ")"
        Rule::user_ty => {
            // user_ty = { qualified_name ~ generic_args? }
            let mut it = inner.into_inner();
            let qn = it.next().expect("grammar: user_ty name");
            let name = build_qualified_name(qn);
            let type_args: Vec<Spanned<Type>> = it
                .next()
                .map(|ga| {
                    ga.into_inner()
                        .filter(|p| p.as_rule() == Rule::ty)
                        .map(|p| Spanned::new(build_ty(p.clone()), s(&p)))
                        .collect()
                })
                .unwrap_or_default();
            Type::Named { name, type_args }
        }
        r => unreachable!("unexpected base_ty inner: {:?}", r),
    }
}

fn build_primitive_ty(pair: Pair<Rule>) -> Type {
    // primitive_ty = { kw_int_ty | kw_float_ty | ... }
    // The inner pair IS a kw_* — check its text
    let inner = pair.into_inner().next().expect("grammar: primitive_ty kw");
    match inner.as_str() {
        "int" => Type::Primitive(PrimitiveType::Int),
        "float" => Type::Primitive(PrimitiveType::Float),
        "bool" => Type::Primitive(PrimitiveType::Bool),
        "string" => Type::Primitive(PrimitiveType::String),
        "duration" => Type::Primitive(PrimitiveType::Duration),
        other => unreachable!("unexpected primitive type: {}", other),
    }
}

// ── Bindings and Functions ───────────────────────────────────────────

fn build_binding_decl(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> BindingDecl {
    // binding_decl = { kw_let ~ ident ~ (":" ~ ty)? ~ "=" ~ expression ~ ";"? }
    let children = non_kw_inner(pair);
    let mut it = children.into_iter();
    let name_pair = it.next().expect("grammar: binding name");
    let name = Spanned::new(SmolStr::new(name_pair.as_str()), s(&name_pair));

    let next = it.next().expect("grammar: binding ty or expr");
    let (ty, value_pair) = if next.as_rule() == Rule::ty {
        let ty = Some(Spanned::new(build_ty(next.clone()), s(&next)));
        let vp = it.next().expect("grammar: binding expression");
        (ty, vp)
    } else {
        (None, next)
    };

    let vsp = s(&value_pair);
    BindingDecl {
        name,
        ty,
        value: Spanned::new(build_expression(value_pair, diags), vsp),
    }
}

fn build_function_decl(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> FunctionDecl {
    // function_decl = { kw_def ~ ident ~ "(" ~ typed_param_list? ~ ")" ~ "->" ~ ty ~ "=" ~ expression ~ ";"? }
    let children = non_kw_inner(pair);
    let mut it = children.into_iter();
    let name_pair = it.next().expect("grammar: function name");
    let name = Spanned::new(SmolStr::new(name_pair.as_str()), s(&name_pair));

    let mut params: Vec<TypedParam> = Vec::new();
    let mut return_type_opt: Option<Spanned<Type>> = None;
    let mut body_opt: Option<Spanned<Expr>> = None;

    for p in it {
        match p.as_rule() {
            Rule::typed_param_list => params = build_typed_param_list(p),
            Rule::ty => return_type_opt = Some(Spanned::new(build_ty(p.clone()), s(&p))),
            Rule::expression => {
                let sp = s(&p);
                body_opt = Some(Spanned::new(build_expression(p, diags), sp));
            }
            r => unreachable!("unexpected function_decl child: {:?}", r),
        }
    }

    FunctionDecl {
        name,
        params,
        return_type: return_type_opt.expect("grammar: function return type"),
        body: body_opt.expect("grammar: function body"),
    }
}

fn build_typed_param_list(pair: Pair<Rule>) -> Vec<TypedParam> {
    pair.into_inner()
        .filter(|p| p.as_rule() == Rule::typed_param)
        .map(build_typed_param)
        .collect()
}

fn build_typed_param(pair: Pair<Rule>) -> TypedParam {
    // typed_param = { ident ~ ":" ~ ty }
    let children: Vec<Pair<Rule>> = pair.into_inner().collect();
    let mut it = children.into_iter();
    let name_pair = it.next().expect("grammar: typed_param name");
    let name = Spanned::new(SmolStr::new(name_pair.as_str()), s(&name_pair));
    let ty_pair = it.next().expect("grammar: typed_param ty");
    TypedParam {
        name,
        ty: Spanned::new(build_ty(ty_pair.clone()), s(&ty_pair)),
    }
}

// ── Annotations ──────────────────────────────────────────────────────

fn build_annotation(pair: Pair<Rule>) -> Annotation {
    // annotation = { "@" ~ ident ~ ("(" ~ annotation_args ~ ")")? }
    let span = s(&pair);
    let mut it = pair.into_inner();
    let name_pair = it.next().expect("grammar: annotation name");
    let name = Spanned::new(SmolStr::new(name_pair.as_str()), s(&name_pair));
    let args: Vec<AnnotationArg> = it
        .next()
        .map(|args_pair| args_pair.into_inner().map(build_annotation_arg).collect())
        .unwrap_or_default();
    Annotation { name, args, span }
}

fn build_annotation_arg(pair: Pair<Rule>) -> AnnotationArg {
    // annotation_arg = { (ident ~ ":" ~ annotation_value) | annotation_value }
    let mut it = pair.into_inner();
    let first = it.next().expect("grammar: annotation_arg inner");
    if first.as_rule() == Rule::ident {
        let key = Spanned::new(SmolStr::new(first.as_str()), s(&first));
        let val_pair = it.next().expect("grammar: named annotation_arg value");
        AnnotationArg::Named {
            key,
            value: build_annotation_value(val_pair),
        }
    } else {
        AnnotationArg::Positional(build_annotation_value(first))
    }
}

fn build_annotation_value(pair: Pair<Rule>) -> AnnotationValue {
    // annotation_value = { literal | list_literal }
    let inner = pair
        .into_inner()
        .next()
        .expect("grammar: annotation_value inner");
    match inner.as_rule() {
        Rule::literal => AnnotationValue::Literal(build_literal(inner)),
        Rule::list_literal => {
            let vals: Vec<AnnotationValue> =
                inner.into_inner().map(build_annotation_value).collect();
            AnnotationValue::List(vals)
        }
        r => unreachable!("unexpected annotation_value inner: {:?}", r),
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Expression builders
// ═══════════════════════════════════════════════════════════════════════

fn build_expression(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> Expr {
    // expression = { implies_expr }
    let inner = pair.into_inner().next().expect("grammar: expression inner");
    build_implies_expr(inner, diags)
}

fn build_implies_expr(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> Expr {
    // implies_expr = { or_expr ~ (kw_implies ~ or_expr)? }
    // After filtering keywords, children are or_expr pairs
    let children = non_kw_inner(pair);
    let mut it = children.into_iter();
    let lhs_pair = it.next().expect("grammar: implies lhs");
    let lhs_sp = s(&lhs_pair);
    let lhs = build_or_expr(lhs_pair, diags);

    if let Some(rhs_pair) = it.next() {
        let rhs_sp = s(&rhs_pair);
        let rhs = build_or_expr(rhs_pair, diags);
        Expr::Binary {
            op: Spanned::new(BinaryOp::Implies, Span::DUMMY),
            left: Box::new(Spanned::new(lhs, lhs_sp)),
            right: Box::new(Spanned::new(rhs, rhs_sp)),
        }
    } else {
        lhs
    }
}

fn build_or_expr(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> Expr {
    // or_expr = { and_expr ~ (or_op ~ and_expr)* }
    fold_left_binary(
        pair,
        diags,
        Rule::or_op,
        build_and_expr,
        |op_text| match op_text {
            "||" | "or" => BinaryOp::Or,
            other => unreachable!("unexpected or op: {}", other),
        },
    )
}

fn build_and_expr(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> Expr {
    // and_expr = { eq_expr ~ (and_op ~ eq_expr)* }
    fold_left_binary(
        pair,
        diags,
        Rule::and_op,
        build_eq_expr,
        |op_text| match op_text {
            "&&" | "and" => BinaryOp::And,
            other => unreachable!("unexpected and op: {}", other),
        },
    )
}

fn build_eq_expr(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> Expr {
    // eq_expr = { rel_expr ~ (eq_op ~ rel_expr)* }
    fold_left_binary(
        pair,
        diags,
        Rule::eq_op,
        build_rel_expr,
        |op_text| match op_text {
            "==" => BinaryOp::Eq,
            "!=" => BinaryOp::Neq,
            other => unreachable!("unexpected eq op: {}", other),
        },
    )
}

fn build_rel_expr(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> Expr {
    // rel_expr = { temporal_expr ~ (rel_op ~ temporal_expr)* }
    fold_left_binary(
        pair,
        diags,
        Rule::rel_op,
        build_temporal_expr,
        |op_text| match op_text.trim() {
            "<=" => BinaryOp::Le,
            ">=" => BinaryOp::Ge,
            "<" => BinaryOp::Lt,
            ">" => BinaryOp::Gt,
            "in" => BinaryOp::In,
            other => unreachable!("unexpected rel_op: {}", other),
        },
    )
}

fn build_temporal_expr(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> Expr {
    // temporal_expr = { temporal_atom ~ (kw_until ~ expression)? }
    let children: Vec<Pair<Rule>> = pair.into_inner().collect();
    let mut atom_opt: Option<(Expr, Span)> = None;
    let mut release_opt: Option<(Expr, Span)> = None;
    let mut saw_until = false;

    for p in children {
        match p.as_rule() {
            Rule::temporal_atom => {
                let sp = s(&p);
                atom_opt = Some((build_temporal_atom(p, diags), sp));
            }
            Rule::kw_until => saw_until = true,
            Rule::expression if saw_until => {
                let sp = s(&p);
                release_opt = Some((build_expression(p, diags), sp));
            }
            _ if is_kw(p.as_rule()) => {}
            _ => {}
        }
    }

    let (atom, atom_sp) = atom_opt.expect("grammar: temporal_atom");
    if let Some((release, rsp)) = release_opt {
        Expr::Temporal(TemporalExpr::Until {
            hold: Box::new(Spanned::new(atom, atom_sp)),
            release: Box::new(Spanned::new(release, rsp)),
        })
    } else {
        atom
    }
}

fn build_temporal_atom(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> Expr {
    // temporal_atom = { always_expr | ... | add_expr }
    let inner = pair
        .into_inner()
        .next()
        .expect("grammar: temporal_atom inner");
    match inner.as_rule() {
        Rule::always_expr => {
            // always_expr = { kw_always ~ "(" ~ expression ~ ")" ~ (kw_within ~ expression)? }
            let exprs: Vec<Pair<Rule>> = inner
                .into_inner()
                .filter(|p| p.as_rule() == Rule::expression)
                .collect();
            let mut it = exprs.into_iter();
            let cond_pair = it.next().expect("grammar: always condition");
            let csp = s(&cond_pair);
            let condition = Box::new(Spanned::new(build_expression(cond_pair, diags), csp));
            let within = it.next().map(|wp| {
                let wsp = s(&wp);
                Box::new(Spanned::new(build_expression(wp, diags), wsp))
            });
            Expr::Temporal(TemporalExpr::Always { condition, within })
        }
        Rule::eventually_expr => {
            let exprs: Vec<Pair<Rule>> = inner
                .into_inner()
                .filter(|p| p.as_rule() == Rule::expression)
                .collect();
            let mut it = exprs.into_iter();
            let cond_pair = it.next().expect("grammar: eventually condition");
            let csp = s(&cond_pair);
            let condition = Box::new(Spanned::new(build_expression(cond_pair, diags), csp));
            let within = it.next().map(|wp| {
                let wsp = s(&wp);
                Box::new(Spanned::new(build_expression(wp, diags), wsp))
            });
            Expr::Temporal(TemporalExpr::Eventually { condition, within })
        }
        Rule::never_expr => {
            let cond_pair = inner
                .into_inner()
                .find(|p| p.as_rule() == Rule::expression)
                .expect("grammar: never condition");
            let csp = s(&cond_pair);
            Expr::Temporal(TemporalExpr::Never {
                condition: Box::new(Spanned::new(build_expression(cond_pair, diags), csp)),
            })
        }
        Rule::next_expr => {
            let cond_pair = inner
                .into_inner()
                .find(|p| p.as_rule() == Rule::expression)
                .expect("grammar: next condition");
            let csp = s(&cond_pair);
            Expr::Temporal(TemporalExpr::Next {
                condition: Box::new(Spanned::new(build_expression(cond_pair, diags), csp)),
            })
        }
        Rule::before_expr => {
            let mut it = inner
                .into_inner()
                .filter(|p| p.as_rule() == Rule::expression);
            let first_pair = it.next().expect("grammar: before first");
            let fsp = s(&first_pair);
            let second_pair = it.next().expect("grammar: before second");
            let ssp = s(&second_pair);
            Expr::Temporal(TemporalExpr::Before {
                first: Box::new(Spanned::new(build_expression(first_pair, diags), fsp)),
                second: Box::new(Spanned::new(build_expression(second_pair, diags), ssp)),
            })
        }
        Rule::after_expr => {
            let mut it = inner
                .into_inner()
                .filter(|p| p.as_rule() == Rule::expression);
            let cond_pair = it.next().expect("grammar: after condition");
            let csp = s(&cond_pair);
            let trig_pair = it.next().expect("grammar: after trigger");
            let tsp = s(&trig_pair);
            Expr::Temporal(TemporalExpr::After {
                condition: Box::new(Spanned::new(build_expression(cond_pair, diags), csp)),
                trigger: Box::new(Spanned::new(build_expression(trig_pair, diags), tsp)),
            })
        }
        Rule::add_expr => build_add_expr(inner, diags),
        r => unreachable!("unexpected temporal_atom inner: {:?}", r),
    }
}

fn build_add_expr(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> Expr {
    fold_left_binary(
        pair,
        diags,
        Rule::add_op,
        build_mul_expr,
        |op_text| match op_text {
            "+" => BinaryOp::Add,
            "-" => BinaryOp::Sub,
            other => unreachable!("unexpected add op: {}", other),
        },
    )
}

fn build_mul_expr(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> Expr {
    fold_left_binary(
        pair,
        diags,
        Rule::mul_op,
        build_unary_expr,
        |op_text| match op_text {
            "*" => BinaryOp::Mul,
            "/" => BinaryOp::Div,
            "%" => BinaryOp::Mod,
            other => unreachable!("unexpected mul op: {}", other),
        },
    )
}

fn build_unary_expr(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> Expr {
    // unary_expr = { (unary_op ~ unary_expr) | postfix_expr }
    let mut it = pair.into_inner();
    let first = it.next().expect("grammar: unary_expr inner");
    match first.as_rule() {
        Rule::unary_op => {
            let op_sp = s(&first);
            let op = match first.as_str() {
                "!" => UnaryOp::Not,
                "-" => UnaryOp::Neg,
                other => unreachable!("unexpected unary op: {}", other),
            };
            let operand_pair = it.next().expect("grammar: unary operand");
            let osp = s(&operand_pair);
            Expr::Unary {
                op: Spanned::new(op, op_sp),
                operand: Box::new(Spanned::new(build_unary_expr(operand_pair, diags), osp)),
            }
        }
        Rule::postfix_expr => build_postfix_expr(first, diags),
        r => unreachable!("unexpected unary_expr inner: {:?}", r),
    }
}

fn build_postfix_expr(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> Expr {
    // postfix_expr = { primary ~ postfix_op* }
    let mut it = pair.into_inner();
    let primary_pair = it.next().expect("grammar: postfix primary");
    let primary_sp = s(&primary_pair);
    let mut acc = Spanned::new(build_primary(primary_pair, diags), primary_sp);

    for op_pair in it {
        let op_sp = s(&op_pair);
        // postfix_op = { postfix_dot_op | postfix_index_op | postfix_call_op | postfix_predicate_op }
        let op_inner = op_pair
            .into_inner()
            .next()
            .expect("grammar: postfix_op inner");
        acc = match op_inner.as_rule() {
            Rule::postfix_dot_op => {
                // postfix_dot_op = { "." ~ ident ~ postfix_call_op? }
                let mut dot_it = op_inner.into_inner();
                let field_pair = dot_it.next().expect("grammar: dot_op ident");
                let fsp = s(&field_pair);
                let field_name = Spanned::new(SmolStr::new(field_pair.as_str()), fsp);

                if let Some(call_op) = dot_it.next() {
                    // method call
                    let args = build_call_args(call_op, diags);
                    let new_sp = acc.span.merge(op_sp);
                    Spanned::new(
                        Expr::MethodCall {
                            object: Box::new(acc),
                            method: field_name,
                            args,
                        },
                        new_sp,
                    )
                } else {
                    let new_sp = acc.span.merge(op_sp);
                    Spanned::new(
                        Expr::FieldAccess {
                            object: Box::new(acc),
                            field: field_name,
                        },
                        new_sp,
                    )
                }
            }
            Rule::postfix_call_op => {
                let args = build_call_args(op_inner, diags);
                let new_sp = acc.span.merge(op_sp);
                Spanned::new(
                    Expr::Call {
                        callee: Box::new(acc),
                        args,
                    },
                    new_sp,
                )
            }
            Rule::postfix_index_op => {
                let idx_pair = op_inner
                    .into_inner()
                    .next()
                    .expect("grammar: index_op expression");
                let isp = s(&idx_pair);
                let idx = Spanned::new(build_expression(idx_pair, diags), isp);
                let new_sp = acc.span.merge(op_sp);
                Spanned::new(
                    Expr::IndexAccess {
                        object: Box::new(acc),
                        index: Box::new(idx),
                    },
                    new_sp,
                )
            }
            Rule::postfix_predicate_op => {
                // postfix_predicate_op = { predicate_kw ~ expression }
                let mut pred_it = op_inner.into_inner();
                let kw_pair = pred_it.next().expect("grammar: predicate_kw");
                let kind = build_predicate_kind(kw_pair);
                let arg_pair = pred_it.next().expect("grammar: predicate arg");
                let asp = s(&arg_pair);
                let arg = Spanned::new(build_expression(arg_pair, diags), asp);
                let new_sp = acc.span.merge(op_sp);
                Spanned::new(
                    Expr::Predicate {
                        kind,
                        subject: Box::new(acc),
                        argument: Box::new(arg),
                    },
                    new_sp,
                )
            }
            r => unreachable!("unexpected postfix_op inner: {:?}", r),
        };
    }

    acc.node
}

fn build_predicate_kind(pair: Pair<Rule>) -> PredicateKind {
    // predicate_kw = { kw_contains | kw_matches | kw_starts_with | kw_ends_with }
    let inner = pair
        .into_inner()
        .next()
        .expect("grammar: predicate_kw inner");
    match inner.as_str() {
        "contains" => PredicateKind::Contains,
        "matches" => PredicateKind::Matches,
        "starts_with" => PredicateKind::StartsWith,
        "ends_with" => PredicateKind::EndsWith,
        other => unreachable!("unexpected predicate kw: {}", other),
    }
}

fn build_call_args(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> Vec<Argument> {
    // postfix_call_op = { "(" ~ argument_list? ~ ")" }
    pair.into_inner()
        .next()
        .map(|al| al.into_inner().map(|a| build_argument(a, diags)).collect())
        .unwrap_or_default()
}

fn build_argument(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> Argument {
    // argument = { (ident ~ "=" ~ !">" ~ expression) | expression }
    let mut it = pair.into_inner();
    let first = it.next().expect("grammar: argument inner");
    if first.as_rule() == Rule::ident {
        // Named argument: ident "=" expression
        let key = Spanned::new(SmolStr::new(first.as_str()), s(&first));
        let val_pair = it.next().expect("grammar: named argument expression");
        let vsp = s(&val_pair);
        Argument {
            name: Some(key),
            value: Spanned::new(build_expression(val_pair, diags), vsp),
        }
    } else {
        // Positional: first IS the expression pair
        let vsp = s(&first);
        Argument {
            name: None,
            value: Spanned::new(build_expression(first, diags), vsp),
        }
    }
}

fn build_primary(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> Expr {
    let inner = pair.into_inner().next().expect("grammar: primary inner");
    match inner.as_rule() {
        Rule::literal => Expr::Literal(build_literal(inner)),
        Rule::context_expr => {
            // context_expr = { kw_context ~ "." ~ qualified_name }
            let qn_pair = non_kw_inner(inner)
                .into_iter()
                .next()
                .expect("grammar: context_expr qn");
            Expr::Context(build_qualified_name(qn_pair))
        }
        Rule::match_expr => build_match_expr(inner, diags),
        Rule::quantifier_expr => build_quantifier_expr(inner, diags),
        Rule::count_expr => build_count_expr(inner, diags),
        Rule::list_expr => {
            let items: Vec<Spanned<Expr>> = inner
                .into_inner()
                .filter(|p| p.as_rule() == Rule::expression)
                .map(|p| Spanned::new(build_expression(p.clone(), diags), s(&p)))
                .collect();
            Expr::List(items)
        }
        Rule::object_expr => {
            let fields: Vec<ObjectField> = inner
                .into_inner()
                .filter(|p| p.as_rule() == Rule::object_field)
                .map(|f| {
                    let mut fit = f.into_inner();
                    let key_pair = fit.next().expect("grammar: object_field key");
                    let ksp = s(&key_pair);
                    let key_str = if key_pair.as_rule() == Rule::string_lit {
                        SmolStr::new(strip_string_quotes(key_pair.as_str()))
                    } else {
                        SmolStr::new(key_pair.as_str())
                    };
                    let val_pair = fit.next().expect("grammar: object_field value");
                    let vsp = s(&val_pair);
                    ObjectField {
                        key: Spanned::new(key_str, ksp),
                        value: Spanned::new(build_expression(val_pair, diags), vsp),
                    }
                })
                .collect();
            Expr::Object(fields)
        }
        Rule::lambda_expr => Expr::Lambda(build_lambda(inner, diags)),
        Rule::grouped_expr => {
            let expr_pair = inner
                .into_inner()
                .next()
                .expect("grammar: grouped_expr inner");
            build_expression(expr_pair, diags)
        }
        Rule::qualified_name => Expr::Identifier(build_qualified_name(inner)),
        r => unreachable!("unexpected primary inner: {:?}", r),
    }
}

// ── Match expressions ─────────────────────────────────────────────────

fn build_match_expr(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> Expr {
    // match_expr = { kw_match ~ expression ~ "{" ~ match_arm ~ ("," ~ match_arm)* ~ ","? ~ "}" }
    let children: Vec<Pair<Rule>> = pair.into_inner().collect();
    let mut scrutinee_opt: Option<Spanned<Expr>> = None;
    let mut arms: Vec<MatchArm> = Vec::new();

    for p in children {
        match p.as_rule() {
            Rule::kw_match => {}
            Rule::expression if scrutinee_opt.is_none() => {
                let ssp = s(&p);
                scrutinee_opt = Some(Spanned::new(build_expression(p, diags), ssp));
            }
            Rule::match_arm => arms.push(build_match_arm(p, diags)),
            _ if is_kw(p.as_rule()) => {}
            _ => {}
        }
    }

    Expr::Match {
        scrutinee: Box::new(scrutinee_opt.expect("grammar: match scrutinee")),
        arms,
    }
}

fn build_match_arm(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> MatchArm {
    // match_arm = { pattern ~ "->" ~ match_result }
    let span = s(&pair);
    let mut it = pair.into_inner();
    let pat_pair = it.next().expect("grammar: match_arm pattern");
    let psp = s(&pat_pair);
    let result_pair = it.next().expect("grammar: match_arm result");
    let rsp = s(&result_pair);
    MatchArm {
        pattern: Spanned::new(build_pattern(pat_pair, diags), psp),
        result: Spanned::new(build_match_result(result_pair, diags), rsp),
        span,
    }
}

fn build_match_result(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> MatchResult {
    let inner = pair
        .into_inner()
        .next()
        .expect("grammar: match_result inner");
    match inner.as_rule() {
        Rule::verdict_clause => MatchResult::Verdict(build_verdict_clause(inner, diags)),
        Rule::block_expr => MatchResult::Block(build_block_stmts(inner, diags)),
        Rule::expression => MatchResult::Expr(build_expression(inner, diags)),
        r => unreachable!("unexpected match_result inner: {:?}", r),
    }
}

fn build_block_stmts(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> Vec<Spanned<BlockStatement>> {
    pair.into_inner()
        .filter(|p| p.as_rule() == Rule::block_statement)
        .map(|p| Spanned::new(build_block_statement(p.clone(), diags), s(&p)))
        .collect()
}

fn build_block_statement(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> BlockStatement {
    let inner = pair
        .into_inner()
        .next()
        .expect("grammar: block_statement inner");
    match inner.as_rule() {
        Rule::binding_decl => BlockStatement::Binding(build_binding_decl(inner, diags)),
        Rule::verdict_clause => BlockStatement::Verdict(build_verdict_clause(inner, diags)),
        Rule::action_clause => BlockStatement::Action(build_action_clause(inner, diags)),
        Rule::expression => BlockStatement::Expr(build_expression(inner, diags)),
        r => unreachable!("unexpected block_statement inner: {:?}", r),
    }
}

// ── Quantifier / count ────────────────────────────────────────────────

fn build_quantifier_expr(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> Expr {
    // quantifier_expr = { quantifier_kw ~ "(" ~ expression ~ "," ~ lambda_expr ~ ")" }
    let children: Vec<Pair<Rule>> = pair.into_inner().collect();
    let mut kind_opt: Option<QuantifierKind> = None;
    let mut collection_opt: Option<Spanned<Expr>> = None;
    let mut lambda_opt: Option<Lambda> = None;

    for p in children {
        match p.as_rule() {
            Rule::quantifier_kw => {
                // quantifier_kw = { kw_all | kw_any | kw_none | kw_exists }
                let kw = p.into_inner().next().expect("grammar: quantifier_kw inner");
                kind_opt = Some(match kw.as_str() {
                    "all" => QuantifierKind::All,
                    "any" => QuantifierKind::Any,
                    "none" => QuantifierKind::None,
                    "exists" => QuantifierKind::Exists,
                    other => unreachable!("unexpected quantifier: {}", other),
                });
            }
            Rule::expression if collection_opt.is_none() => {
                let csp = s(&p);
                collection_opt = Some(Spanned::new(build_expression(p, diags), csp));
            }
            Rule::lambda_expr => {
                lambda_opt = Some(build_lambda(p, diags));
            }
            _ if is_kw(p.as_rule()) => {}
            _ => {}
        }
    }

    Expr::Quantifier {
        kind: kind_opt.expect("grammar: quantifier kind"),
        collection: Box::new(collection_opt.expect("grammar: quantifier collection")),
        predicate: Box::new(lambda_opt.expect("grammar: quantifier lambda")),
    }
}

fn build_count_expr(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> Expr {
    // count_expr = { kw_count ~ "(" ~ expression ~ ("," ~ lambda_expr)? ~ ")" }
    let children: Vec<Pair<Rule>> = pair.into_inner().collect();
    let mut collection_opt: Option<Spanned<Expr>> = None;
    let mut filter: Option<Box<Lambda>> = None;

    for p in children {
        match p.as_rule() {
            Rule::expression if collection_opt.is_none() => {
                let csp = s(&p);
                collection_opt = Some(Spanned::new(build_expression(p, diags), csp));
            }
            Rule::lambda_expr => {
                filter = Some(Box::new(build_lambda(p, diags)));
            }
            _ if is_kw(p.as_rule()) => {}
            _ => {}
        }
    }

    Expr::Count {
        collection: Box::new(collection_opt.expect("grammar: count collection")),
        filter,
    }
}

// ── Lambda ────────────────────────────────────────────────────────────

fn build_lambda(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> Lambda {
    // lambda_expr = { multi_lambda | single_lambda }
    let inner = pair
        .into_inner()
        .next()
        .expect("grammar: lambda_expr inner");
    match inner.as_rule() {
        Rule::single_lambda => {
            // single_lambda = { ident ~ "=>" ~ expression }
            let mut it = inner.into_inner();
            let param_pair = it.next().expect("grammar: single_lambda param");
            let name = Spanned::new(SmolStr::new(param_pair.as_str()), s(&param_pair));
            let body_pair = it.next().expect("grammar: single_lambda body");
            let bsp = s(&body_pair);
            Lambda {
                params: vec![LambdaParam { name, ty: None }],
                body: Box::new(Spanned::new(build_expression(body_pair, diags), bsp)),
            }
        }
        Rule::multi_lambda => {
            // multi_lambda = { "(" ~ lambda_param_list ~ ")" ~ "=>" ~ expression }
            let mut it = inner.into_inner();
            let params_pair = it.next().expect("grammar: multi_lambda params");
            let params: Vec<LambdaParam> = params_pair
                .into_inner()
                .filter(|p| p.as_rule() == Rule::lambda_param)
                .map(build_lambda_param)
                .collect();
            let body_pair = it.next().expect("grammar: multi_lambda body");
            let bsp = s(&body_pair);
            Lambda {
                params,
                body: Box::new(Spanned::new(build_expression(body_pair, diags), bsp)),
            }
        }
        r => unreachable!("unexpected lambda_expr inner: {:?}", r),
    }
}

fn build_lambda_param(pair: Pair<Rule>) -> LambdaParam {
    // lambda_param = { ident ~ (":" ~ ty)? }
    let children: Vec<Pair<Rule>> = pair.into_inner().collect();
    let mut it = children.into_iter();
    let name_pair = it.next().expect("grammar: lambda_param name");
    let name = Spanned::new(SmolStr::new(name_pair.as_str()), s(&name_pair));
    let ty = it
        .next()
        .filter(|p| p.as_rule() == Rule::ty)
        .map(|p| Spanned::new(build_ty(p.clone()), s(&p)));
    LambdaParam { name, ty }
}

// ── Patterns ──────────────────────────────────────────────────────────

fn build_pattern(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> Pattern {
    // pattern = { or_pattern }
    let inner = pair.into_inner().next().expect("grammar: pattern inner");
    build_or_pattern(inner, diags)
}

fn build_or_pattern(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> Pattern {
    // or_pattern = { primary_pattern ~ ("|" ~ primary_pattern)* }
    let mut parts: Vec<Spanned<Pattern>> = pair
        .into_inner()
        .filter(|p| p.as_rule() == Rule::primary_pattern)
        .map(|p| Spanned::new(build_primary_pattern(p.clone(), diags), s(&p)))
        .collect();
    if parts.len() == 1 {
        parts.remove(0).node
    } else {
        Pattern::Or(parts)
    }
}

fn build_primary_pattern(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> Pattern {
    // primary_pattern = { guarded_pattern | base_pattern }
    let inner = pair
        .into_inner()
        .next()
        .expect("grammar: primary_pattern inner");
    match inner.as_rule() {
        Rule::guarded_pattern => {
            // guarded_pattern = { base_pattern ~ kw_when ~ expression }
            let children: Vec<Pair<Rule>> = inner.into_inner().collect();
            let mut base_opt: Option<(Pattern, Span)> = None;
            let mut cond_opt: Option<(Expr, Span)> = None;
            let mut saw_when = false;
            for p in children {
                match p.as_rule() {
                    Rule::base_pattern => {
                        let bsp = s(&p);
                        base_opt = Some((build_base_pattern(p, diags), bsp));
                    }
                    Rule::kw_when => saw_when = true,
                    Rule::expression if saw_when => {
                        let csp = s(&p);
                        cond_opt = Some((build_expression(p, diags), csp));
                    }
                    _ if is_kw(p.as_rule()) => {}
                    _ => {}
                }
            }
            let (base, bsp) = base_opt.expect("grammar: guarded base");
            let (cond, csp) = cond_opt.expect("grammar: guarded condition");
            Pattern::Guard {
                pattern: Box::new(Spanned::new(base, bsp)),
                condition: Box::new(Spanned::new(cond, csp)),
            }
        }
        Rule::base_pattern => build_base_pattern(inner, diags),
        r => unreachable!("unexpected primary_pattern inner: {:?}", r),
    }
}

fn build_base_pattern(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> Pattern {
    let text = pair.as_str().trim();
    let children: Vec<Pair<Rule>> = pair.into_inner().collect();

    if children.is_empty() {
        if text == "_" {
            return Pattern::Wildcard;
        }
        unreachable!("base_pattern with no children: {:?}", text);
    }

    let first = &children[0];
    match first.as_rule() {
        Rule::literal => Pattern::Literal(build_literal(first.clone())),
        Rule::qualified_name => {
            let qn = build_qualified_name(first.clone());
            let fields: Vec<PatternField> = children[1..]
                .iter()
                .flat_map(|p| {
                    if p.as_rule() == Rule::pattern_field_list {
                        p.clone()
                            .into_inner()
                            .filter(|f| f.as_rule() == Rule::pattern_field)
                            .map(|f| build_pattern_field(f, diags))
                            .collect::<Vec<_>>()
                    } else {
                        vec![]
                    }
                })
                .collect();
            if text.contains('{') {
                Pattern::Destructure { name: qn, fields }
            } else if qn.segments.len() == 1 {
                Pattern::Binding(qn.segments.into_iter().next().expect("one segment"))
            } else {
                Pattern::Destructure {
                    name: qn,
                    fields: vec![],
                }
            }
        }
        Rule::pattern_list => {
            let pats: Vec<Spanned<Pattern>> = first
                .clone()
                .into_inner()
                .filter(|p| p.as_rule() == Rule::pattern)
                .map(|pp| Spanned::new(build_pattern(pp.clone(), diags), s(&pp)))
                .collect();
            Pattern::List(pats)
        }
        Rule::pattern => {
            if text.starts_with('[') {
                Pattern::List(vec![])
            } else {
                build_pattern(first.clone(), diags)
            }
        }
        Rule::ident => Pattern::Binding(Spanned::new(SmolStr::new(first.as_str()), s(first))),
        r => unreachable!("unexpected base_pattern first child: {:?}", r),
    }
}

fn build_pattern_field(pair: Pair<Rule>, diags: &mut DiagnosticSink) -> PatternField {
    let text = pair.as_str().trim();
    let children: Vec<Pair<Rule>> = pair.into_inner().collect();

    if children.is_empty() {
        return PatternField::Wildcard(Span::DUMMY);
    }

    let first = &children[0];
    if first.as_rule() == Rule::ident {
        if children.len() >= 2 && children[1].as_rule() == Rule::pattern {
            let key = Spanned::new(SmolStr::new(first.as_str()), s(first));
            let pat_pair = children[1].clone();
            let psp = s(&pat_pair);
            PatternField::Named {
                key,
                pattern: Spanned::new(build_pattern(pat_pair, diags), psp),
            }
        } else {
            PatternField::Shorthand(Spanned::new(SmolStr::new(first.as_str()), s(first)))
        }
    } else {
        let _ = text;
        unreachable!("unexpected pattern_field first: {:?}", first.as_rule())
    }
}

// ── Literals ──────────────────────────────────────────────────────────

fn build_literal(pair: Pair<Rule>) -> Literal {
    // literal = { duration_lit | float_lit | bool_lit | int_lit | string_lit | raw_string_lit | regex_lit }
    let inner = pair.into_inner().next().expect("grammar: literal inner");
    match inner.as_rule() {
        Rule::bool_lit => Literal::Bool(inner.as_str() == "true"),
        Rule::int_lit => Literal::Int(inner.as_str().parse().unwrap_or(0)),
        Rule::float_lit => Literal::Float(inner.as_str().parse().unwrap_or(0.0)),
        Rule::duration_lit => Literal::Duration(parse_duration(inner.as_str())),
        Rule::string_lit => Literal::String(SmolStr::new(strip_string_quotes(inner.as_str()))),
        Rule::raw_string_lit => {
            let text = inner.as_str();
            Literal::String(SmolStr::new(&text[2..text.len() - 1]))
        }
        Rule::regex_lit => Literal::Regex(SmolStr::new(inner.as_str())),
        r => unreachable!("unexpected literal inner: {:?}", r),
    }
}

fn parse_duration(text: &str) -> DurationLit {
    if let Some(rest) = text.strip_suffix("ms") {
        DurationLit {
            value: rest.parse().unwrap_or(0),
            unit: DurationUnit::Milliseconds,
        }
    } else if let Some(rest) = text.strip_suffix('s') {
        DurationLit {
            value: rest.parse().unwrap_or(0),
            unit: DurationUnit::Seconds,
        }
    } else if let Some(rest) = text.strip_suffix('m') {
        DurationLit {
            value: rest.parse().unwrap_or(0),
            unit: DurationUnit::Minutes,
        }
    } else if let Some(rest) = text.strip_suffix('h') {
        DurationLit {
            value: rest.parse().unwrap_or(0),
            unit: DurationUnit::Hours,
        }
    } else if let Some(rest) = text.strip_suffix('d') {
        DurationLit {
            value: rest.parse().unwrap_or(0),
            unit: DurationUnit::Days,
        }
    } else {
        unreachable!("unexpected duration literal: {}", text)
    }
}

/// Strip surrounding double-quotes from a string literal token.
fn strip_string_quotes(text: &str) -> &str {
    if text.starts_with('"') && text.ends_with('"') && text.len() >= 2 {
        &text[1..text.len() - 1]
    } else {
        text
    }
}

fn build_qualified_name(pair: Pair<Rule>) -> QualifiedName {
    let span = s(&pair);
    let segments: Vec<Spanned<SmolStr>> = pair
        .into_inner()
        .map(|p| Spanned::new(SmolStr::new(p.as_str()), s(&p)))
        .collect();
    QualifiedName { segments, span }
}

// ═══════════════════════════════════════════════════════════════════════
//  Left-associative binary fold
// ═══════════════════════════════════════════════════════════════════════

/// Fold a binary chain rule `sub_expr (op_rule sub_expr)*` left-to-right.
fn fold_left_binary<F, G>(
    pair: Pair<Rule>,
    diags: &mut DiagnosticSink,
    op_rule: Rule,
    build_sub: F,
    op_from_str: G,
) -> Expr
where
    F: Fn(Pair<Rule>, &mut DiagnosticSink) -> Expr,
    G: Fn(&str) -> BinaryOp,
{
    let mut inner = pair.into_inner();
    let first = inner.next().expect("grammar: binary chain first operand");
    let first_sp = s(&first);
    let mut acc = Spanned::new(build_sub(first, diags), first_sp);

    while let Some(op_candidate) = inner.next() {
        if op_candidate.as_rule() != op_rule {
            unreachable!(
                "fold_left_binary: expected {:?}, got {:?}",
                op_rule,
                op_candidate.as_rule()
            );
        }
        let op_sp = s(&op_candidate);
        // For or_op/and_op, get the text of the inner kw or literal
        let op_text = op_candidate.as_str().trim().to_owned();
        let op = op_from_str(&op_text);
        let rhs_pair = inner.next().expect("grammar: binary chain rhs");
        let rhs_sp = s(&rhs_pair);
        let rhs = Spanned::new(build_sub(rhs_pair, diags), rhs_sp);
        let merged = acc.span.merge(rhs.span);
        acc = Spanned::new(
            Expr::Binary {
                op: Spanned::new(op, op_sp),
                left: Box::new(acc),
                right: Box::new(rhs),
            },
            merged,
        );
    }

    acc.node
}

// ═══════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_ident() {
        let r = AegisParser::parse(Rule::ident, "Empty");
        assert!(r.is_ok(), "ident Empty: {:?}", r);
    }

    #[test]
    fn debug_policy_decl() {
        let r = AegisParser::parse(Rule::policy_decl, "policy Empty {}");
        assert!(r.is_ok(), "policy_decl: {:?}", r);
    }

    #[test]
    fn debug_declaration() {
        let r = AegisParser::parse(Rule::declaration, "policy Empty {}");
        assert!(r.is_ok(), "declaration: {:?}", r);
    }
}
