use std::collections::{HashMap, HashSet};

use smol_str::SmolStr;

use crate::ast::*;
use crate::diagnostics::{Diagnostic, DiagnosticCode, DiagnosticSink};
use crate::ir::*;

// ═══════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════

/// Returns `true` if `expr` contains a `next(...)` temporal anywhere in
/// its subtree.  Used by the lowering pass to detect composite patterns
/// that require special state-machine construction.
fn expr_contains_next(expr: &Expr) -> bool {
    match expr {
        Expr::Temporal(TemporalExpr::Next { .. }) => true,
        Expr::Temporal(TemporalExpr::Always { condition, .. })
        | Expr::Temporal(TemporalExpr::Eventually { condition, .. })
        | Expr::Temporal(TemporalExpr::Never { condition }) => expr_contains_next(&condition.node),
        Expr::Temporal(TemporalExpr::Until { hold, release }) => {
            expr_contains_next(&hold.node) || expr_contains_next(&release.node)
        }
        Expr::Temporal(TemporalExpr::Before { first, second }) => {
            expr_contains_next(&first.node) || expr_contains_next(&second.node)
        }
        Expr::Temporal(TemporalExpr::After { condition, trigger }) => {
            expr_contains_next(&condition.node) || expr_contains_next(&trigger.node)
        }
        Expr::Binary { left, right, .. } => {
            expr_contains_next(&left.node) || expr_contains_next(&right.node)
        }
        Expr::Unary { operand, .. } => expr_contains_next(&operand.node),
        Expr::FieldAccess { object, .. } => expr_contains_next(&object.node),
        Expr::IndexAccess { object, index } => {
            expr_contains_next(&object.node) || expr_contains_next(&index.node)
        }
        Expr::Call { args, .. } => args.iter().any(|a| expr_contains_next(&a.value.node)),
        Expr::MethodCall { object, args, .. } => {
            expr_contains_next(&object.node)
                || args.iter().any(|a| expr_contains_next(&a.value.node))
        }
        Expr::Quantifier {
            collection,
            predicate,
            ..
        } => expr_contains_next(&collection.node) || expr_contains_next(&predicate.body.node),
        Expr::Predicate {
            subject, argument, ..
        } => expr_contains_next(&subject.node) || expr_contains_next(&argument.node),
        Expr::Count {
            collection, filter, ..
        } => {
            expr_contains_next(&collection.node)
                || filter
                    .as_ref()
                    .is_some_and(|f| expr_contains_next(&f.body.node))
        }
        Expr::Match {
            scrutinee, arms, ..
        } => {
            expr_contains_next(&scrutinee.node)
                || arms.iter().any(|a| match &a.result.node {
                    MatchResult::Expr(e) => expr_contains_next(e),
                    MatchResult::Block(stmts) => stmts.iter().any(|s| match &s.node {
                        BlockStatement::Expr(e) => expr_contains_next(e),
                        _ => false,
                    }),
                    MatchResult::Verdict(_) => false,
                })
        }
        Expr::Block(stmts) => stmts.iter().any(|s| match &s.node {
            BlockStatement::Expr(e) => expr_contains_next(e),
            _ => false,
        }),
        Expr::Lambda(lambda) => expr_contains_next(&lambda.body.node),
        Expr::Object(fields) => fields.iter().any(|f| expr_contains_next(&f.value.node)),
        Expr::List(elems) => elems.iter().any(|e| expr_contains_next(&e.node)),
        // Terminals: no nested next possible.
        Expr::Literal(_) | Expr::Identifier(_) | Expr::Context(_) => false,
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Lowering context — tracks local bindings and generates sequential IDs
// ═══════════════════════════════════════════════════════════════════════

/// Maps local variable names to their slot IDs for `RefRoot::Local(n)`.
struct LocalScope {
    /// Stack of scopes. Each scope maps names to local slot IDs.
    frames: Vec<HashMap<SmolStr, u32>>,
    next_slot: u32,
}

impl LocalScope {
    fn new() -> Self {
        Self {
            frames: vec![HashMap::new()],
            next_slot: 0,
        }
    }

    fn push(&mut self) {
        self.frames.push(HashMap::new());
    }

    fn pop(&mut self) {
        self.frames.pop();
    }

    fn bind(&mut self, name: SmolStr) -> u32 {
        let slot = self.next_slot;
        self.next_slot += 1;
        if let Some(frame) = self.frames.last_mut() {
            frame.insert(name, slot);
        }
        slot
    }

    fn lookup(&self, name: &str) -> Option<u32> {
        for frame in self.frames.iter().rev() {
            if let Some(&slot) = frame.get(name) {
                return Some(slot);
            }
        }
        None
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Inheritance resolution
// ═══════════════════════════════════════════════════════════════════════

/// Collect the effective member list for a policy by walking its inheritance
/// chain. Ancestors are prepended (base first), so derived members appear last
/// and take precedence for last-wins fields like `severity`.
///
/// `visited` guards against inheritance cycles — a policy seen twice yields an
/// empty slice for that second visit rather than looping forever.  Because
/// Aegis uses single inheritance (`extends` takes at most one base), a true
/// diamond (shared ancestor reachable via two paths) cannot arise.  Each
/// ancestor therefore appears at most once in the returned member list, and
/// the `visited` set is only exercised by malformed mutual-extension cycles.
fn collect_inherited_members<'a>(
    policy: &'a PolicyDecl,
    all_policies: &HashMap<SmolStr, &'a PolicyDecl>,
    visited: &mut HashSet<SmolStr>,
) -> Vec<&'a Spanned<PolicyMember>> {
    let name = policy.name.node.clone();
    if !visited.insert(name) {
        // Already on the current ancestry path — cycle detected.
        return vec![];
    }

    let mut members: Vec<&'a Spanned<PolicyMember>> = Vec::new();

    if let Some(base_name) = &policy.extends {
        let base_key = base_name.last().node.clone();
        if let Some(&base) = all_policies.get(&base_key) {
            let base_members = collect_inherited_members(base, all_policies, visited);
            members.extend(base_members);
        }
    }

    members.extend(policy.members.iter());
    members
}

// ═══════════════════════════════════════════════════════════════════════
//  The lowering pass
// ═══════════════════════════════════════════════════════════════════════

/// Lowers a type-checked Aegis AST into the Policy IR.
///
/// Assumes the program has already passed type checking. Errors emitted
/// here are structural issues that the type checker didn't catch (e.g.,
/// unresolvable duration literals in constraint windows).
pub struct Lowering {
    sm_builder: StateMachineBuilder,
    next_rule_id: u32,
    locals: LocalScope,
    diag: DiagnosticSink,
    /// Compiled top-level functions available for inlining.
    functions: HashMap<SmolStr, FunctionDecl>,
}

impl Default for Lowering {
    fn default() -> Self {
        Self::new()
    }
}

impl Lowering {
    pub fn new() -> Self {
        Self {
            sm_builder: StateMachineBuilder::new(),
            next_rule_id: 0,
            locals: LocalScope::new(),
            diag: DiagnosticSink::new(),
            functions: HashMap::new(),
        }
    }

    pub fn diagnostics(&self) -> &DiagnosticSink {
        &self.diag
    }

    pub fn into_diagnostics(self) -> DiagnosticSink {
        self.diag
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Entry point: lower an entire program
    // ═══════════════════════════════════════════════════════════════════

    /// Lower a full program. Returns one `CompiledPolicy` per policy
    /// declaration in the source. Top-level proofs, bindings, and
    /// functions are incorporated into every policy that references them.
    pub fn lower_program(&mut self, program: &Program) -> Vec<CompiledPolicy> {
        // First pass: collect top-level functions for reference resolution
        for decl in &program.declarations {
            if let Declaration::Function(fd) = &decl.node {
                self.functions.insert(fd.name.node.clone(), fd.clone());
            }
        }

        // Collect top-level proofs (they apply to all policies in the file)
        let top_level_proofs: Vec<&ProofDecl> = program
            .declarations
            .iter()
            .filter_map(|d| match &d.node {
                Declaration::Proof(p) => Some(p),
                _ => None,
            })
            .collect();

        // Build a name → decl map for inheritance resolution
        let policy_map: HashMap<SmolStr, &PolicyDecl> = program
            .declarations
            .iter()
            .filter_map(|d| match &d.node {
                Declaration::Policy(pd) => Some((pd.name.node.clone(), pd)),
                _ => None,
            })
            .collect();

        // Lower each policy
        let mut policies = Vec::new();
        for decl in &program.declarations {
            if let Declaration::Policy(pd) = &decl.node {
                let compiled = self.lower_policy(pd, &top_level_proofs, &policy_map);
                policies.push(compiled);
            }
        }

        policies
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Policy lowering
    // ═══════════════════════════════════════════════════════════════════

    fn lower_policy(
        &mut self,
        policy: &PolicyDecl,
        top_level_proofs: &[&ProofDecl],
        all_policies: &HashMap<SmolStr, &PolicyDecl>,
    ) -> CompiledPolicy {
        let mut severity = SeverityLevel::Medium; // default
        let mut scopes = Vec::new();
        let mut rules = Vec::new();
        let mut constraints = Vec::new();
        let mut state_machines = Vec::new();

        self.locals.push();

        // Resolve effective members: base ancestors first, own members last.
        // Own members can override inherited severity/scope (last-wins semantics).
        let mut visited = HashSet::new();
        let effective_members = collect_inherited_members(policy, all_policies, &mut visited);

        for member in effective_members {
            match &member.node {
                PolicyMember::Severity(s) => severity = *s,

                PolicyMember::Scope(targets) => {
                    for t in targets {
                        scopes.push(self.scope_target_to_string(t));
                    }
                }

                PolicyMember::Rule(rule) => {
                    rules.push(self.lower_rule(rule));
                }

                PolicyMember::Proof(proof) => {
                    let mut sms = self.lower_proof(proof);
                    state_machines.append(&mut sms);
                }

                PolicyMember::Constraint(c) => {
                    if let Some(compiled) = self.lower_constraint(c) {
                        constraints.push(compiled);
                    }
                }

                PolicyMember::Binding(b) => {
                    let _slot = self.locals.bind(b.name.node.clone());
                    // Bindings at policy level become constants available
                    // to rules and proofs. The runtime pre-evaluates them.
                }

                PolicyMember::Function(_) => {
                    // Already collected in first pass
                }
            }
        }

        // Also compile top-level proofs
        for proof in top_level_proofs {
            let mut sms = self.lower_proof(proof);
            state_machines.append(&mut sms);
        }

        self.locals.pop();

        // Extract annotation metadata
        let annotations = policy
            .annotations
            .iter()
            .filter_map(|ann| {
                if ann.args.len() == 1 {
                    if let AnnotationArg::Positional(AnnotationValue::Literal(Literal::String(s))) =
                        &ann.args[0]
                    {
                        return Some((ann.name.node.clone(), s.clone()));
                    }
                }
                None
            })
            .collect();

        // Compute source hash for cache invalidation
        let source_hash = {
            let mut h: u64 = 0xcbf29ce484222325; // FNV offset basis
            for c in policy.name.node.as_bytes() {
                h ^= *c as u64;
                h = h.wrapping_mul(0x100000001b3); // FNV prime
            }
            h
        };

        CompiledPolicy {
            name: policy.name.node.clone(),
            severity,
            scopes,
            rules,
            constraints,
            state_machines,
            metadata: PolicyMetadata {
                annotations,
                source_hash,
                compiler_version: SmolStr::new(env!("CARGO_PKG_VERSION")),
            },
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Rule lowering
    // ═══════════════════════════════════════════════════════════════════

    fn lower_rule(&mut self, rule: &RuleDecl) -> CompiledRule {
        let id = self.next_rule_id;
        self.next_rule_id += 1;

        let on_events: Vec<SmolStr> = rule
            .on_events
            .iter()
            .map(|t| self.scope_target_to_string(t))
            .collect();

        // Extract the when condition (if any)
        let condition = rule.clauses.iter().find_map(|c| match &c.node {
            RuleClause::When(expr) => Some(self.lower_expr(&expr.node)),
            _ => None,
        });

        // Extract all verdicts
        let verdicts: Vec<IRVerdict> = rule
            .clauses
            .iter()
            .filter_map(|c| match &c.node {
                RuleClause::Verdict(vc) => Some(IRVerdict {
                    verdict: vc.verdict.node,
                    message: vc
                        .message
                        .as_ref()
                        .map(|m| Box::new(self.lower_expr(&m.node))),
                }),
                _ => None,
            })
            .collect();

        // Extract all actions
        let actions: Vec<IRAction> = rule
            .clauses
            .iter()
            .filter_map(|c| match &c.node {
                RuleClause::Action(ac) => Some(self.lower_action(ac)),
                _ => None,
            })
            .collect();

        // Extract rule-level severity override
        let severity = rule.clauses.iter().find_map(|c| match &c.node {
            RuleClause::Severity(s) => Some(*s),
            _ => None,
        });

        CompiledRule {
            id,
            on_events,
            condition,
            verdicts,
            actions,
            severity,
        }
    }

    fn lower_action(&mut self, action: &ActionClause) -> IRAction {
        let args = match &action.args {
            ActionArgs::None => vec![],
            ActionArgs::Positional(expr) => {
                vec![(SmolStr::new("_"), self.lower_expr(&expr.node))]
            }
            ActionArgs::Named(pairs) => pairs
                .iter()
                .map(|(key, val)| (key.node.clone(), self.lower_expr(&val.node)))
                .collect(),
        };

        IRAction {
            verb: action.verb.node,
            args,
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Constraint lowering
    // ═══════════════════════════════════════════════════════════════════

    fn lower_constraint(&mut self, c: &ConstraintDecl) -> Option<CompiledConstraint> {
        let limit = self.eval_const_int(&c.limit.node);
        let window = self.eval_const_duration_millis(&c.window.node);

        match (limit, window) {
            (Some(l), Some(w)) => Some(CompiledConstraint {
                kind: c.kind,
                target: c.target.to_string().into(),
                limit: l,
                window_millis: w,
            }),
            _ => {
                self.diag.emit(Diagnostic::error(
                    c.target.span,
                    DiagnosticCode::E0303,
                    "constraint limit and window must be compile-time constants",
                ));
                None
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Proof lowering — temporal invariants → state machines
    // ═══════════════════════════════════════════════════════════════════

    fn lower_proof(&mut self, proof: &ProofDecl) -> Vec<StateMachine> {
        let mut machines = Vec::new();

        for inv in &proof.invariants {
            for cond in &inv.conditions {
                if let Some(sm) = self.lower_temporal_to_sm(
                    &cond.node,
                    proof.name.node.clone(),
                    inv.name.node.clone(),
                ) {
                    machines.push(sm);
                }
            }
        }

        machines
    }

    /// Lower a temporal expression into a state machine.
    /// Returns `None` for non-temporal expressions (which are
    /// treated as static assertions, not runtime monitors).
    fn lower_temporal_to_sm(
        &mut self,
        expr: &Expr,
        proof_name: SmolStr,
        invariant_name: SmolStr,
    ) -> Option<StateMachine> {
        match expr {
            Expr::Temporal(temporal) => match temporal {
                TemporalExpr::Always { condition, within } => {
                    // ── Composite next() patterns ─────────────────────────
                    //
                    // `always(next(ψ))` and `always(trigger implies next(ψ))`
                    // require a composite state machine rather than a flat
                    // always(φ).  Detect these before the general path.

                    // Case 1: always(next(ψ))
                    if let Expr::Temporal(TemporalExpr::Next { condition: inner }) = &condition.node
                    {
                        let response = self.lower_expr(&inner.node);
                        return Some(self.sm_builder.compile_always_next(
                            proof_name,
                            invariant_name,
                            response,
                        ));
                    }

                    // Case 2: always(trigger implies next(ψ))
                    if let Expr::Binary { op, left, right } = &condition.node {
                        if op.node == BinaryOp::Implies {
                            if let Expr::Temporal(TemporalExpr::Next { condition: inner }) =
                                &right.node
                            {
                                let trigger = self.lower_expr(&left.node);
                                let response = self.lower_expr(&inner.node);
                                return Some(self.sm_builder.compile_always_implies_next(
                                    proof_name,
                                    invariant_name,
                                    trigger,
                                    response,
                                ));
                            }
                        }
                    }

                    // Reject other placements of next() inside always().
                    // (The checker enforces this at the syntax level, but be
                    // defensive in case lowering is called without checking.)
                    if expr_contains_next(&condition.node) {
                        self.diag.emit(Diagnostic::error(
                            condition.span,
                            DiagnosticCode::E0203,
                            "unsupported next() pattern inside always(); \
                             use always(next(ψ)) or always(trigger implies next(ψ))",
                        ));
                        return None;
                    }

                    // ── General always(φ) path ────────────────────────────
                    let predicate = self.lower_expr(&condition.node);
                    let deadline = within
                        .as_ref()
                        .and_then(|w| self.eval_const_duration_millis(&w.node));
                    Some(self.sm_builder.compile_always(
                        proof_name,
                        invariant_name,
                        predicate,
                        deadline,
                    ))
                }

                TemporalExpr::Eventually { condition, within } => {
                    let predicate = self.lower_expr(&condition.node);
                    let deadline = within
                        .as_ref()
                        .and_then(|w| self.eval_const_duration_millis(&w.node));
                    Some(self.sm_builder.compile_eventually(
                        proof_name,
                        invariant_name,
                        predicate,
                        deadline,
                    ))
                }

                TemporalExpr::Never { condition } => {
                    let predicate = self.lower_expr(&condition.node);
                    Some(
                        self.sm_builder
                            .compile_never(proof_name, invariant_name, predicate),
                    )
                }

                TemporalExpr::Until { hold, release } => {
                    let hold_ir = self.lower_expr(&hold.node);
                    let release_ir = self.lower_expr(&release.node);
                    Some(self.sm_builder.compile_until(
                        proof_name,
                        invariant_name,
                        hold_ir,
                        release_ir,
                    ))
                }

                TemporalExpr::Next { condition } => {
                    // Standalone `next(φ)`: check φ on the very next event,
                    // then reach a terminal state.  For repeated sequencing
                    // (e.g. "after every login, the next event must be MFA"),
                    // use `always(trigger implies next(ψ))` instead.
                    let predicate = self.lower_expr(&condition.node);
                    Some(
                        self.sm_builder
                            .compile_next(proof_name, invariant_name, predicate),
                    )
                }

                TemporalExpr::Before { first, second } => {
                    // `before(φ, ψ)`: φ must become true before ψ.
                    //   State 0 (waiting): neither has happened.
                    //     On φ → State 1 (satisfied). On ψ → State 2 (violated).
                    //   State 1 (satisfied): φ came first.
                    //   State 2 (violated): ψ came first.
                    let first_ir = self.lower_expr(&first.node);
                    let second_ir = self.lower_expr(&second.node);
                    let id = self.sm_builder.next_id;
                    self.sm_builder.next_id += 1;
                    Some(StateMachine {
                        id,
                        name: proof_name,
                        invariant_name,
                        kind: TemporalKind::Eventually, // semantically closest
                        states: vec![
                            State {
                                id: 0,
                                label: SmolStr::new("waiting"),
                                kind: StateKind::Active,
                            },
                            State {
                                id: 1,
                                label: SmolStr::new("first_occurred"),
                                kind: StateKind::Satisfied,
                            },
                            State {
                                id: 2,
                                label: SmolStr::new("second_occurred_first"),
                                kind: StateKind::Violated,
                            },
                        ],
                        transitions: vec![
                            Transition {
                                from: 0,
                                to: 1,
                                guard: TransitionGuard::Predicate(first_ir),
                            },
                            Transition {
                                from: 0,
                                to: 2,
                                guard: TransitionGuard::Predicate(second_ir),
                            },
                        ],
                        initial_state: 0,
                        accepting_states: vec![1],
                        violating_states: vec![2],
                        deadline_millis: None,
                    })
                }

                TemporalExpr::After { condition, trigger } => {
                    // `after(φ, ψ)`: φ must hold after ψ occurs.
                    //   State 0 (waiting_for_trigger): ψ hasn't happened yet.
                    //     On ψ → State 1.
                    //   State 1 (checking): ψ occurred, now monitor φ.
                    //     On φ → State 2. On ¬φ → State 3.
                    let cond_ir = self.lower_expr(&condition.node);
                    let trig_ir = self.lower_expr(&trigger.node);
                    let id = self.sm_builder.next_id;
                    self.sm_builder.next_id += 1;
                    Some(StateMachine {
                        id,
                        name: proof_name,
                        invariant_name,
                        kind: TemporalKind::Eventually, // semantically closest
                        states: vec![
                            State {
                                id: 0,
                                label: SmolStr::new("waiting_for_trigger"),
                                kind: StateKind::Active,
                            },
                            State {
                                id: 1,
                                label: SmolStr::new("triggered"),
                                kind: StateKind::Active,
                            },
                            State {
                                id: 2,
                                label: SmolStr::new("satisfied"),
                                kind: StateKind::Satisfied,
                            },
                            State {
                                id: 3,
                                label: SmolStr::new("violated"),
                                kind: StateKind::Violated,
                            },
                        ],
                        transitions: vec![
                            Transition {
                                from: 0,
                                to: 0,
                                guard: TransitionGuard::NegatedPredicate(trig_ir.clone()),
                            },
                            Transition {
                                from: 0,
                                to: 1,
                                guard: TransitionGuard::Predicate(trig_ir),
                            },
                            Transition {
                                from: 1,
                                to: 2,
                                guard: TransitionGuard::Predicate(cond_ir.clone()),
                            },
                            Transition {
                                from: 1,
                                to: 3,
                                guard: TransitionGuard::NegatedPredicate(cond_ir),
                            },
                        ],
                        initial_state: 0,
                        accepting_states: vec![2],
                        violating_states: vec![3],
                        deadline_millis: None,
                    })
                }
            },

            // Non-temporal expression in a proof — treat as a static check.
            // The runtime evaluates it once at policy load time.
            _ => None,
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Expression lowering — AST Expr → IR IRExpr
    // ═══════════════════════════════════════════════════════════════════

    fn lower_expr(&mut self, expr: &Expr) -> IRExpr {
        match expr {
            Expr::Literal(lit) => IRExpr::Literal(lit.clone()),

            Expr::Identifier(name) => self.resolve_name(name),

            Expr::Context(name) => {
                let fields: Vec<SmolStr> = name.segments.iter().map(|s| s.node.clone()).collect();
                IRExpr::Ref(RefPath {
                    root: RefRoot::Context,
                    fields,
                })
            }

            Expr::FieldAccess { object, field } => {
                let obj_ir = self.lower_expr(&object.node);
                // Flatten nested field accesses into a single RefPath
                match obj_ir {
                    IRExpr::Ref(mut path) => {
                        path.fields.push(field.node.clone());
                        IRExpr::Ref(path)
                    }
                    other => IRExpr::MethodCall {
                        object: Box::new(other),
                        method: field.node.clone(),
                        args: vec![],
                    },
                }
            }

            Expr::IndexAccess { object, index } => {
                // Lower to a method call: obj.__index__(idx)
                let obj_ir = self.lower_expr(&object.node);
                let idx_ir = self.lower_expr(&index.node);
                IRExpr::MethodCall {
                    object: Box::new(obj_ir),
                    method: SmolStr::new("__index__"),
                    args: vec![idx_ir],
                }
            }

            Expr::Call { callee, args } => {
                let lowered_args: Vec<IRExpr> = args
                    .iter()
                    .map(|a| self.lower_expr(&a.value.node))
                    .collect();

                // Resolve the callee to a function name
                if let Expr::Identifier(name) = &callee.node {
                    let fn_name = name.to_string();
                    return IRExpr::Call {
                        function: fn_name.into(),
                        args: lowered_args,
                    };
                }

                // Method call on an object
                if let Expr::FieldAccess { object, field } = &callee.node {
                    let obj_ir = self.lower_expr(&object.node);
                    return IRExpr::MethodCall {
                        object: Box::new(obj_ir),
                        method: field.node.clone(),
                        args: lowered_args,
                    };
                }

                // Fallback: treat callee as expression
                let callee_ir = self.lower_expr(&callee.node);
                IRExpr::MethodCall {
                    object: Box::new(callee_ir),
                    method: SmolStr::new("__call__"),
                    args: lowered_args,
                }
            }

            Expr::MethodCall {
                object,
                method,
                args,
            } => {
                let obj_ir = self.lower_expr(&object.node);
                let lowered_args: Vec<IRExpr> = args
                    .iter()
                    .map(|a| self.lower_expr(&a.value.node))
                    .collect();
                IRExpr::MethodCall {
                    object: Box::new(obj_ir),
                    method: method.node.clone(),
                    args: lowered_args,
                }
            }

            Expr::Binary { op, left, right } => IRExpr::Binary {
                op: op.node,
                left: Box::new(self.lower_expr(&left.node)),
                right: Box::new(self.lower_expr(&right.node)),
            },

            Expr::Unary { op, operand } => IRExpr::Unary {
                op: op.node,
                operand: Box::new(self.lower_expr(&operand.node)),
            },

            Expr::Temporal(temporal) => {
                // Temporal expressions outside of proof blocks (already
                // checked by the type checker) — lower the inner predicate
                // for use in static assertions.
                match temporal {
                    TemporalExpr::Always { condition, .. }
                    | TemporalExpr::Eventually { condition, .. }
                    | TemporalExpr::Never { condition }
                    | TemporalExpr::Next { condition } => self.lower_expr(&condition.node),
                    TemporalExpr::Until { hold, .. } => self.lower_expr(&hold.node),
                    TemporalExpr::Before { first, .. } => self.lower_expr(&first.node),
                    TemporalExpr::After { condition, .. } => self.lower_expr(&condition.node),
                }
            }

            Expr::Predicate {
                kind,
                subject,
                argument,
            } => IRExpr::Predicate {
                kind: *kind,
                subject: Box::new(self.lower_expr(&subject.node)),
                argument: Box::new(self.lower_expr(&argument.node)),
            },

            Expr::Quantifier {
                kind,
                collection,
                predicate,
            } => {
                let coll_ir = self.lower_expr(&collection.node);
                // Inline the lambda: capture the parameter name and lower the body
                let param_name = predicate
                    .params
                    .first()
                    .map(|p| p.name.node.clone())
                    .unwrap_or_else(|| SmolStr::new("_it"));

                self.locals.push();
                let _slot = self.locals.bind(param_name.clone());
                let body_ir = self.lower_expr(&predicate.body.node);
                self.locals.pop();

                IRExpr::Quantifier {
                    kind: *kind,
                    collection: Box::new(coll_ir),
                    param: param_name,
                    body: Box::new(body_ir),
                }
            }

            Expr::Count { collection, filter } => {
                let coll_ir = self.lower_expr(&collection.node);
                let (param, filter_ir) = if let Some(lambda) = filter {
                    let param_name = lambda
                        .params
                        .first()
                        .map(|p| p.name.node.clone())
                        .unwrap_or_else(|| SmolStr::new("_it"));
                    self.locals.push();
                    let _slot = self.locals.bind(param_name.clone());
                    let body_ir = self.lower_expr(&lambda.body.node);
                    self.locals.pop();
                    (Some(param_name), Some(Box::new(body_ir)))
                } else {
                    (None, None)
                };

                IRExpr::Count {
                    collection: Box::new(coll_ir),
                    param,
                    filter: filter_ir,
                }
            }

            Expr::Match { scrutinee, arms } => {
                let subject_ir = self.lower_expr(&scrutinee.node);
                let decision = self.lower_match_to_decision_tree(&subject_ir, arms);
                IRExpr::DecisionTree(Box::new(decision))
            }

            Expr::Lambda(lambda) => {
                // Standalone lambdas outside of quantifier context are lowered
                // to their body with parameters as free variables.
                self.locals.push();
                for param in &lambda.params {
                    self.locals.bind(param.name.node.clone());
                }
                let body_ir = self.lower_expr(&lambda.body.node);
                self.locals.pop();
                body_ir
            }

            Expr::List(elements) => {
                let items: Vec<IRExpr> =
                    elements.iter().map(|e| self.lower_expr(&e.node)).collect();
                IRExpr::List(items)
            }

            Expr::Object(_fields) => {
                // Object literals in the IR become runtime-constructed maps.
                // For now, lower to an empty list placeholder — the runtime
                // handles object construction.
                IRExpr::List(vec![])
            }

            Expr::Block(stmts) => {
                // Lower block to the last expression's value
                self.locals.push();
                let mut last = IRExpr::Literal(Literal::Bool(false));
                for stmt in stmts {
                    last = self.lower_block_statement(&stmt.node);
                }
                self.locals.pop();
                last
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Name resolution — map AST names to IR references
    // ═══════════════════════════════════════════════════════════════════

    fn resolve_name(&self, name: &QualifiedName) -> IRExpr {
        let segments = &name.segments;

        if segments.is_empty() {
            return IRExpr::Literal(Literal::Bool(false)); // shouldn't happen
        }

        let first = segments[0].node.as_str();

        // Check for well-known roots
        match first {
            "event" => {
                let fields: Vec<SmolStr> = segments[1..].iter().map(|s| s.node.clone()).collect();
                return IRExpr::Ref(RefPath {
                    root: RefRoot::Event,
                    fields,
                });
            }
            "context" => {
                let fields: Vec<SmolStr> = segments[1..].iter().map(|s| s.node.clone()).collect();
                return IRExpr::Ref(RefPath {
                    root: RefRoot::Context,
                    fields,
                });
            }
            "policy" => {
                let fields: Vec<SmolStr> = segments[1..].iter().map(|s| s.node.clone()).collect();
                return IRExpr::Ref(RefPath {
                    root: RefRoot::Policy,
                    fields,
                });
            }
            _ => {}
        }

        // Check local bindings
        if let Some(slot) = self.locals.lookup(first) {
            let fields: Vec<SmolStr> = segments[1..].iter().map(|s| s.node.clone()).collect();
            return IRExpr::Ref(RefPath {
                root: RefRoot::Local(slot),
                fields,
            });
        }

        // Single-segment name that isn't a local — could be a function
        // reference or an unresolved name. Emit as a call with zero args
        // if it's a known function, otherwise as a context reference
        // (the runtime will resolve it dynamically).
        if segments.len() == 1 {
            if self.functions.contains_key(first) {
                return IRExpr::Call {
                    function: SmolStr::new(first),
                    args: vec![],
                };
            }
            // Unresolved — treat as a context reference for forward compat
            return IRExpr::Ref(RefPath {
                root: RefRoot::Context,
                fields: vec![SmolStr::new(first)],
            });
        }

        // Multi-segment name: first segment might be a module or import alias.
        // For v1, treat as a dotted context reference.
        let fields: Vec<SmolStr> = segments.iter().map(|s| s.node.clone()).collect();
        IRExpr::Ref(RefPath {
            root: RefRoot::Context,
            fields,
        })
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Pattern match → decision tree compilation
    // ═══════════════════════════════════════════════════════════════════

    fn lower_match_to_decision_tree(
        &mut self,
        subject: &IRExpr,
        arms: &[MatchArm],
    ) -> DecisionNode {
        let mut cases = Vec::new();
        let mut default = None;

        for arm in arms {
            let body = self.lower_match_result(&arm.result.node);

            match &arm.pattern.node {
                Pattern::Wildcard => {
                    default = Some(Box::new(body));
                }

                Pattern::Literal(lit) => {
                    cases.push(DecisionCase {
                        test: CaseTest::Literal(lit.clone()),
                        body,
                    });
                }

                Pattern::Binding(_ident) => {
                    // Binding pattern — acts as a default that also binds
                    // the value. For v1, treat as default.
                    default = Some(Box::new(body));
                }

                Pattern::Destructure { name, fields: _ } => {
                    cases.push(DecisionCase {
                        test: CaseTest::Constructor(name.to_string().into()),
                        body,
                    });
                }

                Pattern::Guard {
                    pattern: _,
                    condition,
                } => {
                    let guard_ir = self.lower_expr(&condition.node);
                    cases.push(DecisionCase {
                        test: CaseTest::Guard(guard_ir),
                        body,
                    });
                }

                Pattern::Or(alternatives) => {
                    // Or-pattern: expand each alternative as a separate case
                    // pointing to the same body
                    for alt in alternatives {
                        if let Pattern::Literal(lit) = &alt.node {
                            cases.push(DecisionCase {
                                test: CaseTest::Literal(lit.clone()),
                                body: body.clone(),
                            });
                        }
                    }
                }

                Pattern::List(_) => {
                    // List patterns — complex, deferred to v2
                    default = Some(Box::new(body));
                }
            }
        }

        DecisionNode::Switch {
            subject: Box::new(subject.clone()),
            cases,
            default,
        }
    }

    fn lower_match_result(&mut self, result: &MatchResult) -> DecisionNode {
        match result {
            MatchResult::Expr(expr) => DecisionNode::Leaf(Box::new(self.lower_expr(expr))),
            MatchResult::Verdict(vc) => DecisionNode::VerdictLeaf(Box::new(IRVerdict {
                verdict: vc.verdict.node,
                message: vc
                    .message
                    .as_ref()
                    .map(|m| Box::new(self.lower_expr(&m.node))),
            })),
            MatchResult::Block(stmts) => {
                self.locals.push();
                let mut last_ir = IRExpr::Literal(Literal::Bool(false));
                let mut last_verdict: Option<IRVerdict> = None;

                for stmt in stmts {
                    match &stmt.node {
                        BlockStatement::Binding(b) => {
                            self.locals.bind(b.name.node.clone());
                        }
                        BlockStatement::Expr(e) => {
                            last_ir = self.lower_expr(e);
                        }
                        BlockStatement::Verdict(vc) => {
                            last_verdict = Some(IRVerdict {
                                verdict: vc.verdict.node,
                                message: vc
                                    .message
                                    .as_ref()
                                    .map(|m| Box::new(self.lower_expr(&m.node))),
                            });
                        }
                        BlockStatement::Action(_) => {
                            // Actions in match blocks are side-effecting;
                            // they're collected separately by the rule lowering.
                        }
                    }
                }
                self.locals.pop();

                if let Some(v) = last_verdict {
                    DecisionNode::VerdictLeaf(Box::new(v))
                } else {
                    DecisionNode::Leaf(Box::new(last_ir))
                }
            }
        }
    }

    fn lower_block_statement(&mut self, stmt: &BlockStatement) -> IRExpr {
        match stmt {
            BlockStatement::Binding(b) => {
                self.locals.bind(b.name.node.clone());
                self.lower_expr(&b.value.node)
            }
            BlockStatement::Expr(e) => self.lower_expr(e),
            BlockStatement::Verdict(_) => {
                // Verdicts don't produce values in block context
                IRExpr::Literal(Literal::Bool(true))
            }
            BlockStatement::Action(_) => IRExpr::Literal(Literal::Bool(true)),
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Constant evaluation — for constraint windows and deadlines
    // ═══════════════════════════════════════════════════════════════════

    fn eval_const_int(&self, expr: &Expr) -> Option<u64> {
        match expr {
            Expr::Literal(Literal::Int(n)) => Some(*n as u64),
            _ => None,
        }
    }

    fn eval_const_duration_millis(&self, expr: &Expr) -> Option<u64> {
        match expr {
            Expr::Literal(Literal::Duration(d)) => Some(d.to_millis()),
            _ => None,
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Helpers
    // ═══════════════════════════════════════════════════════════════════

    fn scope_target_to_string(&self, target: &ScopeTarget) -> SmolStr {
        match target {
            ScopeTarget::Name(name) => name.to_string().into(),
            ScopeTarget::Literal(s) => s.node.clone(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Convenience: one-shot compilation
// ═══════════════════════════════════════════════════════════════════════

/// Compile a type-checked program to Policy IR in one call.
///
/// ```ignore
/// let policies = aegis_compiler::lower::compile(&program);
/// for policy in &policies {
///     println!("Compiled {} with {} rules, {} state machines",
///         policy.name, policy.rules.len(), policy.state_machines.len());
/// }
/// ```
pub fn compile(program: &Program) -> (Vec<CompiledPolicy>, DiagnosticSink) {
    let mut lowering = Lowering::new();
    let policies = lowering.lower_program(program);
    (policies, lowering.into_diagnostics())
}
