use smol_str::SmolStr;

use crate::ast::*;
use crate::diagnostics::{Diagnostic, DiagnosticCode, DiagnosticSink};
use crate::types::{FunctionSig, Ty, TypeEnv};

/// Context flags for the checker — tracks where we are in the AST.
#[derive(Debug, Clone, Copy)]
struct CheckContext {
    /// Are we inside a proof/invariant block? Temporal operators only valid here.
    in_proof: bool,
    /// Are we inside a rule body? `event` binding is available here.
    in_rule: bool,
    /// Are we inside a policy? `context` expressions valid here.
    in_policy: bool,
    /// Nesting depth of temporal operators (v1: max 1).
    temporal_depth: u32,
}

impl CheckContext {
    fn top_level() -> Self {
        Self {
            in_proof: false,
            in_rule: false,
            in_policy: false,
            temporal_depth: 0,
        }
    }
}

/// The Aegis type checker.
///
/// Usage:
/// ```ignore
/// let mut checker = TypeChecker::new();
/// checker.check_program(&program);
/// if checker.diagnostics().has_errors() {
///     // report errors
/// }
/// ```
pub struct TypeChecker {
    env: TypeEnv,
    diag: DiagnosticSink,
}

impl Default for TypeChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl TypeChecker {
    pub fn new() -> Self {
        Self {
            env: TypeEnv::new(),
            diag: DiagnosticSink::new(),
        }
    }

    pub fn diagnostics(&self) -> &DiagnosticSink {
        &self.diag
    }

    pub fn into_diagnostics(self) -> DiagnosticSink {
        self.diag
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Top-level
    // ═══════════════════════════════════════════════════════════════════

    pub fn check_program(&mut self, program: &Program) {
        let ctx = CheckContext::top_level();

        // First pass: register all top-level type and function definitions
        // so they can be referenced in any order.
        for decl in &program.declarations {
            self.register_declaration(&decl.node);
        }

        // Second pass: check bodies.
        for decl in &program.declarations {
            self.check_declaration(&decl.node, decl.span, ctx);
        }
    }

    fn register_declaration(&mut self, decl: &Declaration) {
        match decl {
            Declaration::Type(td) => {
                let fields: Vec<(SmolStr, Ty)> = td
                    .fields
                    .iter()
                    .map(|f| (f.name.node.clone(), self.resolve_type(&f.ty.node)))
                    .collect();
                let ty = Ty::Struct(crate::types::StructType {
                    name: td.name.node.clone(),
                    fields,
                    type_params: vec![],
                });
                self.env.define_type(td.name.node.clone(), ty);
            }
            Declaration::Function(fd) => {
                let params: Vec<(SmolStr, Ty)> = fd
                    .params
                    .iter()
                    .map(|p| (p.name.node.clone(), self.resolve_type(&p.ty.node)))
                    .collect();
                let ret = self.resolve_type(&fd.return_type.node);
                self.env
                    .define_function(fd.name.node.clone(), FunctionSig { params, ret });
            }
            Declaration::Policy(pd) => {
                // Register the policy name as a type (for `extends`)
                self.env.define_type(
                    pd.name.node.clone(),
                    Ty::Struct(crate::types::StructType {
                        name: pd.name.node.clone(),
                        fields: vec![],
                        type_params: vec![],
                    }),
                );
            }
            _ => {}
        }
    }

    fn check_declaration(&mut self, decl: &Declaration, span: Span, ctx: CheckContext) {
        match decl {
            Declaration::Import(_) => {
                // Import resolution is a separate pass (module system).
                // For now we just accept imports structurally.
            }
            Declaration::Policy(pd) => self.check_policy(pd, span, ctx),
            Declaration::Proof(pd) => self.check_proof(pd, span, ctx),
            Declaration::Type(_) => {
                // Already registered in first pass
            }
            Declaration::Binding(bd) => self.check_binding(bd, span, ctx),
            Declaration::Function(fd) => self.check_function(fd, span, ctx),
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Policy checking
    // ═══════════════════════════════════════════════════════════════════

    fn check_policy(&mut self, policy: &PolicyDecl, _span: Span, _ctx: CheckContext) {
        // Check that extends target exists
        if let Some(ref extends) = policy.extends {
            let name = extends.to_string();
            if self.env.lookup_type(&name).is_none() {
                self.diag.emit(Diagnostic::error(
                    extends.span,
                    DiagnosticCode::E0304,
                    format!("policy extends unknown type `{name}`"),
                ));
            }
        }

        let policy_ctx = CheckContext {
            in_policy: true,
            ..CheckContext::top_level()
        };

        self.env.push_scope();

        // Check for duplicate severity
        let severity_count = policy
            .members
            .iter()
            .filter(|m| matches!(m.node, PolicyMember::Severity(_)))
            .count();
        if severity_count > 1 {
            self.diag.emit(Diagnostic::warning(
                policy.name.span,
                DiagnosticCode::E0301,
                "multiple severity clauses in policy; only the last one takes effect",
            ));
        }

        for member in &policy.members {
            self.check_policy_member(&member.node, member.span, policy_ctx);
        }

        self.env.pop_scope();
    }

    fn check_policy_member(&mut self, member: &PolicyMember, span: Span, ctx: CheckContext) {
        match member {
            PolicyMember::Severity(_) => {} // Structurally valid by grammar
            PolicyMember::Scope(_targets) => {
                // Future: validate scope targets against known event types
            }
            PolicyMember::Rule(rule) => self.check_rule(rule, span, ctx),
            PolicyMember::Proof(proof) => self.check_proof(proof, span, ctx),
            PolicyMember::Constraint(c) => self.check_constraint(c, span, ctx),
            PolicyMember::Binding(b) => self.check_binding(b, span, ctx),
            PolicyMember::Function(f) => self.check_function(f, span, ctx),
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Rule checking
    // ═══════════════════════════════════════════════════════════════════

    fn check_rule(&mut self, rule: &RuleDecl, _span: Span, ctx: CheckContext) {
        let rule_ctx = CheckContext {
            in_rule: true,
            ..ctx
        };

        self.env.push_scope();

        // Inject a refined `event` binding when the rule targets a single
        // literal event name with a known schema.  For multi-event rules or
        // unrecognised event names the global open/dynamic `event` binding
        // (registered in `TypeEnv::register_builtins`) remains in scope.
        if rule.on_events.len() == 1 {
            if let ScopeTarget::Literal(ev_name) = &rule.on_events[0] {
                if let Some(schema) = crate::types::event_schema(ev_name.node.as_str()) {
                    self.env.bind(SmolStr::new("event"), schema);
                }
            }
        }

        // Check rule has at least one verdict
        let has_verdict = rule
            .clauses
            .iter()
            .any(|c| matches!(c.node, RuleClause::Verdict(_)));
        if !has_verdict {
            let span = rule.clauses.last().map(|c| c.span).unwrap_or(Span::DUMMY);
            self.diag.emit(Diagnostic::warning(
                span,
                DiagnosticCode::E0300,
                "rule has no verdict (allow, deny, audit, redact); \
                 actions will execute but no enforcement decision is made",
            ));
        }

        for clause in &rule.clauses {
            self.check_rule_clause(&clause.node, clause.span, rule_ctx);
        }

        self.env.pop_scope();
    }

    fn check_rule_clause(&mut self, clause: &RuleClause, span: Span, ctx: CheckContext) {
        match clause {
            RuleClause::When(expr) => {
                let ty = self.check_expr(&expr.node, expr.span, ctx);
                if !ty.is_bool() && !ty.is_error() {
                    self.diag.emit(Diagnostic::error(
                        expr.span,
                        DiagnosticCode::E0101,
                        format!("`when` clause requires a boolean expression, found `{ty}`"),
                    ));
                }
            }
            RuleClause::Verdict(vc) => {
                if let Some(ref msg) = vc.message {
                    let ty = self.check_expr(&msg.node, msg.span, ctx);
                    if !ty.is_string() && !ty.is_error() {
                        self.diag.emit(Diagnostic::error(
                            msg.span,
                            DiagnosticCode::E0100,
                            format!("verdict message must be a string, found `{ty}`"),
                        ));
                    }
                }
            }
            RuleClause::Action(ac) => {
                self.check_action_args(&ac.args, span, ctx);
            }
            RuleClause::Severity(_) => {}
            RuleClause::Constraint(c) => self.check_constraint(c, span, ctx),
        }
    }

    fn check_action_args(&mut self, args: &ActionArgs, _span: Span, ctx: CheckContext) {
        match args {
            ActionArgs::None => {}
            ActionArgs::Positional(expr) => {
                self.check_expr(&expr.node, expr.span, ctx);
            }
            ActionArgs::Named(pairs) => {
                for (_, expr) in pairs {
                    self.check_expr(&expr.node, expr.span, ctx);
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Constraint checking
    // ═══════════════════════════════════════════════════════════════════

    fn check_constraint(&mut self, constraint: &ConstraintDecl, _span: Span, ctx: CheckContext) {
        let limit_ty = self.check_expr(&constraint.limit.node, constraint.limit.span, ctx);
        if !limit_ty.is_numeric() && !limit_ty.is_error() {
            self.diag.emit(Diagnostic::error(
                constraint.limit.span,
                DiagnosticCode::E0303,
                format!(
                    "{} limit must be numeric, found `{limit_ty}`",
                    match constraint.kind {
                        ConstraintKind::RateLimit => "rate_limit",
                        ConstraintKind::Quota => "quota",
                    }
                ),
            ));
        }

        let window_ty = self.check_expr(&constraint.window.node, constraint.window.span, ctx);
        if !window_ty.is_duration() && !window_ty.is_error() {
            self.diag.emit(Diagnostic::error(
                constraint.window.span,
                DiagnosticCode::E0303,
                format!(
                    "{} window must be a duration, found `{window_ty}`",
                    match constraint.kind {
                        ConstraintKind::RateLimit => "rate_limit",
                        ConstraintKind::Quota => "quota",
                    }
                ),
            ));
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Proof checking
    // ═══════════════════════════════════════════════════════════════════

    fn check_proof(&mut self, proof: &ProofDecl, _span: Span, ctx: CheckContext) {
        let proof_ctx = CheckContext {
            in_proof: true,
            ..ctx
        };

        for inv in &proof.invariants {
            self.check_invariant(inv, proof_ctx);
        }
    }

    fn check_invariant(&mut self, inv: &InvariantDecl, ctx: CheckContext) {
        for cond in &inv.conditions {
            let ty = self.check_expr(&cond.node, cond.span, ctx);
            // Invariant conditions should be boolean or temporal
            if !ty.is_bool() && !matches!(ty, Ty::Temporal) && !ty.is_error() {
                self.diag.emit(Diagnostic::error(
                    cond.span,
                    DiagnosticCode::E0200,
                    format!("invariant condition must be boolean or temporal, found `{ty}`"),
                ));
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Binding and function checking
    // ═══════════════════════════════════════════════════════════════════

    fn check_binding(&mut self, binding: &BindingDecl, _span: Span, ctx: CheckContext) {
        let value_ty = self.check_expr(&binding.value.node, binding.value.span, ctx);

        if let Some(ref declared_ty) = binding.ty {
            let expected = self.resolve_type(&declared_ty.node);
            if !value_ty.is_subtype_of(&expected) && !value_ty.is_error() {
                self.diag.emit(Diagnostic::type_mismatch(
                    binding.value.span,
                    &expected,
                    &value_ty,
                ));
            }
            self.env.bind(binding.name.node.clone(), expected);
        } else {
            self.env.bind(binding.name.node.clone(), value_ty);
        }
    }

    fn check_function(&mut self, func: &FunctionDecl, _span: Span, ctx: CheckContext) {
        self.env.push_scope();

        // Bind parameters
        for param in &func.params {
            let ty = self.resolve_type(&param.ty.node);
            self.env.bind(param.name.node.clone(), ty);
        }

        let body_ty = self.check_expr(&func.body.node, func.body.span, ctx);
        let expected_ret = self.resolve_type(&func.return_type.node);

        if !body_ty.is_subtype_of(&expected_ret) && !body_ty.is_error() {
            self.diag.emit(
                Diagnostic::type_mismatch(func.body.span, &expected_ret, &body_ty).with_note(
                    Some(func.return_type.span),
                    format!("declared return type is `{expected_ret}`"),
                ),
            );
        }

        self.env.pop_scope();
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Expression type checking
    // ═══════════════════════════════════════════════════════════════════

    fn check_expr(&mut self, expr: &Expr, span: Span, ctx: CheckContext) -> Ty {
        match expr {
            Expr::Literal(lit) => self.check_literal(lit),

            Expr::Identifier(name) => {
                let full_name = name.to_string();
                // Try as variable first, then as function
                if let Some(ty) = self.env.lookup_binding(&full_name) {
                    return ty.clone();
                }
                if name.segments.len() == 1 {
                    // Single-segment name might be a simple variable
                    let simple = name.segments[0].node.as_str();
                    if let Some(ty) = self.env.lookup_binding(simple) {
                        return ty.clone();
                    }
                    if self.env.lookup_function(simple).is_some() {
                        // Return a placeholder — actual checking happens at call site
                        return Ty::Error; // Refined at call
                    }
                } else {
                    // Multi-segment name (e.g. `event.tool_name`).
                    //
                    // The pest grammar's `qualified_name` rule greedily matches
                    // dot-separated identifiers, so `event.tool_name` arrives as
                    // `Identifier(["event", "tool_name"])` rather than as a
                    // `FieldAccess` node.  Resolve by looking up the base segment
                    // and walking the rest as virtual field accesses.
                    let base = name.segments[0].node.as_str();
                    if let Some(base_ty) = self.env.lookup_binding(base).cloned() {
                        let mut ty = base_ty;
                        for seg in &name.segments[1..] {
                            ty = match &ty {
                                Ty::Struct(st) => {
                                    if let Some((_, ft)) =
                                        st.fields.iter().find(|(n, _)| n == &seg.node)
                                    {
                                        ft.clone()
                                    } else if st.fields.is_empty() {
                                        // Open / dynamic struct — allow any field
                                        Ty::Struct(crate::types::StructType {
                                            name: SmolStr::new("Dynamic"),
                                            fields: vec![],
                                            type_params: vec![],
                                        })
                                    } else {
                                        self.diag.emit(Diagnostic::error(
                                            seg.span,
                                            DiagnosticCode::E0108,
                                            format!(
                                                "field `{}` not found on type `{}`",
                                                seg.node, st.name
                                            ),
                                        ));
                                        return Ty::Error;
                                    }
                                }
                                Ty::Error => return Ty::Error,
                                _ => {
                                    self.diag.emit(Diagnostic::error(
                                        span,
                                        DiagnosticCode::E0108,
                                        format!(
                                            "cannot access field `{}` on type `{ty}`",
                                            seg.node
                                        ),
                                    ));
                                    return Ty::Error;
                                }
                            };
                        }
                        return ty;
                    }
                }
                self.diag.emit(Diagnostic::undefined_var(span, &full_name));
                Ty::Error
            }

            Expr::Context(_name) => {
                if !ctx.in_policy && !ctx.in_rule {
                    self.diag.emit(Diagnostic::error(
                        span,
                        DiagnosticCode::E0001,
                        "`context` is only available inside a policy",
                    ));
                    return Ty::Error;
                }
                // Context fields are dynamically typed in v1 — return a generic
                // struct that allows field access. A future version will infer
                // context shape from scope declarations.
                Ty::Struct(crate::types::StructType {
                    name: SmolStr::new("Context"),
                    fields: vec![],
                    type_params: vec![],
                })
            }

            Expr::FieldAccess { object, field } => {
                let obj_ty = self.check_expr(&object.node, object.span, ctx);
                match &obj_ty {
                    Ty::Struct(st) => {
                        if let Some((_, field_ty)) =
                            st.fields.iter().find(|(n, _)| n == &field.node)
                        {
                            field_ty.clone()
                        } else if st.fields.is_empty() {
                            // Open struct (e.g. Context, Event) — allow any field access
                            Ty::Struct(crate::types::StructType {
                                name: SmolStr::new("Dynamic"),
                                fields: vec![],
                                type_params: vec![],
                            })
                        } else {
                            self.diag.emit(Diagnostic::error(
                                field.span,
                                DiagnosticCode::E0108,
                                format!("field `{}` not found on type `{}`", field.node, st.name),
                            ));
                            Ty::Error
                        }
                    }
                    Ty::Error => Ty::Error,
                    _ => {
                        self.diag.emit(Diagnostic::error(
                            object.span,
                            DiagnosticCode::E0108,
                            format!("cannot access field on type `{obj_ty}`"),
                        ));
                        Ty::Error
                    }
                }
            }

            Expr::IndexAccess { object, index } => {
                let obj_ty = self.check_expr(&object.node, object.span, ctx);
                let idx_ty = self.check_expr(&index.node, index.span, ctx);
                match &obj_ty {
                    Ty::List(elem) => {
                        if !idx_ty.is_numeric() && !idx_ty.is_error() {
                            self.diag.emit(Diagnostic::error(
                                index.span,
                                DiagnosticCode::E0102,
                                format!("list index must be numeric, found `{idx_ty}`"),
                            ));
                        }
                        *elem.clone()
                    }
                    Ty::Map(_, v) => *v.clone(),
                    Ty::Error => Ty::Error,
                    _ => {
                        self.diag.emit(Diagnostic::error(
                            object.span,
                            DiagnosticCode::E0103,
                            format!("cannot index into type `{obj_ty}`"),
                        ));
                        Ty::Error
                    }
                }
            }

            Expr::Call { callee, args } => {
                // Check if callee is a known function name
                if let Expr::Identifier(name) = &callee.node {
                    if name.segments.len() == 1 {
                        let fn_name = name.segments[0].node.as_str();
                        if let Some(sig) = self.env.lookup_function(fn_name).cloned() {
                            if args.len() != sig.params.len() {
                                self.diag.emit(Diagnostic::error(
                                    span,
                                    DiagnosticCode::E0105,
                                    format!(
                                        "`{fn_name}` expects {} arguments, got {}",
                                        sig.params.len(),
                                        args.len()
                                    ),
                                ));
                            }
                            // Check argument types
                            for (arg, (_, expected_ty)) in args.iter().zip(sig.params.iter()) {
                                let arg_ty = self.check_expr(&arg.value.node, arg.value.span, ctx);
                                if !arg_ty.is_subtype_of(expected_ty) && !arg_ty.is_error() {
                                    self.diag.emit(Diagnostic::type_mismatch(
                                        arg.value.span,
                                        expected_ty,
                                        &arg_ty,
                                    ));
                                }
                            }
                            return sig.ret.clone();
                        }
                    }
                }
                // Generic call — check args but return unknown
                for arg in args {
                    self.check_expr(&arg.value.node, arg.value.span, ctx);
                }
                Ty::Error
            }

            Expr::MethodCall {
                object,
                method: _,
                args,
            } => {
                let _obj_ty = self.check_expr(&object.node, object.span, ctx);
                for arg in args {
                    self.check_expr(&arg.value.node, arg.value.span, ctx);
                }
                // Method resolution is deferred to a later pass.
                // For now, return a permissive type.
                Ty::Struct(crate::types::StructType {
                    name: SmolStr::new("Dynamic"),
                    fields: vec![],
                    type_params: vec![],
                })
            }

            Expr::Binary { op, left, right } => {
                let left_ty = self.check_expr(&left.node, left.span, ctx);
                let right_ty = self.check_expr(&right.node, right.span, ctx);
                self.check_binary_op(&op.node, &left_ty, &right_ty, span)
            }

            Expr::Unary { op, operand } => {
                let operand_ty = self.check_expr(&operand.node, operand.span, ctx);
                match op.node {
                    UnaryOp::Not => {
                        if !operand_ty.is_bool() && !operand_ty.is_error() {
                            self.diag.emit(Diagnostic::error(
                                operand.span,
                                DiagnosticCode::E0101,
                                format!("`!` requires boolean operand, found `{operand_ty}`"),
                            ));
                        }
                        Ty::Primitive(PrimitiveType::Bool)
                    }
                    UnaryOp::Neg => {
                        if !operand_ty.is_numeric() && !operand_ty.is_error() {
                            self.diag.emit(Diagnostic::error(
                                operand.span,
                                DiagnosticCode::E0102,
                                format!("unary `-` requires numeric operand, found `{operand_ty}`"),
                            ));
                        }
                        operand_ty
                    }
                }
            }

            Expr::Temporal(temporal) => self.check_temporal(temporal, span, ctx),

            Expr::Predicate {
                kind,
                subject,
                argument,
            } => {
                let subj_ty = self.check_expr(&subject.node, subject.span, ctx);
                let arg_ty = self.check_expr(&argument.node, argument.span, ctx);

                match kind {
                    PredicateKind::Contains => {
                        // string contains string, or collection contains element.
                        // Open structs (event/context fields) are treated as
                        // dynamically typed and accepted without error.
                        if !subj_ty.is_string()
                            && !subj_ty.is_collection()
                            && !subj_ty.is_error()
                            && !subj_ty.is_open_struct()
                        {
                            self.diag.emit(Diagnostic::error(
                                subject.span,
                                DiagnosticCode::E0107,
                                format!(
                                    "`contains` requires string or collection, found `{subj_ty}`"
                                ),
                            ));
                        }
                    }
                    PredicateKind::Matches => {
                        if !subj_ty.is_string() && !subj_ty.is_error() && !subj_ty.is_open_struct()
                        {
                            self.diag.emit(Diagnostic::error(
                                subject.span,
                                DiagnosticCode::E0107,
                                format!("`matches` requires a string, found `{subj_ty}`"),
                            ));
                        }
                    }
                    PredicateKind::StartsWith | PredicateKind::EndsWith => {
                        if !subj_ty.is_string() && !subj_ty.is_error() && !subj_ty.is_open_struct()
                        {
                            self.diag.emit(Diagnostic::error(
                                subject.span,
                                DiagnosticCode::E0107,
                                format!(
                                    "`{}` requires a string, found `{subj_ty}`",
                                    match kind {
                                        PredicateKind::StartsWith => "starts_with",
                                        PredicateKind::EndsWith => "ends_with",
                                        _ => unreachable!(),
                                    }
                                ),
                            ));
                        }
                        if !arg_ty.is_string() && !arg_ty.is_error() {
                            self.diag.emit(Diagnostic::error(
                                argument.span,
                                DiagnosticCode::E0100,
                                format!("expected string argument, found `{arg_ty}`"),
                            ));
                        }
                    }
                }
                Ty::Primitive(PrimitiveType::Bool)
            }

            Expr::Quantifier {
                kind: _,
                collection,
                predicate,
            } => {
                let coll_ty = self.check_expr(&collection.node, collection.span, ctx);
                if !coll_ty.is_collection() && !coll_ty.is_error() {
                    // Allow open struct types (dynamic context access)
                    if !matches!(&coll_ty, Ty::Struct(s) if s.fields.is_empty()) {
                        self.diag.emit(Diagnostic::error(
                            collection.span,
                            DiagnosticCode::E0103,
                            format!("quantifier requires a collection, found `{coll_ty}`"),
                        ));
                    }
                }
                // Check the lambda body in a new scope with the parameter bound
                self.env.push_scope();
                let elem_ty = coll_ty
                    .element_type()
                    .cloned()
                    .unwrap_or_else(|| self.env.fresh_type_var());
                for param in &predicate.params {
                    self.env.bind(param.name.node.clone(), elem_ty.clone());
                }
                let body_ty = self.check_expr(&predicate.body.node, predicate.body.span, ctx);
                if !body_ty.is_bool() && !body_ty.is_error() {
                    self.diag.emit(Diagnostic::error(
                        predicate.body.span,
                        DiagnosticCode::E0101,
                        format!("quantifier predicate must return bool, found `{body_ty}`"),
                    ));
                }
                self.env.pop_scope();
                Ty::Primitive(PrimitiveType::Bool)
            }

            Expr::Count { collection, filter } => {
                let coll_ty = self.check_expr(&collection.node, collection.span, ctx);
                if let Some(ref lambda) = filter {
                    self.env.push_scope();
                    let elem_ty = coll_ty
                        .element_type()
                        .cloned()
                        .unwrap_or_else(|| self.env.fresh_type_var());
                    for param in &lambda.params {
                        self.env.bind(param.name.node.clone(), elem_ty.clone());
                    }
                    let body_ty = self.check_expr(&lambda.body.node, lambda.body.span, ctx);
                    if !body_ty.is_bool() && !body_ty.is_error() {
                        self.diag.emit(Diagnostic::error(
                            lambda.body.span,
                            DiagnosticCode::E0101,
                            format!("count filter must return bool, found `{body_ty}`"),
                        ));
                    }
                    self.env.pop_scope();
                }
                Ty::Primitive(PrimitiveType::Int)
            }

            Expr::Match { scrutinee, arms } => {
                let _scrut_ty = self.check_expr(&scrutinee.node, scrutinee.span, ctx);
                let mut result_ty: Option<Ty> = None;
                for arm in arms {
                    // Pattern checking deferred — future pass
                    let arm_ty = self.check_match_result(&arm.result.node, arm.result.span, ctx);
                    if let Some(ref prev) = result_ty {
                        if !arm_ty.is_subtype_of(prev) && !arm_ty.is_error() && !prev.is_error() {
                            // Different arm types — widen to union or verdict
                            if matches!(arm_ty, Ty::Verdict) || matches!(prev, Ty::Verdict) {
                                result_ty = Some(Ty::Verdict);
                            }
                        }
                    } else {
                        result_ty = Some(arm_ty);
                    }
                }
                result_ty.unwrap_or(Ty::Never)
            }

            Expr::Lambda(lambda) => {
                // Lambda types are inferred from context (quantifier, etc.)
                // Just check the body
                self.env.push_scope();
                for param in &lambda.params {
                    let ty = param
                        .ty
                        .as_ref()
                        .map(|t| self.resolve_type(&t.node))
                        .unwrap_or_else(|| self.env.fresh_type_var());
                    self.env.bind(param.name.node.clone(), ty);
                }
                let body_ty = self.check_expr(&lambda.body.node, lambda.body.span, ctx);
                self.env.pop_scope();
                body_ty
            }

            Expr::List(elements) => {
                if elements.is_empty() {
                    return Ty::List(Box::new(self.env.fresh_type_var()));
                }
                let first_ty = self.check_expr(&elements[0].node, elements[0].span, ctx);
                for elem in &elements[1..] {
                    let ty = self.check_expr(&elem.node, elem.span, ctx);
                    if !ty.is_subtype_of(&first_ty) && !ty.is_error() {
                        self.diag
                            .emit(Diagnostic::type_mismatch(elem.span, &first_ty, &ty));
                    }
                }
                Ty::List(Box::new(first_ty))
            }

            Expr::Object(_fields) => {
                // Object literals produce anonymous struct types
                Ty::Struct(crate::types::StructType {
                    name: SmolStr::new("Object"),
                    fields: vec![],
                    type_params: vec![],
                })
            }

            Expr::Block(stmts) => {
                self.env.push_scope();
                let mut last_ty = Ty::Never;
                for stmt in stmts {
                    last_ty = self.check_block_statement(&stmt.node, stmt.span, ctx);
                }
                self.env.pop_scope();
                last_ty
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Temporal expression checking — the formal verification core
    // ═══════════════════════════════════════════════════════════════════

    fn check_temporal(&mut self, temporal: &TemporalExpr, span: Span, ctx: CheckContext) -> Ty {
        if !ctx.in_proof {
            let op_name = match temporal {
                TemporalExpr::Always { .. } => "always",
                TemporalExpr::Eventually { .. } => "eventually",
                TemporalExpr::Never { .. } => "never",
                TemporalExpr::Until { .. } => "until",
                TemporalExpr::Next { .. } => "next",
                TemporalExpr::Before { .. } => "before",
                TemporalExpr::After { .. } => "after",
            };
            self.diag
                .emit(Diagnostic::temporal_outside_proof(span, op_name));
            return Ty::Error;
        }

        if ctx.temporal_depth > 0 {
            self.diag.emit(Diagnostic::error(
                span,
                DiagnosticCode::E0203,
                "nested temporal operators are not supported in v1; \
                 decompose into separate invariants",
            ));
            // Continue checking for better error messages
        }

        let inner_ctx = CheckContext {
            temporal_depth: ctx.temporal_depth + 1,
            ..ctx
        };

        match temporal {
            TemporalExpr::Always { condition, within }
            | TemporalExpr::Eventually { condition, within } => {
                let cond_ty = self.check_expr(&condition.node, condition.span, inner_ctx);
                if !cond_ty.is_bool() && !cond_ty.is_error() {
                    let op = if matches!(temporal, TemporalExpr::Always { .. }) {
                        "always"
                    } else {
                        "eventually"
                    };
                    self.diag
                        .emit(Diagnostic::temporal_requires_bool(condition.span, op));
                }
                if let Some(ref dur) = within {
                    let dur_ty = self.check_expr(&dur.node, dur.span, ctx);
                    if !dur_ty.is_duration() && !dur_ty.is_error() {
                        self.diag
                            .emit(Diagnostic::within_requires_duration(dur.span));
                    }
                }
                Ty::Temporal
            }

            TemporalExpr::Never { condition } => {
                let cond_ty = self.check_expr(&condition.node, condition.span, inner_ctx);
                if !cond_ty.is_bool() && !cond_ty.is_error() {
                    self.diag
                        .emit(Diagnostic::temporal_requires_bool(condition.span, "never"));
                }
                Ty::Temporal
            }

            TemporalExpr::Until { hold, release } => {
                let hold_ty = self.check_expr(&hold.node, hold.span, inner_ctx);
                let release_ty = self.check_expr(&release.node, release.span, inner_ctx);
                if !hold_ty.is_bool() && !hold_ty.is_error() {
                    self.diag.emit(Diagnostic::temporal_requires_bool(
                        hold.span,
                        "until (left)",
                    ));
                }
                if !release_ty.is_bool() && !release_ty.is_error() {
                    self.diag.emit(Diagnostic::temporal_requires_bool(
                        release.span,
                        "until (right)",
                    ));
                }
                Ty::Temporal
            }

            TemporalExpr::Next { condition } => {
                let cond_ty = self.check_expr(&condition.node, condition.span, inner_ctx);
                if !cond_ty.is_bool() && !cond_ty.is_error() {
                    self.diag
                        .emit(Diagnostic::temporal_requires_bool(condition.span, "next"));
                }
                Ty::Temporal
            }

            TemporalExpr::Before { first, second } => {
                let first_ty = self.check_expr(&first.node, first.span, inner_ctx);
                let second_ty = self.check_expr(&second.node, second.span, inner_ctx);
                if !first_ty.is_bool() && !first_ty.is_error() {
                    self.diag
                        .emit(Diagnostic::temporal_requires_bool(first.span, "before"));
                }
                if !second_ty.is_bool() && !second_ty.is_error() {
                    self.diag
                        .emit(Diagnostic::temporal_requires_bool(second.span, "before"));
                }
                Ty::Temporal
            }

            TemporalExpr::After { condition, trigger } => {
                let cond_ty = self.check_expr(&condition.node, condition.span, inner_ctx);
                let trig_ty = self.check_expr(&trigger.node, trigger.span, inner_ctx);
                if !cond_ty.is_bool() && !cond_ty.is_error() {
                    self.diag
                        .emit(Diagnostic::temporal_requires_bool(condition.span, "after"));
                }
                if !trig_ty.is_bool() && !trig_ty.is_error() {
                    self.diag
                        .emit(Diagnostic::temporal_requires_bool(trigger.span, "after"));
                }
                Ty::Temporal
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Binary operator checking
    // ═══════════════════════════════════════════════════════════════════

    fn check_binary_op(&mut self, op: &BinaryOp, left: &Ty, right: &Ty, span: Span) -> Ty {
        if left.is_error() || right.is_error() {
            return Ty::Error;
        }

        match op {
            // Arithmetic: both numeric, result is wider type
            BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod => {
                // String concatenation via +
                if matches!(op, BinaryOp::Add) && left.is_string() && right.is_string() {
                    return Ty::Primitive(PrimitiveType::String);
                }
                if !left.is_numeric() || !right.is_numeric() {
                    self.diag.emit(Diagnostic::error(
                        span,
                        DiagnosticCode::E0106,
                        format!(
                            "arithmetic operator requires numeric operands, found `{left}` and `{right}`"
                        ),
                    ));
                    return Ty::Error;
                }
                // Float wins
                if matches!(left, Ty::Primitive(PrimitiveType::Float))
                    || matches!(right, Ty::Primitive(PrimitiveType::Float))
                {
                    Ty::Primitive(PrimitiveType::Float)
                } else {
                    Ty::Primitive(PrimitiveType::Int)
                }
            }

            // Comparison: both numeric or both string, result is bool
            BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
                if (left.is_numeric() && right.is_numeric())
                    || (left.is_string() && right.is_string())
                    || (left.is_duration() && right.is_duration())
                {
                    Ty::Primitive(PrimitiveType::Bool)
                } else {
                    self.diag.emit(Diagnostic::error(
                        span,
                        DiagnosticCode::E0106,
                        format!(
                            "comparison requires compatible types, found `{left}` and `{right}`"
                        ),
                    ));
                    Ty::Error
                }
            }

            // Equality: any two compatible types, result is bool
            BinaryOp::Eq | BinaryOp::Neq => Ty::Primitive(PrimitiveType::Bool),

            // Logical: both bool, result is bool
            BinaryOp::And | BinaryOp::Or | BinaryOp::Implies => {
                if !left.is_bool() || !right.is_bool() {
                    self.diag.emit(Diagnostic::error(
                        span,
                        DiagnosticCode::E0106,
                        format!(
                            "logical operator requires boolean operands, found `{left}` and `{right}`"
                        ),
                    ));
                    return Ty::Error;
                }
                Ty::Primitive(PrimitiveType::Bool)
            }

            // Membership: element in collection
            BinaryOp::In => Ty::Primitive(PrimitiveType::Bool),
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Helpers
    // ═══════════════════════════════════════════════════════════════════

    fn check_literal(&self, lit: &Literal) -> Ty {
        match lit {
            Literal::Bool(_) => Ty::Primitive(PrimitiveType::Bool),
            Literal::Int(_) => Ty::Primitive(PrimitiveType::Int),
            Literal::Float(_) => Ty::Primitive(PrimitiveType::Float),
            Literal::String(_) => Ty::Primitive(PrimitiveType::String),
            Literal::Duration(_) => Ty::Primitive(PrimitiveType::Duration),
            Literal::Regex(_) => Ty::Primitive(PrimitiveType::String), // Regex is string-like
        }
    }

    fn check_match_result(&mut self, result: &MatchResult, span: Span, ctx: CheckContext) -> Ty {
        match result {
            MatchResult::Expr(expr) => self.check_expr(expr, span, ctx),
            MatchResult::Verdict(_) => Ty::Verdict,
            MatchResult::Block(stmts) => {
                self.env.push_scope();
                let mut last_ty = Ty::Never;
                for stmt in stmts {
                    last_ty = self.check_block_statement(&stmt.node, stmt.span, ctx);
                }
                self.env.pop_scope();
                last_ty
            }
        }
    }

    fn check_block_statement(
        &mut self,
        stmt: &BlockStatement,
        span: Span,
        ctx: CheckContext,
    ) -> Ty {
        match stmt {
            BlockStatement::Binding(b) => {
                self.check_binding(b, span, ctx);
                Ty::Never // bindings don't produce values
            }
            BlockStatement::Expr(e) => self.check_expr(e, span, ctx),
            BlockStatement::Verdict(_) => Ty::Verdict,
            BlockStatement::Action(ac) => {
                self.check_action_args(&ac.args, span, ctx);
                Ty::Never
            }
        }
    }

    /// Resolve an AST type to a semantic type.
    fn resolve_type(&mut self, ty: &crate::ast::nodes::Type) -> Ty {
        match ty {
            crate::ast::nodes::Type::Primitive(p) => Ty::Primitive(*p),
            crate::ast::nodes::Type::List(inner) => {
                Ty::List(Box::new(self.resolve_type(&inner.node)))
            }
            crate::ast::nodes::Type::Map(k, v) => Ty::Map(
                Box::new(self.resolve_type(&k.node)),
                Box::new(self.resolve_type(&v.node)),
            ),
            crate::ast::nodes::Type::Set(inner) => {
                Ty::Set(Box::new(self.resolve_type(&inner.node)))
            }
            crate::ast::nodes::Type::Named { name, type_args: _ } => {
                let type_name = name.to_string();
                if let Some(ty) = self.env.lookup_type(&type_name).cloned() {
                    ty
                } else {
                    // Try just the last segment
                    let simple = name.last().node.as_str();
                    if let Some(ty) = self.env.lookup_type(simple).cloned() {
                        ty
                    } else {
                        self.diag
                            .emit(Diagnostic::undefined_type(name.span, &type_name));
                        Ty::Error
                    }
                }
            }
            crate::ast::nodes::Type::Union(members) => {
                let resolved: Vec<Ty> =
                    members.iter().map(|m| self.resolve_type(&m.node)).collect();
                Ty::Union(resolved)
            }
        }
    }
}
