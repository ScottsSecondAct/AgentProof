//! ANTLR4 parse tree → Aegis AST visitor.
//!
//! Transforms the concrete syntax tree produced by the ANTLR4-generated
//! parser into the typed AST defined in [`crate::ast`]. Every grammar rule
//! in `AegisParser.g4` has a corresponding `visit_*` method here.
//!
//! # Architecture
//!
//! The ANTLR4 tool generates a Rust module with context types for each
//! parser rule (e.g., `ProgramContext`, `ExpressionContext`). This visitor
//! walks those contexts and builds our AST nodes, capturing source spans
//! from token positions for error reporting.
//!
//! The generated parser is expected in `crate::generated::aegisparser`.
//! Run the ANTLR4 tool to produce it:
//! ```sh
//! java -jar antlr4.jar -Dlanguage=Rust -visitor AegisLexer.g4 AegisParser.g4
//! ```

use smol_str::SmolStr;

use crate::ast::*;

// ═══════════════════════════════════════════════════════════════════════
//  Token helpers — extract text and spans from ANTLR4 tokens
// ═══════════════════════════════════════════════════════════════════════

/// Trait abstracting over ANTLR4 token access so the visitor logic is
/// testable without the generated parser. The real implementation
/// delegates to `antlr4rust::Token`.
pub trait TokenAccess {
    fn text(&self) -> &str;
    fn start_byte(&self) -> u32;
    fn stop_byte(&self) -> u32;
}

/// Trait abstracting over ANTLR4 rule context access.
pub trait RuleContext {
    fn start_token(&self) -> Option<&dyn TokenAccess>;
    fn stop_token(&self) -> Option<&dyn TokenAccess>;
}

fn span_from(ctx: &dyn RuleContext) -> Span {
    let start = ctx.start_token().map(|t| t.start_byte()).unwrap_or(0);
    let end = ctx.stop_token().map(|t| t.stop_byte() + 1).unwrap_or(start);
    Span::new(start, end)
}

fn ident_from(token: &dyn TokenAccess) -> Ident {
    Spanned::new(
        SmolStr::new(token.text()),
        Span::new(token.start_byte(), token.stop_byte() + 1),
    )
}

// ═══════════════════════════════════════════════════════════════════════
//  AstBuilder — the visitor implementation
//
//  Each visit_* method corresponds to a parser rule. They are called
//  by the ANTLR4 runtime's tree walker. We implement them as plain
//  methods taking trait-object references so the core logic compiles
//  without the generated parser present.
//
//  When integrating with the actual generated parser, a thin adapter
//  implements `AegisParserVisitor` and delegates to these methods.
// ═══════════════════════════════════════════════════════════════════════

/// Builds an Aegis AST from parse tree contexts.
///
/// Usage (with generated parser):
/// ```ignore
/// let input = InputStream::new(source);
/// let lexer = AegisLexer::new(input);
/// let tokens = CommonTokenStream::new(lexer);
/// let mut parser = AegisParser::new(tokens);
/// let tree = parser.program().unwrap();
///
/// let mut builder = AstBuilder::new(source);
/// let program = builder.visit_program(&tree);
/// ```
pub struct AstBuilder<'src> {
    /// The original source text, used for extracting string literal content.
    source: &'src str,
}

impl<'src> AstBuilder<'src> {
    pub fn new(source: &'src str) -> Self {
        Self { source }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Program
    // ═══════════════════════════════════════════════════════════════════

    /// Visit the top-level `program` rule: `declaration* EOF`
    pub fn build_program(&self, declarations: Vec<DeclContext<'_>>, span: Span) -> Program {
        let decls = declarations
            .into_iter()
            .filter_map(|d| self.build_declaration(d))
            .collect();

        Program {
            declarations: decls,
            span,
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Declarations
    // ═══════════════════════════════════════════════════════════════════

    /// Discriminated union over the declaration alternatives.
    /// The ANTLR4 adapter constructs this from the parse tree.
    pub fn build_declaration(&self, ctx: DeclContext<'_>) -> Option<Spanned<Declaration>> {
        let span = ctx.span;
        let decl = match ctx.kind {
            DeclKind::Import(i) => Declaration::Import(self.build_import(i)),
            DeclKind::Policy(p) => Declaration::Policy(self.build_policy(p)),
            DeclKind::Proof(p) => Declaration::Proof(self.build_proof(p)),
            DeclKind::Type(t) => Declaration::Type(self.build_type_decl(t)),
            DeclKind::Binding(b) => Declaration::Binding(self.build_binding(b)),
            DeclKind::Function(f) => Declaration::Function(self.build_function(f)),
        };
        Some(Spanned::new(decl, span))
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Imports
    // ═══════════════════════════════════════════════════════════════════

    fn build_import(&self, ctx: ImportContext<'_>) -> ImportDecl {
        let path = self.build_qualified_name(&ctx.path);
        let kind = match ctx.kind {
            ImportStyle::Module { alias } => ImportKind::Module {
                alias: alias.map(|a| ident_from(a)),
            },
            ImportStyle::Names(targets) => {
                let tgts = targets
                    .into_iter()
                    .map(|t| ImportTarget {
                        name: ident_from(t.name),
                        alias: t.alias.map(|a| ident_from(a)),
                    })
                    .collect();
                ImportKind::Names(tgts)
            }
            ImportStyle::Glob => ImportKind::Glob,
        };
        ImportDecl { path, kind }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Policy
    // ═══════════════════════════════════════════════════════════════════

    fn build_policy(&self, ctx: PolicyContext<'_>) -> PolicyDecl {
        let annotations = ctx
            .annotations
            .iter()
            .map(|a| self.build_annotation(a))
            .collect();

        let name = ident_from(ctx.name);
        let extends = ctx.extends.map(|e| self.build_qualified_name(e));

        let members = ctx
            .members
            .into_iter()
            .map(|m| {
                let span = m.span;
                let member = self.build_policy_member(m);
                Spanned::new(member, span)
            })
            .collect();

        PolicyDecl {
            annotations,
            name,
            extends,
            members,
        }
    }

    fn build_policy_member(&self, ctx: PolicyMemberContext<'_>) -> PolicyMember {
        match ctx.kind {
            PolicyMemberKind::Severity(level) => PolicyMember::Severity(level),
            PolicyMemberKind::Scope(targets) => {
                let tgts = targets
                    .into_iter()
                    .map(|t| self.build_scope_target(t))
                    .collect();
                PolicyMember::Scope(tgts)
            }
            PolicyMemberKind::Rule(r) => PolicyMember::Rule(self.build_rule(r)),
            PolicyMemberKind::Proof(p) => PolicyMember::Proof(self.build_proof(p)),
            PolicyMemberKind::Constraint(c) => PolicyMember::Constraint(self.build_constraint(c)),
            PolicyMemberKind::Binding(b) => PolicyMember::Binding(self.build_binding(b)),
            PolicyMemberKind::Function(f) => PolicyMember::Function(self.build_function(f)),
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Rules
    // ═══════════════════════════════════════════════════════════════════

    fn build_rule(&self, ctx: RuleContext_<'_>) -> RuleDecl {
        let annotations = ctx
            .annotations
            .iter()
            .map(|a| self.build_annotation(a))
            .collect();

        let on_events = ctx
            .on_events
            .into_iter()
            .map(|t| self.build_scope_target(t))
            .collect();

        let clauses = ctx
            .clauses
            .into_iter()
            .map(|c| {
                let span = c.span;
                let clause = self.build_rule_clause(c);
                Spanned::new(clause, span)
            })
            .collect();

        RuleDecl {
            annotations,
            on_events,
            clauses,
        }
    }

    fn build_rule_clause(&self, ctx: RuleClauseContext<'_>) -> RuleClause {
        match ctx.kind {
            RuleClauseKind::When(expr) => {
                let e = self.build_expr(expr);
                RuleClause::When(e)
            }
            RuleClauseKind::Verdict(v) => RuleClause::Verdict(self.build_verdict(v)),
            RuleClauseKind::Action(a) => RuleClause::Action(self.build_action(a)),
            RuleClauseKind::Severity(level) => RuleClause::Severity(level),
            RuleClauseKind::Constraint(c) => RuleClause::Constraint(self.build_constraint(c)),
        }
    }

    fn build_verdict(&self, ctx: VerdictContext<'_>) -> VerdictClause {
        VerdictClause {
            verdict: Spanned::new(ctx.verdict, ctx.verdict_span),
            message: ctx.message.map(|m| self.build_expr(m)),
        }
    }

    fn build_action(&self, ctx: ActionContext<'_>) -> ActionClause {
        let args = match ctx.args {
            ActionArgsContext::None => ActionArgs::None,
            ActionArgsContext::Positional(expr) => ActionArgs::Positional(self.build_expr(expr)),
            ActionArgsContext::Named(pairs) => {
                let args = pairs
                    .into_iter()
                    .map(|(key, val)| (ident_from(key), self.build_expr(val)))
                    .collect();
                ActionArgs::Named(args)
            }
        };

        ActionClause {
            verb: Spanned::new(ctx.verb, ctx.verb_span),
            args,
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Constraints
    // ═══════════════════════════════════════════════════════════════════

    fn build_constraint(&self, ctx: ConstraintContext<'_>) -> ConstraintDecl {
        ConstraintDecl {
            kind: ctx.kind,
            target: self.build_qualified_name(ctx.target),
            limit: self.build_expr(ctx.limit),
            window: self.build_expr(ctx.window),
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Proofs and invariants
    // ═══════════════════════════════════════════════════════════════════

    fn build_proof(&self, ctx: ProofContext<'_>) -> ProofDecl {
        let invariants = ctx
            .invariants
            .into_iter()
            .map(|inv| self.build_invariant(inv))
            .collect();

        ProofDecl {
            name: ident_from(ctx.name),
            invariants,
        }
    }

    fn build_invariant(&self, ctx: InvariantContext<'_>) -> InvariantDecl {
        let conditions = ctx
            .conditions
            .into_iter()
            .map(|e| self.build_expr(e))
            .collect();

        InvariantDecl {
            name: ident_from(ctx.name),
            conditions,
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Type declarations
    // ═══════════════════════════════════════════════════════════════════

    fn build_type_decl(&self, ctx: TypeDeclContext<'_>) -> TypeDecl {
        let generic_params = ctx
            .generic_params
            .into_iter()
            .map(|gp| GenericParam {
                name: ident_from(gp.name),
                bound: gp.bound.map(|b| self.build_type(b)),
            })
            .collect();

        let fields = ctx
            .fields
            .into_iter()
            .map(|f| TypedField {
                name: ident_from(f.name),
                ty: self.build_type(f.ty),
            })
            .collect();

        TypeDecl {
            name: ident_from(ctx.name),
            generic_params,
            fields,
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Types
    // ═══════════════════════════════════════════════════════════════════

    fn build_type(&self, ctx: TypeContext<'_>) -> Spanned<Type> {
        let span = ctx.span;
        let ty = match ctx.kind {
            TypeKind::Primitive(prim) => Type::Primitive(prim),
            TypeKind::List(inner) => Type::List(Box::new(self.build_type(*inner))),
            TypeKind::Map(key, val) => Type::Map(
                Box::new(self.build_type(*key)),
                Box::new(self.build_type(*val)),
            ),
            TypeKind::Set(inner) => Type::Set(Box::new(self.build_type(*inner))),
            TypeKind::Named { name, type_args } => Type::Named {
                name: self.build_qualified_name(name),
                type_args: type_args.into_iter().map(|t| self.build_type(t)).collect(),
            },
            TypeKind::Union(members) => {
                Type::Union(members.into_iter().map(|m| self.build_type(m)).collect())
            }
            TypeKind::Paren(inner) => return self.build_type(*inner),
        };
        Spanned::new(ty, span)
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Bindings and functions
    // ═══════════════════════════════════════════════════════════════════

    fn build_binding(&self, ctx: BindingContext<'_>) -> BindingDecl {
        BindingDecl {
            name: ident_from(ctx.name),
            ty: ctx.ty.map(|t| self.build_type(t)),
            value: self.build_expr(ctx.value),
        }
    }

    fn build_function(&self, ctx: FunctionContext<'_>) -> FunctionDecl {
        let params = ctx
            .params
            .into_iter()
            .map(|p| TypedParam {
                name: ident_from(p.name),
                ty: self.build_type(p.ty),
            })
            .collect();

        FunctionDecl {
            name: ident_from(ctx.name),
            params,
            return_type: self.build_type(ctx.return_type),
            body: self.build_expr(ctx.body),
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Expressions — the heart of the visitor
    // ═══════════════════════════════════════════════════════════════════

    pub fn build_expr(&self, ctx: ExprContext<'_>) -> Spanned<Expr> {
        let span = ctx.span;
        let expr = match ctx.kind {
            ExprKind::Literal(lit) => Expr::Literal(self.build_literal(lit)),

            ExprKind::Identifier(name) => Expr::Identifier(self.build_qualified_name(name)),

            ExprKind::Context(name) => Expr::Context(self.build_qualified_name(name)),

            ExprKind::FieldAccess { object, field } => Expr::FieldAccess {
                object: Box::new(self.build_expr(*object)),
                field: ident_from(field),
            },

            ExprKind::IndexAccess { object, index } => Expr::IndexAccess {
                object: Box::new(self.build_expr(*object)),
                index: Box::new(self.build_expr(*index)),
            },

            ExprKind::Call { callee, args } => Expr::Call {
                callee: Box::new(self.build_expr(*callee)),
                args: args.into_iter().map(|a| self.build_argument(a)).collect(),
            },

            ExprKind::MethodCall {
                object,
                method,
                args,
            } => Expr::MethodCall {
                object: Box::new(self.build_expr(*object)),
                method: ident_from(method),
                args: args.into_iter().map(|a| self.build_argument(a)).collect(),
            },

            ExprKind::Binary {
                op,
                op_span,
                left,
                right,
            } => Expr::Binary {
                op: Spanned::new(op, op_span),
                left: Box::new(self.build_expr(*left)),
                right: Box::new(self.build_expr(*right)),
            },

            ExprKind::Unary {
                op,
                op_span,
                operand,
            } => Expr::Unary {
                op: Spanned::new(op, op_span),
                operand: Box::new(self.build_expr(*operand)),
            },

            ExprKind::Temporal(temporal) => Expr::Temporal(self.build_temporal(*temporal)),

            ExprKind::Predicate {
                kind,
                subject,
                argument,
            } => Expr::Predicate {
                kind,
                subject: Box::new(self.build_expr(*subject)),
                argument: Box::new(self.build_expr(*argument)),
            },

            ExprKind::Quantifier {
                kind,
                collection,
                predicate,
            } => Expr::Quantifier {
                kind,
                collection: Box::new(self.build_expr(*collection)),
                predicate: Box::new(self.build_lambda(*predicate)),
            },

            ExprKind::Count { collection, filter } => Expr::Count {
                collection: Box::new(self.build_expr(*collection)),
                filter: filter.map(|f| Box::new(self.build_lambda(*f))),
            },

            ExprKind::Match { scrutinee, arms } => Expr::Match {
                scrutinee: Box::new(self.build_expr(*scrutinee)),
                arms: arms.into_iter().map(|a| self.build_match_arm(a)).collect(),
            },

            ExprKind::Lambda(lambda) => Expr::Lambda(self.build_lambda(*lambda)),

            ExprKind::List(elements) => {
                Expr::List(elements.into_iter().map(|e| self.build_expr(e)).collect())
            }

            ExprKind::Object(fields) => Expr::Object(
                fields
                    .into_iter()
                    .map(|f| ObjectField {
                        key: Spanned::new(
                            SmolStr::new(f.key.text()),
                            Span::new(f.key.start_byte(), f.key.stop_byte() + 1),
                        ),
                        value: self.build_expr(f.value),
                    })
                    .collect(),
            ),

            ExprKind::Block(stmts) => Expr::Block(
                stmts
                    .into_iter()
                    .map(|s| {
                        let sp = s.span;
                        let stmt = self.build_block_statement(s);
                        Spanned::new(stmt, sp)
                    })
                    .collect(),
            ),

            ExprKind::Paren(inner) => return self.build_expr(*inner),
        };
        Spanned::new(expr, span)
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Temporal expressions
    // ═══════════════════════════════════════════════════════════════════

    fn build_temporal(&self, ctx: TemporalContext<'_>) -> TemporalExpr {
        match ctx {
            TemporalContext::Always { condition, within } => TemporalExpr::Always {
                condition: Box::new(self.build_expr(*condition)),
                within: within.map(|w| Box::new(self.build_expr(*w))),
            },
            TemporalContext::Eventually { condition, within } => TemporalExpr::Eventually {
                condition: Box::new(self.build_expr(*condition)),
                within: within.map(|w| Box::new(self.build_expr(*w))),
            },
            TemporalContext::Never { condition } => TemporalExpr::Never {
                condition: Box::new(self.build_expr(*condition)),
            },
            TemporalContext::Until { hold, release } => TemporalExpr::Until {
                hold: Box::new(self.build_expr(*hold)),
                release: Box::new(self.build_expr(*release)),
            },
            TemporalContext::Next { condition } => TemporalExpr::Next {
                condition: Box::new(self.build_expr(*condition)),
            },
            TemporalContext::Before { first, second } => TemporalExpr::Before {
                first: Box::new(self.build_expr(*first)),
                second: Box::new(self.build_expr(*second)),
            },
            TemporalContext::After { condition, trigger } => TemporalExpr::After {
                condition: Box::new(self.build_expr(*condition)),
                trigger: Box::new(self.build_expr(*trigger)),
            },
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Pattern matching
    // ═══════════════════════════════════════════════════════════════════

    fn build_match_arm(&self, ctx: MatchArmContext<'_>) -> MatchArm {
        let pattern = self.build_pattern(ctx.pattern);
        let result = self.build_match_result(ctx.result);
        MatchArm {
            pattern,
            result,
            span: ctx.span,
        }
    }

    fn build_match_result(&self, ctx: MatchResultContext<'_>) -> Spanned<MatchResult> {
        let span = ctx.span;
        let result = match ctx.kind {
            MatchResultKind::Expr(e) => {
                let built = self.build_expr(e);
                MatchResult::Expr(built.node)
            }
            MatchResultKind::Verdict(v) => MatchResult::Verdict(self.build_verdict(v)),
            MatchResultKind::Block(stmts) => {
                let built = stmts
                    .into_iter()
                    .map(|s| {
                        let sp = s.span;
                        Spanned::new(self.build_block_statement(s), sp)
                    })
                    .collect();
                MatchResult::Block(built)
            }
        };
        Spanned::new(result, span)
    }

    fn build_pattern(&self, ctx: PatternContext<'_>) -> Spanned<Pattern> {
        let span = ctx.span;
        let pattern = match ctx.kind {
            PatternKind::Wildcard => Pattern::Wildcard,
            PatternKind::Literal(lit) => Pattern::Literal(self.build_literal(lit)),
            PatternKind::Binding(token) => Pattern::Binding(ident_from(token)),
            PatternKind::Destructure { name, fields } => Pattern::Destructure {
                name: self.build_qualified_name(name),
                fields: fields
                    .into_iter()
                    .map(|f| self.build_pattern_field(f))
                    .collect(),
            },
            PatternKind::List(elements) => Pattern::List(
                elements
                    .into_iter()
                    .map(|e| self.build_pattern(e))
                    .collect(),
            ),
            PatternKind::Guard { pattern, condition } => Pattern::Guard {
                pattern: Box::new(self.build_pattern(*pattern)),
                condition: Box::new(self.build_expr(*condition)),
            },
            PatternKind::Or(alternatives) => Pattern::Or(
                alternatives
                    .into_iter()
                    .map(|a| self.build_pattern(a))
                    .collect(),
            ),
            PatternKind::Paren(inner) => return self.build_pattern(*inner),
        };
        Spanned::new(pattern, span)
    }

    fn build_pattern_field(&self, ctx: PatternFieldContext<'_>) -> PatternField {
        match ctx {
            PatternFieldContext::Named { key, pattern } => PatternField::Named {
                key: ident_from(key),
                pattern: self.build_pattern(pattern),
            },
            PatternFieldContext::Shorthand(token) => PatternField::Shorthand(ident_from(token)),
            PatternFieldContext::Wildcard(span) => PatternField::Wildcard(span),
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Lambdas
    // ═══════════════════════════════════════════════════════════════════

    fn build_lambda(&self, ctx: LambdaContext<'_>) -> Lambda {
        let params = ctx
            .params
            .into_iter()
            .map(|p| LambdaParam {
                name: ident_from(p.name),
                ty: p.ty.map(|t| self.build_type(t)),
            })
            .collect();

        Lambda {
            params,
            body: Box::new(self.build_expr(ctx.body)),
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Block statements
    // ═══════════════════════════════════════════════════════════════════

    fn build_block_statement(&self, ctx: BlockStmtContext<'_>) -> BlockStatement {
        match ctx.kind {
            BlockStmtKind::Binding(b) => BlockStatement::Binding(self.build_binding(b)),
            BlockStmtKind::Expr(e) => {
                let built = self.build_expr(e);
                BlockStatement::Expr(built.node)
            }
            BlockStmtKind::Verdict(v) => BlockStatement::Verdict(self.build_verdict(v)),
            BlockStmtKind::Action(a) => BlockStatement::Action(self.build_action(a)),
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Annotations
    // ═══════════════════════════════════════════════════════════════════

    fn build_annotation(&self, ctx: &AnnotationContext<'_>) -> Annotation {
        let args = ctx
            .args
            .iter()
            .map(|a| match a {
                AnnotationArgContext::Positional(val) => {
                    AnnotationArg::Positional(self.build_annotation_value(val))
                }
                AnnotationArgContext::Named { key, value } => AnnotationArg::Named {
                    key: ident_from(*key),
                    value: self.build_annotation_value(value),
                },
            })
            .collect();

        Annotation {
            name: ident_from(ctx.name),
            args,
            span: ctx.span,
        }
    }

    fn build_annotation_value(&self, ctx: &AnnotationValueContext<'_>) -> AnnotationValue {
        match ctx {
            AnnotationValueContext::Literal(lit) => {
                AnnotationValue::Literal(self.build_literal(lit.clone()))
            }
            AnnotationValueContext::List(items) => AnnotationValue::List(
                items
                    .iter()
                    .map(|i| self.build_annotation_value(i))
                    .collect(),
            ),
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Arguments and names
    // ═══════════════════════════════════════════════════════════════════

    fn build_argument(&self, ctx: ArgumentContext<'_>) -> Argument {
        Argument {
            name: ctx.name.map(|n| ident_from(n)),
            value: self.build_expr(ctx.value),
        }
    }

    fn build_qualified_name(&self, ctx: &QualifiedNameContext<'_>) -> QualifiedName {
        let segments: Vec<Ident> = ctx.segments.iter().map(|s| ident_from(*s)).collect();
        let span = if segments.is_empty() {
            Span::DUMMY
        } else {
            segments[0].span.merge(segments.last().unwrap().span)
        };
        QualifiedName { segments, span }
    }

    fn build_scope_target(&self, ctx: ScopeTargetContext<'_>) -> ScopeTarget {
        match ctx {
            ScopeTargetContext::Name(name) => ScopeTarget::Name(self.build_qualified_name(name)),
            ScopeTargetContext::Literal(token) => ScopeTarget::Literal(Spanned::new(
                SmolStr::new(self.unquote_string(token.text())),
                Span::new(token.start_byte(), token.stop_byte() + 1),
            )),
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Literals
    // ═══════════════════════════════════════════════════════════════════

    fn build_literal(&self, ctx: LiteralContext<'_>) -> Literal {
        match ctx {
            LiteralContext::Bool(val) => Literal::Bool(val),
            LiteralContext::Int(text) => {
                let cleaned = text.trim_end_matches(|c| c == 'l' || c == 'L');
                Literal::Int(cleaned.parse().unwrap_or(0))
            }
            LiteralContext::Float(text) => {
                let cleaned = text.trim_end_matches(|c| "fFdD".contains(c));
                Literal::Float(cleaned.parse().unwrap_or(0.0))
            }
            LiteralContext::String(text) => {
                Literal::String(SmolStr::new(self.unquote_string(text)))
            }
            LiteralContext::RawString(text) => {
                // r"..." → strip r" and trailing "
                let inner = &text[2..text.len() - 1];
                Literal::String(SmolStr::new(inner))
            }
            LiteralContext::Duration { value, unit } => {
                Literal::Duration(DurationLit { value, unit })
            }
            LiteralContext::Regex(text) => {
                // /pattern/flags → strip delimiters
                let inner = text
                    .trim_start_matches('/')
                    .rsplit_once('/')
                    .map(|(pat, _flags)| pat)
                    .unwrap_or(text);
                Literal::Regex(SmolStr::new(inner))
            }
        }
    }

    /// Strip surrounding quotes and process escape sequences.
    fn unquote_string(&self, s: &str) -> String {
        if s.len() < 2 {
            return s.to_string();
        }
        let inner = &s[1..s.len() - 1];
        let mut result = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some('n') => result.push('\n'),
                    Some('t') => result.push('\t'),
                    Some('r') => result.push('\r'),
                    Some('\\') => result.push('\\'),
                    Some('"') => result.push('"'),
                    Some('\'') => result.push('\''),
                    Some(other) => {
                        result.push('\\');
                        result.push(other);
                    }
                    None => result.push('\\'),
                }
            } else {
                result.push(c);
            }
        }
        result
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Intermediate context types
//
//  These are the "bridge" types between ANTLR4's generated contexts
//  and the AstBuilder. The ANTLR4 adapter (a thin glue layer) converts
//  the generated `*Context` types into these, then AstBuilder converts
//  them into AST nodes.
//
//  This separation means the core visitor logic is testable and
//  compilable without the generated parser present.
// ═══════════════════════════════════════════════════════════════════════

pub struct DeclContext<'a> {
    pub kind: DeclKind<'a>,
    pub span: Span,
}

pub enum DeclKind<'a> {
    Import(ImportContext<'a>),
    Policy(PolicyContext<'a>),
    Proof(ProofContext<'a>),
    Type(TypeDeclContext<'a>),
    Binding(BindingContext<'a>),
    Function(FunctionContext<'a>),
}

pub struct ImportContext<'a> {
    pub path: &'a QualifiedNameContext<'a>,
    pub kind: ImportStyle<'a>,
}

pub enum ImportStyle<'a> {
    Module { alias: Option<&'a dyn TokenAccess> },
    Names(Vec<ImportTargetContext<'a>>),
    Glob,
}

pub struct ImportTargetContext<'a> {
    pub name: &'a dyn TokenAccess,
    pub alias: Option<&'a dyn TokenAccess>,
}

pub struct PolicyContext<'a> {
    pub annotations: Vec<AnnotationContext<'a>>,
    pub name: &'a dyn TokenAccess,
    pub extends: Option<&'a QualifiedNameContext<'a>>,
    pub members: Vec<PolicyMemberContext<'a>>,
}

pub struct PolicyMemberContext<'a> {
    pub kind: PolicyMemberKind<'a>,
    pub span: Span,
}

pub enum PolicyMemberKind<'a> {
    Severity(SeverityLevel),
    Scope(Vec<ScopeTargetContext<'a>>),
    Rule(RuleContext_<'a>),
    Proof(ProofContext<'a>),
    Constraint(ConstraintContext<'a>),
    Binding(BindingContext<'a>),
    Function(FunctionContext<'a>),
}

// Named RuleContext_ to avoid conflict with the trait RuleContext
pub struct RuleContext_<'a> {
    pub annotations: Vec<AnnotationContext<'a>>,
    pub on_events: Vec<ScopeTargetContext<'a>>,
    pub clauses: Vec<RuleClauseContext<'a>>,
}

pub struct RuleClauseContext<'a> {
    pub kind: RuleClauseKind<'a>,
    pub span: Span,
}

pub enum RuleClauseKind<'a> {
    When(ExprContext<'a>),
    Verdict(VerdictContext<'a>),
    Action(ActionContext<'a>),
    Severity(SeverityLevel),
    Constraint(ConstraintContext<'a>),
}

pub struct VerdictContext<'a> {
    pub verdict: Verdict,
    pub verdict_span: Span,
    pub message: Option<ExprContext<'a>>,
}

pub struct ActionContext<'a> {
    pub verb: ActionVerb,
    pub verb_span: Span,
    pub args: ActionArgsContext<'a>,
}

pub enum ActionArgsContext<'a> {
    None,
    Positional(ExprContext<'a>),
    Named(Vec<(&'a dyn TokenAccess, ExprContext<'a>)>),
}

pub struct ConstraintContext<'a> {
    pub kind: ConstraintKind,
    pub target: &'a QualifiedNameContext<'a>,
    pub limit: ExprContext<'a>,
    pub window: ExprContext<'a>,
}

pub struct ProofContext<'a> {
    pub name: &'a dyn TokenAccess,
    pub invariants: Vec<InvariantContext<'a>>,
}

pub struct InvariantContext<'a> {
    pub name: &'a dyn TokenAccess,
    pub conditions: Vec<ExprContext<'a>>,
}

pub struct TypeDeclContext<'a> {
    pub name: &'a dyn TokenAccess,
    pub generic_params: Vec<GenericParamContext<'a>>,
    pub fields: Vec<TypedFieldContext<'a>>,
}

pub struct GenericParamContext<'a> {
    pub name: &'a dyn TokenAccess,
    pub bound: Option<TypeContext<'a>>,
}

pub struct TypedFieldContext<'a> {
    pub name: &'a dyn TokenAccess,
    pub ty: TypeContext<'a>,
}

pub struct TypeContext<'a> {
    pub kind: TypeKind<'a>,
    pub span: Span,
}

pub enum TypeKind<'a> {
    Primitive(PrimitiveType),
    List(Box<TypeContext<'a>>),
    Map(Box<TypeContext<'a>>, Box<TypeContext<'a>>),
    Set(Box<TypeContext<'a>>),
    Named {
        name: &'a QualifiedNameContext<'a>,
        type_args: Vec<TypeContext<'a>>,
    },
    Union(Vec<TypeContext<'a>>),
    Paren(Box<TypeContext<'a>>),
}

pub struct BindingContext<'a> {
    pub name: &'a dyn TokenAccess,
    pub ty: Option<TypeContext<'a>>,
    pub value: ExprContext<'a>,
}

pub struct FunctionContext<'a> {
    pub name: &'a dyn TokenAccess,
    pub params: Vec<TypedParamContext<'a>>,
    pub return_type: TypeContext<'a>,
    pub body: ExprContext<'a>,
}

pub struct TypedParamContext<'a> {
    pub name: &'a dyn TokenAccess,
    pub ty: TypeContext<'a>,
}

pub struct ExprContext<'a> {
    pub kind: ExprKind<'a>,
    pub span: Span,
}

pub enum ExprKind<'a> {
    Literal(LiteralContext<'a>),
    Identifier(&'a QualifiedNameContext<'a>),
    Context(&'a QualifiedNameContext<'a>),
    FieldAccess {
        object: Box<ExprContext<'a>>,
        field: &'a dyn TokenAccess,
    },
    IndexAccess {
        object: Box<ExprContext<'a>>,
        index: Box<ExprContext<'a>>,
    },
    Call {
        callee: Box<ExprContext<'a>>,
        args: Vec<ArgumentContext<'a>>,
    },
    MethodCall {
        object: Box<ExprContext<'a>>,
        method: &'a dyn TokenAccess,
        args: Vec<ArgumentContext<'a>>,
    },
    Binary {
        op: BinaryOp,
        op_span: Span,
        left: Box<ExprContext<'a>>,
        right: Box<ExprContext<'a>>,
    },
    Unary {
        op: UnaryOp,
        op_span: Span,
        operand: Box<ExprContext<'a>>,
    },
    Temporal(Box<TemporalContext<'a>>),
    Predicate {
        kind: PredicateKind,
        subject: Box<ExprContext<'a>>,
        argument: Box<ExprContext<'a>>,
    },
    Quantifier {
        kind: QuantifierKind,
        collection: Box<ExprContext<'a>>,
        predicate: Box<LambdaContext<'a>>,
    },
    Count {
        collection: Box<ExprContext<'a>>,
        filter: Option<Box<LambdaContext<'a>>>,
    },
    Match {
        scrutinee: Box<ExprContext<'a>>,
        arms: Vec<MatchArmContext<'a>>,
    },
    Lambda(Box<LambdaContext<'a>>),
    List(Vec<ExprContext<'a>>),
    Object(Vec<ObjectFieldContext<'a>>),
    Block(Vec<BlockStmtContext<'a>>),
    Paren(Box<ExprContext<'a>>),
}

pub enum TemporalContext<'a> {
    Always {
        condition: Box<ExprContext<'a>>,
        within: Option<Box<ExprContext<'a>>>,
    },
    Eventually {
        condition: Box<ExprContext<'a>>,
        within: Option<Box<ExprContext<'a>>>,
    },
    Never {
        condition: Box<ExprContext<'a>>,
    },
    Until {
        hold: Box<ExprContext<'a>>,
        release: Box<ExprContext<'a>>,
    },
    Next {
        condition: Box<ExprContext<'a>>,
    },
    Before {
        first: Box<ExprContext<'a>>,
        second: Box<ExprContext<'a>>,
    },
    After {
        condition: Box<ExprContext<'a>>,
        trigger: Box<ExprContext<'a>>,
    },
}

pub struct LambdaContext<'a> {
    pub params: Vec<LambdaParamContext<'a>>,
    pub body: ExprContext<'a>,
}

pub struct LambdaParamContext<'a> {
    pub name: &'a dyn TokenAccess,
    pub ty: Option<TypeContext<'a>>,
}

pub struct MatchArmContext<'a> {
    pub pattern: PatternContext<'a>,
    pub result: MatchResultContext<'a>,
    pub span: Span,
}

pub struct MatchResultContext<'a> {
    pub kind: MatchResultKind<'a>,
    pub span: Span,
}

pub enum MatchResultKind<'a> {
    Expr(ExprContext<'a>),
    Verdict(VerdictContext<'a>),
    Block(Vec<BlockStmtContext<'a>>),
}

pub struct PatternContext<'a> {
    pub kind: PatternKind<'a>,
    pub span: Span,
}

pub enum PatternKind<'a> {
    Wildcard,
    Literal(LiteralContext<'a>),
    Binding(&'a dyn TokenAccess),
    Destructure {
        name: &'a QualifiedNameContext<'a>,
        fields: Vec<PatternFieldContext<'a>>,
    },
    List(Vec<PatternContext<'a>>),
    Guard {
        pattern: Box<PatternContext<'a>>,
        condition: Box<ExprContext<'a>>,
    },
    Or(Vec<PatternContext<'a>>),
    Paren(Box<PatternContext<'a>>),
}

pub enum PatternFieldContext<'a> {
    Named {
        key: &'a dyn TokenAccess,
        pattern: PatternContext<'a>,
    },
    Shorthand(&'a dyn TokenAccess),
    Wildcard(Span),
}

pub struct ArgumentContext<'a> {
    pub name: Option<&'a dyn TokenAccess>,
    pub value: ExprContext<'a>,
}

pub struct ObjectFieldContext<'a> {
    pub key: &'a dyn TokenAccess,
    pub value: ExprContext<'a>,
}

pub struct BlockStmtContext<'a> {
    pub kind: BlockStmtKind<'a>,
    pub span: Span,
}

pub enum BlockStmtKind<'a> {
    Binding(BindingContext<'a>),
    Expr(ExprContext<'a>),
    Verdict(VerdictContext<'a>),
    Action(ActionContext<'a>),
}

pub struct AnnotationContext<'a> {
    pub name: &'a dyn TokenAccess,
    pub args: Vec<AnnotationArgContext<'a>>,
    pub span: Span,
}

pub enum AnnotationArgContext<'a> {
    Positional(AnnotationValueContext<'a>),
    Named {
        key: &'a dyn TokenAccess,
        value: AnnotationValueContext<'a>,
    },
}

#[derive(Clone)]
pub enum AnnotationValueContext<'a> {
    Literal(LiteralContext<'a>),
    List(Vec<AnnotationValueContext<'a>>),
}

#[derive(Clone)]
pub enum LiteralContext<'a> {
    Bool(bool),
    Int(&'a str),
    Float(&'a str),
    String(&'a str),
    RawString(&'a str),
    Duration { value: u64, unit: DurationUnit },
    Regex(&'a str),
}

pub struct QualifiedNameContext<'a> {
    pub segments: Vec<&'a dyn TokenAccess>,
}

pub enum ScopeTargetContext<'a> {
    Name(&'a QualifiedNameContext<'a>),
    Literal(&'a dyn TokenAccess),
}
