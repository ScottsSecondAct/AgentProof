use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

use super::span::{Span, Spanned};

// ═══════════════════════════════════════════════════════════════════════
//  Top-level program
// ═══════════════════════════════════════════════════════════════════════

pub type Ident = Spanned<SmolStr>;

/// A complete Aegis source file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Program {
    pub declarations: Vec<Spanned<Declaration>>,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Declaration {
    Import(ImportDecl),
    Policy(PolicyDecl),
    Proof(ProofDecl),
    Type(TypeDecl),
    Binding(BindingDecl),
    Function(FunctionDecl),
}

// ═══════════════════════════════════════════════════════════════════════
//  Imports
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportDecl {
    pub path: QualifiedName,
    pub kind: ImportKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImportKind {
    /// `import automaguard.stdlib.pii as pii`
    Module { alias: Option<Ident> },
    /// `from automaguard.stdlib import network, compliance`
    Names(Vec<ImportTarget>),
    /// `from automaguard.stdlib import *`
    Glob,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportTarget {
    pub name: Ident,
    pub alias: Option<Ident>,
}

// ═══════════════════════════════════════════════════════════════════════
//  Policy — the primary top-level construct
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecl {
    pub annotations: Vec<Annotation>,
    pub name: Ident,
    pub extends: Option<QualifiedName>,
    pub members: Vec<Spanned<PolicyMember>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyMember {
    Severity(SeverityLevel),
    Scope(Vec<ScopeTarget>),
    Rule(RuleDecl),
    Proof(ProofDecl),
    Constraint(ConstraintDecl),
    Binding(BindingDecl),
    Function(FunctionDecl),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SeverityLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScopeTarget {
    Name(QualifiedName),
    Literal(Spanned<SmolStr>),
}

// ═══════════════════════════════════════════════════════════════════════
//  Rules — event-triggered policy checks
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDecl {
    pub annotations: Vec<Annotation>,
    pub on_events: Vec<ScopeTarget>,
    pub clauses: Vec<Spanned<RuleClause>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleClause {
    When(Spanned<Expr>),
    Verdict(VerdictClause),
    Action(ActionClause),
    Severity(SeverityLevel),
    Constraint(ConstraintDecl),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictClause {
    pub verdict: Spanned<Verdict>,
    pub message: Option<Spanned<Expr>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Verdict {
    Allow,
    Deny,
    Audit,
    Redact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionClause {
    pub verb: Spanned<ActionVerb>,
    pub args: ActionArgs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionVerb {
    Log,
    Notify,
    Escalate,
    Block,
    Tag,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionArgs {
    None,
    Positional(Spanned<Expr>),
    Named(Vec<(Ident, Spanned<Expr>)>),
}

// ═══════════════════════════════════════════════════════════════════════
//  Runtime constraints
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintDecl {
    pub kind: ConstraintKind,
    pub target: QualifiedName,
    pub limit: Spanned<Expr>,
    pub window: Spanned<Expr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConstraintKind {
    RateLimit,
    Quota,
}

// ═══════════════════════════════════════════════════════════════════════
//  Proofs and invariants
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofDecl {
    pub name: Ident,
    pub invariants: Vec<InvariantDecl>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantDecl {
    pub name: Ident,
    pub conditions: Vec<Spanned<Expr>>,
}

// ═══════════════════════════════════════════════════════════════════════
//  Type declarations
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeDecl {
    pub name: Ident,
    pub generic_params: Vec<GenericParam>,
    pub fields: Vec<TypedField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericParam {
    pub name: Ident,
    pub bound: Option<Spanned<Type>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedField {
    pub name: Ident,
    pub ty: Spanned<Type>,
}

// ═══════════════════════════════════════════════════════════════════════
//  Types
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Type {
    /// `int`, `float`, `bool`, `string`, `duration`
    Primitive(PrimitiveType),
    /// `List<T>`
    List(Box<Spanned<Type>>),
    /// `Map<K, V>`
    Map(Box<Spanned<Type>>, Box<Spanned<Type>>),
    /// `Set<T>`
    Set(Box<Spanned<Type>>),
    /// User-defined: `Endpoint`, `DataClassification<T>`
    Named {
        name: QualifiedName,
        type_args: Vec<Spanned<Type>>,
    },
    /// `string | int` — union types for pattern matching
    Union(Vec<Spanned<Type>>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PrimitiveType {
    Int,
    Float,
    Bool,
    String,
    Duration,
}

// ═══════════════════════════════════════════════════════════════════════
//  Bindings and functions
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindingDecl {
    pub name: Ident,
    pub ty: Option<Spanned<Type>>,
    pub value: Spanned<Expr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDecl {
    pub name: Ident,
    pub params: Vec<TypedParam>,
    pub return_type: Spanned<Type>,
    pub body: Spanned<Expr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedParam {
    pub name: Ident,
    pub ty: Spanned<Type>,
}

// ═══════════════════════════════════════════════════════════════════════
//  Expressions
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Expr {
    // ── Literals ─────────────────────────────────────────────────────
    Literal(Literal),

    // ── Names and access ─────────────────────────────────────────────
    Identifier(QualifiedName),
    Context(QualifiedName), // context.tool_calls
    FieldAccess {
        object: Box<Spanned<Expr>>,
        field: Ident,
    },
    IndexAccess {
        object: Box<Spanned<Expr>>,
        index: Box<Spanned<Expr>>,
    },

    // ── Calls ────────────────────────────────────────────────────────
    Call {
        callee: Box<Spanned<Expr>>,
        args: Vec<Argument>,
    },
    MethodCall {
        object: Box<Spanned<Expr>>,
        method: Ident,
        args: Vec<Argument>,
    },

    // ── Binary operators ─────────────────────────────────────────────
    Binary {
        op: Spanned<BinaryOp>,
        left: Box<Spanned<Expr>>,
        right: Box<Spanned<Expr>>,
    },

    // ── Unary operators ──────────────────────────────────────────────
    Unary {
        op: Spanned<UnaryOp>,
        operand: Box<Spanned<Expr>>,
    },

    // ── Temporal operators (the moat) ────────────────────────────────
    Temporal(TemporalExpr),

    // ── Built-in predicates ──────────────────────────────────────────
    Predicate {
        kind: PredicateKind,
        subject: Box<Spanned<Expr>>,
        argument: Box<Spanned<Expr>>,
    },

    // ── Quantifiers ──────────────────────────────────────────────────
    Quantifier {
        kind: QuantifierKind,
        collection: Box<Spanned<Expr>>,
        predicate: Box<Lambda>,
    },

    // ── Count ────────────────────────────────────────────────────────
    Count {
        collection: Box<Spanned<Expr>>,
        filter: Option<Box<Lambda>>,
    },

    // ── Pattern matching ─────────────────────────────────────────────
    Match {
        scrutinee: Box<Spanned<Expr>>,
        arms: Vec<MatchArm>,
    },

    // ── Lambda ───────────────────────────────────────────────────────
    Lambda(Lambda),

    // ── Collections ──────────────────────────────────────────────────
    List(Vec<Spanned<Expr>>),
    Object(Vec<ObjectField>),

    // ── Block ────────────────────────────────────────────────────────
    Block(Vec<Spanned<BlockStatement>>),
}

// ── Temporal expressions ─────────────────────────────────────────────
//
// These are the formal verification primitives — they compile down to
// state machine transitions in the policy IR.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TemporalExpr {
    /// `always(φ)` — φ must hold in every reachable state (□φ in LTL)
    Always {
        condition: Box<Spanned<Expr>>,
        within: Option<Box<Spanned<Expr>>>,
    },
    /// `eventually(φ)` — φ must hold in some future state (◇φ in LTL)
    Eventually {
        condition: Box<Spanned<Expr>>,
        within: Option<Box<Spanned<Expr>>>,
    },
    /// `never(φ)` — φ must not hold in any reachable state (□¬φ)
    Never { condition: Box<Spanned<Expr>> },
    /// `φ until ψ` — φ must hold until ψ becomes true (φ U ψ)
    Until {
        hold: Box<Spanned<Expr>>,
        release: Box<Spanned<Expr>>,
    },
    /// `next(φ)` — φ must hold in the next state (Xφ)
    Next { condition: Box<Spanned<Expr>> },
    /// `before(φ, ψ)` — φ must become true before ψ
    Before {
        first: Box<Spanned<Expr>>,
        second: Box<Spanned<Expr>>,
    },
    /// `after(φ, ψ)` — φ must hold after ψ has occurred
    After {
        condition: Box<Spanned<Expr>>,
        trigger: Box<Spanned<Expr>>,
    },
}

// ── Operators ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BinaryOp {
    // Arithmetic
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    // Comparison
    Eq,
    Neq,
    Lt,
    Le,
    Gt,
    Ge,
    // Logical
    And,
    Or,
    Implies,
    // Membership
    In,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UnaryOp {
    Not,
    Neg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PredicateKind {
    Contains,
    Matches,
    StartsWith,
    EndsWith,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuantifierKind {
    All,
    Any,
    None,
    Exists,
}

// ── Supporting expression types ──────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Literal {
    Bool(bool),
    Int(i64),
    Float(f64),
    String(SmolStr),
    Duration(DurationLit),
    Regex(SmolStr),
}

/// A parsed duration: `5m`, `100ms`, `24h`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DurationLit {
    pub value: u64,
    pub unit: DurationUnit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DurationUnit {
    Milliseconds,
    Seconds,
    Minutes,
    Hours,
    Days,
}

impl DurationLit {
    /// Convert to milliseconds for uniform comparison.
    pub fn to_millis(self) -> u64 {
        match self.unit {
            DurationUnit::Milliseconds => self.value,
            DurationUnit::Seconds => self.value * 1_000,
            DurationUnit::Minutes => self.value * 60_000,
            DurationUnit::Hours => self.value * 3_600_000,
            DurationUnit::Days => self.value * 86_400_000,
        }
    }
}

#[cfg(test)]
mod duration_tests {
    use super::*;

    fn dur(value: u64, unit: DurationUnit) -> DurationLit {
        DurationLit { value, unit }
    }

    #[test]
    fn milliseconds_pass_through() {
        assert_eq!(dur(500, DurationUnit::Milliseconds).to_millis(), 500);
    }

    #[test]
    fn zero_millis() {
        assert_eq!(dur(0, DurationUnit::Milliseconds).to_millis(), 0);
    }

    #[test]
    fn seconds_to_millis() {
        assert_eq!(dur(5, DurationUnit::Seconds).to_millis(), 5_000);
    }

    #[test]
    fn minutes_to_millis() {
        assert_eq!(dur(2, DurationUnit::Minutes).to_millis(), 120_000);
    }

    #[test]
    fn hours_to_millis() {
        assert_eq!(dur(1, DurationUnit::Hours).to_millis(), 3_600_000);
    }

    #[test]
    fn days_to_millis() {
        assert_eq!(dur(1, DurationUnit::Days).to_millis(), 86_400_000);
    }

    #[test]
    fn multi_unit_values_scale_correctly() {
        assert_eq!(dur(3, DurationUnit::Hours).to_millis(), 10_800_000);
        assert_eq!(dur(30, DurationUnit::Seconds).to_millis(), 30_000);
    }
}

#[cfg(test)]
mod qualified_name_tests {
    use super::*;
    use crate::ast::span::{Span, Spanned};
    use smol_str::SmolStr;

    fn ident(s: &str) -> Spanned<SmolStr> {
        Spanned::dummy(SmolStr::new(s))
    }

    #[test]
    fn simple_creates_single_segment() {
        let name = QualifiedName::simple(ident("foo"));
        assert_eq!(name.segments.len(), 1);
        assert_eq!(name.segments[0].node.as_str(), "foo");
    }

    #[test]
    fn simple_span_matches_ident_span() {
        let id = Spanned::new(SmolStr::new("bar"), Span::new(4, 7));
        let name = QualifiedName::simple(id);
        assert_eq!(name.span, Span::new(4, 7));
    }

    #[test]
    fn last_returns_final_segment() {
        let name = QualifiedName {
            segments: vec![ident("a"), ident("b"), ident("c")],
            span: Span::DUMMY,
        };
        assert_eq!(name.last().node.as_str(), "c");
    }

    #[test]
    fn last_on_single_segment() {
        let name = QualifiedName::simple(ident("only"));
        assert_eq!(name.last().node.as_str(), "only");
    }

    #[test]
    fn to_string_single_segment() {
        let name = QualifiedName::simple(ident("policy"));
        assert_eq!(name.to_string(), "policy");
    }

    #[test]
    fn to_string_multiple_segments_joined_by_dot() {
        let name = QualifiedName {
            segments: vec![ident("automaguard"), ident("stdlib"), ident("pii")],
            span: Span::DUMMY,
        };
        assert_eq!(name.to_string(), "automaguard.stdlib.pii");
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argument {
    pub name: Option<Ident>,
    pub value: Spanned<Expr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lambda {
    pub params: Vec<LambdaParam>,
    pub body: Box<Spanned<Expr>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LambdaParam {
    pub name: Ident,
    pub ty: Option<Spanned<Type>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchArm {
    pub pattern: Spanned<Pattern>,
    pub result: Spanned<MatchResult>,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MatchResult {
    Expr(Expr),
    Verdict(VerdictClause),
    Block(Vec<Spanned<BlockStatement>>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockStatement {
    Binding(BindingDecl),
    Expr(Expr),
    Verdict(VerdictClause),
    Action(ActionClause),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectField {
    pub key: Spanned<SmolStr>,
    pub value: Spanned<Expr>,
}

// ═══════════════════════════════════════════════════════════════════════
//  Patterns
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Pattern {
    /// `_`
    Wildcard,
    /// `"tool_call"`, `42`, `true`
    Literal(Literal),
    /// `x` — binds the matched value
    Binding(Ident),
    /// `ToolCall { name: "http" }`
    Destructure {
        name: QualifiedName,
        fields: Vec<PatternField>,
    },
    /// `[first, second, _]`
    List(Vec<Spanned<Pattern>>),
    /// `x when x > 10`
    Guard {
        pattern: Box<Spanned<Pattern>>,
        condition: Box<Spanned<Expr>>,
    },
    /// `"a" | "b" | "c"`
    Or(Vec<Spanned<Pattern>>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatternField {
    Named {
        key: Ident,
        pattern: Spanned<Pattern>,
    },
    Shorthand(Ident),
    Wildcard(Span),
}

// ═══════════════════════════════════════════════════════════════════════
//  Annotations
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub name: Ident,
    pub args: Vec<AnnotationArg>,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnnotationArg {
    Positional(AnnotationValue),
    Named { key: Ident, value: AnnotationValue },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnnotationValue {
    Literal(Literal),
    List(Vec<AnnotationValue>),
}

// ═══════════════════════════════════════════════════════════════════════
//  Qualified names
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualifiedName {
    pub segments: Vec<Ident>,
    pub span: Span,
}

impl QualifiedName {
    pub fn simple(name: Ident) -> Self {
        let span = name.span;
        Self {
            segments: vec![name],
            span,
        }
    }

    pub fn last(&self) -> &Ident {
        self.segments.last().expect("QualifiedName cannot be empty")
    }
}

impl std::fmt::Display for QualifiedName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self
            .segments
            .iter()
            .map(|s| s.node.as_str())
            .collect::<Vec<_>>()
            .join(".");
        f.write_str(&s)
    }
}
