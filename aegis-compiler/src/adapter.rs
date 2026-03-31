//! ANTLR4 adapter — connects the generated parser to the visitor bridge types.
//!
//! This module is gated behind the `antlr4` feature flag. It is the ONLY
//! module that depends on the `antlr4rust` crate and the generated parser.
//!
//! # How to use
//!
//! 1. Generate the parser:
//!    ```sh
//!    java -jar antlr4.jar -Dlanguage=Rust -visitor -o src/generated \
//!        AegisLexer.g4 AegisParser.g4
//!    ```
//!
//! 2. Build with the feature:
//!    ```sh
//!    cargo build --features antlr4
//!    ```
//!
//! 3. Parse a source file:
//!    ```ignore
//!    use aegis_compiler::adapter::parse_source;
//!    let program = parse_source(source_text)?;
//!    ```
//!
//! # Architecture
//!
//! The adapter performs two conversions:
//!
//! 1. ANTLR4 token → `TokenAccess` trait (for span extraction)
//! 2. ANTLR4 `*Context` → visitor bridge types (`ExprContext`, etc.)
//!
//! The visitor's `AstBuilder` then converts bridge types → AST nodes.
//! This layering means the visitor and everything downstream compile
//! and test without any ANTLR4 dependency.

use crate::ast::*;
use crate::visitor::*;

// ═══════════════════════════════════════════════════════════════════════
//  Mock token implementation for standalone use (no ANTLR4)
//
//  When building without the antlr4 feature, this module provides a
//  lightweight token and lexer implementation so the full pipeline can
//  be exercised from in-memory representations.
// ═══════════════════════════════════════════════════════════════════════

/// A simple token for standalone (non-ANTLR4) use.
#[derive(Debug, Clone)]
pub struct SimpleToken {
    pub text: String,
    pub start: u32,
    pub stop: u32,
}

impl SimpleToken {
    pub fn new(text: impl Into<String>, start: u32, stop: u32) -> Self {
        Self {
            text: text.into(),
            start,
            stop,
        }
    }

    pub fn synthetic(text: impl Into<String>) -> Self {
        let t = text.into();
        let len = t.len() as u32;
        Self {
            text: t,
            start: 0,
            stop: if len > 0 { len - 1 } else { 0 },
        }
    }
}

impl TokenAccess for SimpleToken {
    fn text(&self) -> &str {
        &self.text
    }
    fn start_byte(&self) -> u32 {
        self.start
    }
    fn stop_byte(&self) -> u32 {
        self.stop
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Duration literal parser
// ═══════════════════════════════════════════════════════════════════════

/// Parse a duration literal like "5m", "100ms", "24h".
pub fn parse_duration_literal(text: &str) -> Option<(u64, DurationUnit)> {
    // Find where the numeric part ends
    let num_end = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());

    if num_end == 0 {
        return None;
    }

    let value: u64 = text[..num_end].parse().ok()?;
    let unit_str = &text[num_end..];

    let unit = match unit_str {
        "ms" => DurationUnit::Milliseconds,
        "s" => DurationUnit::Seconds,
        "m" => DurationUnit::Minutes,
        "h" => DurationUnit::Hours,
        "d" => DurationUnit::Days,
        _ => return None,
    };

    Some((value, unit))
}

// ═══════════════════════════════════════════════════════════════════════
//  Operator token mapping
// ═══════════════════════════════════════════════════════════════════════

/// Map operator token text to BinaryOp.
pub fn token_to_binary_op(text: &str) -> Option<BinaryOp> {
    match text {
        "+" => Some(BinaryOp::Add),
        "-" => Some(BinaryOp::Sub),
        "*" => Some(BinaryOp::Mul),
        "/" => Some(BinaryOp::Div),
        "%" => Some(BinaryOp::Mod),
        "==" => Some(BinaryOp::Eq),
        "!=" => Some(BinaryOp::Neq),
        "<" => Some(BinaryOp::Lt),
        "<=" => Some(BinaryOp::Le),
        ">" => Some(BinaryOp::Gt),
        ">=" => Some(BinaryOp::Ge),
        "&&" | "and" => Some(BinaryOp::And),
        "||" | "or" => Some(BinaryOp::Or),
        "implies" => Some(BinaryOp::Implies),
        "in" => Some(BinaryOp::In),
        _ => None,
    }
}

/// Map verdict token text to Verdict.
pub fn token_to_verdict(text: &str) -> Option<Verdict> {
    match text {
        "allow" => Some(Verdict::Allow),
        "deny" => Some(Verdict::Deny),
        "audit" => Some(Verdict::Audit),
        "redact" => Some(Verdict::Redact),
        _ => None,
    }
}

/// Map action verb token text to ActionVerb.
pub fn token_to_action_verb(text: &str) -> Option<ActionVerb> {
    match text {
        "log" => Some(ActionVerb::Log),
        "notify" => Some(ActionVerb::Notify),
        "escalate" => Some(ActionVerb::Escalate),
        "block" => Some(ActionVerb::Block),
        "tag" => Some(ActionVerb::Tag),
        _ => None,
    }
}

/// Map severity token text to SeverityLevel.
pub fn token_to_severity(text: &str) -> Option<SeverityLevel> {
    match text {
        "critical" => Some(SeverityLevel::Critical),
        "high" => Some(SeverityLevel::High),
        "medium" => Some(SeverityLevel::Medium),
        "low" => Some(SeverityLevel::Low),
        "info" => Some(SeverityLevel::Info),
        _ => None,
    }
}

/// Map quantifier token text to QuantifierKind.
pub fn token_to_quantifier(text: &str) -> Option<QuantifierKind> {
    match text {
        "all" => Some(QuantifierKind::All),
        "any" => Some(QuantifierKind::Any),
        "none" => Some(QuantifierKind::None),
        "exists" => Some(QuantifierKind::Exists),
        _ => None,
    }
}

/// Map primitive type token text to PrimitiveType.
pub fn token_to_primitive_type(text: &str) -> Option<PrimitiveType> {
    match text {
        "int" => Some(PrimitiveType::Int),
        "float" => Some(PrimitiveType::Float),
        "bool" => Some(PrimitiveType::Bool),
        "string" => Some(PrimitiveType::String),
        "duration" => Some(PrimitiveType::Duration),
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Convenience: build a QualifiedNameContext from a dotted string
// ═══════════════════════════════════════════════════════════════════════

/// Helper to construct a QualifiedNameContext from owned tokens.
/// Useful for testing and for the ANTLR4 adapter.
pub struct OwnedQualifiedName {
    pub tokens: Vec<SimpleToken>,
}

impl OwnedQualifiedName {
    pub fn from_dotted(text: &str, start: u32) -> Self {
        let mut tokens = Vec::new();
        let mut offset = start;
        for segment in text.split('.') {
            let len = segment.len() as u32;
            tokens.push(SimpleToken::new(segment, offset, offset + len - 1));
            offset += len + 1; // +1 for the dot
        }
        Self { tokens }
    }

    pub fn to_context(&self) -> QualifiedNameContext<'_> {
        QualifiedNameContext {
            segments: self.tokens.iter().map(|t| t as &dyn TokenAccess).collect(),
        }
    }
}
