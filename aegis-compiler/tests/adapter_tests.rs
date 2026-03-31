//! Tests for the adapter module — token-to-enum mappings and duration parsing.
//!
//! These are the "parser-adjacent" tests described in CLAUDE.md. The ANTLR4
//! parser is not yet integrated, but the adapter functions it would call are
//! fully implemented and testable in isolation.

use aegis_compiler::adapter::{
    parse_duration_literal, token_to_action_verb, token_to_binary_op, token_to_primitive_type,
    token_to_quantifier, token_to_severity, token_to_verdict, OwnedQualifiedName, SimpleToken,
};
use aegis_compiler::ast::{
    ActionVerb, BinaryOp, DurationUnit, PrimitiveType, QuantifierKind, SeverityLevel, Verdict,
};
use aegis_compiler::visitor::TokenAccess;

// ── SimpleToken ──────────────────────────────────────────────────────────────

#[test]
fn simple_token_stores_text_and_span() {
    let tok = SimpleToken::new("hello", 3, 7);
    assert_eq!(tok.text(), "hello");
    assert_eq!(tok.start_byte(), 3);
    assert_eq!(tok.stop_byte(), 7);
}

#[test]
fn synthetic_token_span_covers_full_text() {
    let tok = SimpleToken::synthetic("allow");
    assert_eq!(tok.text(), "allow");
    assert_eq!(tok.start_byte(), 0);
    assert_eq!(tok.stop_byte(), 4); // len - 1
}

#[test]
fn synthetic_empty_token_has_zero_span() {
    let tok = SimpleToken::synthetic("");
    assert_eq!(tok.start_byte(), 0);
    assert_eq!(tok.stop_byte(), 0);
}

// ── parse_duration_literal ───────────────────────────────────────────────────

#[test]
fn parse_milliseconds() {
    let (v, u) = parse_duration_literal("100ms").unwrap();
    assert_eq!(v, 100);
    assert_eq!(u, DurationUnit::Milliseconds);
}

#[test]
fn parse_seconds() {
    let (v, u) = parse_duration_literal("30s").unwrap();
    assert_eq!(v, 30);
    assert_eq!(u, DurationUnit::Seconds);
}

#[test]
fn parse_minutes() {
    let (v, u) = parse_duration_literal("5m").unwrap();
    assert_eq!(v, 5);
    assert_eq!(u, DurationUnit::Minutes);
}

#[test]
fn parse_hours() {
    let (v, u) = parse_duration_literal("24h").unwrap();
    assert_eq!(v, 24);
    assert_eq!(u, DurationUnit::Hours);
}

#[test]
fn parse_days() {
    let (v, u) = parse_duration_literal("7d").unwrap();
    assert_eq!(v, 7);
    assert_eq!(u, DurationUnit::Days);
}

#[test]
fn parse_large_value() {
    let (v, u) = parse_duration_literal("86400s").unwrap();
    assert_eq!(v, 86400);
    assert_eq!(u, DurationUnit::Seconds);
}

#[test]
fn parse_single_digit() {
    let (v, u) = parse_duration_literal("1m").unwrap();
    assert_eq!(v, 1);
    assert_eq!(u, DurationUnit::Minutes);
}

#[test]
fn missing_unit_returns_none() {
    assert!(parse_duration_literal("100").is_none());
}

#[test]
fn unknown_unit_returns_none() {
    assert!(parse_duration_literal("5x").is_none());
    assert!(parse_duration_literal("10sec").is_none());
    assert!(parse_duration_literal("3min").is_none());
}

#[test]
fn empty_string_returns_none() {
    assert!(parse_duration_literal("").is_none());
}

#[test]
fn unit_only_no_digits_returns_none() {
    assert!(parse_duration_literal("m").is_none());
    assert!(parse_duration_literal("ms").is_none());
}

#[test]
fn leading_non_digit_returns_none() {
    assert!(parse_duration_literal("x5m").is_none());
}

// ── token_to_binary_op ───────────────────────────────────────────────────────

#[test]
fn arithmetic_operators_map_correctly() {
    assert_eq!(token_to_binary_op("+"), Some(BinaryOp::Add));
    assert_eq!(token_to_binary_op("-"), Some(BinaryOp::Sub));
    assert_eq!(token_to_binary_op("*"), Some(BinaryOp::Mul));
    assert_eq!(token_to_binary_op("/"), Some(BinaryOp::Div));
    assert_eq!(token_to_binary_op("%"), Some(BinaryOp::Mod));
}

#[test]
fn comparison_operators_map_correctly() {
    assert_eq!(token_to_binary_op("=="), Some(BinaryOp::Eq));
    assert_eq!(token_to_binary_op("!="), Some(BinaryOp::Neq));
    assert_eq!(token_to_binary_op("<"), Some(BinaryOp::Lt));
    assert_eq!(token_to_binary_op("<="), Some(BinaryOp::Le));
    assert_eq!(token_to_binary_op(">"), Some(BinaryOp::Gt));
    assert_eq!(token_to_binary_op(">="), Some(BinaryOp::Ge));
}

#[test]
fn logical_operators_map_correctly() {
    assert_eq!(token_to_binary_op("&&"), Some(BinaryOp::And));
    assert_eq!(token_to_binary_op("and"), Some(BinaryOp::And));
    assert_eq!(token_to_binary_op("||"), Some(BinaryOp::Or));
    assert_eq!(token_to_binary_op("or"), Some(BinaryOp::Or));
    assert_eq!(token_to_binary_op("implies"), Some(BinaryOp::Implies));
}

#[test]
fn membership_operator_maps_correctly() {
    assert_eq!(token_to_binary_op("in"), Some(BinaryOp::In));
}

#[test]
fn unknown_binary_op_returns_none() {
    assert!(token_to_binary_op("??").is_none());
    assert!(token_to_binary_op("not").is_none());
    assert!(token_to_binary_op("").is_none());
}

// ── token_to_verdict ─────────────────────────────────────────────────────────

#[test]
fn all_verdicts_map_correctly() {
    assert_eq!(token_to_verdict("allow"), Some(Verdict::Allow));
    assert_eq!(token_to_verdict("deny"), Some(Verdict::Deny));
    assert_eq!(token_to_verdict("audit"), Some(Verdict::Audit));
    assert_eq!(token_to_verdict("redact"), Some(Verdict::Redact));
}

#[test]
fn unknown_verdict_returns_none() {
    assert!(token_to_verdict("block").is_none());
    assert!(token_to_verdict("ALLOW").is_none()); // case sensitive
    assert!(token_to_verdict("").is_none());
}

// ── token_to_action_verb ─────────────────────────────────────────────────────

#[test]
fn all_action_verbs_map_correctly() {
    assert_eq!(token_to_action_verb("log"), Some(ActionVerb::Log));
    assert_eq!(token_to_action_verb("notify"), Some(ActionVerb::Notify));
    assert_eq!(token_to_action_verb("escalate"), Some(ActionVerb::Escalate));
    assert_eq!(token_to_action_verb("block"), Some(ActionVerb::Block));
    assert_eq!(token_to_action_verb("tag"), Some(ActionVerb::Tag));
}

#[test]
fn unknown_action_verb_returns_none() {
    assert!(token_to_action_verb("deny").is_none());
    assert!(token_to_action_verb("LOG").is_none());
    assert!(token_to_action_verb("").is_none());
}

// ── token_to_severity ────────────────────────────────────────────────────────

#[test]
fn all_severity_levels_map_correctly() {
    assert_eq!(token_to_severity("critical"), Some(SeverityLevel::Critical));
    assert_eq!(token_to_severity("high"), Some(SeverityLevel::High));
    assert_eq!(token_to_severity("medium"), Some(SeverityLevel::Medium));
    assert_eq!(token_to_severity("low"), Some(SeverityLevel::Low));
    assert_eq!(token_to_severity("info"), Some(SeverityLevel::Info));
}

#[test]
fn unknown_severity_returns_none() {
    assert!(token_to_severity("urgent").is_none());
    assert!(token_to_severity("HIGH").is_none());
    assert!(token_to_severity("").is_none());
}

// ── token_to_quantifier ──────────────────────────────────────────────────────

#[test]
fn all_quantifiers_map_correctly() {
    assert_eq!(token_to_quantifier("all"), Some(QuantifierKind::All));
    assert_eq!(token_to_quantifier("any"), Some(QuantifierKind::Any));
    assert_eq!(token_to_quantifier("none"), Some(QuantifierKind::None));
    assert_eq!(token_to_quantifier("exists"), Some(QuantifierKind::Exists));
}

#[test]
fn unknown_quantifier_returns_none() {
    assert!(token_to_quantifier("every").is_none());
    assert!(token_to_quantifier("ALL").is_none());
    assert!(token_to_quantifier("").is_none());
}

// ── token_to_primitive_type ──────────────────────────────────────────────────

#[test]
fn all_primitive_types_map_correctly() {
    assert_eq!(token_to_primitive_type("int"), Some(PrimitiveType::Int));
    assert_eq!(token_to_primitive_type("float"), Some(PrimitiveType::Float));
    assert_eq!(token_to_primitive_type("bool"), Some(PrimitiveType::Bool));
    assert_eq!(token_to_primitive_type("string"), Some(PrimitiveType::String));
    assert_eq!(token_to_primitive_type("duration"), Some(PrimitiveType::Duration));
}

#[test]
fn unknown_primitive_type_returns_none() {
    assert!(token_to_primitive_type("integer").is_none());
    assert!(token_to_primitive_type("Int").is_none());
    assert!(token_to_primitive_type("").is_none());
}

// ── OwnedQualifiedName ───────────────────────────────────────────────────────

#[test]
fn single_segment_qualified_name() {
    let qn = OwnedQualifiedName::from_dotted("policy", 0);
    assert_eq!(qn.tokens.len(), 1);
    assert_eq!(qn.tokens[0].text(), "policy");
}

#[test]
fn multi_segment_qualified_name_splits_on_dot() {
    let qn = OwnedQualifiedName::from_dotted("agentproof.stdlib.pii", 0);
    assert_eq!(qn.tokens.len(), 3);
    assert_eq!(qn.tokens[0].text(), "agentproof");
    assert_eq!(qn.tokens[1].text(), "stdlib");
    assert_eq!(qn.tokens[2].text(), "pii");
}

#[test]
fn qualified_name_span_starts_at_offset() {
    let qn = OwnedQualifiedName::from_dotted("foo.bar", 10);
    // "foo" starts at 10, stops at 12
    assert_eq!(qn.tokens[0].start_byte(), 10);
    assert_eq!(qn.tokens[0].stop_byte(), 12);
    // "bar" starts at 14 (10 + 3 + 1 dot)
    assert_eq!(qn.tokens[1].start_byte(), 14);
}

#[test]
fn to_context_has_same_segment_count() {
    let qn = OwnedQualifiedName::from_dotted("a.b.c", 0);
    let ctx = qn.to_context();
    assert_eq!(ctx.segments.len(), 3);
}

#[test]
fn to_context_segment_text_matches_tokens() {
    let qn = OwnedQualifiedName::from_dotted("network.allowed", 0);
    let ctx = qn.to_context();
    assert_eq!(ctx.segments[0].text(), "network");
    assert_eq!(ctx.segments[1].text(), "allowed");
}
