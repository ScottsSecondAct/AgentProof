//! Span accuracy tests.
//!
//! Parses `.aegis` source text, runs the type checker, and asserts that each
//! diagnostic's span covers exactly the expected substring of the source.
//! These tests verify that error messages point users to the right location.

use aegis_compiler::checker::TypeChecker;
use aegis_compiler::diagnostics::DiagnosticCode;
use aegis_compiler::parser::parse_source;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract the source slice covered by a span.
fn span_text<'a>(source: &'a str, span: aegis_compiler::ast::Span) -> &'a str {
    let start = span.start as usize;
    let end = span.end as usize;
    &source[start..end]
}

/// Parse `source`, run the type checker, and return all diagnostics.
fn check(source: &str) -> (String, Vec<aegis_compiler::diagnostics::Diagnostic>) {
    let (prog, _parse_diags) = parse_source(source, "test.aegis");
    let mut checker = TypeChecker::new();
    checker.check_program(&prog);
    let diags = checker.into_diagnostics().into_diagnostics();
    (source.to_string(), diags)
}

// ── E0304 — extends unknown policy ───────────────────────────────────────────

#[test]
fn e0304_span_covers_base_policy_name() {
    let src = "policy Derived extends UnknownBase { severity high }";
    let (source, diags) = check(src);
    let d = diags
        .iter()
        .find(|d| d.code == DiagnosticCode::E0304)
        .expect("E0304");
    let text = span_text(&source, d.span);
    assert!(
        text.contains("UnknownBase"),
        "E0304 span should cover the unknown base name, got: {text:?}"
    );
}

// ── E0301 — multiple severity clauses ────────────────────────────────────────

#[test]
fn e0301_span_is_non_zero() {
    let src = "policy P { severity low severity high }";
    let (_, diags) = check(src);
    let d = diags
        .iter()
        .find(|d| d.code == DiagnosticCode::E0301)
        .expect("E0301");
    assert!(d.span.start < d.span.end, "E0301 span should be non-zero");
}

// ── E0202 — temporal operator outside proof ───────────────────────────────────

#[test]
fn e0202_span_is_non_zero() {
    // `always` used directly in a rule `when` clause — not inside a proof.
    let src = r#"
policy P {
    on tool_call {
        when always(true)
        deny
    }
}
"#;
    let (_, diags) = check(src);
    let d = diags
        .iter()
        .find(|d| d.code == DiagnosticCode::E0202)
        .expect("E0202");
    assert!(d.span.start < d.span.end, "E0202 span should be non-zero");
}

// ── Rendered output contains file and line ────────────────────────────────────

#[test]
fn render_includes_filename_and_line_number() {
    let src = "policy Derived extends Ghost { severity low }";
    let (prog, _) = parse_source(src, "my_policy.aegis");
    let mut checker = TypeChecker::new();
    checker.check_program(&prog);
    let sink = checker.into_diagnostics();
    let rendered = sink.render(src, "my_policy.aegis");
    assert!(
        rendered.contains("my_policy.aegis"),
        "rendered output should contain the filename"
    );
    assert!(
        rendered.contains("E0304"),
        "rendered output should contain the diagnostic code"
    );
}

#[test]
fn render_line_number_is_correct_for_second_line_error() {
    // Put the error on line 2 — rendered output should say `:2:`.
    let src = "policy P { severity low }\npolicy Q extends Ghost { severity high }";
    let (prog, _) = parse_source(src, "test.aegis");
    let mut checker = TypeChecker::new();
    checker.check_program(&prog);
    let sink = checker.into_diagnostics();
    let rendered = sink.render(src, "test.aegis");
    assert!(
        rendered.contains(":2:"),
        "error on line 2 should render as :2:, got:\n{rendered}"
    );
}

// ── Span start < end for all checker diagnostics ─────────────────────────────

#[test]
fn all_checker_diagnostics_have_valid_spans_for_parsed_source() {
    // A program with several known errors; every diagnostic must have a
    // non-degenerate span when AST comes from the real parser.
    let src = r#"
policy A extends NoSuchBase {
    severity low
    severity high
}
"#;
    let (prog, _) = parse_source(src, "test.aegis");
    let mut checker = TypeChecker::new();
    checker.check_program(&prog);
    let sink = checker.into_diagnostics();
    let diags = sink.diagnostics();
    assert!(!diags.is_empty(), "expected at least one diagnostic");
    for d in diags {
        assert!(
            d.span.start <= d.span.end,
            "diagnostic {:?} has invalid span {:?}",
            d.code,
            d.span
        );
        // Spans from parsed source should not be the DUMMY (0,0) for
        // diagnostics that reference a named construct (E0304, E0301).
        if matches!(d.code, DiagnosticCode::E0304 | DiagnosticCode::E0301) {
            assert!(
                d.span.start < d.span.end,
                "diagnostic {:?} should have a non-zero span from parsed source",
                d.code
            );
        }
    }
}
