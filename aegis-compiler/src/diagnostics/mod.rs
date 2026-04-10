use std::fmt;

use crate::ast::Span;
use crate::types::Ty;

/// Severity level for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Warning,
    Error,
}

/// A single compiler diagnostic with source location and structured message.
#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub severity: Severity,
    pub span: Span,
    pub message: String,
    pub code: DiagnosticCode,
    pub notes: Vec<Note>,
}

/// Additional context attached to a diagnostic.
#[derive(Debug, Clone)]
pub struct Note {
    pub span: Option<Span>,
    pub message: String,
}

/// Machine-readable diagnostic codes for tooling integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiagnosticCode {
    // ── Name resolution ──────────────────────────────────────────────
    E0001, // Undefined variable
    E0002, // Undefined type
    E0003, // Undefined function
    E0004, // Duplicate definition
    E0005, // Unresolved import

    // ── Type errors ──────────────────────────────────────────────────
    E0100, // Type mismatch
    E0101, // Not a boolean expression (where bool required)
    E0102, // Not a numeric expression (where number required)
    E0103, // Not a collection (where iterable required)
    E0104, // Not a function (attempt to call non-callable)
    E0105, // Wrong number of arguments
    E0106, // Incompatible types in binary operation
    E0107, // Cannot apply predicate to this type
    E0108, // Field not found on struct

    // ── Temporal logic ───────────────────────────────────────────────
    E0200, // Temporal operator requires boolean operand
    E0201, // `within` clause requires duration expression
    E0202, // Temporal operator used outside proof/invariant
    E0203, // Nested temporal operators (unsupported in v1)

    // ── Policy structure ─────────────────────────────────────────────
    E0300, // Rule without verdict
    E0301, // Multiple severity clauses
    E0302, // Unknown scope target
    E0303, // Rate limit requires numeric limit and duration window
    E0304, // Policy extends unknown policy
    E0305, // Non-exhaustive match in rule

    // ── Warnings ─────────────────────────────────────────────────────
    W0001, // Unused binding
    W0002, // Unreachable match arm
    W0003, // Redundant verdict (allow after allow)
    W0004, // Shadowed binding
}

impl fmt::Display for DiagnosticCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Diagnostic {
    pub fn error(span: Span, code: DiagnosticCode, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            span,
            message: message.into(),
            code,
            notes: vec![],
        }
    }

    pub fn warning(span: Span, code: DiagnosticCode, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            span,
            message: message.into(),
            code,
            notes: vec![],
        }
    }

    pub fn with_note(mut self, span: Option<Span>, message: impl Into<String>) -> Self {
        self.notes.push(Note {
            span,
            message: message.into(),
        });
        self
    }

    pub fn type_mismatch(span: Span, expected: &Ty, actual: &Ty) -> Self {
        Self::error(
            span,
            DiagnosticCode::E0100,
            format!("type mismatch: expected `{expected}`, found `{actual}`"),
        )
    }

    pub fn undefined_var(span: Span, name: &str) -> Self {
        Self::error(
            span,
            DiagnosticCode::E0001,
            format!("undefined variable `{name}`"),
        )
    }

    pub fn undefined_type(span: Span, name: &str) -> Self {
        Self::error(
            span,
            DiagnosticCode::E0002,
            format!("undefined type `{name}`"),
        )
    }

    pub fn undefined_function(span: Span, name: &str) -> Self {
        Self::error(
            span,
            DiagnosticCode::E0003,
            format!("undefined function `{name}`"),
        )
    }

    pub fn temporal_requires_bool(span: Span, op: &str) -> Self {
        Self::error(
            span,
            DiagnosticCode::E0200,
            format!("`{op}` requires a boolean expression"),
        )
    }

    pub fn within_requires_duration(span: Span) -> Self {
        Self::error(
            span,
            DiagnosticCode::E0201,
            "`within` clause requires a duration expression",
        )
    }

    pub fn temporal_outside_proof(span: Span, op: &str) -> Self {
        Self::error(
            span,
            DiagnosticCode::E0202,
            format!("`{op}` can only be used inside a proof/invariant block"),
        )
    }
}

/// Collects diagnostics during compilation.
#[derive(Debug, Default)]
pub struct DiagnosticSink {
    diagnostics: Vec<Diagnostic>,
}

impl DiagnosticSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn emit(&mut self, diag: Diagnostic) {
        self.diagnostics.push(diag);
    }

    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| d.severity == Severity::Error)
    }

    pub fn error_count(&self) -> usize {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .count()
    }

    pub fn warning_count(&self) -> usize {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Warning)
            .count()
    }

    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    pub fn into_diagnostics(self) -> Vec<Diagnostic> {
        self.diagnostics
    }

    /// Format diagnostics for terminal output with source context.
    pub fn render(&self, source: &str, filename: &str) -> String {
        let mut output = String::new();
        for diag in &self.diagnostics {
            let prefix = match diag.severity {
                Severity::Error => "error",
                Severity::Warning => "warning",
            };
            let (line, col) = offset_to_line_col(source, diag.span.start);
            output.push_str(&format!(
                "{prefix}[{}]: {}\n  --> {filename}:{line}:{col}\n",
                diag.code, diag.message
            ));

            // Show the source line and a caret pointing to the error.
            if diag.span != Span::DUMMY {
                if let Some(src_line) = source_line(source, line) {
                    let line_num_width = format!("{line}").len();
                    let gutter = " ".repeat(line_num_width);
                    let caret_offset = col.saturating_sub(1);
                    let caret_len = {
                        let span_len = (diag.span.end.saturating_sub(diag.span.start)) as usize;
                        span_len.max(1).min(src_line.len().saturating_sub(caret_offset))
                    };
                    let caret = "^".repeat(caret_len.max(1));
                    output.push_str(&format!("   {gutter} |\n"));
                    output.push_str(&format!(" {line} | {src_line}\n"));
                    output.push_str(&format!(
                        "   {gutter} | {}{caret}\n",
                        " ".repeat(caret_offset)
                    ));
                    output.push_str(&format!("   {gutter} |\n"));
                }
            }

            for note in &diag.notes {
                if let Some(span) = note.span {
                    let (nl, nc) = offset_to_line_col(source, span.start);
                    output.push_str(&format!(
                        "  note: {} ({filename}:{nl}:{nc})\n",
                        note.message
                    ));
                } else {
                    output.push_str(&format!("  note: {}\n", note.message));
                }
            }
            output.push('\n');
        }
        output
    }

    /// Format diagnostics as a JSON value for machine-readable output.
    pub fn to_json(&self, source: &str, filename: &str) -> serde_json::Value {
        let errors: Vec<serde_json::Value> = self
            .diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .map(|d| {
                let (line, col) = offset_to_line_col(source, d.span.start);
                serde_json::json!({
                    "code": d.code.to_string(),
                    "message": d.message,
                    "file": filename,
                    "line": line,
                    "col": col,
                })
            })
            .collect();
        let warnings: Vec<serde_json::Value> = self
            .diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Warning)
            .map(|d| {
                let (line, col) = offset_to_line_col(source, d.span.start);
                serde_json::json!({
                    "code": d.code.to_string(),
                    "message": d.message,
                    "file": filename,
                    "line": line,
                    "col": col,
                })
            })
            .collect();
        serde_json::json!({ "errors": errors, "warnings": warnings })
    }
}

/// Return the source text for the given 1-based line number, without its trailing newline.
fn source_line(source: &str, line: usize) -> Option<&str> {
    source.lines().nth(line.saturating_sub(1))
}

fn offset_to_line_col(source: &str, offset: u32) -> (usize, usize) {
    let offset = offset as usize;
    let mut line = 1;
    let mut col = 1;
    for (i, ch) in source.char_indices() {
        if i >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::PrimitiveType;
    use crate::ast::Span;
    use crate::types::Ty;

    fn dummy_span() -> Span {
        Span::new(0, 5)
    }

    // ── DiagnosticSink ───────────────────────────────────────────────────

    #[test]
    fn new_sink_has_no_errors_or_warnings() {
        let sink = DiagnosticSink::new();
        assert!(!sink.has_errors());
        assert_eq!(sink.error_count(), 0);
        assert_eq!(sink.warning_count(), 0);
        assert!(sink.diagnostics().is_empty());
    }

    #[test]
    fn emit_error_sets_has_errors() {
        let mut sink = DiagnosticSink::new();
        sink.emit(Diagnostic::error(
            dummy_span(),
            DiagnosticCode::E0001,
            "undefined",
        ));
        assert!(sink.has_errors());
        assert_eq!(sink.error_count(), 1);
        assert_eq!(sink.warning_count(), 0);
    }

    #[test]
    fn emit_warning_does_not_set_has_errors() {
        let mut sink = DiagnosticSink::new();
        sink.emit(Diagnostic::warning(
            dummy_span(),
            DiagnosticCode::W0001,
            "unused binding",
        ));
        assert!(!sink.has_errors());
        assert_eq!(sink.error_count(), 0);
        assert_eq!(sink.warning_count(), 1);
    }

    #[test]
    fn error_and_warning_counts_are_independent() {
        let mut sink = DiagnosticSink::new();
        sink.emit(Diagnostic::error(dummy_span(), DiagnosticCode::E0001, "e1"));
        sink.emit(Diagnostic::error(dummy_span(), DiagnosticCode::E0002, "e2"));
        sink.emit(Diagnostic::warning(
            dummy_span(),
            DiagnosticCode::W0001,
            "w1",
        ));
        assert_eq!(sink.error_count(), 2);
        assert_eq!(sink.warning_count(), 1);
    }

    #[test]
    fn into_diagnostics_returns_all_emitted() {
        let mut sink = DiagnosticSink::new();
        sink.emit(Diagnostic::error(dummy_span(), DiagnosticCode::E0001, "e1"));
        sink.emit(Diagnostic::warning(
            dummy_span(),
            DiagnosticCode::W0001,
            "w1",
        ));
        let diags = sink.into_diagnostics();
        assert_eq!(diags.len(), 2);
    }

    #[test]
    fn diagnostics_slice_matches_emitted_order() {
        let mut sink = DiagnosticSink::new();
        sink.emit(Diagnostic::error(
            dummy_span(),
            DiagnosticCode::E0001,
            "first",
        ));
        sink.emit(Diagnostic::error(
            dummy_span(),
            DiagnosticCode::E0002,
            "second",
        ));
        let diags = sink.diagnostics();
        assert_eq!(diags[0].code, DiagnosticCode::E0001);
        assert_eq!(diags[1].code, DiagnosticCode::E0002);
    }

    // ── Diagnostic constructors ──────────────────────────────────────────

    #[test]
    fn error_constructor_sets_severity_error() {
        let d = Diagnostic::error(dummy_span(), DiagnosticCode::E0001, "msg");
        assert_eq!(d.severity, Severity::Error);
    }

    #[test]
    fn warning_constructor_sets_severity_warning() {
        let d = Diagnostic::warning(dummy_span(), DiagnosticCode::W0001, "msg");
        assert_eq!(d.severity, Severity::Warning);
    }

    #[test]
    fn constructor_stores_span_and_message() {
        let span = Span::new(10, 20);
        let d = Diagnostic::error(span, DiagnosticCode::E0003, "missing fn");
        assert_eq!(d.span, span);
        assert_eq!(d.message, "missing fn");
    }

    #[test]
    fn with_note_without_span_attaches_note() {
        let d = Diagnostic::error(dummy_span(), DiagnosticCode::E0001, "err")
            .with_note(None, "see also");
        assert_eq!(d.notes.len(), 1);
        assert_eq!(d.notes[0].message, "see also");
        assert!(d.notes[0].span.is_none());
    }

    #[test]
    fn with_note_with_span_attaches_note() {
        let note_span = Span::new(10, 15);
        let d = Diagnostic::error(dummy_span(), DiagnosticCode::E0001, "err")
            .with_note(Some(note_span), "defined here");
        assert_eq!(d.notes[0].span, Some(note_span));
        assert_eq!(d.notes[0].message, "defined here");
    }

    #[test]
    fn with_note_chaining_adds_multiple_notes() {
        let d = Diagnostic::error(dummy_span(), DiagnosticCode::E0001, "err")
            .with_note(None, "note 1")
            .with_note(None, "note 2");
        assert_eq!(d.notes.len(), 2);
    }

    // ── Named constructors ───────────────────────────────────────────────

    #[test]
    fn type_mismatch_emits_e0100_with_type_names() {
        let d = Diagnostic::type_mismatch(
            dummy_span(),
            &Ty::Primitive(PrimitiveType::Int),
            &Ty::Primitive(PrimitiveType::String),
        );
        assert_eq!(d.code, DiagnosticCode::E0100);
        assert_eq!(d.severity, Severity::Error);
        assert!(d.message.contains("int"), "message: {}", d.message);
        assert!(d.message.contains("string"), "message: {}", d.message);
    }

    #[test]
    fn undefined_var_emits_e0001_with_name() {
        let d = Diagnostic::undefined_var(dummy_span(), "my_variable");
        assert_eq!(d.code, DiagnosticCode::E0001);
        assert!(d.message.contains("my_variable"), "message: {}", d.message);
    }

    #[test]
    fn undefined_type_emits_e0002_with_name() {
        let d = Diagnostic::undefined_type(dummy_span(), "MyType");
        assert_eq!(d.code, DiagnosticCode::E0002);
        assert!(d.message.contains("MyType"), "message: {}", d.message);
    }

    #[test]
    fn undefined_function_emits_e0003_with_name() {
        let d = Diagnostic::undefined_function(dummy_span(), "compute");
        assert_eq!(d.code, DiagnosticCode::E0003);
        assert!(d.message.contains("compute"), "message: {}", d.message);
    }

    #[test]
    fn temporal_requires_bool_emits_e0200_with_op() {
        let d = Diagnostic::temporal_requires_bool(dummy_span(), "always");
        assert_eq!(d.code, DiagnosticCode::E0200);
        assert!(d.message.contains("always"), "message: {}", d.message);
    }

    #[test]
    fn within_requires_duration_emits_e0201() {
        let d = Diagnostic::within_requires_duration(dummy_span());
        assert_eq!(d.code, DiagnosticCode::E0201);
    }

    #[test]
    fn temporal_outside_proof_emits_e0202_with_op() {
        let d = Diagnostic::temporal_outside_proof(dummy_span(), "never");
        assert_eq!(d.code, DiagnosticCode::E0202);
        assert!(d.message.contains("never"), "message: {}", d.message);
    }

    // ── Rendering ────────────────────────────────────────────────────────

    #[test]
    fn render_empty_sink_produces_empty_string() {
        let sink = DiagnosticSink::new();
        assert_eq!(sink.render("source code", "test.aegis"), "");
    }

    #[test]
    fn render_includes_filename_code_and_message() {
        let mut sink = DiagnosticSink::new();
        sink.emit(Diagnostic::error(
            Span::new(0, 5),
            DiagnosticCode::E0001,
            "undefined x",
        ));
        let out = sink.render("hello world", "policy.aegis");
        assert!(out.contains("policy.aegis"), "output: {out}");
        assert!(out.contains("E0001"), "output: {out}");
        assert!(out.contains("undefined x"), "output: {out}");
    }

    #[test]
    fn render_error_prefix_vs_warning_prefix() {
        let mut sink = DiagnosticSink::new();
        sink.emit(Diagnostic::error(dummy_span(), DiagnosticCode::E0001, "e"));
        sink.emit(Diagnostic::warning(
            dummy_span(),
            DiagnosticCode::W0001,
            "w",
        ));
        let out = sink.render("src", "f.aegis");
        assert!(out.contains("error["), "output: {out}");
        assert!(out.contains("warning["), "output: {out}");
    }

    // ── offset_to_line_col ───────────────────────────────────────────────

    #[test]
    fn offset_zero_is_line_1_col_1() {
        let (line, col) = offset_to_line_col("hello", 0);
        assert_eq!((line, col), (1, 1));
    }

    #[test]
    fn offset_on_second_line() {
        // "abc\ndef" — offset 4 is start of second line
        let (line, col) = offset_to_line_col("abc\ndef", 4);
        assert_eq!((line, col), (2, 1));
    }

    #[test]
    fn offset_mid_first_line() {
        let (line, col) = offset_to_line_col("hello world", 6);
        assert_eq!((line, col), (1, 7));
    }
}
