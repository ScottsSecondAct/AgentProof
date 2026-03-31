use serde::{Deserialize, Serialize};

/// Byte offset in the source text.
pub type ByteOffset = u32;

/// A contiguous region of source text, used by every AST node and diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Span {
    pub start: ByteOffset,
    pub end: ByteOffset,
}

impl Span {
    pub const DUMMY: Span = Span { start: 0, end: 0 };

    pub fn new(start: u32, end: u32) -> Self {
        Self { start, end }
    }

    /// Merge two spans into the smallest span containing both.
    pub fn merge(self, other: Span) -> Span {
        Span {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }

    pub fn len(self) -> u32 {
        self.end - self.start
    }

    pub fn is_empty(self) -> bool {
        self.start == self.end
    }
}

/// A value annotated with its source location.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Spanned<T> {
    pub node: T,
    pub span: Span,
}

impl<T> Spanned<T> {
    pub fn new(node: T, span: Span) -> Self {
        Self { node, span }
    }

    pub fn dummy(node: T) -> Self {
        Self {
            node,
            span: Span::DUMMY,
        }
    }

    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Spanned<U> {
        Spanned {
            node: f(self.node),
            span: self.span,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Span ─────────────────────────────────────────────────────────────

    #[test]
    fn span_new_captures_bounds() {
        let s = Span::new(10, 20);
        assert_eq!(s.start, 10);
        assert_eq!(s.end, 20);
    }

    #[test]
    fn span_dummy_is_zero_zero() {
        assert_eq!(Span::DUMMY.start, 0);
        assert_eq!(Span::DUMMY.end, 0);
    }

    #[test]
    fn span_len_returns_difference() {
        let s = Span::new(5, 15);
        assert_eq!(s.len(), 10);
    }

    #[test]
    fn span_len_zero_when_empty() {
        assert_eq!(Span::new(7, 7).len(), 0);
    }

    #[test]
    fn span_is_empty_when_start_equals_end() {
        assert!(Span::new(5, 5).is_empty());
    }

    #[test]
    fn span_is_not_empty_when_start_differs() {
        assert!(!Span::new(5, 6).is_empty());
    }

    #[test]
    fn span_merge_overlapping_produces_bounding_span() {
        let a = Span::new(5, 10);
        let b = Span::new(8, 20);
        let merged = a.merge(b);
        assert_eq!(merged.start, 5);
        assert_eq!(merged.end, 20);
    }

    #[test]
    fn span_merge_non_overlapping() {
        let a = Span::new(0, 5);
        let b = Span::new(10, 20);
        let merged = a.merge(b);
        assert_eq!(merged.start, 0);
        assert_eq!(merged.end, 20);
    }

    #[test]
    fn span_merge_is_symmetric() {
        let a = Span::new(0, 5);
        let b = Span::new(10, 20);
        assert_eq!(a.merge(b), b.merge(a));
    }

    #[test]
    fn span_merge_with_self_is_identity() {
        let s = Span::new(3, 9);
        assert_eq!(s.merge(s), s);
    }

    // ── Spanned<T> ───────────────────────────────────────────────────────

    #[test]
    fn spanned_new_stores_node_and_span() {
        let s = Spanned::new(42u32, Span::new(1, 5));
        assert_eq!(s.node, 42);
        assert_eq!(s.span, Span::new(1, 5));
    }

    #[test]
    fn spanned_dummy_uses_dummy_span() {
        let s = Spanned::dummy("hello");
        assert_eq!(s.span, Span::DUMMY);
        assert_eq!(s.node, "hello");
    }

    #[test]
    fn spanned_map_transforms_node_preserves_span() {
        let s = Spanned::new(10i32, Span::new(0, 3));
        let doubled = s.map(|x| x * 2);
        assert_eq!(doubled.node, 20);
        assert_eq!(doubled.span, Span::new(0, 3));
    }

    #[test]
    fn spanned_map_can_change_type() {
        let s = Spanned::new(42u32, Span::new(1, 2));
        let stringified = s.map(|x| x.to_string());
        assert_eq!(stringified.node, "42");
        assert_eq!(stringified.span, Span::new(1, 2));
    }
}
