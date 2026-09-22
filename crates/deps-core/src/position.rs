//! Protocol-agnostic position and range types (issue #1071).
//!
//! [`Position`] and [`Range`] are the domain-level replacement for
//! `tower_lsp_server::ls_types::{Position, Range}` in [`crate::ecosystem::Dependency`]'s
//! range accessors: field-for-field identical, but this module carries no dependency on
//! `tower-lsp-server`, so a consumer that only needs `deps-core`'s parsed-dependency data
//! (e.g. `deps-cli`, `deps-engine`) never has to name an LSP-protocol type to read a
//! dependency's position in its manifest.
//!
//! `deps-core`'s own [`crate::lsp_helpers`] still constructs real
//! `tower_lsp_server::ls_types::CodeAction` objects directly (`Hover` and `Diagnostic` are
//! now the protocol-agnostic [`crate::hover::Hover`]/[`crate::diagnostic::Diagnostic`]
//! domain types instead, issues #1083/#1277) — that coupling is unaffected by this module
//! (see `lib.rs`'s "LSP type stability" doc section)
//! — and converts a [`Position`]/[`Range`] into its `ls_types` equivalent via the [`From`]
//! impls below wherever one needs to be embedded in such a response. These impls are legal
//! under Rust's orphan rules because [`Position`]/[`Range`] are local to this crate; the
//! same is not true for `url::Url` ⇄ `tower_lsp_server::ls_types::Uri` (neither type is
//! local to any crate that would want to convert between them), which is why that
//! conversion is a pair of free functions in `deps-lsp` instead (see
//! `crates/deps-lsp/src/lsp_types_interop.rs`).

#[cfg(feature = "lsp-responses")]
use tower_lsp_server::ls_types;

/// A zero-indexed line/UTF-16-code-unit-offset position, field-for-field identical to
/// `tower_lsp_server::ls_types::Position` but carrying no dependency on `tower-lsp-server`.
///
/// # Examples
///
/// ```
/// use deps_core::position::Position;
///
/// let pos = Position::new(3, 7);
/// assert_eq!(pos.line, 3);
/// assert_eq!(pos.character, 7);
/// assert_eq!(pos, Position::new(3, 7));
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Position {
    /// Zero-indexed line number.
    pub line: u32,
    /// Zero-indexed UTF-16 code unit offset on [`Self::line`].
    pub character: u32,
}

impl Position {
    /// Builds a [`Position`] from its `line`/`character` fields.
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate (e.g. the 14 ecosystem crates constructing a
    /// [`crate::ecosystem::Dependency`] impl) must call this constructor instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::position::Position;
    ///
    /// let pos = Position::new(0, 4);
    /// assert_eq!(pos.line, 0);
    /// ```
    #[must_use]
    pub const fn new(line: u32, character: u32) -> Self {
        Self { line, character }
    }
}

#[cfg(feature = "lsp-responses")]
impl From<ls_types::Position> for Position {
    fn from(value: ls_types::Position) -> Self {
        Self {
            line: value.line,
            character: value.character,
        }
    }
}

#[cfg(feature = "lsp-responses")]
impl From<Position> for ls_types::Position {
    fn from(value: Position) -> Self {
        Self::new(value.line, value.character)
    }
}

/// A `[start, end)` span over [`Position`]s, field-for-field identical to
/// `tower_lsp_server::ls_types::Range` but carrying no dependency on `tower-lsp-server`.
///
/// # Examples
///
/// ```
/// use deps_core::position::{Position, Range};
///
/// let range = Range::new(Position::new(0, 0), Position::new(0, 4));
/// assert_eq!(range.start, Position::new(0, 0));
/// assert_eq!(range.end, Position::new(0, 4));
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Range {
    /// Inclusive start position.
    pub start: Position,
    /// Exclusive end position.
    pub end: Position,
}

impl Range {
    /// Builds a [`Range`] from its `start`/`end` fields.
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate (e.g. the 14 ecosystem crates constructing a
    /// [`crate::ecosystem::Dependency`] impl) must call this constructor instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::position::{Position, Range};
    ///
    /// let range = Range::new(Position::new(1, 0), Position::new(1, 8));
    /// assert_eq!(range.start.line, 1);
    /// ```
    #[must_use]
    pub const fn new(start: Position, end: Position) -> Self {
        Self { start, end }
    }
}

#[cfg(feature = "lsp-responses")]
impl From<ls_types::Range> for Range {
    fn from(value: ls_types::Range) -> Self {
        Self {
            start: value.start.into(),
            end: value.end.into(),
        }
    }
}

#[cfg(feature = "lsp-responses")]
impl From<Range> for ls_types::Range {
    fn from(value: Range) -> Self {
        Self::new(value.start.into(), value.end.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_position_roundtrips_through_ls_types() {
        let original = Position::new(12, 34);
        let ls_pos: ls_types::Position = original.into();
        assert_eq!(ls_pos.line, 12);
        assert_eq!(ls_pos.character, 34);
        assert_eq!(Position::from(ls_pos), original);
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_range_roundtrips_through_ls_types() {
        let original = Range::new(Position::new(0, 0), Position::new(2, 5));
        let ls_range: ls_types::Range = original.into();
        assert_eq!(ls_range.start.line, 0);
        assert_eq!(ls_range.end.line, 2);
        assert_eq!(Range::from(ls_range), original);
    }

    #[test]
    fn test_range_usable_as_hashmap_key() {
        use std::collections::HashMap;

        let mut map: HashMap<Range, &str> = HashMap::new();
        map.insert(
            Range::new(Position::new(0, 0), Position::new(0, 4)),
            "serde",
        );
        assert_eq!(
            map.get(&Range::new(Position::new(0, 0), Position::new(0, 4))),
            Some(&"serde")
        );
    }
}
