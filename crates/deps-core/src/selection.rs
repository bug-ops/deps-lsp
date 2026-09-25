//! Manifest-scoped state that can refine a registry's "latest matching" version selection.
//!
//! Beyond the plain requirement text — e.g. Composer's `minimum-stability` field (#424,
//! #1433, #1444).
//!
//! [`SelectionContext`] used to carry Composer's `minimum-stability` as a raw
//! `Option<String>`, with `Registry::get_latest_matching`/`select_latest_matching` each
//! having a context-less trait method and a separate `_with_context` twin a caller had to
//! remember to call instead. #1444 collapses that: [`crate::Registry::get_latest_matching`]
//! and [`crate::Registry::select_latest_matching`] now take a required
//! [`SelectionContext`] parameter directly (an explicit [`SelectionContext::none()`] is the
//! only way to opt out, and that choice is now visible at every call site instead of an
//! easy-to-forget separate method name), and the stability value itself is the typed
//! [`StabilityFloor`] rather than a free-form string.
use std::str::FromStr;

/// A Composer `minimum-stability` floor (or per-dependency `@stability` flag), ranked
/// `Dev < Alpha < Beta < Rc < Stable` (#424, #1444).
///
/// Declaration order is the precedence order: [`Ord`] compares two floors exactly as
/// Composer's own stability scale does, so `StabilityFloor::Beta < StabilityFloor::Rc`
/// holds via the derived comparison, with no separate rank table to keep in sync.
///
/// This is the *manifest-declared* stability floor's own type — strict, via
/// [`FromStr`] — distinct from the lenient qualifier classification a *version string*'s
/// own suffix (e.g. `1.0.0-beta.1`) goes through inside `deps-composer`'s
/// `compare_versions`, which still accepts the `a`/`b` short aliases and maps an
/// unrecognized word to [`Self::Stable`] — that leniency is unchanged by this type.
///
/// # Examples
///
/// ```
/// use deps_core::selection::StabilityFloor;
///
/// assert!(StabilityFloor::Dev < StabilityFloor::Alpha);
/// assert!(StabilityFloor::Alpha < StabilityFloor::Beta);
/// assert!(StabilityFloor::Beta < StabilityFloor::Rc);
/// assert!(StabilityFloor::Rc < StabilityFloor::Stable);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StabilityFloor {
    /// `dev` — the loosest floor; admits every stability level.
    Dev,
    /// `alpha`.
    Alpha,
    /// `beta`.
    Beta,
    /// `RC` (release candidate).
    Rc,
    /// `stable` — the strictest floor; Composer's own default.
    Stable,
}

/// [`StabilityFloor::from_str`]'s error.
///
/// `raw` was not one of the five recognized stability keywords (`dev`, `alpha`, `beta`,
/// `rc`, `stable`), matched ASCII-case-insensitively and with no surrounding-whitespace
/// tolerance.
///
/// # Examples
///
/// ```
/// use deps_core::selection::{StabilityFloor, UnknownStability};
///
/// assert_eq!("betta".parse::<StabilityFloor>(), Err(UnknownStability));
/// assert_eq!(" beta".parse::<StabilityFloor>(), Err(UnknownStability));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unrecognized stability keyword")]
pub struct UnknownStability;

impl FromStr for StabilityFloor {
    type Err = UnknownStability;

    /// Strict: accepts exactly `dev`, `alpha`, `beta`, `rc`, `stable`,
    /// ASCII-case-insensitively (so `RC`, `Beta`, `STABLE` still parse) — no surrounding
    /// whitespace tolerance, and no `a`/`b` short-alias acceptance (those are valid only
    /// inside a *version qualifier* suffix, not as a `minimum-stability` config value or
    /// `@flag`).
    ///
    /// This is the strict, config-value classifier; `deps-composer`'s own
    /// `qualifier_stability` (private to that crate) is the deliberately separate, lenient
    /// classifier for a version string's own qualifier suffix (accepts `a`/`b`, defaults an
    /// unrecognized word to [`StabilityFloor::Stable`]) — if a keyword is ever added here,
    /// check whether it belongs there too.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::selection::StabilityFloor;
    ///
    /// assert_eq!("beta".parse(), Ok(StabilityFloor::Beta));
    /// assert_eq!("RC".parse(), Ok(StabilityFloor::Rc));
    /// assert_eq!("STABLE".parse(), Ok(StabilityFloor::Stable));
    ///
    /// assert!("a".parse::<StabilityFloor>().is_err());
    /// assert!("b".parse::<StabilityFloor>().is_err());
    /// assert!("".parse::<StabilityFloor>().is_err());
    /// assert!(" beta".parse::<StabilityFloor>().is_err());
    /// assert!("stable ".parse::<StabilityFloor>().is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "dev" => Ok(Self::Dev),
            "alpha" => Ok(Self::Alpha),
            "beta" => Ok(Self::Beta),
            "rc" => Ok(Self::Rc),
            "stable" => Ok(Self::Stable),
            _ => Err(UnknownStability),
        }
    }
}

/// One manifest-declared `minimum-stability` value that failed to parse.
///
/// Failed via [`StabilityFloor::from_str`] — returned by
/// [`crate::ParseResult::invalid_minimum_stability`] and surfaced as a diagnostic by
/// `deps_core::lsp_helpers::diagnostics`' shared notice.
///
/// # Examples
///
/// ```
/// use deps_core::selection::InvalidStabilityOccurrence;
/// use deps_core::position::{Position, Range};
///
/// let occurrence = InvalidStabilityOccurrence {
///     range: Range::new(Position::new(0, 0), Position::new(0, 5)),
///     raw: "betta".to_string(),
/// };
/// assert_eq!(occurrence.raw, "betta");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidStabilityOccurrence {
    /// Range of the offending value — the value's own span for a string that failed to
    /// parse, or the declaring key's span for a non-string value.
    pub range: crate::position::Range,
    /// The string contents (for a string value that failed to parse) or the raw JSON
    /// token text (for a non-string value).
    pub raw: String,
}

/// Manifest-scoped state that can refine a registry's "latest matching" version selection
/// beyond the plain requirement text — e.g. Composer's `minimum-stability` field (#424,
/// #1433, #1444).
///
/// Opaque and ecosystem-owned: the type carries whatever an ecosystem's own [`crate::ParseResult`]
/// puts into it (today, only Composer's `minimum-stability`), and only that ecosystem's own
/// [`crate::Registry`] implementation reads it back — every other registry ignores it via
/// [`crate::Registry::get_latest_matching`]/[`crate::Registry::select_latest_matching`]'s own
/// default. Every LSP call site that needs "the latest version for this dependency" (hover,
/// completion, code actions, and the background fetch path) obtains one from
/// [`crate::ParseResult::selection_context`] and threads it into those two required-parameter
/// trait methods, so a call site that already has a `ParseResult` in scope no longer has to
/// independently remember to extract and thread the same manifest-level state by hand
/// (#1433).
///
/// [`PartialEq`] is derived so a caller can detect *that* the context changed between two
/// parses (e.g. `deps-lsp`'s edit-triggered refetch escalation) without needing to know what
/// changed.
///
/// # Examples
///
/// ```
/// use deps_core::selection::{SelectionContext, StabilityFloor};
///
/// let none = SelectionContext::none();
/// assert_eq!(none.minimum_stability(), None);
///
/// let composer = SelectionContext::with_minimum_stability(StabilityFloor::Alpha);
/// assert_eq!(composer.minimum_stability(), Some(StabilityFloor::Alpha));
/// assert_ne!(none, composer);
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SelectionContext {
    minimum_stability: Option<StabilityFloor>,
}

impl SelectionContext {
    /// The empty context: every [`crate::Registry::get_latest_matching`]/
    /// [`crate::Registry::select_latest_matching`] call degrades to plain requirement-text
    /// matching. [`crate::ParseResult::selection_context`]'s default for every ecosystem with
    /// no selection-context concept of its own.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::selection::SelectionContext;
    ///
    /// assert_eq!(SelectionContext::none().minimum_stability(), None);
    /// ```
    #[must_use]
    pub const fn none() -> Self {
        Self {
            minimum_stability: None,
        }
    }

    /// Builds a context carrying a manifest's own `minimum-stability` floor
    /// (`ComposerParseResult`'s `MinimumStability::Declared`, #424/#1433/#1444).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::selection::{SelectionContext, StabilityFloor};
    ///
    /// let ctx = SelectionContext::with_minimum_stability(StabilityFloor::Beta);
    /// assert_eq!(ctx.minimum_stability(), Some(StabilityFloor::Beta));
    /// ```
    #[must_use]
    pub const fn with_minimum_stability(floor: StabilityFloor) -> Self {
        Self {
            minimum_stability: Some(floor),
        }
    }

    /// The manifest's own stability floor, read by
    /// [`crate::Registry::get_latest_matching`]/[`crate::Registry::select_latest_matching`]'s
    /// one real implementor (`PackagistRegistry`) — every other registry ignores it via those
    /// methods' own defaults.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::selection::SelectionContext;
    ///
    /// assert_eq!(SelectionContext::none().minimum_stability(), None);
    /// ```
    #[must_use]
    pub const fn minimum_stability(&self) -> Option<StabilityFloor> {
        self.minimum_stability
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stability_floor_from_str_accepts_all_five_words_case_insensitively() {
        for (word, expected) in [
            ("dev", StabilityFloor::Dev),
            ("DEV", StabilityFloor::Dev),
            ("alpha", StabilityFloor::Alpha),
            ("Alpha", StabilityFloor::Alpha),
            ("beta", StabilityFloor::Beta),
            ("BETA", StabilityFloor::Beta),
            ("rc", StabilityFloor::Rc),
            ("RC", StabilityFloor::Rc),
            ("stable", StabilityFloor::Stable),
            ("Stable", StabilityFloor::Stable),
        ] {
            assert_eq!(
                word.parse::<StabilityFloor>(),
                Ok(expected),
                "word: {word:?}"
            );
        }
    }

    #[test]
    fn stability_floor_from_str_rejects_unrecognized_words() {
        for word in ["a", "b", "", " beta", "stable ", "betta", "RC1"] {
            assert!(
                word.parse::<StabilityFloor>().is_err(),
                "expected {word:?} to be rejected"
            );
        }
    }

    #[test]
    fn stability_floor_ord_matches_composer_precedence() {
        let mut floors = [
            StabilityFloor::Stable,
            StabilityFloor::Dev,
            StabilityFloor::Rc,
            StabilityFloor::Alpha,
            StabilityFloor::Beta,
        ];
        floors.sort();
        assert_eq!(
            floors,
            [
                StabilityFloor::Dev,
                StabilityFloor::Alpha,
                StabilityFloor::Beta,
                StabilityFloor::Rc,
                StabilityFloor::Stable,
            ]
        );
    }

    #[test]
    fn selection_context_none_has_no_minimum_stability() {
        assert_eq!(SelectionContext::none().minimum_stability(), None);
        assert_eq!(SelectionContext::default(), SelectionContext::none());
    }

    #[test]
    fn selection_context_with_minimum_stability_roundtrips() {
        let ctx = SelectionContext::with_minimum_stability(StabilityFloor::Rc);
        assert_eq!(ctx.minimum_stability(), Some(StabilityFloor::Rc));
        assert_ne!(ctx, SelectionContext::none());
    }
}
