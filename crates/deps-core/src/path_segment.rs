//! A URL path segment checked, at construction, not to be a dot-segment (`.`/`..`).
//!
//! [`is_dot_segment`] and
//! [`dot_segment_rejection_error`] already
//! gate every registry-fetch URL builder in this workspace against the #341/#349/#365 defect
//! class, but only by convention: each ecosystem crate calls the predicate itself, right
//! before calling a URL builder that still accepts a raw `&str`, so a new call site can
//! forget the check and the compiler will not notice (#341/#365 recurred five times this
//! way). [`SafePathSegment`] closes that gap by making the checked segment the *only* value a
//! fetch-URL builder's signature can accept, so the guard becomes unforgettable rather than
//! merely documented.

use crate::error::Result;
use crate::lsp_helpers::{dot_segment_rejection_error, is_dot_segment};

/// Error returned by [`SafePathSegment::new`] when `segment` is exactly `.` or `..`.
///
/// Borrows the rejected segment rather than owning it: every caller either reads it
/// immediately (the rejection is already fatal to the current operation) or discards it in
/// favor of [`SafePathSegment::checked_or_reject`]'s own registry-error construction, so an
/// owned `String` would only add an allocation on an already-adversarial-input path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("path segment {segment:?} is a dot-segment (\".\" or \"..\")")]
pub struct DotSegmentError<'a> {
    segment: &'a str,
}

impl<'a> DotSegmentError<'a> {
    /// The rejected segment, for building a registry-specific
    /// [`DepsError`](crate::error::DepsError) via
    /// [`dot_segment_rejection_error`].
    #[must_use]
    pub const fn segment(&self) -> &'a str {
        self.segment
    }
}

/// A single URL path segment, checked at construction not to be exactly `.` or `..`.
///
/// A percent-encoded `.`/`..` segment (`.` is an RFC 3986 unreserved character, so encoding
/// leaves it unchanged) still gets collapsed by a URL parser's dot-segment normalization
/// (RFC 3986 §5.2.4) once interpolated into a request URL, letting it retarget the request
/// off the intended path prefix. A registry-fetch URL builder that takes `SafePathSegment`
/// instead of a raw `&str`/`String` cannot be called with an unchecked value — the dot-segment
/// guard is enforced by the type system rather than by caller convention.
///
/// Borrows rather than owns: every caller in this workspace validates a segment immediately
/// before building a URL from it and never stores the checked value, so an owned `String`
/// would only add an allocation. `Copy` for the same reason — passing it to more than one URL
/// builder (e.g. NuGet's flat-container and registration-index URLs, built from the same
/// package name) needs no explicit `.clone()`.
///
/// # Examples
///
/// ```
/// use deps_core::path_segment::SafePathSegment;
///
/// assert!(SafePathSegment::new("left-pad").is_ok());
/// assert!(SafePathSegment::new(".").is_err());
/// assert!(SafePathSegment::new("..").is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SafePathSegment<'a>(&'a str);

impl<'a> SafePathSegment<'a> {
    /// # Errors
    ///
    /// Returns [`DotSegmentError`] if `segment` is exactly `.` or `..`.
    pub fn new(segment: &'a str) -> std::result::Result<Self, DotSegmentError<'a>> {
        if is_dot_segment(segment) {
            Err(DotSegmentError { segment })
        } else {
            Ok(Self(segment))
        }
    }

    /// Validates `segment`, converting a rejection directly into the registry-specific
    /// [`DepsError::PackageNotFound`](crate::error::DepsError::PackageNotFound) via
    /// [`dot_segment_rejection_error`] — the
    /// single call every ecosystem crate's own dot-segment gate (`deps-composer`, `deps-dart`,
    /// `deps-npm`, `deps-nuget`) used to hand-roll separately as a `SafePathSegment::new(...)`
    /// + `.map_err(...)` pair (#1514 item 4 follow-up).
    ///
    /// `name` is the full, possibly compound identifier surfaced in the resulting log/error —
    /// not necessarily `segment` itself: a compound name (Composer's `vendor/package`, npm's
    /// `@scope/pkg`) is split into more than one segment before each is checked here, and the
    /// rejection should report the whole declared name a user recognizes, not just whichever
    /// half happened to be the offending one.
    ///
    /// # Errors
    ///
    /// Returns `DepsError::PackageNotFound` if `segment` is exactly `.` or `..`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::path_segment::SafePathSegment;
    ///
    /// assert!(SafePathSegment::checked_or_reject("left-pad", "left-pad", "example URL", "npm").is_ok());
    /// assert!(SafePathSegment::checked_or_reject("..", "@a/..", "example URL", "npm").is_err());
    /// ```
    pub fn checked_or_reject(
        segment: &'a str,
        name: &str,
        context: &str,
        registry: &'static str,
    ) -> Result<Self> {
        Self::new(segment)
            .map_err(|_| dot_segment_rejection_error("is_dot_segment", context, name, registry))
    }

    /// The validated segment's underlying string.
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        self.0
    }
}

impl std::fmt::Display for SafePathSegment<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// One or two validated path segments for a fetch URL built from a package name.
///
/// Covers both a bare identifier and a `<prefix>/<name>`-shaped one — the split shape shared
/// by npm's `@scope/pkg` and Composer's `vendor/package` registry-fetch URLs.
///
/// Each ecosystem keeps its own parsing (npm strips a leading `@` before splitting; Composer
/// splits on the first `/` with no scope marker), so this type carries only the already-split,
/// already-validated result — never the splitting logic itself.
///
/// # Examples
///
/// ```
/// use deps_core::path_segment::{SafePathSegment, SegmentedPathName};
///
/// let bare = SegmentedPathName::Single(SafePathSegment::new("left-pad").unwrap());
/// let prefixed = SegmentedPathName::Prefixed(
///     SafePathSegment::new("monolog").unwrap(),
///     SafePathSegment::new("monolog").unwrap(),
/// );
/// assert!(matches!(bare, SegmentedPathName::Single(_)));
/// assert!(matches!(prefixed, SegmentedPathName::Prefixed(_, _)));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SegmentedPathName<'a> {
    /// A single, unprefixed path segment (Composer's fallback bare form, npm's unscoped
    /// name).
    Single(SafePathSegment<'a>),
    /// A `<prefix>/<name>` pair, each independently validated (npm's `@scope/pkg`,
    /// Composer's `vendor/package`).
    Prefixed(SafePathSegment<'a>, SafePathSegment<'a>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_rejects_bare_dot_dot() {
        assert!(SafePathSegment::new("..").is_err());
    }

    #[test]
    fn test_new_rejects_bare_dot() {
        assert!(SafePathSegment::new(".").is_err());
    }

    #[test]
    fn test_new_accepts_normal_names() {
        assert!(SafePathSegment::new("left-pad").is_ok());
        assert!(SafePathSegment::new("../../search").is_ok());
    }

    #[test]
    fn test_error_carries_the_rejected_segment() {
        let err = SafePathSegment::new("..").unwrap_err();
        assert_eq!(err.segment(), "..");
    }

    #[test]
    fn test_as_str_roundtrips() {
        let segment = SafePathSegment::new("express").unwrap();
        assert_eq!(segment.as_str(), "express");
    }

    #[test]
    fn test_checked_or_reject_accepts_normal_segment() {
        assert!(SafePathSegment::checked_or_reject("express", "express", "ctx", "npm").is_ok());
    }

    #[test]
    fn test_checked_or_reject_rejects_dot_segment() {
        let err = SafePathSegment::checked_or_reject("..", "@a/..", "ctx", "npm").unwrap_err();
        assert!(matches!(
            err,
            crate::error::DepsError::PackageNotFound { .. }
        ));
    }

    /// The reported name must be the full, possibly compound identifier the caller passed in
    /// — not just the offending sub-segment — so a rejection stays diagnosable.
    #[test]
    fn test_checked_or_reject_error_reports_full_name_not_bare_segment() {
        let err = SafePathSegment::checked_or_reject("..", "@a/..", "ctx", "npm").unwrap_err();
        let crate::error::DepsError::PackageNotFound { package, .. } = err else {
            panic!("expected PackageNotFound, got {err:?}");
        };
        assert_eq!(package, "@a/..");
    }
}
