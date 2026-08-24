//! Deno import specifier grammar: `scheme:name[@version-req][/subpath]`.
//!
//! Two entry points:
//! - [`split_scheme`] splits an already-parsed, scheme-qualified [`deps_core::PackageName`]
//!   (e.g. `"jsr:@std/fs"`, no version/subpath) so a registry facade can dispatch it.
//! - [`parse_specifier`] runs the full grammar over a raw manifest value
//!   (`"jsr:@std/fs@1.2/base64"`) to extract the name/version byte ranges the manifest
//!   parser needs.

use std::ops::Range;

/// The two registries a Deno `imports` value can point at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// `jsr:` — routed to the JSR registry.
    Jsr,
    /// `npm:` — routed to the existing `deps-npm` registry client.
    Npm,
}

impl Scheme {
    /// The scheme's textual prefix, without the trailing colon.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Jsr => "jsr",
            Self::Npm => "npm",
        }
    }
}

/// Splits `value` into its scheme and the text after the `scheme:` prefix.
///
/// Returns `None` if `value` does not start with a recognized `jsr:`/`npm:` prefix (any
/// other scheme — `http:`, `https:`, `file:`, `node:`, `data:` — or a bare/relative
/// specifier).
///
/// # Examples
///
/// ```
/// use deps_deno::specifier::{Scheme, split_scheme};
///
/// assert_eq!(split_scheme("jsr:@std/fs"), Some((Scheme::Jsr, "@std/fs")));
/// assert_eq!(split_scheme("npm:react"), Some((Scheme::Npm, "react")));
/// assert_eq!(split_scheme("https://example.com"), None);
/// ```
#[must_use]
pub fn split_scheme(value: &str) -> Option<(Scheme, &str)> {
    if let Some(rest) = value.strip_prefix("jsr:") {
        Some((Scheme::Jsr, rest))
    } else if let Some(rest) = value.strip_prefix("npm:") {
        Some((Scheme::Npm, rest))
    } else {
        None
    }
}

/// Splits a scoped name (`"@scope/pkg"`) into `(scope, pkg)`, or `None` if `name` is not
/// scoped (no leading `@`) or malformed (missing `/`, empty scope, or empty package name).
///
/// # Examples
///
/// ```
/// use deps_deno::specifier::split_scoped;
///
/// assert_eq!(split_scoped("@std/fs"), Some(("std", "fs")));
/// assert_eq!(split_scoped("react"), None);
/// assert_eq!(split_scoped("@std"), None);
/// ```
#[must_use]
pub fn split_scoped(name: &str) -> Option<(&str, &str)> {
    let rest = name.strip_prefix('@')?;
    let (scope, pkg) = rest.split_once('/')?;
    if scope.is_empty() || pkg.is_empty() {
        return None;
    }
    Some((scope, pkg))
}

/// A parsed Deno import specifier value, with byte ranges relative to the *value* string
/// (excluding the surrounding JSON quotes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSpecifier {
    /// Which registry this specifier routes to.
    pub scheme: Scheme,
    /// The scheme-qualified name, e.g. `"jsr:@std/fs"` or `"npm:react"` — identical to
    /// `value[name_range]`.
    pub name: String,
    /// Byte range of `name` within the value, including the `scheme:` prefix (so it spans
    /// the exact same text as [`deps_core::PackageName`] holds, per the architecture's D2
    /// decision to keep the scheme inside the package name).
    pub name_range: Range<usize>,
    /// Version requirement text, if present. `Some(String::new())` when the user has
    /// typed `@` but nothing after it yet — still a version-completion position, not the
    /// absence of one.
    pub version_req: Option<String>,
    /// Byte range of `version_req` within the value, if present.
    pub version_range: Option<Range<usize>>,
}

/// Parses a raw Deno import value (e.g. `"jsr:@std/fs@1.2/base64"`) per the grammar:
///
/// ```text
/// value  ::= scheme ":" name ["@" version-req] ["/" subpath]
/// scheme ::= "jsr" | "npm"
/// name   ::= "@" scope "/" pkg | pkg          (jsr: requires the scoped form)
/// ```
///
/// The name is bounded by segment count (scoped = exactly 2 segments, unscoped = 1)
/// *before* looking for an optional `@version-req`, so an unversioned subpath
/// (`"jsr:@std/fs/walk"`, `"npm:preact/hooks"`) is correctly excluded from `name` rather
/// than swallowed into it — a version requirement, once found, then runs only to the next
/// `/` or end of string, so a versioned subpath (`"jsr:@std/fs@1/base64"`) is handled the
/// same way.
///
/// Returns `None` for anything else: a missing/unrecognized scheme (`http://`, `file:`, a
/// bare alias, a relative path, ...), a malformed scoped name (`"jsr:@std"` — missing
/// `/pkg`, `"jsr:@/pkg"` — empty scope, `"jsr:@std/"` — empty pkg), or an empty unscoped
/// name.
///
/// Note this grammar is scheme-agnostic about scoping: `"jsr:std"` (unscoped) parses
/// successfully here, even though JSR's own registry requires scoped packages. That
/// requirement is enforced as a diagnostic lint by
/// [`DenoFormatter::validate_package_name`](crate::formatter::DenoFormatter), not as a
/// parse-time rejection — consistent with `EcosystemFormatter::validate_package_name`'s
/// contract that `PackageName` construction stays infallible.
///
/// # Examples
///
/// ```
/// use deps_deno::specifier::{Scheme, parse_specifier};
///
/// let parsed = parse_specifier("jsr:@std/fs@1.2").unwrap();
/// assert_eq!(parsed.scheme, Scheme::Jsr);
/// assert_eq!(parsed.name, "jsr:@std/fs");
/// assert_eq!(parsed.version_req.as_deref(), Some("1.2"));
///
/// // Unversioned subpath: the subpath must not be swallowed into the name.
/// let parsed = parse_specifier("jsr:@std/fs/walk").unwrap();
/// assert_eq!(parsed.name, "jsr:@std/fs");
/// assert_eq!(parsed.version_req, None);
/// ```
#[must_use]
pub fn parse_specifier(value: &str) -> Option<ParsedSpecifier> {
    let (scheme, rest) = split_scheme(value)?;
    let prefix_len = value.len() - rest.len();

    let name_end_in_rest = if let Some(after_at) = rest.strip_prefix('@') {
        // Scoped: exactly two segments, "@scope/pkg".
        let slash_rel = after_at.find('/')?;
        if slash_rel == 0 {
            return None; // empty scope, e.g. "jsr:@/pkg"
        }
        let after_slash = &after_at[slash_rel + 1..];
        let pkg_end_rel = after_slash.find(['@', '/']).unwrap_or(after_slash.len());
        if pkg_end_rel == 0 {
            return None; // empty pkg name, e.g. "jsr:@std/"
        }
        1 + slash_rel + 1 + pkg_end_rel
    } else {
        // Unscoped: exactly one segment.
        rest.find(['@', '/']).unwrap_or(rest.len())
    };

    if name_end_in_rest == 0 {
        return None;
    }

    let name_range = 0..prefix_len + name_end_in_rest;
    let name = value[name_range.clone()].to_string();

    let after_name = &rest[name_end_in_rest..];
    let (version_req, version_range) = if let Some(after_at) = after_name.strip_prefix('@') {
        let ver_end_rel = after_at.find('/').unwrap_or(after_at.len());
        let ver_start = prefix_len + name_end_in_rest + 1;
        (
            Some(after_at[..ver_end_rel].to_string()),
            Some(ver_start..ver_start + ver_end_rel),
        )
    } else {
        (None, None)
    };

    Some(ParsedSpecifier {
        scheme,
        name,
        name_range,
        version_req,
        version_range,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsr_unversioned_subpath_excludes_subpath_from_name() {
        // C1: the original grammar (name [@ver] [/subpath]) mis-parsed this as name
        // "@std/fs/walk" because the subpath was only stripped when a version was present.
        let parsed = parse_specifier("jsr:@std/fs/walk").unwrap();
        assert_eq!(parsed.name, "jsr:@std/fs");
        assert_eq!(parsed.version_req, None);
    }

    #[test]
    fn npm_unversioned_subpath_excludes_subpath_from_name() {
        let parsed = parse_specifier("npm:preact/hooks").unwrap();
        assert_eq!(parsed.name, "npm:preact");
        assert_eq!(parsed.version_req, None);
    }

    #[test]
    fn jsr_versioned_subpath() {
        let parsed = parse_specifier("jsr:@std/encoding@1/base64").unwrap();
        assert_eq!(parsed.name, "jsr:@std/encoding");
        assert_eq!(parsed.version_req.as_deref(), Some("1"));
    }

    #[test]
    fn jsr_versioned_trailing_slash_empty_subpath() {
        let parsed = parse_specifier("jsr:@std/fs@1/").unwrap();
        assert_eq!(parsed.name, "jsr:@std/fs");
        assert_eq!(parsed.version_req.as_deref(), Some("1"));
    }

    #[test]
    fn empty_version_after_at_still_emits_a_version_range() {
        // S7: cursor right after typing '@' must still produce Some(version_range) (an
        // empty-span range), not None, so `CompletionContext::Version` can fire at exactly
        // that keystroke.
        let parsed = parse_specifier("jsr:@std/fs@").unwrap();
        assert_eq!(parsed.version_req.as_deref(), Some(""));
        let range = parsed.version_range.unwrap();
        assert_eq!(range.start, range.end);
    }

    #[test]
    fn npm_dist_tag_parses_but_later_fails_to_compile_as_a_range() {
        // M6: `npm:react@latest` parses fine at the specifier-grammar level; it is
        // `compile_requirement` (node_semver::Range::parse) that correctly rejects it —
        // the same as a dist-tag in package.json.
        let parsed = parse_specifier("npm:react@latest").unwrap();
        assert_eq!(parsed.name, "npm:react");
        assert_eq!(parsed.version_req.as_deref(), Some("latest"));
        assert!(node_semver::Range::parse("latest").is_err());
    }

    #[test]
    fn npm_scoped_name_with_version() {
        let parsed = parse_specifier("npm:@types/node@^18").unwrap();
        assert_eq!(parsed.name, "npm:@types/node");
        assert_eq!(parsed.version_req.as_deref(), Some("^18"));
    }

    #[test]
    fn unversioned_unscoped_name() {
        let parsed = parse_specifier("npm:chalk").unwrap();
        assert_eq!(parsed.name, "npm:chalk");
        assert_eq!(parsed.version_req, None);
    }

    #[test]
    fn unversioned_scoped_name_no_subpath() {
        let parsed = parse_specifier("jsr:@std/fs").unwrap();
        assert_eq!(parsed.name, "jsr:@std/fs");
        assert_eq!(parsed.version_req, None);
    }

    #[test]
    fn rejects_unknown_scheme() {
        assert!(parse_specifier("http://example.com/x.ts").is_none());
        assert!(parse_specifier("file:./local.ts").is_none());
        assert!(parse_specifier("./relative.ts").is_none());
        assert!(parse_specifier("node:fs").is_none());
        assert!(parse_specifier("bare-alias").is_none());
    }

    #[test]
    fn rejects_malformed_jsr_names() {
        assert!(parse_specifier("jsr:@std").is_none()); // missing "/pkg"
        assert!(parse_specifier("jsr:@std/").is_none()); // empty pkg
        assert!(parse_specifier("jsr:@/fs").is_none()); // empty scope
    }

    #[test]
    fn unscoped_jsr_name_parses_but_is_not_this_functions_job_to_reject() {
        // jsr: mandates a scoped package name, but that is a `validate_package_name`
        // diagnostic lint (see `DenoFormatter`), not a parse-time rejection here.
        let parsed = parse_specifier("jsr:std").unwrap();
        assert_eq!(parsed.name, "jsr:std");
    }

    #[test]
    fn name_range_spans_the_full_scheme_qualified_name() {
        // D2: name_range must cover the identical text PackageName holds, i.e. including
        // the "scheme:" prefix, not just the bare name after it.
        let value = "jsr:@std/fs@1.2";
        let parsed = parse_specifier(value).unwrap();
        assert_eq!(&value[parsed.name_range], "jsr:@std/fs");
    }

    #[test]
    fn version_range_slices_correctly() {
        let value = "jsr:@std/fs@1.2.3";
        let parsed = parse_specifier(value).unwrap();
        assert_eq!(&value[parsed.version_range.unwrap()], "1.2.3");
    }

    #[test]
    fn split_scheme_basic() {
        assert_eq!(split_scheme("jsr:@std/fs"), Some((Scheme::Jsr, "@std/fs")));
        assert_eq!(split_scheme("npm:react"), Some((Scheme::Npm, "react")));
        assert_eq!(split_scheme("https://x"), None);
    }

    #[test]
    fn split_scoped_basic() {
        assert_eq!(split_scoped("@std/fs"), Some(("std", "fs")));
        assert_eq!(split_scoped("react"), None);
        assert_eq!(split_scoped("@std"), None);
        assert_eq!(split_scoped("@/fs"), None);
        assert_eq!(split_scoped("@std/"), None);
    }
}
