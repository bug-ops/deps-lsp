//! Per-package exemption lists of the native release-age settings (`min-release-age-exclude`,
//! `minimumReleaseAgeExclude(s)`, uv `exclude-newer-package`).
//!
//! A list is parsed once per dialect. An entry this reader cannot interpret exactly rejects the
//! whole list, so a partially understood list never exempts more than the user wrote. Lists come
//! from repository-controlled files, so every size is capped: entries, bytes per entry, the total
//! number of exempt versions, and the length of a package name that is matched at all.

use std::collections::HashMap;
use std::sync::Arc;

use crate::ConcreteVersion;

/// Most entries one list may carry.
const MAX_ENTRIES: usize = 1024;
/// Longest single entry, in bytes.
const MAX_ENTRY_BYTES: usize = 512;
/// Most exempt versions one list may name in total, across every entry.
const MAX_VERSIONS: usize = 4096;
/// Most wildcard patterns one list may carry; each costs a scan per looked-up name.
const MAX_WILDCARD_ENTRIES: usize = 64;
/// Most pattern bytes the wildcard patterns of one list may total.
const MAX_WILDCARD_BYTES: usize = 4096;
/// Longest package name matched against a list; npm names are at most 214 bytes, and a longer
/// one cannot be a real package, so it is never exempt.
const MAX_NAME_BYTES: usize = 214;

/// Package-manager dialect an exemption list is written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExemptionSyntax {
    /// npm `min-release-age-exclude` (minimatch `*` within one path segment).
    Npm,
    /// pnpm `minimumReleaseAgeExclude`.
    Pnpm,
    /// Bun `minimumReleaseAgeExcludes`.
    Bun,
    /// uv `exclude-newer-package` names, matched exactly.
    Uv,
}

/// Which versions of a package an exemption list releases from the window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exemption {
    /// The package is not exempt.
    None,
    /// Every version of the package is exempt.
    AllVersions,
    /// Only the listed versions are exempt. Shared with the list, never copied per lookup.
    Versions(Arc<[ConcreteVersion]>),
}

/// Why an exemption list was rejected as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExemptionError {
    /// An entry uses syntax this reader does not support.
    #[error("unsupported exemption entry")]
    Unsupported,
    /// The list or one of its entries exceeds the size caps.
    #[error("exemption list too large")]
    TooLarge,
}

/// How far a `*` reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StarScope {
    /// A `*` never crosses a `/` (npm's minimatch).
    WithinSegment,
    /// A `*` matches any character, `/` included.
    AnyCharacter,
    /// No wildcard: the name must match exactly.
    Exact,
}

impl ExemptionSyntax {
    const fn star_scope(self) -> StarScope {
        match self {
            Self::Npm => StarScope::WithinSegment,
            Self::Pnpm | Self::Bun => StarScope::AnyCharacter,
            Self::Uv => StarScope::Exact,
        }
    }

    const fn allows_version_alternatives(self) -> bool {
        matches!(self, Self::Pnpm | Self::Bun)
    }
}

/// The versions an exact name exempts (`None`: every version). Entries naming the same name
/// are merged at parse time.
type ExactVersions = Option<Arc<[ConcreteVersion]>>;

/// A parsed per-package exemption list.
///
/// # Examples
///
/// ```
/// use deps_core::native_cooldown::{Exemption, ExemptionSyntax, parse_exemptions};
///
/// let list = parse_exemptions(&["@types/*", "lodash@4.17.21"], ExemptionSyntax::Npm).unwrap();
/// assert_eq!(list.lookup("@types/node"), Exemption::AllVersions);
/// assert!(matches!(list.lookup("lodash"), Exemption::Versions(versions) if versions.len() == 1));
/// assert_eq!(list.lookup("express"), Exemption::None);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExemptionList {
    scope: StarScope,
    /// Patterns without `*`, found by hash: a lookup never scans them.
    exact: HashMap<String, ExactVersions>,
    /// Patterns with `*` (always exempting every version), scanned per lookup and therefore
    /// capped in number and total size.
    wildcards: Vec<String>,
}

impl ExemptionList {
    /// What the list exempts for the package `name`.
    ///
    /// An entry without a version wins over version-scoped entries for the same name. A name
    /// longer than any real package name is never exempt.
    #[must_use]
    pub fn lookup(&self, name: &str) -> Exemption {
        if name.len() > MAX_NAME_BYTES {
            return Exemption::None;
        }
        let versions = match self.exact.get(name) {
            Some(None) => return Exemption::AllVersions,
            Some(Some(listed)) => Some(Arc::clone(listed)),
            None => None,
        };
        if self
            .wildcards
            .iter()
            .any(|pattern| matches_name(pattern, name, self.scope))
        {
            return Exemption::AllVersions;
        }
        versions.map_or(Exemption::None, Exemption::Versions)
    }
}

/// Parses `entries` in the given dialect.
///
/// # Errors
///
/// [`ExemptionError::TooLarge`] when there are more than 1024 entries, one exceeds 512 bytes,
/// the list names more than 4096 versions in total, or it carries more than 64 distinct wildcard
/// patterns or more than 4096 wildcard bytes; [`ExemptionError::Unsupported`] when any
/// entry uses syntax outside the supported subset (globs other than `*`, negation, version
/// ranges, a wildcard combined with a version).
pub fn parse_exemptions(
    entries: &[&str],
    syntax: ExemptionSyntax,
) -> Result<ExemptionList, ExemptionError> {
    if entries.len() > MAX_ENTRIES || entries.iter().any(|entry| entry.len() > MAX_ENTRY_BYTES) {
        return Err(ExemptionError::TooLarge);
    }
    let mut merged: Vec<(String, Option<Vec<ConcreteVersion>>)> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut total_versions = 0_usize;
    for raw in entries {
        let (pattern, versions) = parse_entry(raw, syntax)?;
        total_versions += versions.as_ref().map_or(0, Vec::len);
        if total_versions > MAX_VERSIONS {
            return Err(ExemptionError::TooLarge);
        }
        match index.get(&pattern) {
            Some(&at) => merge(&mut merged, at, versions),
            None => {
                index.insert(pattern.clone(), merged.len());
                merged.push((pattern, versions));
            }
        }
    }
    let mut exact = HashMap::new();
    let mut wildcards = Vec::new();
    for (pattern, versions) in merged {
        if pattern.contains('*') {
            wildcards.push(pattern);
        } else {
            exact.insert(pattern, versions.map(Arc::from));
        }
    }
    let wildcard_bytes: usize = wildcards.iter().map(String::len).sum();
    if wildcards.len() > MAX_WILDCARD_ENTRIES || wildcard_bytes > MAX_WILDCARD_BYTES {
        return Err(ExemptionError::TooLarge);
    }
    Ok(ExemptionList {
        scope: syntax.star_scope(),
        exact,
        wildcards,
    })
}

/// Folds a repeated pattern into the entry at `at`: an entry without versions wins.
fn merge(
    merged: &mut [(String, Option<Vec<ConcreteVersion>>)],
    at: usize,
    versions: Option<Vec<ConcreteVersion>>,
) {
    let Some((_, existing)) = merged.get_mut(at) else {
        return;
    };
    *existing = match (existing.take(), versions) {
        (Some(mut have), Some(more)) => {
            have.extend(more);
            Some(have)
        }
        _ => None,
    };
}

fn parse_entry(
    raw: &str,
    syntax: ExemptionSyntax,
) -> Result<(String, Option<Vec<ConcreteVersion>>), ExemptionError> {
    let (pattern, version_text) = split_version(raw, syntax);
    let name_ok = !pattern.is_empty()
        && pattern.bytes().all(is_name_byte)
        && (syntax != ExemptionSyntax::Uv || !pattern.contains('*'));
    if !name_ok {
        return Err(ExemptionError::Unsupported);
    }
    let versions = match version_text {
        None => None,
        Some(_) if pattern.contains('*') => return Err(ExemptionError::Unsupported),
        Some(text) => Some(parse_versions(text, syntax)?),
    };
    Ok((pattern.to_owned(), versions))
}

/// Splits `name@versions` at the last `@` that is not the scope marker.
fn split_version(raw: &str, syntax: ExemptionSyntax) -> (&str, Option<&str>) {
    if syntax == ExemptionSyntax::Uv {
        return (raw, None);
    }
    let split = raw
        .rfind('@')
        .filter(|&at| at > 0)
        .and_then(|at| raw.split_at_checked(at));
    match split {
        Some((name, rest)) => (name, rest.strip_prefix('@')),
        None => (raw, None),
    }
}

fn parse_versions(
    text: &str,
    syntax: ExemptionSyntax,
) -> Result<Vec<ConcreteVersion>, ExemptionError> {
    let parts: Vec<&str> = if syntax.allows_version_alternatives() {
        text.split("||").map(str::trim).collect()
    } else {
        vec![text]
    };
    let exact = |part: &&str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+' | b'_'))
    };
    if parts.iter().all(exact) {
        Ok(parts.into_iter().map(ConcreteVersion::new).collect())
    } else {
        Err(ExemptionError::Unsupported)
    }
}

/// Bytes a supported name pattern may contain: no glob syntax other than `*`, no negation, no
/// whitespace.
const fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'@' | b'/' | b'*')
}

fn matches_name(pattern: &str, name: &str, scope: StarScope) -> bool {
    match scope {
        StarScope::Exact => pattern == name,
        StarScope::AnyCharacter => glob_matches(pattern, name),
        StarScope::WithinSegment => {
            let mut pattern_segments = pattern.split('/');
            let mut name_segments = name.split('/');
            loop {
                match (pattern_segments.next(), name_segments.next()) {
                    (None, None) => return true,
                    (Some(p), Some(n)) if glob_matches(p, n) => {}
                    _ => return false,
                }
            }
        }
    }
}

/// Linear-time `*` matcher: the text between stars is located left to right with one
/// substring search each, so there is no backtracking and no nested scan.
fn glob_matches(pattern: &str, text: &str) -> bool {
    let Some((first, after_first)) = pattern.split_once('*') else {
        return pattern == text;
    };
    let Some(rest) = text.strip_prefix(first) else {
        return false;
    };
    let (middle, last) = after_first.rsplit_once('*').unwrap_or(("", after_first));
    let Some(mut rest) = rest.strip_suffix(last) else {
        return false;
    };
    for piece in middle.split('*').filter(|piece| !piece.is_empty()) {
        let Some((_, after)) = rest.split_once(piece) else {
            return false;
        };
        rest = after;
    }
    true
}
