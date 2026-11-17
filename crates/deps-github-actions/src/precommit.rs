//! `.pre-commit-config.yaml` parser (#575, spec 044).
//!
//! Lives in this crate, not in `deps-precommit`, because the pre-commit ecosystem is a
//! [`crate::GitTagsFlavor`] of [`crate::GithubActionsEcosystem`]: a `repos[]` entry is an
//! `owner/repo@rev` pin like a workflow `uses:` step and reuses its dependency type, pin
//! classification and SHA-comment handling. `deps-precommit` depends on this crate.
//!
//! Only `https://github.com/<owner>/<repo>` repositories are resolvable. `local`, `meta` and
//! every other host or URL shape are skipped without error; a GitHub entry whose `repo` or
//! `rev` is missing or not a string is skipped with a warning.

use crate::parser::{RefSite, build_ref_dependency};
use crate::types::{GithubActionsDependency, GithubActionsParseResult};
use deps_core::lsp_helpers::{CommentStyle, LineOffsetTable, MarkedScalar, byte_span_to_range};
use deps_core::parser::DependencySource;
use deps_core::yaml_walk::{FrameKind, FrameStack, ScalarPosition};
use deps_core::{DepsError, Range, Result};
use url::Url;
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
use yaml_rust2::scanner::Marker;

const MANIFEST_LABEL: &str = ".pre-commit-config.yaml";
const GITHUB_HTTPS_PREFIX: &str = "https://github.com/";
const SHORT_HEX_REV_LENGTHS: std::ops::Range<usize> = 7..40;

/// What a YAML frame is in the pre-commit configuration's structure.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    /// Anything the parser does not read.
    Other,
    /// The document's root mapping.
    Root,
    /// The `repos:` sequence.
    ReposSeq,
    /// One `repos[]` mapping.
    Entry,
}

/// The key of the pair whose value is being read.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum Key {
    #[default]
    Other,
    Repos,
    Repo,
    Rev,
}

#[derive(Default)]
struct RawEntry {
    repo: Option<MarkedScalar>,
    rev: Option<MarkedScalar>,
}

impl RawEntry {
    /// `repo: local` / `repo: meta`: never a pin, so it must not use the dependency limit.
    fn is_local_or_meta(&self) -> bool {
        self.repo
            .as_ref()
            .is_some_and(|repo| matches!(repo.text().trim(), "local" | "meta"))
    }
}

struct PreCommitReceiver {
    stack: FrameStack<Role, Key, ()>,
    entries: Vec<RawEntry>,
}

impl PreCommitReceiver {
    fn child_role(&self, kind: FrameKind) -> Role {
        match (self.stack.top(), kind) {
            (None, FrameKind::Mapping) => Role::Root,
            (Some(top), FrameKind::Sequence)
                if *top.role() == Role::Root && *top.pending_key() == Key::Repos =>
            {
                Role::ReposSeq
            }
            (Some(top), FrameKind::Mapping) if *top.role() == Role::ReposSeq => Role::Entry,
            _ => Role::Other,
        }
    }

    fn push_container(&mut self, kind: FrameKind) {
        let role = self.child_role(kind);
        if role == Role::Entry {
            self.entries.push(RawEntry::default());
        }
        self.stack.push(kind, role, ());
    }

    fn key_for(&self, name: &str) -> Key {
        match (self.stack.top_role_or(Role::Other), name) {
            (Role::Root, "repos") => Key::Repos,
            (Role::Entry, "repo") => Key::Repo,
            (Role::Entry, "rev") => Key::Rev,
            _ => Key::Other,
        }
    }

    fn record_value(&mut self, scalar: MarkedScalar) {
        let Some(top) = self.stack.top() else {
            return;
        };
        if *top.role() != Role::Entry {
            return;
        }
        let key = *top.pending_key();
        let Some(entry) = self.entries.last_mut() else {
            return;
        };
        match key {
            Key::Repo => entry.repo = Some(scalar),
            Key::Rev => entry.rev = Some(scalar),
            Key::Repos | Key::Other => {}
        }
    }
}

impl MarkedEventReceiver for PreCommitReceiver {
    fn on_event(&mut self, event: Event, marker: Marker) {
        match event {
            Event::MappingStart(..) => self.push_container(FrameKind::Mapping),
            Event::SequenceStart(..) => self.push_container(FrameKind::Sequence),
            Event::MappingEnd | Event::SequenceEnd => {
                self.stack.pop();
            }
            Event::Scalar(value, style, _anchor, _tag) => {
                if self.stack.scalar_position() == ScalarPosition::Key {
                    let key = self.key_for(&value);
                    self.stack.observe_key(key);
                } else {
                    self.record_value(MarkedScalar::new(value, style, &marker));
                    self.stack.consume_value();
                }
            }
            Event::Alias(_) => self.stack.consume_value(),
            Event::Nothing
            | Event::StreamStart
            | Event::StreamEnd
            | Event::DocumentStart
            | Event::DocumentEnd => {}
        }
    }
}

/// The `owner/repo` of an `https://github.com/<owner>/<repo>[.git][/]` URL, `None` for any
/// other host, scheme, userinfo, port, query, fragment or path depth.
fn github_repo_name(url: &str) -> Option<String> {
    let path = url.strip_prefix(GITHUB_HTTPS_PREFIX)?;
    let path = path.strip_suffix('/').unwrap_or(path);
    let path = path.strip_suffix(".git").unwrap_or(path);
    let (owner, repo) = path.split_once('/')?;
    let name = format!("{owner}/{repo}");
    (!repo.contains('/') && crate::is_valid_github_identity(&name)).then_some(name)
}

/// Whether `scalar` is a plain YAML number, boolean or null, which pre-commit rejects where a
/// string is required (`rev: 12`, `rev: 24.1`, `rev:`).
fn is_plain_non_string(scalar: &MarkedScalar) -> bool {
    let text = scalar.text();
    scalar.is_plain()
        && (matches!(
            text,
            "" | "~"
                | "null"
                | "Null"
                | "NULL"
                | "true"
                | "True"
                | "TRUE"
                | "false"
                | "False"
                | "FALSE"
        ) || (text.starts_with(|c: char| c.is_ascii_digit() || matches!(c, '+' | '-' | '.'))
            && text.parse::<f64>().is_ok()))
}

fn is_short_hex(rev: &str) -> bool {
    SHORT_HEX_REV_LENGTHS.contains(&rev.len()) && rev.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The trimmed byte span of `scalar` and its trimmed text.
// `span_start` is re-anchored over leading whitespace of the located span, which `trim_start`
// cuts only at char boundaries.
fn trimmed_span(
    scalar: &MarkedScalar,
    content: &str,
    line_table: &LineOffsetTable,
) -> Option<(usize, usize, String)> {
    let (raw_start, raw_end) = scalar.span(content, line_table)?;
    let text = scalar.text();
    let leading = text.len() - text.trim_start().len();
    let trailing = text.len() - text.trim_end().len();
    Some((
        raw_start + leading,
        raw_end.saturating_sub(trailing),
        text.trim().to_owned(),
    ))
}

/// A `repos[]` entry that should have been a pin but has a missing, non-string or empty
/// `repo` or `rev`; counted and reported once per document.
struct MalformedEntry;

/// `Ok(None)` for an entry that is deliberately not a GitHub pin (`local`, `meta`, another
/// host); `Err` for a malformed one.
fn build_dependency(
    content: &str,
    line_table: &LineOffsetTable,
    entry: RawEntry,
) -> std::result::Result<Option<GithubActionsDependency>, MalformedEntry> {
    let repo = entry.repo.ok_or(MalformedEntry)?;
    let Some((name_start, name_end, repo_text)) = trimmed_span(&repo, content, line_table) else {
        return Ok(None);
    };
    let Some(name) = github_repo_name(&repo_text).filter(|_| !is_plain_non_string(&repo)) else {
        tracing::debug!("skipping a pre-commit repository that is not an https GitHub URL");
        return Ok(None);
    };
    let name_range = byte_span_to_range(content, line_table, name_start, name_end);

    let rev = entry
        .rev
        .filter(|rev| !is_plain_non_string(rev))
        .ok_or(MalformedEntry)?;
    let Some((ref_start, _, ref_text)) = trimmed_span(&rev, content, line_table) else {
        return Ok(None);
    };
    if ref_text.is_empty() {
        return Err(MalformedEntry);
    }
    if is_short_hex(&ref_text) {
        return Ok(Some(non_resolvable(name, name_range, rev.is_plain())));
    }
    Ok(Some(build_ref_dependency(&RefSite {
        content,
        line_table,
        name,
        name_range,
        ref_text,
        ref_start,
        line: rev.line(),
        style: rev.style(),
        is_plain_scalar: rev.is_plain(),
        accepted_comments: CommentStyle::ALL,
    })))
}

/// A short commit hash cannot be matched against tags, so it carries no version to check.
fn non_resolvable(
    name: String,
    name_range: Range,
    is_plain_scalar: bool,
) -> GithubActionsDependency {
    GithubActionsDependency {
        name: name.into(),
        name_range,
        version_req: None,
        version_range: None,
        pin: None,
        source: DependencySource::Registry,
        is_plain_scalar,
        is_last_on_line: true,
    }
}

/// Parses a pre-commit configuration into one dependency per GitHub `repos[]` entry that has
/// a `rev`.
///
/// Entries for `local`/`meta` repositories and non-GitHub hosts are skipped without error.
/// A `rev` of 7 to 39 hex digits is a short commit hash with no resolvable version.
///
/// # Errors
///
/// Returns an error when `content` is not valid YAML or exceeds the shared nesting-depth or
/// expansion-size gate.
///
/// # Examples
///
/// ```
/// use deps_core::Dependency;
/// use deps_github_actions::parse_precommit_config;
///
/// let content = "repos:\n  - repo: https://github.com/psf/black\n    rev: 24.1.0\n";
/// let uri = deps_core::test_util::test_uri("/repo/.pre-commit-config.yaml");
/// let result = parse_precommit_config(content, &uri).unwrap();
///
/// assert_eq!(result.dependencies.len(), 1);
/// assert_eq!(result.dependencies[0].name(), "psf/black");
/// ```
pub fn parse_precommit_config(content: &str, uri: &Url) -> Result<GithubActionsParseResult> {
    deps_core::check_yaml_bounds(content, MANIFEST_LABEL)?;

    let mut receiver = PreCommitReceiver {
        stack: FrameStack::new(),
        entries: Vec::new(),
    };
    Parser::new_from_str(content)
        .load(&mut receiver, false)
        .map_err(|e| DepsError::parse_error(MANIFEST_LABEL, &e))?;

    let line_table = LineOffsetTable::new(content);
    let mut budget = deps_core::DependencyBudget::new(deps_core::MAX_DEPENDENCIES_PER_DOCUMENT);
    let mut dependencies = Vec::new();
    let mut malformed = 0_usize;
    let mut first_malformed = None;
    for (index, entry) in receiver.entries.into_iter().enumerate() {
        if entry.is_local_or_meta() || !budget.allow() {
            continue;
        }
        match build_dependency(content, &line_table, entry) {
            Ok(dependency) => dependencies.extend(dependency),
            Err(MalformedEntry) => {
                malformed += 1;
                first_malformed.get_or_insert(index);
            }
        }
    }
    if let Some(first) = first_malformed {
        tracing::warn!(
            malformed,
            first_index = first,
            "skipped pre-commit `repos[]` entries whose `repo` or `rev` is missing, empty or not a string"
        );
    }

    Ok(GithubActionsParseResult {
        dependencies,
        uri: uri.clone(),
        dependency_truncation: budget.truncation(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_and_meta_entries_do_not_use_the_dependency_limit() {
        let limit = deps_core::MAX_DEPENDENCIES_PER_DOCUMENT;
        let mut content = String::from("repos:\n");
        for _ in 0..limit {
            content.push_str("  - repo: local\n    hooks: []\n  - repo: meta\n    hooks: []\n");
        }
        content.push_str("  - repo: https://github.com/psf/black\n    rev: 24.1.0\n");
        let uri = deps_core::test_util::test_uri("/repo/.pre-commit-config.yaml");

        let parsed = parse_precommit_config(&content, &uri).expect("valid yaml");

        assert_eq!(parsed.dependencies.len(), 1);
        assert!(parsed.dependency_truncation.is_none());
    }
}
