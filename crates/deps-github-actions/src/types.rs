//! GitHub Actions dependency and version types.

use deps_core::lsp_helpers::CommitSha;
use deps_core::parser::DependencySource;
use deps_core::position::Range;
use std::fmt;
use url::Url;
use yaml_rust2::scanner::TScalarStyle;

/// How a `uses:` step's ref is pinned, driving requirement synthesis and edit shape.
///
/// `None` on [`GithubActionsDependency::pin`] (rather than a fourth variant here) covers
/// every non-resolvable form (`./local`, `docker://…`, a reusable-workflow call, or a bare
/// `uses: owner/repo` with no `@` at all) — those have no ref to classify.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinStyle {
    /// A tag ref, e.g. `@v4` or `@v4.2.0`.
    Tag,
    /// A 40-character commit SHA ref, optionally annotated with a trailing
    /// `# vX.Y.Z` comment naming the tag it corresponds to.
    Sha {
        /// The pinned commit, validated and lowercase-canonical.
        sha: CommitSha,
        /// The `# vX`/`# vX.Y`/`# vX.Y.Z` comment, if present and tag-shaped (see
        /// `parser`'s comment-tag rule, issue #907).
        comment: Option<ShaComment>,
    },
    /// A branch ref, e.g. `@main`.
    Branch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Delimiter {
    DoubleQuote,
    SingleQuote,
    Space,
    Tab,
    CloseBrace,
}

impl Delimiter {
    const fn as_char(self) -> char {
        match self {
            Self::DoubleQuote => '"',
            Self::SingleQuote => '\'',
            Self::Space => ' ',
            Self::Tab => '\t',
            Self::CloseBrace => '}',
        }
    }

    const fn blank(c: char) -> Option<Self> {
        match c {
            ' ' => Some(Self::Space),
            '\t' => Some(Self::Tab),
            _ => None,
        }
    }
}

/// The closing quote and flow-mapping `}` between a full-SHA ref and its `# tag` comment.
///
/// For instance the closing `"` of `uses: "a/b@<sha>" # v4`, or the `}` of
/// `{uses: a/b@<sha>} # v4`. Blanks before the `}` (`{ uses: a/b@<sha> } # v4`) are kept.
///
/// Non-empty only for a [`ShaComment`] that was read past those delimiters; every SHA-comment
/// rewrite re-emits them verbatim so the surrounding quote or flow mapping stays balanced. At most
/// one `}` is accepted: further closers end an outer collection, where a trailing comment cannot
/// be attributed to this ref. Restricted by construction to ASCII characters, so its byte length
/// equals its column width.
///
/// # Examples
///
/// ```
/// use deps_github_actions::ClosingDelimiters;
///
/// let none = ClosingDelimiters::default();
/// assert!(none.is_empty());
/// assert_eq!(none.byte_len(), 0);
/// assert_eq!(none.to_string(), "");
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClosingDelimiters(Vec<Delimiter>);

impl ClosingDelimiters {
    /// Parses the delimiters at the start of `tail` (the source text after the ref).
    ///
    /// A quoted scalar requires its own closing quote first; then blanks followed by one
    /// flow-mapping `}` may follow. Blanks not followed by `}` are not consumed, and block
    /// scalars or any other tail shape yield an empty value.
    pub(crate) fn parse(tail: &str, style: TScalarStyle) -> Self {
        let opening = match style {
            TScalarStyle::Plain => None,
            TScalarStyle::SingleQuoted => Some(Delimiter::SingleQuote),
            TScalarStyle::DoubleQuoted => Some(Delimiter::DoubleQuote),
            TScalarStyle::Literal | TScalarStyle::Folded => return Self::default(),
        };
        let mut chars = tail.chars();
        let mut delimiters = Vec::new();
        if let Some(quote) = opening {
            if chars.next() != Some(quote.as_char()) {
                return Self::default();
            }
            delimiters.push(quote);
        }
        let rest = chars.as_str();
        let blanks: Vec<Delimiter> = rest.chars().map_while(Delimiter::blank).collect();
        if rest.chars().nth(blanks.len()) == Some(Delimiter::CloseBrace.as_char()) {
            delimiters.extend(blanks);
            delimiters.push(Delimiter::CloseBrace);
        }
        Self(delimiters)
    }

    /// Whether no delimiter sits between the ref and its comment.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Length in bytes (equal to the column width, all delimiters being ASCII).
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Display for ClosingDelimiters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0
            .iter()
            .try_for_each(|d| fmt::Write::write_char(f, d.as_char()))
    }
}

/// The trailing `# <tag>` comment of a SHA-pinned `uses:` step.
///
/// Built only by the parser, so `tag` is always a tag-shaped token (see `parser`'s
/// comment-tag rule, issue #907) and `literal` is exactly the text the dependency's
/// `version_range` spans (`<sha>{closers} # <tag>`).
///
/// # Examples
///
/// ```
/// use deps_core::Dependency;
/// use deps_github_actions::{PinStyle, parse_workflow_yaml};
///
/// let sha = "a".repeat(40);
/// let content = format!("steps:\n  - uses: actions/checkout@{sha} # v4.2.0\n");
/// let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
/// let result = parse_workflow_yaml(&content, &uri).unwrap();
/// let Some(PinStyle::Sha { comment: Some(comment), .. }) = &result.dependencies[0].pin else {
///     unreachable!("fixture is a commented SHA pin");
/// };
/// assert_eq!(comment.tag(), "v4.2.0");
/// assert_eq!(comment.literal(), format!("{sha} # v4.2.0"));
/// assert!(comment.closing_delimiters().is_empty());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShaComment {
    tag: String,
    tag_range: Range,
    closers: ClosingDelimiters,
    literal: String,
}

impl ShaComment {
    pub(crate) const fn new(
        tag: String,
        tag_range: Range,
        closers: ClosingDelimiters,
        literal: String,
    ) -> Self {
        Self {
            tag,
            tag_range,
            closers,
            literal,
        }
    }

    /// The tag named by the comment (`v4.2.0`), without the `#`.
    #[must_use]
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// LSP range of the tag token alone, excluding the `#` and surrounding blanks.
    #[must_use]
    pub const fn tag_range(&self) -> Range {
        self.tag_range
    }

    /// The closing quote/flow closers between the SHA and the comment.
    #[must_use]
    pub const fn closing_delimiters(&self) -> &ClosingDelimiters {
        &self.closers
    }

    /// The raw `<sha>{closers} # <tag>` text the dependency's `version_range` spans.
    #[must_use]
    pub fn literal(&self) -> &str {
        &self.literal
    }
}

#[cfg(test)]
impl PinStyle {
    /// A [`PinStyle::Sha`] with a synthetic `# tag` comment, for tests that build dependencies
    /// by hand instead of parsing a workflow.
    pub(crate) fn sha_for_test(sha: &str, comment_tag: Option<&str>) -> Self {
        let sha = CommitSha::parse(sha).expect("test SHA must be 40 hex characters");
        let comment = comment_tag.map(|tag| {
            ShaComment::new(
                tag.to_string(),
                Range::default(),
                ClosingDelimiters::default(),
                format!("{sha} # {tag}"),
            )
        });
        Self::Sha { sha, comment }
    }
}

/// Parsed `uses:` dependency from a GitHub Actions workflow file, with position tracking.
///
/// `name` is `owner/repo` — truncated at the second `/` for a subdirectory action
/// (`github/codeql-action/init@v3` -> `github/codeql-action`) or a reusable-workflow call
/// (`owner/repo/.github/workflows/x.yml@ref` -> `owner/repo`).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubActionsDependency {
    /// `owner/repo` identity.
    pub name: deps_core::PackageName,
    /// LSP range of the `owner/repo` text (truncated at the second `/`).
    pub name_range: Range,
    /// Normalized version requirement: the tag text for a [`PinStyle::Tag`] or a
    /// [`PinStyle::Sha`] with a `comment`, the raw SHA for a commentless
    /// [`PinStyle::Sha`], the branch name for [`PinStyle::Branch`] — `None` for a
    /// non-resolvable source.
    pub version_req: Option<deps_core::VersionReq>,
    /// LSP range of the ref text — for a [`PinStyle::Sha`] with a `comment`, this
    /// extends through the comment token (`<40hex> # v4.2.0`), including any
    /// [`ClosingDelimiters`] in between (`<40hex>" # v4.2.0`). `None` for a
    /// non-resolvable source or a bare `uses: owner/repo` with no `@` at all.
    pub version_range: Option<Range>,
    /// How the ref is pinned; `None` for a non-resolvable source.
    pub pin: Option<PinStyle>,
    /// Dependency source: [`DependencySource::Registry`] for any `@ref` form (tag, SHA,
    /// or branch — all resolvable against the GitHub tags API by `name` alone),
    /// [`DependencySource::Path`] for `./local`, [`DependencySource::Url`] for
    /// `docker://image:tag` and a reusable-workflow call.
    pub source: DependencySource,
    /// Whether the whole `uses:` value was written as a plain (unquoted) YAML scalar,
    /// as opposed to single- or double-quoted (`uses: "actions/checkout@v4"`).
    ///
    /// For a quoted scalar, `version_range` spans text *inside* the quotes — writing
    /// `{sha} # {tag}` there would place a `#` inside the string rather than starting a
    /// YAML comment, producing a `uses:` value GitHub Actions rejects and that re-parses
    /// as [`PinStyle::Branch`] (issue #473, spec 031 FR-010). A SHA-pin code action must
    /// check this before writing any edit that assumes an unquoted YAML comment can
    /// follow the ref text — see `crate::formatter::GithubActionsFormatter::sha_pin_replacement_for`'s
    /// caller.
    pub is_plain_scalar: bool,
    /// Whether only whitespace, or a whitespace-preceded YAML comment, follows the ref
    /// text on its source line — `true` for `None`-`pin`/non-ref sources, where the value
    /// is irrelevant.
    ///
    /// `false` for a `uses:` step written in YAML **flow** style
    /// (`{uses: actions/checkout@v4, with: {node: 20}}`), where real YAML content
    /// (`, with: {...}}`) follows the ref on the same line. A SHA-pin edit appends
    /// `# <tag>` right after the ref text — safe for ordinary block-style lines, but for
    /// a flow-style line it turns the rest of the flow collection into a comment,
    /// producing invalid (unterminated) YAML. A SHA-pin code action must check this
    /// alongside [`Self::is_plain_scalar`] before writing any such edit (security audit
    /// finding, issue #633) — see
    /// `crate::formatter::GithubActionsFormatter::sha_pin_replacement_for`'s caller.
    pub is_last_on_line: bool,
}

impl GithubActionsDependency {
    /// The SHA pin's comment, when the step is a commented [`PinStyle::Sha`].
    #[must_use]
    pub const fn sha_comment(&self) -> Option<&ShaComment> {
        match &self.pin {
            Some(PinStyle::Sha {
                comment: Some(comment),
                ..
            }) => Some(comment),
            Some(PinStyle::Sha { comment: None, .. } | PinStyle::Tag | PinStyle::Branch) | None => {
                None
            }
        }
    }
}

impl deps_core::Dependency for GithubActionsDependency {
    fn name(&self) -> &deps_core::PackageName {
        &self.name
    }

    fn name_range(&self) -> Range {
        self.name_range
    }

    fn version_requirement(&self) -> Option<&deps_core::VersionReq> {
        self.version_req.as_ref()
    }

    fn version_range(&self) -> Option<Range> {
        self.version_range
    }

    fn source(&self) -> DependencySource {
        self.source.clone()
    }

    fn version_literal(&self) -> Option<&str> {
        self.sha_comment().map(ShaComment::literal)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Version information for a GitHub Actions dependency (a repository tag).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct GithubActionsVersion {
    /// The tag as published on GitHub, `v` prefix (or lack of one) kept as-is.
    pub version: deps_core::ConcreteVersion,
    /// The commit SHA this tag points at, as reported by the GitHub tags API.
    pub sha: deps_core::lsp_helpers::CommitSha,
    /// Whether the tag's semver `pre` component is non-empty, computed once from the
    /// `semver::Version` already parsed while sorting tags.
    pub prerelease: bool,
    /// When the matching GitHub Release was published, if the tags API's own response
    /// (which carries no timestamp) was enriched with one via
    /// [`crate::registry::GithubActionsRegistry::get_versions_with`]
    /// (#486). `None` for a plain [`GithubActionsRegistry::get_versions`](crate::registry::GithubActionsRegistry::get_versions)
    /// call, or when the tag has no matching (non-draft, dated) GitHub Release.
    pub published_at: Option<deps_core::PublishTime>,
}

// No yank/deprecation signal in GitHub's tags API (mirrors deps-swift), so status is always `Available`.
deps_core::impl_version!(GithubActionsVersion {
    version: version,
    status: |_v: &GithubActionsVersion| deps_core::RemovalStatus::Available,
    published_at: published_at,
    prerelease: |v: &GithubActionsVersion| v.prerelease,
});

/// Result of parsing a `.github/workflows/*.yml`/`*.yaml` file.
#[non_exhaustive]
#[derive(Debug)]
pub struct GithubActionsParseResult {
    /// Every `uses:` dependency found, including non-resolvable ones (their consumers
    /// filter on `version_range()`/`source()` as usual).
    pub dependencies: Vec<GithubActionsDependency>,
    /// URI of the parsed workflow file.
    pub uri: Url,
    /// `Some((kept, total))` once the manifest declared more dependencies than
    /// `deps_core::MAX_DEPENDENCIES_PER_DOCUMENT` (#796), read by
    /// [`deps_core::ParseResult::dependency_truncation`]'s override below.
    pub dependency_truncation: Option<(usize, usize)>,
}

deps_core::impl_parse_result!(
    GithubActionsParseResult,
    GithubActionsDependency {
        dependencies: dependencies,
        uri: uri,
        dependency_truncation: dependency_truncation,
    }
);

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::registry::Version;
    use deps_core::{Dependency, ParseResult, Position};

    fn range() -> Range {
        Range::new(Position::new(0, 0), Position::new(0, 10))
    }

    #[test]
    fn test_closing_delimiters_parse() {
        use TScalarStyle::{DoubleQuoted, Folded, Literal, Plain, SingleQuoted};
        let cases = [
            (" # v4", Plain, ""),
            ("\" # v4", DoubleQuoted, "\""),
            ("' # v4", SingleQuoted, "'"),
            ("} # v4", Plain, "}"),
            ("\"} # v4", DoubleQuoted, "\"}"),
            ("}} # v4", Plain, "}"),
            ("}}", Plain, "}"),
            ("\"}} # v4", DoubleQuoted, "\"}"),
            (" } # v4", Plain, " }"),
            ("\t } # v4", Plain, "\t }"),
            ("\" } # v4", DoubleQuoted, "\" }"),
            ("   # v4", Plain, ""),
            ("\"  # v4", DoubleQuoted, "\""),
            (" # v4", DoubleQuoted, ""),
            ("' # v4", DoubleQuoted, ""),
            ("\"} # v4", Plain, ""),
            ("} # v4", Literal, ""),
            ("} # v4", Folded, ""),
        ];
        for (tail, style, expected) in cases {
            let parsed = ClosingDelimiters::parse(tail, style);
            assert_eq!(parsed.to_string(), expected, "{tail:?} as {style:?}");
            assert_eq!(parsed.byte_len(), expected.len(), "{tail:?}");
            assert_eq!(parsed.is_empty(), expected.is_empty(), "{tail:?}");
        }
    }

    #[test]
    fn test_github_actions_dependency_tag_pin() {
        let dep = GithubActionsDependency {
            name: "actions/checkout".into(),
            name_range: range(),
            version_req: Some("v4".into()),
            version_range: Some(range()),
            pin: Some(PinStyle::Tag),
            source: DependencySource::Registry,
            is_plain_scalar: true,
            is_last_on_line: true,
        };
        assert_eq!(dep.name(), "actions/checkout");
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some("v4")
        );
        assert_eq!(dep.version_literal(), None);
    }

    #[test]
    fn test_github_actions_dependency_sha_with_comment_carries_literal() {
        let dep = GithubActionsDependency {
            name: "actions/checkout".into(),
            name_range: range(),
            version_req: Some("v4.2.0".into()),
            version_range: Some(range()),
            pin: Some(PinStyle::sha_for_test(
                "b4ffde65f46336ab88eb53be808477a3936bae11",
                Some("v4.2.0"),
            )),
            source: DependencySource::Registry,
            is_plain_scalar: true,
            is_last_on_line: true,
        };
        assert_eq!(
            dep.version_literal(),
            Some("b4ffde65f46336ab88eb53be808477a3936bae11 # v4.2.0")
        );
        assert_ne!(
            dep.version_literal(),
            dep.version_requirement().map(deps_core::VersionReq::as_str)
        );
    }

    #[test]
    fn test_github_actions_version_prerelease() {
        let stable = GithubActionsVersion {
            version: "v4.2.0".into(),
            sha: deps_core::lsp_helpers::CommitSha::parse(&"a".repeat(40)).unwrap(),
            prerelease: false,
            published_at: None,
        };
        let pre = GithubActionsVersion {
            version: "v4.2.0-beta.1".into(),
            sha: deps_core::lsp_helpers::CommitSha::parse(&"b".repeat(40)).unwrap(),
            prerelease: true,
            published_at: None,
        };
        assert!(!stable.is_prerelease());
        assert!(pre.is_prerelease());
        assert!(!stable.removal_status().blocks_resolution());
    }

    #[test]
    fn test_parse_result_dependencies_and_uri() {
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let result = GithubActionsParseResult {
            dependencies: vec![GithubActionsDependency {
                name: "actions/checkout".into(),
                name_range: range(),
                version_req: Some("v4".into()),
                version_range: Some(range()),
                pin: Some(PinStyle::Tag),
                source: DependencySource::Registry,
                is_plain_scalar: true,
                is_last_on_line: true,
            }],
            uri,
            dependency_truncation: None,
        };
        assert_eq!(result.dependencies().len(), 1);
        assert!(result.uri().path().ends_with("ci.yml"));
    }
}
