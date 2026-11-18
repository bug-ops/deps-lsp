//! `update --open-pr --close-superseded` (#2073): after a request is opened, closes the open
//! requests of the same author that the new one makes obsolete.
//!
//! Every request carries a hidden [`RequestMarker`] naming the update set it proposes. A request
//! is closed only when all six gates hold: same author, same repository, a `deps-cli/<eco>/`
//! branch (narrowed to the manifest's directory part), exactly one commit, a marker of the same
//! scope, and every target at or below the new one. At most [`MAX_CANDIDATES_READ`] candidates
//! are read per run, oldest first. A request that gained commits is kept, but an edit to the
//! title or body text is not detected, and a request of another author, a newer proposal or a
//! request without a marker is never touched. Any failed step is a warning and closes nothing.

use deps_core::lsp_helpers::{EcosystemFormatter, RequirementGate};
use deps_core::{ConcreteVersion, EcosystemId, VersionReq};
use serde::{Deserialize, Serialize};

use super::git::{Runner, Step, Tool};
use super::{OpenedRequest, PrError, PrHost, RepoContext, UpdateGroup, proposed_updates};
use crate::update::UpdatePlan;

const MARKER_OPEN: &str = "<!-- deps-cli:request ";
const MARKER_CLOSE: &str = " -->";
const MARKER_VERSION: u8 = 1;
/// Larger markers are left out of the body, so such a request is never closed later.
const MARKER_MAX_BYTES: usize = 16 * 1024;
/// Candidates read per run; each costs one `gh` call or two `glab` calls.
const MAX_CANDIDATES_READ: usize = 50;
const GITHUB_LIST_LIMIT: usize = 200;
const GITLAB_LIST_LIMIT: usize = 100;

/// Whether `--close-superseded` was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupersededPolicy {
    /// Leave earlier requests open.
    Keep,
    /// Close the earlier requests the new one supersedes.
    Close,
}

impl SupersededPolicy {
    /// The policy a `--close-superseded` flag selects.
    #[must_use]
    pub const fn from_flag(close: bool) -> Self {
        if close { Self::Close } else { Self::Keep }
    }
}

/// How the update set of a run was chosen; a request of one mode never supersedes another's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunMode {
    /// The default planner.
    Default,
    /// `--security-only`.
    SecurityOnly,
}

impl RunMode {
    /// The mode a `--security-only` flag selects.
    #[must_use]
    pub const fn from_security_only(security_only: bool) -> Self {
        if security_only {
            Self::SecurityOnly
        } else {
            Self::Default
        }
    }
}

/// Serializes an [`EcosystemId`] as its canonical id; an unknown id fails to parse, so a marker
/// naming one is treated as absent.
mod ecosystem_id {
    use std::str::FromStr;

    use deps_core::EcosystemId;
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "the signature serde's `with` requires"
    )]
    pub(super) fn serialize<S: Serializer>(id: &EcosystemId, out: S) -> Result<S::Ok, S::Error> {
        out.serialize_str(id.id())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        input: D,
    ) -> Result<EcosystemId, D::Error> {
        EcosystemId::from_str(&String::deserialize(input)?).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MarkerUpdate {
    name: String,
    target: String,
}

/// The update set a request proposes, embedded in its body as a hidden comment.
///
/// # Examples
///
/// ```
/// use deps_cli::update::pr::RunMode;
///
/// assert_eq!(RunMode::from_security_only(true), RunMode::SecurityOnly);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestMarker {
    v: u8,
    #[serde(with = "ecosystem_id")]
    ecosystem: EcosystemId,
    pub(super) manifest: String,
    group: String,
    pub(super) mode: RunMode,
    updates: Vec<MarkerUpdate>,
}

impl RequestMarker {
    /// The marker of the update set `plan` proposes for `ctx`'s manifest.
    #[must_use]
    pub fn new(
        ctx: &RepoContext,
        ecosystem: EcosystemId,
        mode: RunMode,
        plan: &UpdatePlan,
        formatter: &dyn EcosystemFormatter,
        group: Option<&UpdateGroup>,
    ) -> Self {
        Self {
            v: MARKER_VERSION,
            ecosystem,
            manifest: ctx.manifest_path(),
            group: group.map_or_else(String::new, |group| group.name().as_str().to_owned()),
            mode,
            updates: proposed_updates(plan, formatter)
                .into_iter()
                .map(|(name, target)| MarkerUpdate {
                    name,
                    target: target.as_str().to_owned(),
                })
                .collect(),
        }
    }

    /// The hidden comment, or `None` when it would be too large to embed. Every `>` is escaped,
    /// so no value can end the comment early.
    pub(super) fn render(&self) -> Option<String> {
        let json = serde_json::to_string(self).ok()?.replace('>', "\\u003e");
        let comment = format!("{MARKER_OPEN}{json}{MARKER_CLOSE}");
        (comment.len() <= MARKER_MAX_BYTES).then_some(comment)
    }

    pub(super) fn from_body(body: &str) -> Option<Self> {
        let (_, after_open) = body.rsplit_once(MARKER_OPEN)?;
        let (json, _) = after_open.split_once(MARKER_CLOSE)?;
        serde_json::from_str::<Self>(json)
            .ok()
            .filter(|marker| marker.v == MARKER_VERSION)
    }

    fn same_scope(&self, other: &Self) -> bool {
        self.ecosystem == other.ecosystem
            && self.manifest == other.manifest
            && self.group == other.group
            && self.mode == other.mode
    }

    /// Whether `newer` proposes, for every dependency of `self`, a target at or above
    /// `self`'s. A comparison the formatter cannot make counts as not covered.
    fn is_covered_by(&self, newer: &Self, formatter: &dyn EcosystemFormatter) -> bool {
        let ordering = version_ordering(self.ecosystem);
        !self.updates.is_empty()
            && self.updates.iter().all(|old| {
                newer.updates.iter().any(|new| {
                    new.name == old.name
                        && target_at_least(ordering, formatter, &new.target, &old.target)
                })
            })
    }
}

/// How a request's targets are ordered to decide that a newer request covers an older one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VersionOrdering {
    /// A `>=<old target>` requirement compiled by the formatter; verified sound for the seven
    /// ecosystems whose matcher follows their resolver.
    RequirementFloor,
    /// The formatter's own `compare_versions`, `None` for a pair it cannot order.
    Native,
    /// No version ordering exists (refs and hashes), so a request is never closed.
    Unordered,
}

const fn version_ordering(ecosystem: EcosystemId) -> VersionOrdering {
    match ecosystem {
        EcosystemId::Cargo
        | EcosystemId::Npm
        | EcosystemId::Pypi
        | EcosystemId::Bundler
        | EcosystemId::Composer
        | EcosystemId::Dart
        | EcosystemId::Deno => VersionOrdering::RequirementFloor,
        EcosystemId::Go
        | EcosystemId::Maven
        | EcosystemId::Gradle
        | EcosystemId::Swift
        | EcosystemId::NuGet => VersionOrdering::Native,
        EcosystemId::GithubActions | EcosystemId::GitlabCi | EcosystemId::PreCommit => {
            VersionOrdering::Unordered
        }
    }
}

/// Whether `new` is at or above `old`; a pair the ordering cannot decide is not.
fn target_at_least(
    ordering: VersionOrdering,
    formatter: &dyn EcosystemFormatter,
    new: &str,
    old: &str,
) -> bool {
    match ordering {
        VersionOrdering::RequirementFloor => formatter
            .compile_requirement(&VersionReq::new(format!(">={old}")))
            .is_some_and(|floor| floor.matches(&ConcreteVersion::new(new)) == Some(true)),
        VersionOrdering::Native => formatter
            .compare_versions(&ConcreteVersion::new(new), &ConcreteVersion::new(old))
            .is_some_and(std::cmp::Ordering::is_ge),
        VersionOrdering::Unordered => false,
    }
}

/// A pull or merge request number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestNumber(u64);

impl std::fmt::Display for RequestNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// Why a step of the superseded-request cleanup failed.
#[derive(Debug, thiserror::Error)]
pub enum SupersedeError {
    /// A host CLI step failed.
    #[error(transparent)]
    Host(#[from] PrError),
    /// The ecosystem's version matcher is not known to order versions soundly.
    #[error("closing superseded requests is not supported for {0}")]
    UnsupportedEcosystem(EcosystemId),
    /// A host CLI printed output that could not be read.
    #[error("{tool} printed output that could not be read while {step}")]
    Unreadable {
        /// The program.
        tool: Tool,
        /// The step.
        step: Step,
    },
    /// A host CLI printed more than the capture cap, so the answer is incomplete.
    #[error("{tool} printed more than the capture limit while {step}")]
    Truncated {
        /// The program.
        tool: Tool,
        /// The step.
        step: Step,
    },
}

/// What the cleanup did.
#[derive(Debug, Default)]
pub struct SupersedeReport {
    /// Requests that were closed.
    pub closed: Vec<RequestNumber>,
    /// Steps that failed; each one left its request open.
    pub failures: Vec<SupersedeError>,
    /// How much of the open requests the run looked at.
    pub coverage: SweepCoverage,
}

/// How much of the author's open requests a sweep looked at.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum SweepCoverage {
    /// Every listed candidate was read.
    #[default]
    Complete,
    /// The listing was full, so more open requests may exist than were listed.
    ListingFull,
    /// More candidates matched than `MAX_CANDIDATES_READ`; the newest were not read.
    CandidateCapReached,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Author {
    login: String,
    bot: bool,
}

/// What the gates need to know about one request.
#[derive(Debug)]
struct Request {
    number: RequestNumber,
    author: Author,
    same_repository: bool,
    head: String,
    commits: usize,
    body: String,
}

#[derive(Deserialize)]
struct GhAuthor {
    login: String,
    is_bot: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GhMeta {
    number: u64,
    author: GhAuthor,
    head_ref_name: String,
    is_cross_repository: bool,
    commits: usize,
    body: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GhListed {
    number: u64,
    head_ref_name: String,
}

#[derive(Deserialize)]
struct GlabAuthor {
    username: String,
}

#[derive(Deserialize)]
struct GlabMr {
    iid: u64,
    author: GlabAuthor,
    source_branch: String,
    source_project_id: u64,
    target_project_id: u64,
    description: Option<String>,
}

#[derive(Deserialize)]
struct GlabListed {
    iid: u64,
    source_branch: String,
}

/// The first request page: the candidates whose head carries the prefix, and whether it was full.
struct Listing {
    numbers: Vec<RequestNumber>,
    full: bool,
}

struct Host<'a> {
    runner: Runner,
    kind: PrHost,
    ctx: &'a RepoContext,
}

impl Host<'_> {
    const fn tool(&self) -> Tool {
        match self.kind {
            PrHost::Github => Tool::Gh,
            PrHost::Gitlab => Tool::Glab,
        }
    }

    async fn read(&self, step: Step, args: Vec<String>) -> Result<String, SupersedeError> {
        let tool = self.tool();
        let output = self.runner.run(tool, step, &self.ctx.root, args).await?;
        match output.code {
            Some(0) if output.truncated => Err(SupersedeError::Truncated { tool, step }),
            Some(0) => Ok(output.stdout),
            code => Err(PrError::ToolFailed { tool, step, code }.into()),
        }
    }

    fn parse<T: serde::de::DeserializeOwned>(
        &self,
        step: Step,
        text: &str,
    ) -> Result<T, SupersedeError> {
        serde_json::from_str(text).map_err(|_| SupersedeError::Unreadable {
            tool: self.tool(),
            step,
        })
    }

    /// Reads one request by URL or number.
    async fn fetch(&self, reference: &str) -> Result<Request, SupersedeError> {
        let step = Step::ReadRequest;
        match self.kind {
            PrHost::Github => {
                let meta = self
                    .read(
                        step,
                        strings(&[
                            "pr",
                            "view",
                            reference,
                            "--json",
                            "number,author,headRefName,isCrossRepository,commits,body",
                            "--jq",
                            "{number,author,headRefName,isCrossRepository,commits:(.commits|length),body}",
                        ]),
                    )
                    .await?;
                let meta: GhMeta = self.parse(step, &meta)?;
                Ok(Request {
                    number: RequestNumber(meta.number),
                    author: Author {
                        login: meta.author.login,
                        bot: meta.author.is_bot,
                    },
                    same_repository: !meta.is_cross_repository,
                    head: meta.head_ref_name,
                    commits: meta.commits,
                    body: meta.body.unwrap_or_default(),
                })
            }
            PrHost::Gitlab => {
                let view = self
                    .read(
                        step,
                        strings(&["mr", "view", glab_reference(reference), "--output", "json"]),
                    )
                    .await?;
                let mr: GlabMr = self.parse(step, &view)?;
                let commits = self
                    .read(
                        step,
                        vec![
                            "api".to_owned(),
                            format!("projects/:id/merge_requests/{}/commits", mr.iid),
                        ],
                    )
                    .await?;
                let commits: Vec<serde::de::IgnoredAny> = self.parse(step, &commits)?;
                Ok(Request {
                    number: RequestNumber(mr.iid),
                    author: Author {
                        login: mr.author.username,
                        bot: false,
                    },
                    same_repository: mr.source_project_id == mr.target_project_id,
                    head: mr.source_branch,
                    commits: commits.len(),
                    body: mr.description.unwrap_or_default(),
                })
            }
        }
    }

    /// Lists the open requests of `author` whose head starts with `prefix`.
    async fn list(&self, author: &Author, prefix: &str) -> Result<Listing, SupersedeError> {
        let step = Step::ListRequests;
        let (listed, limit): (Vec<(u64, String)>, usize) = match self.kind {
            PrHost::Github => {
                let who = if author.bot {
                    let slug = author.login.strip_prefix("app/").unwrap_or(&author.login);
                    format!("--app={}", slug.strip_suffix("[bot]").unwrap_or(slug))
                } else {
                    format!("--author={}", author.login)
                };
                let text = self
                    .read(
                        step,
                        vec![
                            "pr".to_owned(),
                            "list".to_owned(),
                            "--state=open".to_owned(),
                            who,
                            format!("--limit={GITHUB_LIST_LIMIT}"),
                            "--json=number,headRefName".to_owned(),
                        ],
                    )
                    .await?;
                let rows: Vec<GhListed> = self.parse(step, &text)?;
                (
                    rows.into_iter()
                        .map(|row| (row.number, row.head_ref_name))
                        .collect(),
                    GITHUB_LIST_LIMIT,
                )
            }
            PrHost::Gitlab => {
                let text = self
                    .read(
                        step,
                        vec![
                            "mr".to_owned(),
                            "list".to_owned(),
                            format!("--author={}", author.login),
                            format!("--per-page={GITLAB_LIST_LIMIT}"),
                            "--output=json".to_owned(),
                        ],
                    )
                    .await?;
                let rows: Vec<GlabListed> = self.parse(step, &text)?;
                (
                    rows.into_iter()
                        .map(|row| (row.iid, row.source_branch))
                        .collect(),
                    GITLAB_LIST_LIMIT,
                )
            }
        };
        Ok(Listing {
            full: listed.len() >= limit,
            numbers: listed
                .into_iter()
                .filter(|(_, head)| head.starts_with(prefix))
                .map(|(number, _)| RequestNumber(number))
                .collect(),
        })
    }

    /// Closes the request, then comments on it. A failed comment leaves the request closed and
    /// comes back as the `Ok` value; a failed close posts nothing.
    async fn close(
        &self,
        number: RequestNumber,
        by: &str,
    ) -> Result<Option<SupersedeError>, SupersedeError> {
        let id = number.0.to_string();
        let comment = format!("Superseded by {by}.");
        let (close, note) = match self.kind {
            PrHost::Github => (
                vec!["pr".to_owned(), "close".to_owned(), id.clone()],
                vec![
                    "pr".to_owned(),
                    "comment".to_owned(),
                    id,
                    format!("--body={comment}"),
                ],
            ),
            PrHost::Gitlab => (
                vec!["mr".to_owned(), "close".to_owned(), id.clone()],
                vec![
                    "mr".to_owned(),
                    "note".to_owned(),
                    id,
                    format!("--message={comment}"),
                ],
            ),
        };
        self.read(Step::CloseRequest, close).await?;
        Ok(self.read(Step::CloseRequest, note).await.err())
    }
}

/// The argument `glab mr view` documents (an id or a branch).
///
/// The iid of a `.../merge_requests/<iid>` URL, any other reference unchanged.
fn glab_reference(reference: &str) -> &str {
    let path = reference.split(['?', '#']).next().unwrap_or(reference);
    match path.trim_end_matches('/').rsplit_once('/') {
        Some((head, iid))
            if head.ends_with("/merge_requests") && iid.bytes().all(|b| b.is_ascii_digit()) =>
        {
            iid
        }
        _ => reference,
    }
}

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}

/// The six gates: author, repository, branch, commit count, marker scope and targets.
struct Gates<'a> {
    author: &'a Author,
    prefix: String,
    marker: &'a RequestMarker,
    formatter: &'a dyn EcosystemFormatter,
}

impl Gates<'_> {
    fn admits(&self, request: &Request) -> bool {
        request.author == *self.author
            && request.same_repository
            && request.head.starts_with(&self.prefix)
            && request.commits == 1
            && RequestMarker::from_body(&request.body).is_some_and(|older| {
                older.same_scope(self.marker) && older.is_covered_by(self.marker, self.formatter)
            })
    }
}

/// Closes the open requests of the new request's author that `opened` supersedes.
///
/// Never fails: a failed listing, read or close is reported in [`SupersedeReport::failures`] and
/// leaves its request open. Run it after the URL was printed.
pub async fn close_superseded(
    ctx: &RepoContext,
    host: PrHost,
    opened: &OpenedRequest,
    marker: &RequestMarker,
    formatter: &dyn EcosystemFormatter,
) -> SupersedeReport {
    let mut report = SupersedeReport::default();
    if version_ordering(marker.ecosystem) == VersionOrdering::Unordered {
        report
            .failures
            .push(SupersedeError::UnsupportedEcosystem(marker.ecosystem));
        return report;
    }
    let host = Host {
        runner: ctx.runner(),
        kind: host,
        ctx,
    };
    if let Err(error) = sweep(&host, opened, marker, formatter, &mut report).await {
        report.failures.push(error);
    }
    report
}

async fn sweep(
    host: &Host<'_>,
    opened: &OpenedRequest,
    marker: &RequestMarker,
    formatter: &dyn EcosystemFormatter,
    report: &mut SupersedeReport,
) -> Result<(), SupersedeError> {
    let new = host.fetch(opened.url()).await?;
    let prefix = format!(
        "{}{}/{}",
        super::BRANCH_PREFIX,
        marker.ecosystem.id(),
        super::branch_dir_segment(host.ctx)
    );
    let listing = host.list(&new.author, &prefix).await?;
    let mut candidates: Vec<RequestNumber> = listing
        .numbers
        .into_iter()
        .filter(|n| *n != new.number)
        .collect();
    candidates.sort_by_key(|number| number.0);
    report.coverage = if candidates.len() > MAX_CANDIDATES_READ {
        SweepCoverage::CandidateCapReached
    } else if listing.full {
        SweepCoverage::ListingFull
    } else {
        SweepCoverage::Complete
    };
    candidates.truncate(MAX_CANDIDATES_READ);
    let gates = Gates {
        author: &new.author,
        prefix,
        marker,
        formatter,
    };
    for number in candidates {
        let outcome = match host.fetch(&number.0.to_string()).await {
            Ok(request) if gates.admits(&request) => host.close(number, opened.url()).await,
            Ok(_) => continue,
            Err(error) => Err(error),
        };
        match outcome {
            Ok(note_failure) => {
                report.closed.push(number);
                report.failures.extend(note_failure);
            }
            Err(error) => report.failures.push(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker(updates: &[(&str, &str)]) -> RequestMarker {
        RequestMarker {
            v: MARKER_VERSION,
            ecosystem: EcosystemId::Cargo,
            manifest: "Cargo.toml".to_owned(),
            group: String::new(),
            mode: RunMode::Default,
            updates: updates
                .iter()
                .map(|(name, target)| MarkerUpdate {
                    name: (*name).to_owned(),
                    target: (*target).to_owned(),
                })
                .collect(),
        }
    }

    #[test]
    fn test_render_escapes_the_comment_terminator_and_round_trips() {
        let hostile = marker(&[("a-->b>c", "1.0.0")]);

        let comment = hostile.render().expect("small marker");

        let inner = comment
            .strip_prefix(MARKER_OPEN)
            .and_then(|rest| rest.strip_suffix(MARKER_CLOSE))
            .expect("framed comment");
        assert!(!inner.contains('>'));
        assert_eq!(
            RequestMarker::from_body(&format!("text\n{comment}\n")),
            Some(hostile)
        );
    }

    #[test]
    fn test_the_ordering_of_each_ecosystem_is_pinned() {
        let of = |kind: VersionOrdering| -> Vec<&str> {
            EcosystemId::ALL
                .iter()
                .filter(|id| version_ordering(**id) == kind)
                .map(|id| id.id())
                .collect()
        };

        assert_eq!(
            of(VersionOrdering::RequirementFloor),
            [
                "cargo", "npm", "pypi", "bundler", "dart", "composer", "deno"
            ]
        );
        assert_eq!(
            of(VersionOrdering::Native),
            ["go", "maven", "gradle", "swift", "nuget"]
        );
        assert_eq!(
            of(VersionOrdering::Unordered),
            ["github-actions", "gitlab-ci", "pre-commit"]
        );
    }

    #[cfg(all(feature = "nuget", feature = "gradle"))]
    #[test]
    fn test_native_ordering_closes_through_the_formatter_and_fails_closed() {
        let native = |ecosystem, updates: &[(&str, &str)]| {
            let mut marker = marker(updates);
            marker.ecosystem = ecosystem;
            marker
        };
        let nuget = deps_engine::setup::NuGetFormatter;
        let old = native(EcosystemId::NuGet, &[("a", "1.1.0")]);

        assert!(old.is_covered_by(&native(EcosystemId::NuGet, &[("a", "1.1.0")]), &nuget));
        assert!(old.is_covered_by(&native(EcosystemId::NuGet, &[("a", "1.10.0")]), &nuget));
        assert!(
            !old.is_covered_by(&native(EcosystemId::NuGet, &[("a", "1.0.9")]), &nuget),
            "the >= requirement string wrongly matched 1.0.9"
        );
        assert!(!old.is_covered_by(&native(EcosystemId::NuGet, &[("a", "1.x")]), &nuget));
        let gradle = deps_engine::setup::GradleFormatter;
        let gradle_old = native(EcosystemId::Gradle, &[("g:a", "1.0")]);
        assert!(
            !gradle_old.is_covered_by(&native(EcosystemId::Gradle, &[("g:a", "1.0.0")]), &gradle),
            "equal prefix, different length: Gradle and Maven disagree"
        );
        assert!(gradle_old.is_covered_by(&native(EcosystemId::Gradle, &[("g:a", "1.1")]), &gradle));
    }

    #[test]
    fn test_glab_reference_takes_the_iid_of_a_merge_request_url() {
        assert_eq!(
            glab_reference("https://gitlab.example/g/p/-/merge_requests/12"),
            "12"
        );
        assert_eq!(
            glab_reference("https://gitlab.example/g/p/-/merge_requests/12/?x=1"),
            "12"
        );
        assert_eq!(glab_reference("7"), "7");
        assert_eq!(
            glab_reference("https://example.test/pr/9"),
            "https://example.test/pr/9"
        );
    }

    #[test]
    fn test_from_body_rejects_an_unknown_ecosystem_id() {
        let comment = marker(&[("a", "1.0.0")])
            .render()
            .expect("small marker")
            .replace("\"cargo\"", "\"cobol\"");

        assert_eq!(RequestMarker::from_body(&comment), None);
    }

    #[test]
    fn test_render_omits_a_marker_over_the_cap() {
        let big = marker(&[(&"n".repeat(MARKER_MAX_BYTES), "1.0.0")]);

        assert_eq!(big.render(), None);
    }

    #[test]
    fn test_from_body_rejects_other_versions_and_garbage() {
        let mut other = marker(&[("a", "1.0.0")]);
        other.v = 2;
        let comment = other.render().expect("small marker");

        assert_eq!(RequestMarker::from_body(&comment), None);
        assert_eq!(RequestMarker::from_body("no marker"), None);
        assert_eq!(
            RequestMarker::from_body(&format!("{MARKER_OPEN}not json{MARKER_CLOSE}")),
            None
        );
    }

    #[test]
    fn test_is_covered_by_needs_every_target_at_or_above_and_fails_closed() {
        let formatter = deps_engine::setup::CargoFormatter;
        let old = marker(&[("a", "1.1.0"), ("b", "2.0.0")]);

        assert!(old.is_covered_by(
            &marker(&[("a", "1.1.0"), ("b", "2.1.0"), ("c", "1.0.0")]),
            &formatter
        ));
        assert!(!old.is_covered_by(&marker(&[("a", "1.0.9"), ("b", "2.0.0")]), &formatter));
        assert!(!old.is_covered_by(&marker(&[("a", "1.1.0")]), &formatter));
        assert!(!marker(&[]).is_covered_by(&old, &formatter));
        let opaque = deps_core::test_util::StubFormatter::new();
        assert!(
            !old.is_covered_by(&old, &opaque),
            "no matcher means not covered"
        );
    }
}
