//! Versioned JSON output (FR-007).
//!
//! Schema mirrors `specs/062-cli-check-mode/plan.md` §4 exactly. `schema_version` lets
//! downstream tooling detect a future breaking change to this shape (constitution
//! principle 8) — bump it, and document the bump in `CHANGELOG.md` as `Breaking`, whenever
//! a field is renamed, removed, or its wire type/nullability changes (e.g. a sentinel value
//! like `""` becoming `null`); adding a new optional field is not itself a bump.

use super::DryRun;
use crate::report::{Category, CheckReport};
use crate::update::regen::{
    Companion, DisplayLockPath, LockStateChange, LockfileOutcome, NotApplicableReason,
    PinResolution, Program, RegenerationError, Removal, SkipCause, UnsupportedReason,
};
use deps_core::EcosystemId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;

/// The current `schema_version` this module emits and [`ReportDocument`] can deserialize.
pub const SCHEMA_VERSION: u32 = 1;

/// Wire-token wrapper for [`EcosystemId`] in JSON DTOs.
///
/// Serializes to the same `id()` string the pre-#1626 `String` field carried, and
/// deserializes through [`EcosystemId`]'s [`std::str::FromStr`] impl, so an unrecognized
/// token is rejected instead of accepted as an opaque string.
///
/// # Examples
///
/// ```
/// use deps_cli::format::json::EcosystemToken;
/// use deps_core::EcosystemId;
///
/// let token = EcosystemToken(EcosystemId::Cargo);
/// assert_eq!(serde_json::to_string(&token).unwrap(), "\"cargo\"");
/// let parsed: EcosystemToken = serde_json::from_str("\"cargo\"").unwrap();
/// assert_eq!(parsed.0, EcosystemId::Cargo);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcosystemToken(pub EcosystemId);

impl Serialize for EcosystemToken {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0.id())
    }
}

impl<'de> Deserialize<'de> for EcosystemToken {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let token = String::deserialize(deserializer)?;
        token
            .parse::<EcosystemId>()
            .map(EcosystemToken)
            .map_err(serde::de::Error::custom)
    }
}

/// Wire token for [`deps_core::diagnostic::Severity`] in JSON DTOs.
///
/// Byte-identical to [`crate::format::severity_str`]'s output. Kept as its own closed enum
/// rather than reusing `Severity`'s own `Serialize` impl, which encodes the LSP protocol's
/// `1..=4` integer form for an unrelated wire contract (`crate::policy_config`'s diagnostics
/// config).
///
/// # Examples
///
/// ```
/// use deps_cli::format::json::SeverityToken;
/// use deps_core::diagnostic::Severity;
///
/// let token = SeverityToken::from(Severity::Warning);
/// assert_eq!(serde_json::to_string(&token).unwrap(), "\"warning\"");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SeverityToken {
    /// Reports an error.
    Error,
    /// Reports a warning.
    Warning,
    /// Reports information.
    Information,
    /// Reports a hint.
    Hint,
}

impl From<deps_core::diagnostic::Severity> for SeverityToken {
    fn from(severity: deps_core::diagnostic::Severity) -> Self {
        use deps_core::diagnostic::Severity;
        match severity {
            Severity::Error => Self::Error,
            Severity::Warning => Self::Warning,
            Severity::Information => Self::Information,
            Severity::Hint => Self::Hint,
        }
    }
}

/// Top-level JSON document shape.
#[derive(Debug, Serialize, serde::Deserialize, PartialEq)]
pub struct ReportDocument {
    /// The schema version this document was produced under.
    pub schema_version: u32,
    /// Every finding, in the order [`CheckReport::findings`] held them.
    pub findings: Vec<FindingDocument>,
    /// Per-category finding counts (FR-009's category tokens as keys).
    ///
    /// Kept as `BTreeMap<Category, usize>` in memory ([`Category`]'s `Ord` is declaration
    /// order, used elsewhere for `--fail-on`/table/SARIF ordering), but serialized through
    /// `serialize_summary_lexicographically` (#1626 critic S1) so the JSON key order stays
    /// the pre-#1626 `BTreeMap<String, usize>`'s lexicographic order rather than drifting to
    /// `Category`'s declaration order.
    #[serde(serialize_with = "serialize_summary_lexicographically")]
    pub summary: BTreeMap<Category, usize>,
}

/// Serializes `summary` as a JSON object with keys in [`Category::as_str`] lexicographic
/// order, matching the pre-#1626 `BTreeMap<String, usize>` wire order exactly.
fn serialize_summary_lexicographically<S: Serializer>(
    summary: &BTreeMap<Category, usize>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;

    let mut entries: Vec<(&Category, &usize)> = summary.iter().collect();
    entries.sort_by_key(|(category, _)| category.as_str());

    let mut map = serializer.serialize_map(Some(entries.len()))?;
    for (category, count) in entries {
        map.serialize_entry(category.as_str(), count)?;
    }
    map.end()
}

/// One finding's JSON shape.
#[derive(Debug, Serialize, serde::Deserialize, PartialEq)]
pub struct FindingDocument {
    /// The ecosystem id (e.g. `"cargo"`).
    pub ecosystem: EcosystemToken,
    /// The manifest path, as reported by [`crate::walk`].
    pub manifest_path: String,
    /// The dependency name, when the finding could be traced to one manifest occurrence.
    pub dependency_name: Option<String>,
    /// The declared version requirement, when known.
    pub requirement: Option<String>,
    /// The FR-009 category token.
    pub category: Category,
    /// The lowercase severity token (`error`/`warning`/`information`/`hint`).
    pub severity: SeverityToken,
    /// The LSP range within the manifest.
    pub range: RangeDocument,
    /// The human-readable finding message.
    pub message: String,
}

/// LSP `Range`'s JSON shape (`{"start": {...}, "end": {...}}`).
#[derive(Debug, Serialize, serde::Deserialize, PartialEq)]
pub struct RangeDocument {
    /// The range's start position.
    pub start: PositionDocument,
    /// The range's end position.
    pub end: PositionDocument,
}

/// LSP `Position`'s JSON shape (`{"line": ..., "character": ...}`), both zero-based.
#[derive(Debug, Serialize, serde::Deserialize, PartialEq)]
pub struct PositionDocument {
    /// Zero-based line number.
    pub line: u32,
    /// Zero-based UTF-16 code-unit offset within the line.
    pub character: u32,
}

/// Builds the versioned [`ReportDocument`] for `report`.
///
/// # Examples
///
/// ```
/// use deps_cli::format::json::{SCHEMA_VERSION, to_document};
/// use deps_cli::report::CheckReport;
///
/// let document = to_document(&CheckReport::default());
/// assert_eq!(document.schema_version, SCHEMA_VERSION);
/// assert!(document.findings.is_empty());
/// ```
#[must_use]
pub fn to_document(report: &CheckReport) -> ReportDocument {
    let findings = report
        .findings
        .iter()
        .map(|finding| FindingDocument {
            ecosystem: EcosystemToken(finding.ecosystem),
            manifest_path: finding.manifest_path.display().to_string(),
            dependency_name: finding.dependency_name.clone(),
            requirement: finding.requirement.clone(),
            category: finding.category(),
            severity: SeverityToken::from(finding.severity),
            range: RangeDocument {
                start: PositionDocument {
                    line: finding.range.start.line,
                    character: finding.range.start.character,
                },
                end: PositionDocument {
                    line: finding.range.end.line,
                    character: finding.range.end.character,
                },
            },
            message: finding.message.clone(),
        })
        .collect();

    ReportDocument {
        schema_version: SCHEMA_VERSION,
        findings,
        summary: report.summary(),
    }
}

/// Renders `report` as a pretty-printed JSON string.
///
/// # Errors
///
/// Returns an error only if [`ReportDocument`]'s `Serialize` impl fails, which does not
/// happen for the plain-data shape this module builds.
pub fn render(report: &CheckReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&to_document(report))
}

/// The current `schema_version` [`update_to_document`] emits.
pub const UPDATE_SCHEMA_VERSION: u32 = 2;

/// Wire token for [`crate::update::Outcome`] in JSON DTOs.
///
/// Byte-identical to [`crate::update::Outcome::wire_token`]'s output. Kept as its own
/// discriminant-only enum since `Outcome`'s variants carry data (`ManifestEdit`, `SkipReason`,
/// `UnfixableReason`, ...) that must not leak into the DTO shape.
///
/// # Examples
///
/// ```
/// use deps_cli::format::json::OutcomeToken;
///
/// let token = OutcomeToken::RequiresLockfileUpdate;
/// assert_eq!(serde_json::to_string(&token).unwrap(), "\"requires-lockfile-update\"");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutcomeToken {
    /// A fix plan existed and its edit was written (or would be, under `--dry-run`).
    Applied,
    /// Excluded from this run.
    Skipped,
    /// The already-declared requirement admits the fix target; no edit was needed.
    RequiresLockfileUpdate,
    /// No verified fix could be written.
    Unfixable,
}

impl From<&crate::update::Outcome> for OutcomeToken {
    fn from(outcome: &crate::update::Outcome) -> Self {
        use crate::update::Outcome;
        match outcome {
            Outcome::Applied { .. } | Outcome::AppliedViaLockfile { .. } => Self::Applied,
            Outcome::Skipped { .. } => Self::Skipped,
            Outcome::RequiresLockfileUpdate { .. } => Self::RequiresLockfileUpdate,
            Outcome::Unfixable(_) => Self::Unfixable,
        }
    }
}

/// Top-level JSON document shape for an `update` run (FR-021).
#[derive(Debug, Serialize, serde::Deserialize, PartialEq)]
pub struct UpdateReportDocument {
    /// The schema version this document was produced under.
    pub schema_version: u32,
    /// Whether `--dry-run` was passed — when `true`, every `"applied"` item's edit was
    /// planned but **not** written to disk (critic finding M1/US-005: without this marker,
    /// a `--dry-run` document is indistinguishable from a real run that wrote its edits).
    pub dry_run: bool,
    /// One entry per candidate dependency the planner considered.
    pub items: Vec<UpdateItemDocument>,
    /// The outcome of the lockfile step; always present (additive, no schema bump).
    pub lockfile: LockfileDocument,
}

/// One `update` plan item's JSON shape.
#[derive(Debug, Serialize, serde::Deserialize, PartialEq)]
pub struct UpdateItemDocument {
    /// The dependency's declared (raw) name.
    pub name: String,
    /// The current (resolved in-use, or declared) version.
    pub current: String,
    /// The version this item's edit would move the dependency to, when applicable — `null`
    /// when the item has no concrete target ([`crate::update::PlannedUpdateItem::target`]
    /// returns `None`).
    pub target: Option<String>,
    /// One of `applied` / `skipped` / `requires-lockfile-update` / `unfixable`.
    pub outcome: OutcomeToken,
    /// A one-line human-readable reason for `outcome`.
    pub reason: String,
    /// OSV advisory ids this item resolves — non-empty only in `--security-only` mode; for
    /// `unfixable` rows only when a fix is known (`Yanked`, `UnsupportedRequirementShape`,
    /// `OversizedRequirement`), empty for `NoVerifiedFix` and `FetchFailedOrAbsent`.
    pub advisory_ids: Vec<deps_core::osv::OsvId>,
    /// Spec 075 FR-013: this item's cooldown-fallback attribution, when one was consulted.
    /// Additive (NFR-005) — omitted entirely, not `null`, when the item has none.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cooldown_fallback: Option<CooldownFallbackDocument>,
    /// The sibling release tags the item's OSV verdict holds through, when it holds only
    /// through them (#1767). Additive — omitted entirely when empty.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub matched_tags: Vec<String>,
}

/// [`crate::update::CooldownFallbackNote`]'s JSON shape (spec 075 FR-013).
#[derive(Debug, Serialize, serde::Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CooldownFallbackDocument {
    /// The fallback candidate was written; `latest` names the excluded, cooldown-blocked
    /// version this item targeted instead.
    AppliedInsteadOf {
        /// The excluded, cooldown-blocked `latest` version.
        latest: String,
    },
    /// A fallback candidate existed but was itself OSV-`Flagged`/`Unverified` and was never
    /// written; `version` names it.
    Blocked {
        /// The blocked fallback candidate's version.
        version: String,
    },
}

/// The tool that regenerated a lockfile, as a JSON token.
#[derive(Debug, Clone, Copy, Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ToolToken {
    /// `cargo`.
    Cargo,
    /// `go`.
    Go,
    /// `npm`.
    Npm,
    /// `pnpm`.
    Pnpm,
    /// `yarn`.
    Yarn,
    /// `uv`.
    Uv,
    /// Bundler's `bundle`.
    Bundle,
    /// `deno`.
    Deno,
    /// `bun`.
    Bun,
    /// `poetry`.
    Poetry,
    /// `pdm`.
    Pdm,
    /// `pipenv`.
    Pipenv,
    /// `composer`.
    Composer,
    /// `dart`.
    Dart,
    /// `flutter`.
    Flutter,
    /// `dotnet`.
    Dotnet,
    /// `gradle`.
    Gradle,
    /// `swift`.
    Swift,
}

impl From<Program> for ToolToken {
    fn from(program: Program) -> Self {
        match program {
            Program::Cargo => Self::Cargo,
            Program::Go => Self::Go,
            Program::Npm => Self::Npm,
            Program::Pnpm => Self::Pnpm,
            Program::Yarn => Self::Yarn,
            Program::Uv => Self::Uv,
            Program::Bundle => Self::Bundle,
            Program::Deno => Self::Deno,
            Program::Bun => Self::Bun,
            Program::Poetry => Self::Poetry,
            Program::Pdm => Self::Pdm,
            Program::Pipenv => Self::Pipenv,
            Program::Composer => Self::Composer,
            Program::Dart => Self::Dart,
            Program::Flutter => Self::Flutter,
            Program::Dotnet => Self::Dotnet,
            Program::Gradle => Self::Gradle,
            Program::Swift => Self::Swift,
        }
    }
}

/// Whether a regenerated lockfile holds exactly the target or a newer version.
#[derive(Debug, Clone, Copy, Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum MatchToken {
    /// The lockfile holds exactly the target.
    Exact,
    /// The lockfile holds a newer version that still satisfies the edited requirement.
    Newer,
}

/// One verified pin in a regenerated lockfile.
#[derive(Debug, Serialize, serde::Deserialize, PartialEq)]
pub struct LockfilePinDocument {
    /// The package name.
    pub name: String,
    /// The version the plan applied.
    pub target: String,
    /// The version the regenerated lockfile holds.
    pub resolved: String,
    /// How `resolved` compares with `target`.
    #[serde(rename = "match")]
    pub matched: MatchToken,
}

/// Why regeneration was skipped, as a JSON token.
#[derive(Debug, Clone, Copy, Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SkipToken {
    /// `--lockfile regenerate` was not passed.
    NotEnabled,
    /// `--dry-run`.
    DryRun,
    /// Offline mode.
    Offline,
}

/// Why there was nothing to regenerate, as a JSON token.
#[derive(Debug, Clone, Copy, Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum NotApplicableToken {
    /// The plan applied no edit.
    NothingApplied,
    /// The ecosystem has no lockfile format.
    NoLockfileFormat,
    /// No lockfile exists for the manifest.
    NoLockfilePresent,
    /// Every fix resolved inside the freshness cooldown window and was withheld.
    AllWithheldByCooldown,
}

/// Why regeneration is unsupported, as a JSON token.
#[derive(Debug, Clone, Copy, Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UnsupportedToken {
    /// The manifest may be a workspace member (ancestor lockfile or workspace, or the workspace
    /// directory set via the environment).
    WorkspaceMemberLockfile,
    /// The located lockfile is not the one the tool would update.
    LockfileOwnershipMismatch,
    /// A cooldown-fallback target cannot be pinned by range resolution.
    CooldownFallbackTarget,
    /// The lockfile is a symlink or not a regular file.
    LockfileSymlink,
    /// The project uses Yarn Classic (1.x).
    YarnClassic,
    /// The lock file resolves outside the repository.
    LockfileOutsideRepository,
    /// A `.venv` file or symlink in the project directory selects an interpreter to run.
    SavedVirtualenv,
    /// The project uses a legacy lock layout the tool cannot update safely.
    LegacyLockLayout,
    /// The project centralizes package versions outside the edited manifest.
    CentralPackageVersions,
    /// The project has more lock files than one run handles.
    LockfileSetTooLarge,
    /// The tool has no lock-only update mode that leaves unrelated pins alone.
    LockfileOnlyUpdateUnsupported,
    /// The installed tool is older than the first version the run supports.
    ToolTooOld,
    /// Other dependencies have floating or range requirements the run would re-resolve.
    OtherFloatingRequirements,
}

/// The kind of a failed regeneration, as a JSON token.
#[derive(Debug, Clone, Copy, Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FailureKind {
    /// The tool is not installed.
    ToolchainMissing,
    /// The tool could not be started.
    Spawn,
    /// SIGINT or SIGTERM arrived while the tool was running.
    Interrupted,
    /// The shared time budget ran out.
    TimedOut,
    /// The tool exited unsuccessfully.
    ToolFailed,
    /// A probe printed unexpected output.
    UnexpectedProbeOutput,
    /// A package name or version was unsafe to pass on a command line.
    UnsafeArgument,
    /// The lockfile's name matches no known client.
    UnrecognizedLockfile,
    /// The edited manifest could not be re-parsed.
    ManifestReparseFailed,
    /// The regenerated lockfile could not be read.
    LockfileUnreadable,
    /// The regenerated lockfile does not hold the applied target.
    VersionMismatch,
    /// The tool locked a newer version inside the freshness cooldown window.
    CooldownHeldVersion,
    /// A lock file could not be snapshotted before the tool ran.
    SnapshotFailed,
    /// The lock file could not be restored after a failure.
    RestoreFailed,
    /// The tool could not pin a cooldown-fallback target.
    FallbackPinRejected,
    /// The manifest changed during the run in a way the run did not make.
    ManifestChanged,
    /// A file operation of the run failed.
    Io,
    /// A cooldown-fallback pin could not be kept in the lock file after the manifest write-back.
    FallbackPinNotKept,
    /// A lock-only pin could not be kept in the lock file.
    LockfilePinNotKept,
    /// The run changed the locked coordinates of a configuration beyond the requested update.
    LockStateDrift,
}

impl From<&RegenerationError> for FailureKind {
    fn from(error: &RegenerationError) -> Self {
        match error {
            RegenerationError::ToolchainMissing { .. } => Self::ToolchainMissing,
            RegenerationError::Spawn { .. } => Self::Spawn,
            RegenerationError::Interrupted => Self::Interrupted,
            RegenerationError::TimedOut { .. } => Self::TimedOut,
            RegenerationError::ToolFailed { .. } => Self::ToolFailed,
            RegenerationError::UnexpectedProbeOutput { .. } => Self::UnexpectedProbeOutput,
            RegenerationError::UnsafeArgument { .. } => Self::UnsafeArgument,
            RegenerationError::UnrecognizedLockfile { .. } => Self::UnrecognizedLockfile,
            RegenerationError::ManifestReparseFailed { .. } => Self::ManifestReparseFailed,
            RegenerationError::LockfileUnreadable { .. } => Self::LockfileUnreadable,
            RegenerationError::VersionMismatch { .. } => Self::VersionMismatch,
            RegenerationError::CooldownHeldVersion { .. } => Self::CooldownHeldVersion,
            RegenerationError::SnapshotFailed { .. } => Self::SnapshotFailed,
            RegenerationError::RestoreFailed { .. } => Self::RestoreFailed,
            RegenerationError::FallbackPinRejected { .. } => Self::FallbackPinRejected,
            RegenerationError::ManifestChanged { .. } => Self::ManifestChanged,
            RegenerationError::Io { .. } => Self::Io,
            RegenerationError::FallbackPinNotKept { .. } => Self::FallbackPinNotKept,
            RegenerationError::LockfilePinNotKept { .. } => Self::LockfilePinNotKept,
            RegenerationError::LockStateDrift { .. } => Self::LockStateDrift,
        }
    }
}

/// What an `unsupported` reason refers to; it is a bare string on the wire.
#[derive(Debug, Clone, Copy, Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum UnsupportedDetail {
    /// The tool a lock-only or version refusal names.
    ///
    /// The `reason` token beside `detail` says which namespace it belongs to, so the overlapping
    /// strings (`"npm"`, `"uv"`, ...) are never ambiguous for a reader of the full document.
    Tool(ToolToken),
}

/// The lockfile step of an `update` run, tagged by `status`.
#[derive(Debug, Serialize, serde::Deserialize, PartialEq)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum LockfileDocument {
    /// The lockfile was regenerated and every pin verified.
    Regenerated {
        /// The lockfile's display path.
        path: String,
        /// The tool that updated it.
        tool: ToolToken,
        /// One entry per applied pin.
        pins: Vec<LockfilePinDocument>,
        /// The lock layout migration the run performed; omitted when it performed none.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        migration: Option<MigrationDocument>,
    },
    /// Regeneration was gated off.
    Skipped {
        /// The gate that closed.
        reason: SkipToken,
    },
    /// There was nothing to regenerate.
    NotApplicable {
        /// Why.
        reason: NotApplicableToken,
    },
    /// Regeneration is unsupported for this manifest.
    Unsupported {
        /// Why.
        reason: UnsupportedToken,
        /// The lockfile found, if any.
        path: Option<String>,
        /// The locker or tool the reason refers to, when it names one.
        detail: Option<UnsupportedDetail>,
    },
    /// Regeneration started and failed.
    Failed {
        /// The failure kind.
        kind: FailureKind,
        /// The sanitized error message.
        message: String,
        /// The package of a `version-mismatch`, `lockfile-pin-not-kept` or
        /// `fallback-pin-not-kept`, the first held package of a `cooldown-held-version`, or the
        /// `group:artifact:version` coordinate of a `lock-state-drift`, else `null`.
        package: Option<String>,
        /// The expected version of a `version-mismatch`, or the pinned target of a
        /// `lockfile-pin-not-kept` or `fallback-pin-not-kept`, else `null`.
        expected: Option<String>,
        /// The lockfile's version of a `version-mismatch` or, for a `cooldown-held-version`, the
        /// first held pin's version, else `null`.
        found: Option<String>,
        /// The Gradle configuration of a `lock-state-drift`; omitted for every other kind.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        configuration: Option<String>,
        /// Whether the drifted coordinate was gained or lost; omitted unless `lock-state-drift`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        change: Option<LockStateChangeToken>,
        /// Every held pin of a `cooldown-held-version`, the first included; omitted for every
        /// other kind.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        held: Vec<HeldPinDocument>,
    },
}

/// Wire token of a [`LockStateChange`].
#[derive(Debug, Clone, Copy, Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LockStateChangeToken {
    /// The run added a coordinate the lock did not hold.
    Gained,
    /// The run dropped a coordinate the lock held.
    Lost,
}

/// The typed detail fields of a failed lockfile step; every field absent unless the failure
/// kind defines it.
#[derive(Default)]
struct FailureDetail {
    package: Option<String>,
    expected: Option<String>,
    found: Option<String>,
    configuration: Option<String>,
    change: Option<LockStateChangeToken>,
    held: Vec<HeldPinDocument>,
}

impl FailureDetail {
    fn of(error: &RegenerationError) -> Self {
        let clean = crate::sanitize::sanitize_message_for_display;
        match error {
            RegenerationError::VersionMismatch {
                package,
                expected,
                found,
            } => Self {
                package: Some(clean(package.as_str())),
                expected: Some(clean(expected.as_str())),
                found: found.as_ref().map(|version| clean(version.as_str())),
                ..Self::default()
            },
            RegenerationError::LockfilePinNotKept {
                package, target, ..
            }
            | RegenerationError::FallbackPinNotKept {
                package, target, ..
            } => Self {
                package: Some(clean(package.as_str())),
                expected: Some(clean(target.as_str())),
                ..Self::default()
            },
            RegenerationError::LockStateDrift {
                configuration,
                change,
                ..
            } => {
                let (token, coordinate) = match change {
                    LockStateChange::Gained(coordinate) => {
                        (LockStateChangeToken::Gained, coordinate)
                    }
                    LockStateChange::Lost(coordinate) => (LockStateChangeToken::Lost, coordinate),
                };
                Self {
                    package: Some(clean(coordinate.as_str())),
                    configuration: Some(clean(configuration.as_str())),
                    change: Some(token),
                    ..Self::default()
                }
            }
            RegenerationError::CooldownHeldVersion { first, rest } => Self {
                package: Some(clean(first.package.as_str())),
                found: Some(clean(first.version.as_str())),
                held: std::iter::once(first)
                    .chain(rest)
                    .map(|pin| HeldPinDocument {
                        package: clean(pin.package.as_str()),
                        found: clean(pin.version.as_str()),
                    })
                    .collect(),
                ..Self::default()
            },
            RegenerationError::ToolchainMissing { .. }
            | RegenerationError::Spawn { .. }
            | RegenerationError::Interrupted
            | RegenerationError::TimedOut { .. }
            | RegenerationError::ToolFailed { .. }
            | RegenerationError::UnexpectedProbeOutput { .. }
            | RegenerationError::UnsafeArgument { .. }
            | RegenerationError::UnrecognizedLockfile { .. }
            | RegenerationError::ManifestReparseFailed { .. }
            | RegenerationError::LockfileUnreadable { .. }
            | RegenerationError::SnapshotFailed { .. }
            | RegenerationError::RestoreFailed { .. }
            | RegenerationError::FallbackPinRejected { .. }
            | RegenerationError::ManifestChanged { .. }
            | RegenerationError::Io { .. } => Self::default(),
        }
    }
}

/// The lock files a legacy-to-unified layout migration created and deleted.
#[derive(Debug, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct MigrationDocument {
    /// The unified lock files the run created.
    pub created: Vec<String>,
    /// The legacy lock files the run deleted.
    pub removed: Vec<RemovedLockDocument>,
}

/// One deleted legacy lock file and why it was deleted.
#[derive(Debug, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RemovedLockDocument {
    /// The deleted file.
    pub path: String,
    /// Whether its state was migrated or dropped.
    pub removal: RemovalToken,
}

/// Wire token of a [`Removal`].
#[derive(Debug, Clone, Copy, Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RemovalToken {
    /// The configuration was migrated into the unified lock file.
    Migrated,
    /// The configuration is no longer resolved and its file held no coordinates.
    StaleEmpty,
    /// The configuration is no longer resolved and its coordinates are dropped.
    StaleDropped,
}

impl From<Removal> for RemovalToken {
    fn from(removal: Removal) -> Self {
        match removal {
            Removal::Migrated => Self::Migrated,
            Removal::StaleEmpty => Self::StaleEmpty,
            Removal::StaleDropped => Self::StaleDropped,
        }
    }
}

impl MigrationDocument {
    /// The migration the `companions` record; `None` when they hold neither a created nor a
    /// removed file.
    fn of(lockfile: &DisplayLockPath, companions: &[Companion]) -> Option<Self> {
        let clean = crate::sanitize::sanitize_message_for_display;
        let created: Vec<String> = companions
            .iter()
            .filter_map(|companion| match companion {
                Companion::Created(path) => {
                    Some(clean(&lockfile.display_of(path).display().to_string()))
                }
                Companion::File(_) | Companion::Tree(_) | Companion::Removed { .. } => None,
            })
            .collect();
        let removed: Vec<RemovedLockDocument> = companions
            .iter()
            .filter_map(|companion| match companion {
                Companion::Removed { path, removal } => Some(RemovedLockDocument {
                    path: clean(&lockfile.display_of(path).display().to_string()),
                    removal: (*removal).into(),
                }),
                Companion::File(_) | Companion::Tree(_) | Companion::Created(_) => None,
            })
            .collect();
        (!created.is_empty() || !removed.is_empty()).then_some(Self { created, removed })
    }
}

/// One pin a regeneration left on a version inside the freshness cooldown window.
#[derive(Debug, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct HeldPinDocument {
    /// The held package.
    pub package: String,
    /// The version the lock file would hold, which is inside the window.
    pub found: String,
}

impl From<&LockfileOutcome> for LockfileDocument {
    fn from(outcome: &LockfileOutcome) -> Self {
        let clean = crate::sanitize::sanitize_message_for_display;
        match outcome {
            LockfileOutcome::Regenerated {
                lockfile,
                tool,
                pins,
                companions,
            } => Self::Regenerated {
                path: clean(&lockfile.to_string()),
                tool: (*tool).into(),
                migration: MigrationDocument::of(lockfile, companions),
                pins: pins
                    .iter()
                    .map(|pin| {
                        let (resolved, matched) = match &pin.resolution {
                            PinResolution::Exact => (&pin.target, MatchToken::Exact),
                            PinResolution::Newer(version) => (version, MatchToken::Newer),
                        };
                        LockfilePinDocument {
                            name: clean(pin.package.as_str()),
                            target: clean(pin.target.as_str()),
                            resolved: clean(resolved.as_str()),
                            matched,
                        }
                    })
                    .collect(),
            },
            LockfileOutcome::Skipped(cause) => Self::Skipped {
                reason: match cause {
                    SkipCause::NotEnabled => SkipToken::NotEnabled,
                    SkipCause::DryRun => SkipToken::DryRun,
                    SkipCause::Offline => SkipToken::Offline,
                },
            },
            LockfileOutcome::NotApplicable(reason) => Self::NotApplicable {
                reason: match reason {
                    NotApplicableReason::NothingApplied => NotApplicableToken::NothingApplied,
                    NotApplicableReason::NoLockfileFormat => NotApplicableToken::NoLockfileFormat,
                    NotApplicableReason::NoLockfilePresent => NotApplicableToken::NoLockfilePresent,
                    NotApplicableReason::AllWithheldByCooldown => {
                        NotApplicableToken::AllWithheldByCooldown
                    }
                },
            },
            LockfileOutcome::Unsupported { lockfile, reason } => {
                let (token, detail) = match reason {
                    UnsupportedReason::WorkspaceMemberLockfile => {
                        (UnsupportedToken::WorkspaceMemberLockfile, None)
                    }
                    UnsupportedReason::LockfileOwnershipMismatch => {
                        (UnsupportedToken::LockfileOwnershipMismatch, None)
                    }
                    UnsupportedReason::CooldownFallbackTarget => {
                        (UnsupportedToken::CooldownFallbackTarget, None)
                    }
                    UnsupportedReason::LockfileSymlink => (UnsupportedToken::LockfileSymlink, None),
                    UnsupportedReason::YarnClassic => (UnsupportedToken::YarnClassic, None),
                    UnsupportedReason::SavedVirtualenv => (UnsupportedToken::SavedVirtualenv, None),
                    UnsupportedReason::LockfileOutsideRepository => {
                        (UnsupportedToken::LockfileOutsideRepository, None)
                    }
                    UnsupportedReason::LegacyLockLayout(_) => {
                        (UnsupportedToken::LegacyLockLayout, None)
                    }
                    UnsupportedReason::CentralPackageVersions => {
                        (UnsupportedToken::CentralPackageVersions, None)
                    }
                    UnsupportedReason::LockfileSetTooLarge => {
                        (UnsupportedToken::LockfileSetTooLarge, None)
                    }
                    UnsupportedReason::LockfileOnlyUpdateUnsupported(program) => (
                        UnsupportedToken::LockfileOnlyUpdateUnsupported,
                        Some(UnsupportedDetail::Tool(ToolToken::from(*program))),
                    ),
                    UnsupportedReason::ToolTooOld(program) => (
                        UnsupportedToken::ToolTooOld,
                        Some(UnsupportedDetail::Tool(ToolToken::from(*program))),
                    ),
                    UnsupportedReason::OtherFloatingRequirements => {
                        (UnsupportedToken::OtherFloatingRequirements, None)
                    }
                };
                Self::Unsupported {
                    reason: token,
                    path: lockfile.as_ref().map(|path| clean(&path.to_string())),
                    detail,
                }
            }
            LockfileOutcome::Failed(error) => {
                let detail = FailureDetail::of(error.root_cause());
                Self::Failed {
                    kind: error.into(),
                    message: clean(&error.to_string()),
                    package: detail.package,
                    expected: detail.expected,
                    found: detail.found,
                    configuration: detail.configuration,
                    change: detail.change,
                    held: detail.held,
                }
            }
        }
    }
}

/// Builds the versioned [`UpdateReportDocument`] for `run`.
///
/// # Examples
///
/// ```
/// use deps_cli::format::DryRun;
/// use deps_cli::format::json::{UPDATE_SCHEMA_VERSION, update_to_document};
/// use deps_cli::update::regen::{LockfileOutcome, NotApplicableReason};
/// use deps_cli::update::{UpdatePlan, UpdateRun};
///
/// let run = UpdateRun {
///     plan: UpdatePlan::default(),
///     lockfile: LockfileOutcome::NotApplicable(NotApplicableReason::NothingApplied),
/// };
/// let document = update_to_document(&run, DryRun::No);
/// assert_eq!(document.schema_version, UPDATE_SCHEMA_VERSION);
/// assert!(!document.dry_run);
/// assert!(document.items.is_empty());
/// ```
#[must_use]
pub fn update_to_document(run: &crate::update::UpdateRun, dry_run: DryRun) -> UpdateReportDocument {
    // Security-S3: `target`/`reason`/`cooldown_fallback` carry unvalidated `ConcreteVersion`
    // text, sanitized here like `name`/`current` and `format::table::render_update`.
    let items = run
        .plan
        .items
        .iter()
        .map(|item| UpdateItemDocument {
            name: crate::sanitize::sanitize_message_for_display(&item.name),
            current: crate::sanitize::sanitize_message_for_display(&item.current.render_text()),
            target: item
                .target()
                .map(|v| crate::sanitize::sanitize_message_for_display(v.as_str())),
            outcome: OutcomeToken::from(&item.outcome),
            reason: crate::sanitize::sanitize_message_for_display(&item.reason()),
            advisory_ids: item.advisory_ids.clone(),
            matched_tags: item
                .osv_sibling_match
                .as_ref()
                .map_or_else(Vec::new, |note| {
                    note.tags()
                        .iter()
                        .map(|tag| crate::sanitize::sanitize_message_for_display(tag.as_str()))
                        .collect()
                }),
            cooldown_fallback: item.cooldown_fallback.as_ref().map(|note| match note {
                crate::update::CooldownFallbackNote::AppliedInsteadOf(latest, _) => {
                    CooldownFallbackDocument::AppliedInsteadOf {
                        latest: crate::sanitize::sanitize_message_for_display(latest.as_str()),
                    }
                }
                crate::update::CooldownFallbackNote::Blocked { version } => {
                    CooldownFallbackDocument::Blocked {
                        version: crate::sanitize::sanitize_message_for_display(version.as_str()),
                    }
                }
            }),
        })
        .collect();

    UpdateReportDocument {
        schema_version: UPDATE_SCHEMA_VERSION,
        dry_run: dry_run == DryRun::Yes,
        items,
        lockfile: LockfileDocument::from(&run.lockfile),
    }
}

/// Renders `run` as a pretty-printed JSON string.
///
/// # Errors
///
/// Returns an error only if [`UpdateReportDocument`]'s `Serialize` impl fails, which does not
/// happen for the plain-data shape this module builds.
pub fn render_update(
    run: &crate::update::UpdateRun,
    dry_run: DryRun,
) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&update_to_document(run, dry_run))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_of(plan: &crate::update::UpdatePlan) -> crate::update::UpdateRun {
        crate::update::UpdateRun {
            plan: plan.clone(),
            lockfile: crate::update::regen::LockfileOutcome::NotApplicable(
                crate::update::regen::NotApplicableReason::NothingApplied,
            ),
        }
    }
    #[test]
    fn test_all_withheld_by_cooldown_lockfile_reason_has_its_own_token() {
        let run = crate::update::UpdateRun {
            plan: crate::update::UpdatePlan::default(),
            lockfile: crate::update::regen::LockfileOutcome::NotApplicable(
                crate::update::regen::NotApplicableReason::AllWithheldByCooldown,
            ),
        };

        let json = render_update(&run, DryRun::No).expect("render");

        assert!(json.contains("all-withheld-by-cooldown"), "{json}");
    }

    use crate::report::{Category, CheckFinding};
    use deps_core::EcosystemId;
    use deps_core::diagnostic::{DiagnosticKind, Severity};
    use deps_core::position::{Position, Range};
    use std::path::PathBuf;

    fn finding() -> CheckFinding {
        CheckFinding {
            ecosystem: EcosystemId::Cargo,
            manifest_path: PathBuf::from("Cargo.toml"),
            dependency_name: Some("serde".to_string()),
            requirement: Some("1.0".to_string()),
            kind: DiagnosticKind::Outdated,
            advisory_url: None,
            advisory: None,
            severity: Severity::Hint,
            range: Range::new(Position::new(4, 0), Position::new(4, 10)),
            message: "Newer version available: 1.1.0".to_string(),
        }
    }

    #[test]
    fn test_to_document_empty_report() {
        let document = to_document(&CheckReport::default());
        assert_eq!(document.schema_version, SCHEMA_VERSION);
        assert!(document.findings.is_empty());
        assert!(document.summary.is_empty());
    }

    /// Advisory facts are SARIF-only: the JSON document must not change with them.
    #[test]
    fn test_to_document_ignores_advisory_facts() {
        let plain = finding();
        let with_facts = CheckFinding {
            advisory: Some(crate::report::AdvisoryFacts {
                severity: deps_core::osv::VulnSeverity::High,
                text: "RUSTSEC-2024-0001: summary".to_string(),
            }),
            ..finding()
        };
        let render = |finding| {
            serde_json::to_value(to_document(&CheckReport {
                findings: vec![finding],
            }))
            .unwrap()
        };
        assert_eq!(render(plain), render(with_facts));
    }

    #[test]
    fn test_to_document_maps_finding_fields() {
        let document = to_document(&CheckReport {
            findings: vec![finding()],
        });
        let f = &document.findings[0];
        assert_eq!(f.ecosystem, EcosystemToken(EcosystemId::Cargo));
        assert_eq!(f.manifest_path, "Cargo.toml");
        assert_eq!(f.dependency_name.as_deref(), Some("serde"));
        assert_eq!(f.requirement.as_deref(), Some("1.0"));
        assert_eq!(f.category, Category::Outdated);
        assert_eq!(f.severity, SeverityToken::Hint);
        assert_eq!(f.range.start.line, 4);
        assert_eq!(document.summary.get(&Category::Outdated), Some(&1));
    }

    /// #1626: the JSON wire tokens for `ecosystem`/`category`/`severity` must stay
    /// byte-identical to the pre-retyping `String` fields — `EcosystemId::id()`,
    /// `Category::as_str()`, `crate::format::severity_str()`.
    #[test]
    fn test_to_document_wire_tokens_are_byte_identical() {
        let document = to_document(&CheckReport {
            findings: vec![finding()],
        });
        let rendered = serde_json::to_string(&document).expect("must serialize");
        assert!(rendered.contains("\"ecosystem\":\"cargo\""));
        assert!(rendered.contains("\"category\":\"outdated\""));
        assert!(rendered.contains("\"severity\":\"hint\""));
        assert!(rendered.contains("\"outdated\":1"));
    }

    /// #1626 critic S1: `summary`'s JSON key order must stay lexicographic on
    /// [`Category::as_str`] — the pre-#1626 `BTreeMap<String, usize>` wire order — even though
    /// `Category`'s `Ord` (used for `--fail-on`/table/SARIF ordering elsewhere) is declaration
    /// order. `Outdated` sorts before `Deprecated` by declaration order but after it
    /// lexicographically, so this mix catches a regression the all-`outdated`/`vulnerable`
    /// snapshot test does not.
    #[test]
    fn test_summary_key_order_is_lexicographic_not_declaration_order() {
        let mut deprecated = finding();
        deprecated.kind = crate::report::kind_for(Category::Deprecated);
        let document = to_document(&CheckReport {
            findings: vec![finding(), deprecated],
        });
        let rendered = serde_json::to_string(&document).expect("must serialize");
        let summary_start = rendered
            .find("\"summary\":")
            .expect("summary field must be present");
        let deprecated_index = rendered
            .match_indices("\"deprecated\"")
            .map(|(index, _)| index)
            .find(|&index| index > summary_start)
            .expect("deprecated key must appear in summary");
        let outdated_index = rendered
            .match_indices("\"outdated\"")
            .map(|(index, _)| index)
            .find(|&index| index > summary_start)
            .expect("outdated key must appear in summary");
        assert!(
            deprecated_index < outdated_index,
            "expected lexicographic order (deprecated before outdated), got: {rendered}"
        );
    }

    #[test]
    fn test_summary_counts_sha_comment_mismatch_under_its_own_key() {
        let mut mismatch = finding();
        mismatch.kind = crate::report::kind_for(Category::ShaCommentMismatch);
        let document = to_document(&CheckReport {
            findings: vec![mismatch],
        });
        let rendered = serde_json::to_string(&document).expect("must serialize");
        assert!(
            rendered.contains("\"sha-comment-mismatch\":1"),
            "{rendered}"
        );
        assert_eq!(
            document.summary.get(&Category::ShaCommentMismatch),
            Some(&1)
        );
    }

    #[test]
    fn test_summary_counts_unknown_ref_under_its_own_key() {
        let mut unknown = finding();
        unknown.kind = crate::report::kind_for(Category::UnknownRef);
        let document = to_document(&CheckReport {
            findings: vec![unknown],
        });
        let rendered = serde_json::to_string(&document).expect("must serialize");
        assert!(rendered.contains("\"unknown-ref\":1"), "{rendered}");
        assert_eq!(document.summary.get(&Category::UnknownRef), Some(&1));
    }

    #[test]
    fn test_render_round_trips_through_serde_json() {
        let report = CheckReport {
            findings: vec![finding()],
        };
        let rendered = render(&report).expect("render must succeed");
        let parsed: ReportDocument = serde_json::from_str(&rendered).expect("must round-trip");
        assert_eq!(parsed, to_document(&report));
    }

    #[test]
    fn test_render_includes_schema_version_field() {
        let rendered = render(&CheckReport::default()).expect("render must succeed");
        assert!(rendered.contains("\"schema_version\": 1"));
    }

    /// Snapshot test (S5, spec 062 review): pins the exact JSON document shape so a field
    /// rename, key reordering, or nesting change shows up as a snapshot diff — this
    /// document is a stable, versioned public schema (`SCHEMA_VERSION`), not an
    /// implementation detail.
    #[test]
    fn test_to_document_snapshot() {
        let mut other = finding();
        other.kind = crate::report::kind_for(Category::Vulnerable);
        other.severity = Severity::Error;
        other.manifest_path = PathBuf::from("package.json");
        other.dependency_name = None;
        other.requirement = None;
        other.message = "GHSA-xxxx-yyyy-zzzz: example advisory".to_string();

        let document = to_document(&CheckReport {
            findings: vec![finding(), other],
        });
        insta::assert_json_snapshot!(document);
    }

    fn update_item(outcome: crate::update::Outcome) -> crate::update::PlannedUpdateItem {
        crate::update::PlannedUpdateItem {
            name: "serde".to_string(),
            current: crate::update::CurrentVersion::Resolved(deps_core::ConcreteVersion::from(
                "1.0.0",
            )),
            outcome,
            advisory_ids: vec![deps_core::test_util::osv_id("RUSTSEC-2024-0001")],
            ignore_rule_overridden: false,
            gossip_excluded_version: None,
            cooldown_fallback: None,
            osv_sibling_match: None,
            native_hold: None,
            dependency_kind: None,
            lockfile_fix: crate::update::LockfileFix::default(),
        }
    }

    fn applied_edit() -> deps_core::edit::ManifestEdit {
        deps_core::edit::ManifestEdit {
            range: Range::new(Position::new(0, 0), Position::new(0, 0)),
            new_text: "1.2.0".to_string(),
        }
    }

    fn applied_outcome() -> crate::update::Outcome {
        crate::update::Outcome::Applied {
            edit: applied_edit(),
            target: deps_core::ConcreteVersion::from("1.2.0"),
        }
    }

    /// S5: `update_to_document` on a non-empty plan — every field (including the `dry_run`
    /// marker and advisory ids) must survive into the document, not just the empty-plan
    /// doctest's shape.
    #[test]
    fn test_update_to_document_non_empty_plan_maps_every_field() {
        let plan = crate::update::UpdatePlan {
            items: vec![update_item(applied_outcome())],
        };
        let document = update_to_document(&run_of(&plan), DryRun::Yes);
        assert_eq!(document.schema_version, UPDATE_SCHEMA_VERSION);
        assert!(document.dry_run);
        assert_eq!(document.items.len(), 1);
        let item = &document.items[0];
        assert_eq!(item.name, "serde");
        assert_eq!(item.current, "1.0.0");
        assert_eq!(item.target.as_deref(), Some("1.2.0"));
        assert_eq!(item.outcome, OutcomeToken::Applied);
        assert_eq!(
            item.advisory_ids,
            vec![deps_core::test_util::osv_id("RUSTSEC-2024-0001")]
        );
    }

    /// #1767: a sibling-tag attribution reaches the JSON item as `matched_tags` (and the
    /// reason line), and is omitted entirely when absent.
    #[test]
    fn test_update_to_document_carries_matched_tags() {
        use deps_core::ConcreteVersion;
        use deps_core::lsp_helpers::{DiagnosticMessages, SiblingMatchNote};
        use deps_core::osv::MatchedTags;

        struct Messages;
        impl DiagnosticMessages for Messages {}

        let tags = MatchedTags::new(
            ConcreteVersion::new("v4.9.0"),
            vec![ConcreteVersion::new("v4.9.1")],
        );
        let item = update_item(applied_outcome())
            .with_osv_sibling_match(Some(SiblingMatchNote::new(&Messages, &tags)));
        let plan = crate::update::UpdatePlan { items: vec![item] };
        let document = update_to_document(&run_of(&plan), DryRun::No);
        assert_eq!(document.items[0].matched_tags, ["v4.9.0", "v4.9.1"]);
        assert!(
            document.items[0]
                .reason
                .ends_with("(matched tag v4.9.0, v4.9.1)"),
            "{}",
            document.items[0].reason
        );

        let rendered = render_update(&run_of(&plan), DryRun::No).expect("render must succeed");
        assert!(rendered.contains("matched_tags"));
        let plain = render_update(
            &run_of(&crate::update::UpdatePlan {
                items: vec![update_item(applied_outcome())],
            }),
            DryRun::No,
        )
        .expect("render must succeed");
        assert!(!plain.contains("matched_tags"));
    }

    #[test]
    fn test_render_update_non_empty_plan_round_trips_through_serde_json() {
        let plan = crate::update::UpdatePlan {
            items: vec![update_item(applied_outcome())],
        };
        let rendered = render_update(&run_of(&plan), DryRun::No).expect("render must succeed");
        let parsed: UpdateReportDocument =
            serde_json::from_str(&rendered).expect("must round-trip");
        assert_eq!(parsed, update_to_document(&run_of(&plan), DryRun::No));
    }

    /// #1629: `None` (empty/no target) maps to `null` on the wire (`UPDATE_SCHEMA_VERSION`
    /// bumped to 2), replacing the pre-#1629 `""`-sentinel convention. Asserts the rendered
    /// JSON text itself, not just the struct-level `Option`, so a future accidental
    /// `skip_serializing_if` regression (key *absent* instead of present-and-`null`) is caught.
    #[test]
    fn test_update_to_document_none_target_renders_null() {
        let item = update_item(crate::update::Outcome::Skipped {
            reason: crate::update::SkipReason::NotRequested,
            target: None,
        });
        let plan = crate::update::UpdatePlan { items: vec![item] };
        let document = update_to_document(&run_of(&plan), DryRun::No);
        assert_eq!(document.items[0].target, None);

        let rendered = render_update(&run_of(&plan), DryRun::No).expect("render must succeed");
        let value: serde_json::Value = serde_json::from_str(&rendered).expect("must parse");
        let target = value["items"][0]
            .as_object()
            .expect("item must be an object")
            .get("target")
            .expect("target key must be present, not omitted");
        assert!(
            target.is_null(),
            "target must render as null, got: {target:?}"
        );
    }

    /// #1605 critic S1: `target` and `reason`/`cooldown_fallback` both carry unvalidated
    /// registry text (`ConcreteVersion` is deliberately unchecked) and must both be sanitized.
    #[test]
    fn test_update_to_document_strips_ansi_from_target_and_reason() {
        let mut item = update_item(crate::update::Outcome::Skipped {
            reason: crate::update::SkipReason::NotSafelyEditable(
                deps_core::edit::UnplannableReason::LatestFlaggedByOsv,
            ),
            target: Some(deps_core::ConcreteVersion::from("1.2.0\x1B[31m")),
        });
        item.cooldown_fallback = Some(crate::update::CooldownFallbackNote::Blocked {
            version: deps_core::ConcreteVersion::from("1.1.0\x1B[31m"),
        });
        let mut applied_instead_of_item = update_item(applied_outcome());
        applied_instead_of_item.cooldown_fallback =
            Some(crate::update::CooldownFallbackNote::AppliedInsteadOf(
                deps_core::ConcreteVersion::from("1.3.0\x1B[31m"),
                crate::update::FallbackHold::Freshness,
            ));
        let plan = crate::update::UpdatePlan {
            items: vec![item, applied_instead_of_item],
        };
        let document = update_to_document(&run_of(&plan), DryRun::No);
        let doc_item = &document.items[0];
        let target = doc_item.target.as_deref().expect("target must be Some");
        assert!(!target.contains('\x1B'));
        assert!(target.contains("1.2.0"));
        assert!(!doc_item.reason.contains('\x1B'));
        match &doc_item.cooldown_fallback {
            Some(CooldownFallbackDocument::Blocked { version }) => {
                assert!(!version.contains('\x1B'));
                assert!(version.contains("1.1.0"));
            }
            other => panic!("expected Blocked, got: {other:?}"),
        }
        match &document.items[1].cooldown_fallback {
            Some(CooldownFallbackDocument::AppliedInsteadOf { latest }) => {
                assert!(!latest.contains('\x1B'));
                assert!(latest.contains("1.3.0"));
            }
            other => panic!("expected AppliedInsteadOf, got: {other:?}"),
        }
    }

    /// #1626: `OutcomeToken`'s wire tokens must stay byte-identical to the pre-retyping
    /// `Outcome::wire_token()` strings for every variant.
    #[test]
    fn test_outcome_token_matches_wire_token_for_every_variant() {
        let cases: [(crate::update::Outcome, &str); 4] = [
            (applied_outcome(), "applied"),
            (
                crate::update::Outcome::Skipped {
                    reason: crate::update::SkipReason::NotRequested,
                    target: None,
                },
                "skipped",
            ),
            (
                crate::update::Outcome::RequiresLockfileUpdate {
                    target: deps_core::ConcreteVersion::from("1.2.0"),
                    ecosystem: deps_core::EcosystemId::Cargo,
                },
                "requires-lockfile-update",
            ),
            (
                crate::update::Outcome::Unfixable(crate::update::UnfixableReason::NoVerifiedFix),
                "unfixable",
            ),
        ];
        for (outcome, wire_token) in &cases {
            assert_eq!(outcome.wire_token(), *wire_token);
            let token = OutcomeToken::from(outcome);
            let json = serde_json::to_string(&token).expect("OutcomeToken must serialize");
            assert_eq!(json, format!("\"{wire_token}\""));
            // #1626 tester gap 3: `OutcomeToken` only got direct `Deserialize` coverage for
            // `Applied` (indirectly, via the update-plan round-trip test) — assert all four
            // deserialize back to the exact token that produced their JSON.
            let parsed: OutcomeToken = serde_json::from_str(&json).expect("must round-trip");
            assert_eq!(parsed, token);
        }
    }

    /// #1626 tester gap 1: an unrecognized `outcome` token must be a hard deserialize error,
    /// not silently accepted or defaulted.
    #[test]
    fn test_outcome_token_rejects_unknown_string() {
        let result: Result<OutcomeToken, _> = serde_json::from_str("\"not-a-real-outcome\"");
        assert!(result.is_err());
    }

    /// #1626 critic M1: `SeverityToken`'s wire tokens must stay byte-identical to
    /// `crate::format::severity_str`'s strings for every variant — the doctest and the
    /// `test_to_document_maps_finding_fields`/`test_to_document_wire_tokens_are_byte_identical`
    /// tests above only ever exercised `Hint`/`Warning`; this covers all four.
    #[test]
    fn test_severity_token_matches_severity_str_for_every_variant() {
        for severity in [
            Severity::Error,
            Severity::Warning,
            Severity::Information,
            Severity::Hint,
        ] {
            let wire_token = crate::format::severity_str(severity);
            let token = SeverityToken::from(severity);
            let json = serde_json::to_string(&token).expect("SeverityToken must serialize");
            assert_eq!(json, format!("\"{wire_token}\""));
            let parsed: SeverityToken = serde_json::from_str(&json).expect("must round-trip");
            assert_eq!(parsed, token);
        }
    }

    /// #1626 tester gap 1: an unrecognized `severity` token must be a hard deserialize error.
    #[test]
    fn test_severity_token_rejects_unknown_string() {
        let result: Result<SeverityToken, _> = serde_json::from_str("\"not-a-real-severity\"");
        assert!(result.is_err());
    }

    /// #1626 tester gap 4: `EcosystemToken` round-trips every [`EcosystemId`] variant, not
    /// just `Cargo` — table-driven over [`EcosystemId::ALL`] since `id()`/`FromStr` are
    /// macro-generated from the same variant list, so per-variant divergence is structurally
    /// unlikely but still worth a cheap blanket check.
    #[test]
    fn test_ecosystem_token_round_trips_every_ecosystem_id() {
        for &ecosystem in EcosystemId::ALL {
            let token = EcosystemToken(ecosystem);
            let json = serde_json::to_string(&token).expect("EcosystemToken must serialize");
            assert_eq!(json, format!("\"{}\"", ecosystem.id()));
            let parsed: EcosystemToken = serde_json::from_str(&json).expect("must round-trip");
            assert_eq!(parsed, token);
        }
    }

    /// #2049/#2048: a lock-file-only fix is reported as `applied`, and an interrupted
    /// regeneration carries its own failure kind.
    #[test]
    fn test_update_document_applied_via_lockfile_and_interrupted_snapshot() {
        let plan = crate::update::UpdatePlan {
            items: vec![update_item(crate::update::Outcome::AppliedViaLockfile {
                target: deps_core::ConcreteVersion::from("1.2.0"),
            })],
        };
        let run = crate::update::UpdateRun {
            plan,
            lockfile: crate::update::regen::LockfileOutcome::Failed(
                crate::update::regen::RegenerationError::Interrupted,
            ),
        };
        insta::assert_json_snapshot!(update_to_document(&run, DryRun::No));
    }

    fn failed_lockfile_json(error: crate::update::regen::RegenerationError) -> serde_json::Value {
        let document =
            LockfileDocument::from(&crate::update::regen::LockfileOutcome::Failed(error));
        serde_json::to_value(document).expect("serialize")
    }

    #[test]
    fn test_pin_not_kept_failures_carry_package_and_pinned_target() {
        use crate::update::regen::{RegenerationError, RekeyRefusal};
        let path = PathBuf::from("packages.lock.json");
        let lockfile = RegenerationError::LockfilePinNotKept {
            package: "Newtonsoft.Json".into(),
            target: deps_core::ConcreteVersion::from("13.0.3"),
            path: path.clone(),
            reason: RekeyRefusal::PinnedEntryMissing,
        };
        let fallback = RegenerationError::FallbackPinNotKept {
            package: "left-pad".into(),
            target: deps_core::ConcreteVersion::from("1.3.0"),
            path,
            reason: RekeyRefusal::UnparsableLock,
        };

        let lockfile = failed_lockfile_json(lockfile);
        let fallback = failed_lockfile_json(fallback);

        assert_eq!(lockfile["kind"], "lockfile-pin-not-kept");
        assert_eq!(lockfile["package"], "Newtonsoft.Json");
        assert_eq!(lockfile["expected"], "13.0.3");
        assert!(lockfile["found"].is_null());
        assert!(lockfile.get("configuration").is_none());
        assert!(lockfile.get("change").is_none());
        assert_eq!(fallback["kind"], "fallback-pin-not-kept");
        assert_eq!(fallback["package"], "left-pad");
        assert_eq!(fallback["expected"], "1.3.0");
    }

    #[test]
    fn test_lock_state_drift_carries_configuration_coordinate_and_change() {
        use crate::update::regen::{LockStateChange, RegenerationError};
        let drift = |change: fn(crate::update::regen::LockedCoordinate) -> LockStateChange| {
            RegenerationError::lock_state_drift_for_test(
                PathBuf::from("gradle.lockfile"),
                "compileClasspath",
                "com.google.guava:guava:32.1.2-jre",
                change,
            )
            .expect("valid configuration and coordinate")
        };

        let lost = failed_lockfile_json(drift(LockStateChange::Lost));
        let gained = failed_lockfile_json(drift(LockStateChange::Gained));

        assert_eq!(lost["kind"], "lock-state-drift");
        assert_eq!(lost["package"], "com.google.guava:guava:32.1.2-jre");
        assert_eq!(lost["configuration"], "compileClasspath");
        assert_eq!(lost["change"], "lost");
        assert!(lost["expected"].is_null());
        assert!(lost["found"].is_null());
        assert_eq!(gained["change"], "gained");
    }

    #[test]
    fn test_version_mismatch_carries_package_expected_and_found() {
        use crate::update::regen::RegenerationError;
        let mismatch = |found| RegenerationError::VersionMismatch {
            package: "serde".into(),
            expected: deps_core::ConcreteVersion::from("1.0.200"),
            found,
        };

        let locked =
            failed_lockfile_json(mismatch(Some(deps_core::ConcreteVersion::from("1.0.190"))));
        let absent = failed_lockfile_json(mismatch(None));

        assert_eq!(locked["kind"], "version-mismatch");
        assert_eq!(locked["package"], "serde");
        assert_eq!(locked["expected"], "1.0.200");
        assert_eq!(locked["found"], "1.0.190");
        assert!(locked.get("configuration").is_none());
        assert!(absent["found"].is_null());
    }

    #[test]
    fn test_untyped_failure_leaves_detail_fields_null() {
        let json = failed_lockfile_json(crate::update::regen::RegenerationError::Interrupted);

        assert!(json["package"].is_null());
        assert!(json["expected"].is_null());
        assert!(json["found"].is_null());
        assert!(json.get("configuration").is_none());
    }

    /// #1626 tester gap 1: an unrecognized `ecosystem` token must be a hard deserialize error.
    #[test]
    fn test_ecosystem_token_rejects_unknown_string() {
        let result: Result<EcosystemToken, _> = serde_json::from_str("\"not-a-real-ecosystem\"");
        assert!(result.is_err());
    }
}
