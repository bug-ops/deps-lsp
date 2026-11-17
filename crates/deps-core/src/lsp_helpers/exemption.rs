//! Operator-controlled advisory exemptions (#1964, spec 101).
//!
//! An exemption file lives in the operator's own config directory or is named on the command
//! line, never in a repository-controlled location. [`OperatorExemptions`] has no `Deserialize`
//! and no `Default`: the only ways to obtain one are [`OperatorExemptions::none`] and
//! [`OperatorExemptions::load`], so no workspace config struct can smuggle one in.
//!
//! `Malicious` advisories are never exemptible ([`crate::osv::VulnSeverity::is_exemptible`]).
//!
//! ```compile_fail
//! use deps_core::lsp_helpers::exemption::OperatorExemptions;
//!
//! fn needs_deserialize<T: serde::de::DeserializeOwned>() {}
//! needs_deserialize::<OperatorExemptions>();
//! ```

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use time::{Date, Month, OffsetDateTime};

use crate::PublishTime;
use crate::config_trust::OperatorPath;
use crate::osv::{Advisory, DependencyVulnerabilities, OsvId};
use crate::parser::{TomlDeserializeError, deserialize_toml_checked};

/// Size cap for an exemption file, in bytes.
pub const MAX_EXEMPTION_FILE_BYTES: u64 = 64 * 1024;
/// Maximum number of `[[advisory]]` entries in one file.
pub const MAX_EXEMPTION_ENTRIES: usize = 1024;
/// Maximum length of an entry's `reason`, in characters.
pub const MAX_REASON_CHARS: usize = 500;

const FILE_NAME: &str = "advisory-exemptions.toml";
const DIR_NAME: &str = "deps-lsp";

/// Where an exemption file was named from, and the exact path to read.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Location {
    /// The canonical path inside the operator's user config directory.
    UserConfigDir {
        resolved: PathBuf,
    },
    CommandLine(PathBuf),
}

/// A located advisory-exemption file, proof that its path came from the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExemptionFile {
    location: Location,
}

/// Canonicalized workspace roots that must never contain the operator's exemption file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkspaceRoots {
    roots: Vec<PathBuf>,
}

/// Result of looking for the exemption file in the user config directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserConfigLookup {
    /// The platform reports no user config directory.
    NoConfigDir,
    /// No exemption file exists.
    Absent,
    /// The file exists but sits inside a workspace root, so it is refused (fail closed).
    InsideWorkspace {
        /// The canonical workspace root containing the file.
        root: PathBuf,
    },
    /// The file exists outside every effective workspace root.
    Located(ExemptionFile),
}

/// Why an exemption file could not be loaded; messages are redacted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExemptionFileError {
    /// The file could not be read.
    #[error("cannot read advisory exemption file: {0}")]
    Io(String),
    /// The file exceeds the size cap.
    #[error("advisory exemption file exceeds {limit} bytes")]
    TooLarge {
        /// The size cap in bytes.
        limit: u64,
    },
    /// The file is not valid TOML.
    #[error("invalid TOML in advisory exemption file: {0}")]
    Toml(String),
    /// The file does not match the exemption schema.
    #[error("invalid advisory exemption file: {0}")]
    Schema(String),
    /// Two entries name the same advisory id.
    #[error("duplicate advisory id in exemption file: {0}")]
    DuplicateId(String),
    /// More than the maximum number of entries.
    #[error("advisory exemption file has more than {limit} entries")]
    TooManyEntries {
        /// The entry cap.
        limit: usize,
    },
}

/// The validated, operator-supplied set of exempted advisories, each with its last day of
/// validity (inclusive, UTC; `None` never expires).
///
/// Intentionally neither `Deserialize` nor `Default`; see the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorExemptions {
    entries: BTreeMap<OsvId, Option<Date>>,
}

fn is_active_at(expires: Option<Date>, now: PublishTime) -> bool {
    let Some(expires) = expires else {
        return true;
    };
    OffsetDateTime::from_unix_timestamp(now.as_unix_secs())
        .is_ok_and(|today| today.date() <= expires)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    #[serde(default)]
    advisory: Vec<RawEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    id: String,
    reason: String,
    expires: Option<String>,
}

/// Parses an advisory id with ASCII case folded, so `ghsa-...` in the file and `GHSA-...` from
/// OSV (or the reverse) compare equal; both the stored entries and the lookups go through it.
fn parse_folded_id(raw: &str) -> Option<OsvId> {
    OsvId::parse(&raw.to_ascii_uppercase())
}

/// A reason is required for the audit trail but not kept: trimmed, 1..=500 characters, no
/// control characters.
fn validate_reason(raw: &str) -> Result<(), &'static str> {
    let trimmed = raw.trim();
    let chars = trimmed.chars().count();
    if chars == 0 {
        Err("reason must not be blank")
    } else if chars > MAX_REASON_CHARS {
        Err("reason is too long")
    } else if trimmed.chars().any(char::is_control) {
        Err("reason must not contain control characters")
    } else {
        Ok(())
    }
}

impl RawEntry {
    fn validate(self) -> Result<(OsvId, Option<Date>), ExemptionFileError> {
        let schema = |message: &str| ExemptionFileError::Schema(message.to_owned());
        let id =
            parse_folded_id(&self.id).ok_or_else(|| schema("advisory id is not a valid OSV id"))?;
        validate_reason(&self.reason).map_err(schema)?;
        let expires = self
            .expires
            .as_deref()
            .map(|raw| parse_iso_date(raw).ok_or_else(|| schema("expires must be YYYY-MM-DD")))
            .transpose()?;
        Ok((id, expires))
    }
}

fn parse_iso_date(raw: &str) -> Option<Date> {
    if raw.len() != 10 || raw.get(4..5) != Some("-") || raw.get(7..8) != Some("-") {
        return None;
    }
    let digits = |range: std::ops::Range<usize>| {
        let part = raw.get(range)?;
        if part.bytes().all(|b| b.is_ascii_digit()) {
            part.parse::<u32>().ok()
        } else {
            None
        }
    };
    let year = i32::try_from(digits(0..4)?).ok()?;
    let month = Month::try_from(u8::try_from(digits(5..7)?).ok()?).ok()?;
    let day = u8::try_from(digits(8..10)?).ok()?;
    Date::from_calendar_date(year, month, day).ok()
}

impl WorkspaceRoots {
    /// Canonicalizes `roots` and `home`, dropping roots that fail to canonicalize, filesystem
    /// roots, and any root equal to or an ancestor of the canonical home directory.
    ///
    /// Those roots (`cwd = /`, `cwd = $HOME`) say nothing about repository control, and
    /// keeping them would refuse the operator's own config file.
    #[must_use]
    pub fn new(roots: impl IntoIterator<Item = PathBuf>, home: Option<&OperatorPath>) -> Self {
        let home = home.map(|h| {
            std::fs::canonicalize(h.as_path()).unwrap_or_else(|_| h.as_path().to_path_buf())
        });
        let within_bounds = |dir: &Path| {
            dir.parent().is_some() && home.as_ref().is_none_or(|home| !home.starts_with(dir))
        };
        let mut kept: Vec<PathBuf> = Vec::new();
        for root in roots
            .into_iter()
            .filter_map(|root| std::fs::canonicalize(root).ok())
            .filter(|root| within_bounds(root))
        {
            // The enclosing repository top level (outermost `.git` below home) is as much
            // repository-controlled as the opened folder: a monorepo may open `repo/app`
            // while `repo/.envrc` points the config directory at `repo/.config`.
            let top = root
                .ancestors()
                .take_while(|dir| within_bounds(dir))
                .filter(|dir| dir.join(".git").exists())
                .last()
                .map(Path::to_path_buf);
            for dir in std::iter::once(root).chain(top) {
                if !kept.contains(&dir) {
                    kept.push(dir);
                }
            }
        }
        Self { roots: kept }
    }

    fn containing_any(&self, paths: &[PathBuf]) -> Option<&Path> {
        self.roots
            .iter()
            .map(PathBuf::as_path)
            .find(|root| paths.iter().any(|path| path.starts_with(root)))
    }
}

impl ExemptionFile {
    /// Locates `<config dir>/deps-lsp/advisory-exemptions.toml` for the current user,
    /// refusing it when it sits inside a workspace root.
    #[must_use]
    pub fn user_config_default(roots: &WorkspaceRoots) -> UserConfigLookup {
        OperatorPath::user_config_dir().map_or(UserConfigLookup::NoConfigDir, |dir| {
            Self::under_config_dir(dir, roots)
        })
    }

    /// Like [`Self::user_config_default`] with an explicit config directory, for callers that
    /// resolve it themselves (the server's startup wiring, tests).
    ///
    /// A missing file is [`UserConfigLookup::Absent`] before any containment check. Any other
    /// failure to resolve the path fails closed: the result is a [`UserConfigLookup::Located`]
    /// file whose load reports the error.
    #[must_use]
    pub fn under_config_dir(config_dir: OperatorPath, roots: &WorkspaceRoots) -> UserConfigLookup {
        let path = config_dir.as_path().join(DIR_NAME).join(FILE_NAME);
        let resolved = match std::fs::canonicalize(&path) {
            Ok(resolved) => resolved,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return UserConfigLookup::Absent,
            Err(_) => {
                return UserConfigLookup::Located(Self {
                    location: Location::UserConfigDir { resolved: path },
                });
            }
        };
        // The canonical file alone is not enough: a committed symlink at the file or at
        // `deps-lsp/` lives in the workspace but resolves outside it, so the canonical config
        // directory and the canonical parent plus the file name are checked as well.
        let mut checked = vec![resolved.clone()];
        checked.extend(std::fs::canonicalize(config_dir.as_path()).ok());
        if let (Some(parent), Some(name)) = (path.parent(), path.file_name())
            && let Ok(parent) = std::fs::canonicalize(parent)
        {
            checked.push(parent.join(name));
        }
        match roots.containing_any(&checked) {
            Some(root) => UserConfigLookup::InsideWorkspace {
                root: root.to_path_buf(),
            },
            None => UserConfigLookup::Located(Self {
                location: Location::UserConfigDir { resolved },
            }),
        }
    }

    /// A file named by an operator command-line argument; for `deps-cli` only.
    #[must_use]
    pub const fn from_command_line(path: PathBuf) -> Self {
        Self {
            location: Location::CommandLine(path),
        }
    }

    /// A file at an arbitrary path, for tests.
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub const fn for_test(path: PathBuf) -> Self {
        Self {
            location: Location::CommandLine(path),
        }
    }

    /// Reads at most [`MAX_EXEMPTION_FILE_BYTES`]; `Ok(None)` when the file is over the cap.
    ///
    /// The user-config source must be a regular file: a symlink to a FIFO, a tty or
    /// `/dev/stdin` would block `initialize` or consume the editor transport. The command-line
    /// source keeps allowing pipes (`--advisory-exemptions <(cmd)`).
    fn read(&self) -> std::io::Result<Option<String>> {
        match &self.location {
            Location::CommandLine(path) => {
                crate::fs_probe::read_to_string_capped(path, MAX_EXEMPTION_FILE_BYTES)
            }
            Location::UserConfigDir { resolved } => read_regular_capped(resolved),
        }
    }
}

fn read_regular_capped(path: &Path) -> std::io::Result<Option<String>> {
    use std::io::Read as _;

    let not_regular =
        || std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a regular file");
    // Checked before opening: opening a FIFO for reading blocks until a writer appears.
    if !std::fs::metadata(path)?.is_file() {
        return Err(not_regular());
    }
    let file = std::fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(not_regular());
    }
    let mut buf = Vec::new();
    file.take(MAX_EXEMPTION_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut buf)?;
    if !u64::try_from(buf.len()).is_ok_and(|len| len <= MAX_EXEMPTION_FILE_BYTES) {
        return Ok(None);
    }
    String::from_utf8(buf)
        .map(Some)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.utf8_error()))
}

impl OperatorExemptions {
    /// No exemptions: the identity element.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Reads and validates `file`; `Ok(None)` when it does not exist.
    ///
    /// # Errors
    ///
    /// [`ExemptionFileError`] when the file is unreadable, too large, malformed, or breaks
    /// the schema limits.
    pub fn load(file: &ExemptionFile) -> Result<Option<Self>, ExemptionFileError> {
        let text = match file.read() {
            Ok(Some(text)) => text,
            Ok(None) => {
                return Err(ExemptionFileError::TooLarge {
                    limit: MAX_EXEMPTION_FILE_BYTES,
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(ExemptionFileError::Io(e.to_string())),
        };
        let raw: RawFile = deserialize_toml_checked(&text).map_err(|e| match e {
            TomlDeserializeError::Toml(m) => ExemptionFileError::Toml(m),
            TomlDeserializeError::Deserialize(m) => ExemptionFileError::Schema(m),
        })?;
        if raw.advisory.len() > MAX_EXEMPTION_ENTRIES {
            return Err(ExemptionFileError::TooManyEntries {
                limit: MAX_EXEMPTION_ENTRIES,
            });
        }
        let mut entries = BTreeMap::new();
        for raw_entry in raw.advisory {
            let (id, expires) = raw_entry.validate()?;
            if entries.insert(id.clone(), expires).is_some() {
                return Err(ExemptionFileError::DuplicateId(id.to_string()));
            }
        }
        Ok(Some(Self { entries }))
    }

    /// Whether `advisory` is exempted at `now`: its id or an alias names an unexpired entry
    /// and its severity is exemptible.
    #[must_use]
    pub fn exempts(&self, advisory: &Advisory, now: PublishTime) -> bool {
        advisory.severity.is_exemptible()
            && std::iter::once(advisory.id().as_str())
                .chain(advisory.aliases.iter().map(String::as_str))
                .filter_map(parse_folded_id)
                .any(|id| {
                    self.entries
                        .get(&id)
                        .is_some_and(|expires| is_active_at(*expires, now))
                })
    }

    /// The number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// An [`OperatorExemptions`] set bound to the instant it is evaluated at, present only when it
/// can hide something.
///
/// Every surface that renders OSV advisories (diagnostics, inlay hints, the vulnerability quick
/// fix, hover) builds one with [`Self::new`] and funnels the advisories through
/// [`Self::apply`], so they all agree on which advisories are exempted.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ExemptionCheck<'a> {
    exemptions: &'a OperatorExemptions,
    now: PublishTime,
}

impl<'a> ExemptionCheck<'a> {
    /// `None` when `exemptions` is absent or empty, so callers skip the work entirely.
    pub(crate) fn new(
        exemptions: Option<&'a OperatorExemptions>,
        now: PublishTime,
    ) -> Option<Self> {
        exemptions
            .filter(|exemptions| !exemptions.is_empty())
            .map(|exemptions| Self { exemptions, now })
    }

    /// Whether `advisory` is exempted at this check's instant.
    pub(crate) fn exempts(&self, advisory: &Advisory) -> bool {
        self.exemptions.exempts(advisory, self.now)
    }

    /// `dv` without the exempted advisories, plus the removed ids (sorted).
    ///
    /// Borrowed with an empty id list when `check` is `None`. Otherwise totals follow
    /// `DependencyVulnerabilities::without_exempted`: unfetched overflow stays counted.
    pub(crate) fn apply(
        check: Option<Self>,
        dv: &DependencyVulnerabilities,
    ) -> (Cow<'_, DependencyVulnerabilities>, Vec<OsvId>) {
        match check {
            Some(check) => {
                let (kept, ids) = dv.without_exempted(check.exemptions, check.now);
                (Cow::Owned(kept), ids)
            }
            None => (Cow::Borrowed(dv), Vec::new()),
        }
    }
}

/// Exemptions without an expiry for each of `ids`, for tests of the surfaces that apply them.
#[cfg(test)]
pub(crate) fn test_exemptions(ids: &[&str]) -> OperatorExemptions {
    test_exemptions_expiring(ids, None)
}

/// Like [`test_exemptions`], every entry optionally expiring on `expires` (`YYYY-MM-DD`).
#[cfg(test)]
pub(crate) fn test_exemptions_expiring(ids: &[&str], expires: Option<&str>) -> OperatorExemptions {
    let expires = expires.map_or_else(String::new, |date| format!("expires = \"{date}\"\n"));
    let body = ids
        .iter()
        .map(|id| format!("[[advisory]]\nid = \"{id}\"\nreason = \"accepted\"\n{expires}"))
        .collect::<Vec<_>>()
        .join("\n");
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join(FILE_NAME);
    std::fs::write(&path, body).expect("write");
    OperatorExemptions::load(&ExemptionFile::for_test(path))
        .expect("valid")
        .expect("present")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::osv::VulnSeverity;
    use std::assert_matches;

    fn advisory(id: &str, aliases: &[&str], severity: VulnSeverity) -> Advisory {
        Advisory::new(id.to_owned(), "2023-01-01T00:00:00Z".to_owned(), severity)
            .expect("valid id")
            .with_aliases(aliases.iter().map(|s| (*s).to_owned()).collect())
    }

    fn exemptions(body: &str) -> OperatorExemptions {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(FILE_NAME);
        std::fs::write(&path, body).expect("write");
        OperatorExemptions::load(&ExemptionFile::for_test(path))
            .expect("valid")
            .expect("present")
    }

    #[test]
    fn exemption_check_ignores_an_expired_entry() {
        let live = test_exemptions_expiring(&["GHSA-1"], Some("2999-01-01"));
        let expired = test_exemptions_expiring(&["GHSA-1"], Some("2000-01-01"));
        let a = advisory("GHSA-1", &[], VulnSeverity::High);
        let now = PublishTime::now();
        assert!(ExemptionCheck::new(Some(&live), now).is_some_and(|c| c.exempts(&a)));
        assert!(ExemptionCheck::new(Some(&expired), now).is_some_and(|c| !c.exempts(&a)));
    }

    #[test]
    fn exempts_by_alias_and_respects_expiry_inclusively() {
        let ex =
            exemptions("[[advisory]]\nid = \"CVE-1\"\nreason = \"r\"\nexpires = \"2026-01-02\"\n");
        let a = advisory("GHSA-1", &["CVE-1"], VulnSeverity::High);
        // 2026-01-02T00:00:00Z
        let day_start = 1_767_312_000;
        assert!(ex.exempts(&a, PublishTime::from_unix_secs(day_start + 86_399)));
        assert!(!ex.exempts(&a, PublishTime::from_unix_secs(day_start + 86_400)));
    }

    #[test]
    fn ids_match_case_insensitively_in_both_directions() {
        let lower = exemptions("[[advisory]]\nid = \"ghsa-aaaa-bbbb-cccc\"\nreason = \"r\"\n");
        let upper = exemptions("[[advisory]]\nid = \"CVE-2099-0001\"\nreason = \"r\"\n");
        let osv_cased = advisory("GHSA-aaaa-bbbb-cccc", &[], VulnSeverity::High);
        let by_alias = advisory(
            "GHSA-zzzz-zzzz-zzzz",
            &["cve-2099-0001"],
            VulnSeverity::High,
        );
        let now = PublishTime::from_unix_secs(0);
        assert!(lower.exempts(&osv_cased, now));
        assert!(upper.exempts(&by_alias, now));
    }

    #[test]
    fn ids_differing_only_in_case_are_duplicates() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(FILE_NAME);
        let body = "[[advisory]]\nid = \"CVE-1\"\nreason = \"r\"\n[[advisory]]\nid = \"cve-1\"\nreason = \"r\"\n";
        std::fs::write(&path, body).expect("write");
        let result = OperatorExemptions::load(&ExemptionFile::for_test(path));
        assert_matches!(result, Err(ExemptionFileError::DuplicateId(_)));
    }

    #[test]
    fn never_exempts_malicious_even_by_id() {
        let ex = exemptions("[[advisory]]\nid = \"MAL-1\"\nreason = \"r\"\n");
        let a = advisory("MAL-1", &[], VulnSeverity::Malicious);
        assert!(!ex.exempts(&a, PublishTime::from_unix_secs(0)));
    }

    #[test]
    fn none_exempts_nothing() {
        let a = advisory("GHSA-1", &[], VulnSeverity::High);
        assert!(!OperatorExemptions::none().exempts(&a, PublishTime::from_unix_secs(0)));
    }

    #[test]
    fn iso_date_parsing_is_strict() {
        assert!(parse_iso_date("2026-02-28").is_some());
        for bad in [
            "2026-02-30",
            "2026-2-3",
            "2026/01/01",
            "2026-01/01",
            "2026/01-01",
            "+026-01-01",
            "2026-01-0x",
        ] {
            assert!(parse_iso_date(bad).is_none(), "{bad}");
        }
    }
}
