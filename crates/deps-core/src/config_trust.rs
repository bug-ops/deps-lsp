//! Config-value trust tiers and `${VAR}`/`%VAR%` env-var interpolation (issue #1434).
//!
//! [`ConfigTier`](crate::config_trust::ConfigTier) records a config value's provenance. This
//! module gates **env-var interpolation only**:
//! [`Project`](crate::config_trust::ConfigTier::Project) values never have placeholders
//! expanded. It is NOT a secret-binding gate — a
//! [`User`](crate::config_trust::ConfigTier::User) value is not by itself authorization to
//! attach a credential; callers keep their own credential-tier enforcement (e.g. deps-nuget's
//! C2 binding).
//!
//! [`OperatorPath`](crate::config_trust::OperatorPath) records a different kind of provenance:
//! that a config *file* was located through the operator's own home directory or an absolute
//! operator environment variable, never through the workspace. Together with
//! [`OperatorRegistries`](crate::net_policy::OperatorRegistries) it anchors the one URL-alone
//! registry trust rule (spec 084).
//!
//! `Windows` + `Project` has no production caller today (deps-nuget reaches this only for
//! `User`-tier credentials, and rejects `Project`-tier credentials before expansion ever runs);
//! covered by unit tests only.
//!
//! `deps-cargo`'s `Provenance` and its alias-provenance use of `RegistryTrust` are intentionally
//! separate from this module (env overrides, not interpolation); see that crate's own docs and
//! #1855.

// TODO(#1459): centralize env-override-by-name trust (cargo CARGO_REGISTRIES_*, future
// COMPOSER_AUTH/PIP_INDEX_URL) once a second ecosystem needs it

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::net_policy::EnvSource;

/// The environment variables that may locate an operator-owned config file.
///
/// A closed set, not a free variable name: a caller cannot mint an operator path from
/// `PWD` or any other variable a repository-scoped tool might control (#1822).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperatorEnvVar {
    /// `GOENV`: the Go environment file.
    Goenv,
    /// `XDG_CONFIG_HOME`: the base directory of per-user config on Unix.
    XdgConfigHome,
    /// `APPDATA`: the roaming profile directory on Windows.
    AppData,
}

impl OperatorEnvVar {
    /// The variable's name in the process environment.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Goenv => "GOENV",
            Self::XdgConfigHome => "XDG_CONFIG_HOME",
            Self::AppData => "APPDATA",
        }
    }
}

/// An absolute path located through the operator's own home directory, config directory or
/// operator environment variable, never through the workspace.
///
/// Has no public constructor from an arbitrary path: an `OperatorPath` is proof of provenance.
/// A relative path (a relative `GOENV`, `XDG_CONFIG_HOME` or home) would resolve against whatever
/// directory the server runs in, which a repository can influence, so it is never operator-owned.
///
/// # Examples
///
/// ```
/// use deps_core::config_trust::{EnvPath, OperatorEnvVar, OperatorPath};
/// use deps_core::net_policy::MapEnv;
///
/// let dir = tempfile::tempdir().unwrap();
/// let env = MapEnv::new().with_var("XDG_CONFIG_HOME", dir.path().to_str().unwrap());
/// let EnvPath::Path(xdg) = OperatorPath::from_env(&env, OperatorEnvVar::XdgConfigHome) else {
///     panic!("an absolute path is accepted");
/// };
/// assert_eq!(xdg.join("NuGet").as_path(), dir.path().join("NuGet"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OperatorPath(PathBuf);

/// What [`OperatorPath::from_env`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvPath {
    /// The variable is not set, or is empty (the XDG convention, and what Go does for `GOENV`).
    Unset,
    /// The variable is set to a relative path: it names no operator-owned location, because it
    /// would resolve against a directory a repository can influence. What happens next is the
    /// caller's rule: Go uses no file, NuGet skips it and tries the home-based defaults, Swift
    /// treats its user tier as unusable. An empty value is [`Self::Unset`], not this.
    Ignored,
    /// The variable names an absolute operator-owned path.
    Path(OperatorPath),
}

impl OperatorPath {
    /// The user's home directory, when the platform reports an absolute one.
    #[must_use]
    pub fn home() -> Option<Self> {
        crate::UserHome::current().map(|home| Self(home.path().to_path_buf()))
    }

    /// The path named by `var` in `source`; see [`EnvPath`].
    #[must_use]
    pub fn from_env(source: &impl EnvSource, var: OperatorEnvVar) -> EnvPath {
        match source.var_os(var.name()) {
            None => EnvPath::Unset,
            Some(value) if value.is_empty() => EnvPath::Unset,
            Some(value) if !Path::new(&value).is_absolute() => EnvPath::Ignored,
            Some(value) => EnvPath::Path(Self(PathBuf::from(value))),
        }
    }

    /// The platform's per-user config directory (`os.UserConfigDir()` for Go), when absolute.
    #[must_use]
    pub fn user_config_dir() -> Option<Self> {
        dirs::config_dir().filter(|dir| dir.is_absolute()).map(Self)
    }

    /// This path with one more component. Takes a `&'static str`, which keeps a workspace-controlled
    /// string out of an operator path by convention; it is not otherwise enforced by the type.
    #[must_use]
    pub fn join(&self, segment: &'static str) -> Self {
        Self(self.0.join(segment))
    }

    /// The underlying absolute path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// An operator path for `path`, without the absoluteness check: for tests, whose fixtures
    /// live in temp directories and must also compile on platforms where `/x` is not absolute.
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub fn for_test(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }
}

/// Which tier a config value was read from — records provenance for [`expand_env_vars`]'s
/// interpolation gate. Not a secret-binding gate on its own; see this module's doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigTier {
    /// A committed or ancestor-walked config file — attacker-controlled the instant a hostile
    /// repository is cloned. Never interpolated.
    Project,
    /// A user-home config file (e.g. `~/.npmrc`, a user-profile `NuGet.Config`).
    ///
    /// Not attacker-controlled the way a cloned repository's own files are. Interpolation is
    /// permitted.
    User,
}

/// Which placeholder grammar a config value uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnvVarSyntax {
    /// `${NAME}` (npm's `.npmrc`). The scanner performs no name validation; an unterminated
    /// `${` is kept as literal text, and `${}` looks up the empty name.
    Shell,
    /// `%NAME%` (`NuGet.Config`).
    ///
    /// A well-formed reference requires `NAME` to be non-empty and `[A-Za-z0-9_]+`; anything
    /// else (including a bare `%`, which is URL percent-encoding) is kept as literal text and
    /// scanning resumes just past it.
    Windows,
}

/// Why [`expand_env_vars`] failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvExpansionError {
    /// A referenced environment variable is not set. The whole expansion fails — never a
    /// partial substitution.
    #[error("environment variable {name:?} referenced in config value is not set")]
    UndefinedVar {
        /// The undefined variable's name.
        name: String,
    },
    /// `raw` was [`ConfigTier::Project`] and contained an env-var placeholder.
    ///
    /// Interpolation reads the server's own process environment, so a project-tier value
    /// (attacker-controlled the instant a hostile repository is cloned) could otherwise
    /// exfiltrate an arbitrary environment variable to a URL the value is later used to build.
    #[error("env-var expansion is not permitted in a project-tier config value")]
    NotAllowedInProjectTier,
}

/// The `${` token opening a [`EnvVarSyntax::Shell`] placeholder — the single source of truth
/// for both the scanner and the project-tier gate, so a future placeholder syntax addition
/// cannot silently update one without the other.
const SHELL_PLACEHOLDER_START: &str = "${";

/// One resolved segment of a scan — literal text (borrowed from the input) or a looked-up
/// value.
///
/// Building the output as a list of segments, then allocating the result buffer at its exact
/// final capacity in one pass, avoids a `String`/`Zeroizing<String>` reallocation ever leaving
/// a stale, un-zeroized copy of secret material on the heap.
enum Segment<'a> {
    Literal(&'a str),
    Value(Zeroizing<String>),
}

fn assemble(segments: &[Segment<'_>]) -> Zeroizing<String> {
    let total_len: usize = segments
        .iter()
        .map(|segment| match segment {
            Segment::Literal(s) => s.len(),
            Segment::Value(v) => v.len(),
        })
        .sum();
    let mut out = Zeroizing::new(String::with_capacity(total_len));
    for segment in segments {
        match segment {
            Segment::Literal(s) => out.push_str(s),
            Segment::Value(v) => out.push_str(v.as_str()),
        }
    }
    out
}

// All indices come from `find(SHELL_PLACEHOLDER_START)`/`find('}')`, both ASCII tokens, so
// every slice bound is always a char boundary.
#[allow(clippy::string_slice)]
fn scan_shell(
    raw: &str,
    lookup: &impl Fn(&str) -> Option<Zeroizing<String>>,
) -> Result<Zeroizing<String>, EnvExpansionError> {
    let mut segments = Vec::new();
    let mut rest = raw;
    while let Some(start) = rest.find(SHELL_PLACEHOLDER_START) {
        if start > 0 {
            segments.push(Segment::Literal(&rest[..start]));
        }
        let after = &rest[start + SHELL_PLACEHOLDER_START.len()..];
        let Some(end) = after.find('}') else {
            // No closing brace: keep the rest of the string literal.
            segments.push(Segment::Literal(&rest[start..]));
            rest = "";
            break;
        };
        let var_name = &after[..end];
        let value = lookup(var_name).ok_or_else(|| EnvExpansionError::UndefinedVar {
            name: var_name.to_string(),
        })?;
        segments.push(Segment::Value(value));
        rest = &after[end + 1..];
    }
    if !rest.is_empty() {
        segments.push(Segment::Literal(rest));
    }
    Ok(assemble(&segments))
}

// All indices come from `find('%')`, an ASCII byte, so every slice bound is always a char
// boundary.
#[allow(clippy::string_slice)]
fn scan_windows(
    raw: &str,
    lookup: &impl Fn(&str) -> Option<Zeroizing<String>>,
) -> Result<Zeroizing<String>, EnvExpansionError> {
    let mut segments = Vec::new();
    let mut rest = raw;
    while let Some(pct) = rest.find('%') {
        let literal = &rest[..pct];
        let after = &rest[pct + 1..];
        if let Some(end) = after.find('%') {
            let name = &after[..end];
            if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                if !literal.is_empty() {
                    segments.push(Segment::Literal(literal));
                }
                let value = lookup(name).ok_or_else(|| EnvExpansionError::UndefinedVar {
                    name: name.to_string(),
                })?;
                segments.push(Segment::Value(value));
                rest = &after[end + 1..];
                continue;
            }
        }
        // Not a well-formed `%NAME%` reference: keep everything up to and including this `%`
        // as literal text, then keep scanning from just past it.
        segments.push(Segment::Literal(&rest[..=pct]));
        rest = &rest[pct + 1..];
    }
    if !rest.is_empty() {
        segments.push(Segment::Literal(rest));
    }
    Ok(assemble(&segments))
}

/// Whether `raw` contains a well-formed [`EnvVarSyntax::Windows`] placeholder.
///
/// Runs [`scan_windows`] with a detecting lookup rather than a second, independently-maintained
/// predicate, so the project-tier gate always agrees with the scanner about what counts as a
/// reference (e.g. `%x!%A%` is detected via the well-formed `%A%` found once scanning resumes
/// past the malformed `%x!%`).
fn windows_has_placeholder(raw: &str) -> bool {
    let detected = std::cell::Cell::new(false);
    let _: Result<_, _> = scan_windows(raw, &|_name| {
        detected.set(true);
        None
    });
    detected.get()
}

/// Expands every env-var placeholder in `raw` (grammar selected by `syntax`) against `lookup`.
///
/// [`ConfigTier::Project`] values are never interpolated: if `raw` contains a placeholder (even
/// a malformed/unterminated one, for [`EnvVarSyntax::Shell`]), this returns
/// [`EnvExpansionError::NotAllowedInProjectTier`] before `lookup` is ever called.
/// [`ConfigTier::Project`] with no placeholder returns the value unchanged (`Ok`) — this is a
/// passthrough, not a secret filter (see this module's doc).
///
/// For [`ConfigTier::User`], every referenced variable is looked up left to right; the first
/// unset variable fails the whole expansion closed via
/// [`EnvExpansionError::UndefinedVar`] — never a partial substitution, and `lookup` is never
/// called for a placeholder after that point. A looked-up value is never itself re-scanned for
/// placeholders (no recursive expansion).
///
/// # Errors
///
/// Returns [`EnvExpansionError::NotAllowedInProjectTier`] for a project-tier value containing a
/// placeholder, or [`EnvExpansionError::UndefinedVar`] naming the first placeholder whose
/// variable `lookup` does not resolve.
///
/// # Examples
///
/// ```
/// use deps_core::config_trust::{ConfigTier, EnvVarSyntax, expand_env_vars};
/// use zeroize::Zeroizing;
///
/// let value = expand_env_vars("${HOME}/repo", EnvVarSyntax::Shell, ConfigTier::User, |name| {
///     (name == "HOME").then(|| Zeroizing::new("/home/user".to_string()))
/// })
/// .unwrap();
/// assert_eq!(value.as_str(), "/home/user/repo");
///
/// // A project-tier value containing a placeholder is rejected before `lookup` ever runs.
/// let err = expand_env_vars("${HOME}/repo", EnvVarSyntax::Shell, ConfigTier::Project, |_| {
///     panic!("lookup must not be called for a project-tier value")
/// })
/// .unwrap_err();
/// assert!(matches!(
///     err,
///     deps_core::config_trust::EnvExpansionError::NotAllowedInProjectTier
/// ));
/// ```
pub fn expand_env_vars(
    raw: &str,
    syntax: EnvVarSyntax,
    tier: ConfigTier,
    lookup: impl Fn(&str) -> Option<Zeroizing<String>>,
) -> Result<Zeroizing<String>, EnvExpansionError> {
    if tier == ConfigTier::Project {
        let has_placeholder = match syntax {
            EnvVarSyntax::Shell => raw.contains(SHELL_PLACEHOLDER_START),
            EnvVarSyntax::Windows => windows_has_placeholder(raw),
        };
        if has_placeholder {
            return Err(EnvExpansionError::NotAllowedInProjectTier);
        }
        return Ok(Zeroizing::new(raw.to_owned()));
    }

    match syntax {
        EnvVarSyntax::Shell => scan_shell(raw, &lookup),
        EnvVarSyntax::Windows => scan_windows(raw, &lookup),
    }
}

/// Looks up `name` in the current process environment.
///
/// The production `lookup` for [`expand_env_vars`] in both `deps-npm` and `deps-nuget`. A
/// non-UTF-8 value is treated as unset, same as [`std::env::var`].
///
/// # Examples
///
/// ```
/// use deps_core::config_trust::process_env;
///
/// assert!(process_env("DEPS_LSP_CONFIG_TRUST_DOCTEST_UNSET_VAR_XYZ").is_none());
/// ```
#[must_use]
pub fn process_env(name: &str) -> Option<Zeroizing<String>> {
    std::env::var(name).ok().map(Zeroizing::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net_policy::MapEnv;

    fn z(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_string())
    }

    // --- Shell syntax ---

    #[test]
    fn shell_no_placeholder_passthrough() {
        assert_eq!(
            expand_env_vars(
                "https://npm.example/",
                EnvVarSyntax::Shell,
                ConfigTier::User,
                |_| None
            )
            .unwrap()
            .as_str(),
            "https://npm.example/"
        );
    }

    #[test]
    fn shell_defined_var_expands() {
        let result = expand_env_vars(
            "${NPM_REGISTRY}/",
            EnvVarSyntax::Shell,
            ConfigTier::User,
            |name| (name == "NPM_REGISTRY").then(|| z("https://npm.mycorp.example")),
        );
        assert_eq!(result.unwrap().as_str(), "https://npm.mycorp.example/");
    }

    #[test]
    fn shell_undefined_var_errors() {
        let result = expand_env_vars(
            "${UNDEFINED_VAR}",
            EnvVarSyntax::Shell,
            ConfigTier::User,
            |_| None,
        );
        assert_eq!(
            result,
            Err(EnvExpansionError::UndefinedVar {
                name: "UNDEFINED_VAR".to_string()
            })
        );
    }

    #[test]
    fn shell_unterminated_placeholder_is_literal() {
        assert_eq!(
            expand_env_vars("a${B", EnvVarSyntax::Shell, ConfigTier::User, |_| {
                panic!("lookup must not be called")
            })
            .unwrap()
            .as_str(),
            "a${B"
        );
    }

    #[test]
    fn shell_empty_name_is_undefined() {
        let result = expand_env_vars("${}", EnvVarSyntax::Shell, ConfigTier::User, |name| {
            assert_eq!(name, "");
            None
        });
        assert_eq!(
            result,
            Err(EnvExpansionError::UndefinedVar {
                name: String::new()
            })
        );
    }

    #[test]
    fn shell_adjacent_placeholders() {
        let lookup = |name: &str| match name {
            "A" => Some(z("1")),
            "B" => Some(z("2")),
            _ => None,
        };
        assert_eq!(
            expand_env_vars("${A}${B}", EnvVarSyntax::Shell, ConfigTier::User, lookup)
                .unwrap()
                .as_str(),
            "12"
        );
    }

    #[test]
    fn shell_dollar_before_placeholder() {
        let lookup = |name: &str| (name == "A").then(|| z("1"));
        assert_eq!(
            expand_env_vars("$${A}", EnvVarSyntax::Shell, ConfigTier::User, lookup)
                .unwrap()
                .as_str(),
            "$1"
        );
    }

    #[test]
    fn shell_trailing_brace_is_literal() {
        let lookup = |name: &str| (name == "A").then(|| z("1"));
        assert_eq!(
            expand_env_vars("${A}}", EnvVarSyntax::Shell, ConfigTier::User, lookup)
                .unwrap()
                .as_str(),
            "1}"
        );
    }

    #[test]
    fn shell_surrounding_literal_text() {
        let lookup = |name: &str| (name == "A").then(|| z("1"));
        assert_eq!(
            expand_env_vars("pre${A}post", EnvVarSyntax::Shell, ConfigTier::User, lookup)
                .unwrap()
                .as_str(),
            "pre1post"
        );
    }

    #[test]
    fn shell_looked_up_value_is_not_recursively_expanded() {
        let lookup = |name: &str| (name == "A").then(|| z("${B}"));
        assert_eq!(
            expand_env_vars("${A}", EnvVarSyntax::Shell, ConfigTier::User, lookup)
                .unwrap()
                .as_str(),
            "${B}"
        );
    }

    #[test]
    fn shell_first_unset_var_short_circuits() {
        let calls = std::cell::RefCell::new(Vec::new());
        let lookup = |name: &str| {
            calls.borrow_mut().push(name.to_string());
            None
        };
        let result = expand_env_vars("${A}${B}", EnvVarSyntax::Shell, ConfigTier::User, lookup);
        assert_eq!(
            result,
            Err(EnvExpansionError::UndefinedVar {
                name: "A".to_string()
            })
        );
        assert_eq!(*calls.borrow(), vec!["A".to_string()]);
    }

    // --- Windows syntax ---

    #[test]
    fn windows_set_and_unset() {
        let set = expand_env_vars(
            "%CORP_FEED_PAT%",
            EnvVarSyntax::Windows,
            ConfigTier::User,
            |name| (name == "CORP_FEED_PAT").then(|| z("secret-pat")),
        );
        assert_eq!(set.unwrap().as_str(), "secret-pat");

        let unset = expand_env_vars(
            "%CORP_FEED_PAT%",
            EnvVarSyntax::Windows,
            ConfigTier::User,
            |_| None,
        );
        assert_eq!(
            unset,
            Err(EnvExpansionError::UndefinedVar {
                name: "CORP_FEED_PAT".to_string()
            })
        );
    }

    #[test]
    fn windows_edge_cases() {
        let lookup = |name: &str| match name {
            "A" => Some(z("1")),
            "B" => Some(z("2")),
            _ => None,
        };
        assert_eq!(
            expand_env_vars(
                "pre-%A%-post",
                EnvVarSyntax::Windows,
                ConfigTier::User,
                lookup
            )
            .unwrap()
            .as_str(),
            "pre-1-post"
        );
        assert_eq!(
            expand_env_vars("%A%%B%", EnvVarSyntax::Windows, ConfigTier::User, lookup)
                .unwrap()
                .as_str(),
            "12"
        );
        assert_eq!(
            expand_env_vars(
                "abc%1bad!name%def",
                EnvVarSyntax::Windows,
                ConfigTier::User,
                lookup
            )
            .unwrap()
            .as_str(),
            "abc%1bad!name%def"
        );
        assert_eq!(
            expand_env_vars("abc%A", EnvVarSyntax::Windows, ConfigTier::User, lookup)
                .unwrap()
                .as_str(),
            "abc%A"
        );
        assert_eq!(
            expand_env_vars("%%", EnvVarSyntax::Windows, ConfigTier::User, lookup)
                .unwrap()
                .as_str(),
            "%%"
        );
        assert_eq!(
            expand_env_vars(
                "pre-%UNSET%-post",
                EnvVarSyntax::Windows,
                ConfigTier::User,
                lookup
            ),
            Err(EnvExpansionError::UndefinedVar {
                name: "UNSET".to_string()
            })
        );
    }

    #[test]
    fn windows_malformed_then_well_formed() {
        let lookup = |name: &str| (name == "A").then(|| z("1"));
        assert_eq!(
            expand_env_vars("%x!%A%", EnvVarSyntax::Windows, ConfigTier::User, lookup)
                .unwrap()
                .as_str(),
            "%x!1"
        );
    }

    #[test]
    fn windows_looked_up_value_is_not_recursively_expanded() {
        let lookup = |name: &str| (name == "A").then(|| z("%B%"));
        assert_eq!(
            expand_env_vars("%A%", EnvVarSyntax::Windows, ConfigTier::User, lookup)
                .unwrap()
                .as_str(),
            "%B%"
        );
    }

    #[test]
    fn windows_first_unset_var_short_circuits() {
        let calls = std::cell::RefCell::new(Vec::new());
        let lookup = |name: &str| {
            calls.borrow_mut().push(name.to_string());
            None
        };
        let result = expand_env_vars("%A%%B%", EnvVarSyntax::Windows, ConfigTier::User, lookup);
        assert_eq!(
            result,
            Err(EnvExpansionError::UndefinedVar {
                name: "A".to_string()
            })
        );
        assert_eq!(*calls.borrow(), vec!["A".to_string()]);
    }

    // --- project-tier gate ---

    #[test]
    fn shell_project_tier_rejects_unterminated_placeholder() {
        let result = expand_env_vars("a${B", EnvVarSyntax::Shell, ConfigTier::Project, |_| {
            panic!("lookup must not be called for a project-tier value")
        });
        assert_eq!(result, Err(EnvExpansionError::NotAllowedInProjectTier));
    }

    #[test]
    fn shell_project_tier_rejects_defined_var() {
        let result = expand_env_vars("${PATH}", EnvVarSyntax::Shell, ConfigTier::Project, |_| {
            panic!("lookup must not be called for a project-tier value")
        });
        assert_eq!(result, Err(EnvExpansionError::NotAllowedInProjectTier));
    }

    #[test]
    fn shell_project_tier_no_placeholder_is_passthrough() {
        let result = expand_env_vars(
            "https://npm.example/",
            EnvVarSyntax::Shell,
            ConfigTier::Project,
            |_| panic!("lookup must not be called"),
        );
        assert_eq!(result.unwrap().as_str(), "https://npm.example/");
    }

    #[test]
    fn windows_project_tier_rejects_well_formed_placeholder() {
        let result = expand_env_vars("%A%", EnvVarSyntax::Windows, ConfigTier::Project, |_| {
            panic!("lookup must not be called for a project-tier value")
        });
        assert_eq!(result, Err(EnvExpansionError::NotAllowedInProjectTier));
    }

    #[test]
    fn windows_project_tier_rejects_malformed_then_well_formed() {
        let result = expand_env_vars("%x!%A%", EnvVarSyntax::Windows, ConfigTier::Project, |_| {
            panic!("lookup must not be called for a project-tier value")
        });
        assert_eq!(result, Err(EnvExpansionError::NotAllowedInProjectTier));
    }

    #[test]
    fn windows_project_tier_percent_encoding_not_rejected() {
        let result = expand_env_vars("%20", EnvVarSyntax::Windows, ConfigTier::Project, |_| {
            panic!("lookup must not be called: %20 is not a well-formed placeholder")
        });
        assert_eq!(result.unwrap().as_str(), "%20");
    }

    // --- OperatorPath ---

    #[test]
    fn operator_path_from_env_unset_empty_relative_and_absolute() {
        let abs = std::env::temp_dir();
        let env = MapEnv::new()
            .with_var("GOENV", "")
            .with_var("XDG_CONFIG_HOME", "relative/config")
            .with_var("APPDATA", abs.to_str().unwrap());

        assert_eq!(
            OperatorPath::from_env(&env, OperatorEnvVar::Goenv),
            EnvPath::Unset,
            "empty means unset"
        );
        assert_eq!(
            OperatorPath::from_env(&env, OperatorEnvVar::XdgConfigHome),
            EnvPath::Ignored
        );
        assert_eq!(
            OperatorPath::from_env(&env, OperatorEnvVar::AppData),
            EnvPath::Path(OperatorPath(abs))
        );
        assert_eq!(
            OperatorPath::from_env(&MapEnv::new(), OperatorEnvVar::Goenv),
            EnvPath::Unset
        );
    }

    #[test]
    fn operator_path_goenv_off_is_not_an_absolute_path() {
        let env = MapEnv::new().with_var("GOENV", "off");
        assert_eq!(
            OperatorPath::from_env(&env, OperatorEnvVar::Goenv),
            EnvPath::Ignored
        );
    }

    #[test]
    fn operator_path_join_appends_one_component() {
        let base = OperatorPath(std::env::temp_dir());
        assert_eq!(
            base.join("go").join("env").as_path(),
            std::env::temp_dir().join("go").join("env")
        );
    }

    #[test]
    fn operator_env_var_names_are_the_real_variables() {
        assert_eq!(OperatorEnvVar::Goenv.name(), "GOENV");
        assert_eq!(OperatorEnvVar::XdgConfigHome.name(), "XDG_CONFIG_HOME");
        assert_eq!(OperatorEnvVar::AppData.name(), "APPDATA");
    }

    // --- process_env ---

    #[test]
    fn process_env_unset_var_is_none() {
        assert!(process_env("DEPS_LSP_CONFIG_TRUST_TEST_UNSET_VAR_XYZ").is_none());
    }
}
