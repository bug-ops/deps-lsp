//! Command-line argument surface for the `deps-cli` binary.

use crate::report::Category;
use crate::walk::{GitignorePolicy, SymlinkPolicy};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Upper bound on a `--cooldown` value, mirroring
/// [`deps_core::policy_config::FreshnessConfig`]'s own 30-day clamp on `cooldown_secs`, so a
/// CLI-supplied override can never exceed what a `deps.toml`-supplied one could.
const MAX_COOLDOWN_SECS: u64 = 30 * 24 * 60 * 60;

/// `deps-cli`: dependency-health checks for CI, pre-commit hooks, and shell workflows.
///
/// # Examples
///
/// ```
/// use clap::Parser;
/// use deps_cli::cli::{Cli, Command};
///
/// let cli = Cli::parse_from(["deps-cli", "check", "Cargo.toml"]);
/// let Command::Check(args) = cli.command else {
///     unreachable!()
/// };
/// assert_eq!(args.paths, vec![std::path::PathBuf::from("Cargo.toml")]);
/// ```
#[derive(Debug, Parser)]
#[command(
    name = "deps-cli",
    version,
    about = "Dependency-health checks for CI, pre-commit hooks, and shell workflows"
)]
pub struct Cli {
    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level `deps-cli` subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Walk PATH(s), classify every discovered manifest's dependencies through the same
    /// pipeline `deps-lsp` uses, and report findings.
    Check(CheckArgs),
    /// Plan and write back version-requirement edits for one manifest's outdated or
    /// vulnerable dependencies (spec 068, #1329).
    Update(UpdateArgs),
}

/// Output format for a `check` run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable table, grouped by file then severity (the default).
    Table,
    /// Versioned JSON document (see `crate::format::json`).
    Json,
    /// SARIF 2.1.0 document (see `crate::format::sarif`), for GitHub code scanning and other
    /// SARIF consumers.
    Sarif,
}

/// Arguments for `deps-cli check`.
#[derive(Debug, Parser)]
pub struct CheckArgs {
    /// Paths to walk. Defaults to the current directory when empty.
    pub paths: Vec<PathBuf>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    pub format: OutputFormat,

    /// Comma-separated categories that make the run exit with code 1
    /// (`outdated,yanked,vulnerable,unsatisfiable,mutable-ref,license,deprecated`).
    /// Defaults to `vulnerable,yanked,unsatisfiable` when omitted (FR-010). A finding that
    /// matches none of the seven categories (e.g. an unresolved/unknown package) is always
    /// reported but can never fail a run through this flag.
    #[arg(long, value_delimiter = ',')]
    pub fail_on: Vec<Category>,

    /// Serve only already-cached registry data; never make a new outbound request.
    #[arg(long)]
    pub offline: bool,

    /// Overrides `freshness.cooldown_secs` for this run. Accepts a bare number of seconds
    /// or a suffixed duration (`30m`, `12h`, `3d`).
    #[arg(long, value_parser = parse_cooldown)]
    pub cooldown: Option<u64>,

    /// Path to a `deps.toml` config file. Defaults to `./deps.toml` when present, and to
    /// built-in defaults otherwise.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Restore `.gitignore`/`.ignore` awareness during the walk (`git`'s own default
    /// behavior). `check` does not respect either by default (issue #1109): as a CI
    /// security gate (`git checkout && deps-cli check .` against an untrusted fork PR), both
    /// files are attacker-controlled input, and a one-line addition to either would otherwise
    /// silently remove a manifest from the scan with no warning and exit code 0. Pass this
    /// flag only when scanning a target you trust as much as your own `deps.toml`.
    #[arg(long)]
    pub respect_gitignore: bool,

    /// Follow symlinks during the directory walk and resolve a symlinked manifest's target for
    /// scanning (issue #1112). A symlink whose resolved, canonicalized target falls outside the
    /// walked root is never followed regardless of this flag — see [`crate::walk::walk`]'s doc.
    /// When this flag is not passed (the default), a symlink to a manifest-shaped file is still
    /// detected and reported via a warning (non-zero exit code), it is simply not resolved and
    /// scanned.
    #[arg(long)]
    pub follow_symlinks: bool,
}

impl CheckArgs {
    /// The paths to walk: [`Self::paths`] verbatim, or the current directory when empty
    /// (FR-001).
    ///
    /// # Examples
    ///
    /// ```
    /// use clap::Parser;
    /// use deps_cli::cli::{Cli, Command};
    ///
    /// let cli = Cli::parse_from(["deps-cli", "check"]);
    /// let Command::Check(args) = cli.command else {
    ///     unreachable!()
    /// };
    /// assert_eq!(args.walk_paths(), vec![std::path::PathBuf::from(".")]);
    /// ```
    #[must_use]
    pub fn walk_paths(&self) -> Vec<PathBuf> {
        if self.paths.is_empty() {
            vec![PathBuf::from(".")]
        } else {
            self.paths.clone()
        }
    }

    /// [`Self::respect_gitignore`] translated to [`GitignorePolicy`] — the transposition-proof
    /// type `walk::walk` and `run_check` take, so a `bool` never has to travel past this point.
    #[must_use]
    pub fn gitignore_policy(&self) -> GitignorePolicy {
        if self.respect_gitignore {
            GitignorePolicy::Respect
        } else {
            GitignorePolicy::Ignore
        }
    }

    /// [`Self::follow_symlinks`] translated to [`SymlinkPolicy`] — the transposition-proof
    /// type `walk::walk` and `run_check` take, so a `bool` never has to travel past this point.
    #[must_use]
    pub fn symlink_policy(&self) -> SymlinkPolicy {
        if self.follow_symlinks {
            SymlinkPolicy::Follow
        } else {
            SymlinkPolicy::Skip
        }
    }
}

/// Output format for an `update` run.
///
/// A separate enum from [`OutputFormat`] (not `sarif`-capable, per NFR-005's "duplicate,
/// don't share" precedent): `update` has no diagnostic-finding concept for SARIF to
/// describe, so accepting `--format sarif` only to reject it at runtime would be a worse UX
/// than never accepting it syntactically at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum UpdateOutputFormat {
    /// Human-readable table, one line per item (the default).
    Table,
    /// Versioned JSON document (see `crate::format::json::render_update`).
    Json,
}

/// Arguments for `deps-cli update` (spec 068, #1329).
///
/// `--config`/`--offline`/`--cooldown` clap attributes are **duplicated** from
/// [`CheckArgs`]'s equivalents rather than shared via a `CommonArgs` flatten (NFR-005) — this
/// keeps `CheckArgs`' existing public field layout and clap surface untouched. No
/// `--respect-gitignore`/`--follow-symlinks` (Out of Scope: an explicitly named manifest path
/// is already an explicit choice).
#[derive(Debug, Parser)]
pub struct UpdateArgs {
    /// The single manifest to update (FR-002 — a directory, a glob expanding to more than
    /// one path, or a path no ecosystem recognizes is an execution error).
    pub manifest: PathBuf,

    /// Narrows the update set to only the named dependencies (repeatable), matched after
    /// `formatter.normalize_package_name` on both sides (FR-005).
    #[arg(long, action = clap::ArgAction::Append)]
    pub package: Vec<String>,

    /// Targets only OSV-`Vulnerable` dependencies, via `recommended_fix()` rather than
    /// `latest`; overrides every `[update].ignore` rule (FR-008 through FR-015). For a
    /// registry that does not report yank status at all, the yank check is inert for that
    /// ecosystem — a documented limitation (FR-013), not a bug: such a dependency can still
    /// be classified `applied` even though its yanked status was never actually checked.
    #[arg(long)]
    pub security_only: bool,

    /// Plans and reports without writing the manifest.
    #[arg(long)]
    pub dry_run: bool,

    /// Output format.
    #[arg(long, value_enum, default_value_t = UpdateOutputFormat::Table)]
    pub format: UpdateOutputFormat,

    /// Path to a `deps.toml` config file — the only way `[update].ignore` rules are loaded
    /// (FR-007: `update` never auto-discovers a `deps.toml`).
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Serve only already-cached registry data; never make a new outbound request.
    #[arg(long)]
    pub offline: bool,

    /// Overrides `freshness.cooldown_secs` for this run. Accepts a bare number of seconds
    /// or a suffixed duration (`30m`, `12h`, `3d`). No effect under `--security-only`
    /// (FR-014).
    #[arg(long, value_parser = parse_cooldown)]
    pub cooldown: Option<u64>,
}

/// Parses a `--cooldown` value into a clamped second count.
///
/// Accepts a bare integer (seconds) or an integer suffixed with `s`/`m`/`h`/`d`. Clamped to
/// `MAX_COOLDOWN_SECS` so a CLI override can never exceed `deps.toml`'s own bound.
///
/// # Examples
///
/// ```
/// use deps_cli::cli::parse_cooldown;
///
/// assert_eq!(parse_cooldown("3600").unwrap(), 3600);
/// assert_eq!(parse_cooldown("1h").unwrap(), 3600);
/// assert_eq!(parse_cooldown("3d").unwrap(), 3 * 24 * 60 * 60);
/// assert!(parse_cooldown("nonsense").is_err());
/// ```
///
/// # Errors
///
/// Returns a human-readable message when `input` is empty, has a non-numeric magnitude, or
/// uses an unrecognized unit suffix.
pub fn parse_cooldown(input: &str) -> Result<u64, String> {
    let trimmed = input.trim();
    let Some(last) = trimmed.chars().last() else {
        return Err("cooldown must not be empty".to_string());
    };

    let (digits, unit) = if last.is_ascii_alphabetic() {
        let prefix_len = trimmed.len() - last.len_utf8();
        let digits = trimmed.get(..prefix_len).unwrap_or_default();
        (digits, last.to_ascii_lowercase())
    } else {
        (trimmed, 's')
    };

    let value: u64 = digits
        .parse()
        .map_err(|_| format!("invalid cooldown duration: {input:?}"))?;

    let seconds = match unit {
        's' => Some(value),
        'm' => value.checked_mul(60),
        'h' => value.checked_mul(3_600),
        'd' => value.checked_mul(86_400),
        other => {
            return Err(format!(
                "unknown cooldown unit '{other}' (expected s, m, h, or d)"
            ));
        }
    }
    .ok_or_else(|| format!("cooldown duration overflowed: {input:?}"))?;

    Ok(seconds.min(MAX_COOLDOWN_SECS))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_walk_paths_defaults_to_current_directory() {
        let cli = Cli::parse_from(["deps-cli", "check"]);
        let Command::Check(args) = cli.command else {
            unreachable!()
        };
        assert_eq!(args.walk_paths(), vec![PathBuf::from(".")]);
    }

    #[test]
    fn test_walk_paths_keeps_explicit_paths() {
        let cli = Cli::parse_from(["deps-cli", "check", "a/Cargo.toml", "b/package.json"]);
        let Command::Check(args) = cli.command else {
            unreachable!()
        };
        assert_eq!(
            args.walk_paths(),
            vec![
                PathBuf::from("a/Cargo.toml"),
                PathBuf::from("b/package.json")
            ]
        );
    }

    #[test]
    fn test_fail_on_parses_valid_category_list() {
        let cli = Cli::parse_from(["deps-cli", "check", "--fail-on", "vulnerable,license"]);
        let Command::Check(args) = cli.command else {
            unreachable!()
        };
        assert_eq!(args.fail_on, vec![Category::Vulnerable, Category::License]);
    }

    #[test]
    fn test_fail_on_mutable_ref_token_matches_fr009() {
        let cli = Cli::parse_from(["deps-cli", "check", "--fail-on", "mutable-ref"]);
        let Command::Check(args) = cli.command else {
            unreachable!()
        };
        assert_eq!(args.fail_on, vec![Category::MutableRefPin]);
    }

    #[test]
    fn test_fail_on_rejects_unknown_category() {
        let result = Cli::try_parse_from(["deps-cli", "check", "--fail-on", "not-a-category"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_format_defaults_to_table() {
        let cli = Cli::parse_from(["deps-cli", "check"]);
        let Command::Check(args) = cli.command else {
            unreachable!()
        };
        assert_eq!(args.format, OutputFormat::Table);
    }

    #[test]
    fn test_format_json_parses() {
        let cli = Cli::parse_from(["deps-cli", "check", "--format", "json"]);
        let Command::Check(args) = cli.command else {
            unreachable!()
        };
        assert_eq!(args.format, OutputFormat::Json);
    }

    #[test]
    fn test_format_sarif_parses() {
        let cli = Cli::parse_from(["deps-cli", "check", "--format", "sarif"]);
        let Command::Check(args) = cli.command else {
            unreachable!()
        };
        assert_eq!(args.format, OutputFormat::Sarif);
    }

    #[test]
    fn test_parse_cooldown_bare_seconds() {
        assert_eq!(parse_cooldown("42").unwrap(), 42);
    }

    #[test]
    fn test_parse_cooldown_suffixed_units() {
        assert_eq!(parse_cooldown("30m").unwrap(), 1_800);
        assert_eq!(parse_cooldown("2h").unwrap(), 7_200);
        assert_eq!(parse_cooldown("1d").unwrap(), 86_400);
    }

    #[test]
    fn test_parse_cooldown_clamps_to_thirty_days() {
        assert_eq!(parse_cooldown("999d").unwrap(), MAX_COOLDOWN_SECS);
    }

    #[test]
    fn test_parse_cooldown_rejects_empty() {
        assert!(parse_cooldown("").is_err());
    }

    #[test]
    fn test_parse_cooldown_rejects_unknown_unit() {
        assert!(parse_cooldown("5x").is_err());
    }

    #[test]
    fn test_parse_cooldown_rejects_non_numeric() {
        assert!(parse_cooldown("abc").is_err());
    }

    // --- Command::Update (spec 068, T008) ---

    #[test]
    fn test_update_no_flags_parses_and_reaches_command_update() {
        let cli = Cli::parse_from(["deps-cli", "update", "Cargo.toml"]);
        let Command::Update(args) = cli.command else {
            unreachable!()
        };
        assert_eq!(args.manifest, PathBuf::from("Cargo.toml"));
        assert!(args.package.is_empty());
        assert!(!args.security_only);
        assert!(!args.dry_run);
        assert_eq!(args.format, UpdateOutputFormat::Table);
        assert!(args.config.is_none());
        assert!(!args.offline);
        assert!(args.cooldown.is_none());
    }

    #[test]
    fn test_update_repeatable_package_flag() {
        let cli = Cli::parse_from([
            "deps-cli",
            "update",
            "--package",
            "serde",
            "--package",
            "tokio",
            "Cargo.toml",
        ]);
        let Command::Update(args) = cli.command else {
            unreachable!()
        };
        assert_eq!(args.package, vec!["serde".to_string(), "tokio".to_string()]);
    }

    #[test]
    fn test_update_security_only_and_dry_run_flags() {
        let cli = Cli::parse_from([
            "deps-cli",
            "update",
            "--security-only",
            "--dry-run",
            "Cargo.toml",
        ]);
        let Command::Update(args) = cli.command else {
            unreachable!()
        };
        assert!(args.security_only);
        assert!(args.dry_run);
    }

    #[test]
    fn test_update_config_offline_cooldown_flags() {
        let cli = Cli::parse_from([
            "deps-cli",
            "update",
            "--config",
            "deps.toml",
            "--offline",
            "--cooldown",
            "1h",
            "Cargo.toml",
        ]);
        let Command::Update(args) = cli.command else {
            unreachable!()
        };
        assert_eq!(args.config, Some(PathBuf::from("deps.toml")));
        assert!(args.offline);
        assert_eq!(args.cooldown, Some(3_600));
    }

    #[test]
    fn test_update_requires_a_manifest_argument() {
        let result = Cli::try_parse_from(["deps-cli", "update"]);
        assert!(result.is_err());
    }

    /// `update` has no SARIF concept — `--format sarif` must be rejected at parse time, not
    /// accepted and rejected later at runtime.
    #[test]
    fn test_update_format_sarif_is_rejected_at_parse_time() {
        let result = Cli::try_parse_from(["deps-cli", "update", "--format", "sarif", "Cargo.toml"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_format_json_parses() {
        let cli = Cli::parse_from(["deps-cli", "update", "--format", "json", "Cargo.toml"]);
        let Command::Update(args) = cli.command else {
            unreachable!()
        };
        assert_eq!(args.format, UpdateOutputFormat::Json);
    }
}
