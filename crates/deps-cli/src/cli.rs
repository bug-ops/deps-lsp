//! Command-line argument surface for the `deps-cli` binary.

use crate::report::Category;
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
/// let Command::Check(args) = cli.command;
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

/// Top-level `deps-cli` subcommands. Only `check` exists in this release (spec 062 PR 2) —
/// `--format sarif`, the pre-commit hook, and the GitHub Action wrapper are issue #1063.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Walk PATH(s), classify every discovered manifest's dependencies through the same
    /// pipeline `deps-lsp` uses, and report findings.
    Check(CheckArgs),
}

/// Output format for a `check` run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable table, grouped by file then severity (the default).
    Table,
    /// Versioned JSON document (see `crate::format::json`).
    Json,
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
    /// let Command::Check(args) = cli.command;
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
        let Command::Check(args) = cli.command;
        assert_eq!(args.walk_paths(), vec![PathBuf::from(".")]);
    }

    #[test]
    fn test_walk_paths_keeps_explicit_paths() {
        let cli = Cli::parse_from(["deps-cli", "check", "a/Cargo.toml", "b/package.json"]);
        let Command::Check(args) = cli.command;
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
        let Command::Check(args) = cli.command;
        assert_eq!(args.fail_on, vec![Category::Vulnerable, Category::License]);
    }

    #[test]
    fn test_fail_on_mutable_ref_token_matches_fr009() {
        let cli = Cli::parse_from(["deps-cli", "check", "--fail-on", "mutable-ref"]);
        let Command::Check(args) = cli.command;
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
        let Command::Check(args) = cli.command;
        assert_eq!(args.format, OutputFormat::Table);
    }

    #[test]
    fn test_format_json_parses() {
        let cli = Cli::parse_from(["deps-cli", "check", "--format", "json"]);
        let Command::Check(args) = cli.command;
        assert_eq!(args.format, OutputFormat::Json);
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
}
