//! `deps-cli`: dependency-health checks for CI, pre-commit hooks, and shell workflows.
//!
//! Wires the `check` subcommand end to end: loads config, walks the target path(s),
//! classifies every discovered manifest through the same pipeline `deps-lsp` uses, applies
//! the `--fail-on` policy, prints the selected format, and exits with the mapped code.

use clap::Parser;
use deps_cli::cli::{Cli, Command, OutputFormat};
use deps_cli::config::{self, CliConfig};
use deps_cli::exit::exit_code;
use deps_cli::report::{CheckContext, CheckReport, FailOnPolicy, check_manifest};
use deps_cli::{format, walk};
use deps_core::osv::OsvClient;
use deps_core::{EcosystemRegistry, HttpCache};
use deps_engine::setup::{EcosystemRuntime, register_ecosystems};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

/// Manifest file size cap — mirrors `deps-lsp`'s `document::loader::MAX_FILE_SIZE`
/// (`fs_probe::read_to_string_capped`'s own TOCTOU-safe cap, not reachable from this crate).
const MAX_MANIFEST_FILE_SIZE: u64 = 10_000_000;

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let Command::Check(args) = cli.command;

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("deps-cli: failed to start async runtime: {error}");
            return ExitCode::from(2);
        }
    };

    let walk_paths = args.walk_paths();
    let default_config_dir = config_default_dir(&walk_paths);
    let cli_config = match config::load(args.config.as_deref(), &default_config_dir) {
        Ok(config) => config::apply_overrides(config, args.offline, args.cooldown),
        Err(error) => {
            eprintln!("deps-cli: {error}");
            return ExitCode::from(2);
        }
    };

    let fail_on = if args.fail_on.is_empty() {
        FailOnPolicy::default_categories()
    } else {
        FailOnPolicy::new(args.fail_on.clone())
    };

    let (report, had_execution_error) = runtime.block_on(run_check(walk_paths, cli_config));

    let rendered = match args.format {
        OutputFormat::Table => format::table::render(&report),
        OutputFormat::Json => match format::json::render(&report) {
            Ok(json) => json,
            Err(error) => {
                eprintln!("deps-cli: failed to render JSON report: {error}");
                return ExitCode::from(2);
            }
        },
    };
    print!("{rendered}");

    ExitCode::from(u8::try_from(exit_code(&report, &fail_on, had_execution_error)).unwrap_or(2))
}

/// Builds the shared runtime handles, walks `paths`, and classifies every discovered
/// manifest, returning the assembled [`CheckReport`] and whether any manifest's registry
/// fetch failed (offline excluded) or failed to parse — either of which makes the report
/// incomplete, independent of `--fail-on` (FR-012).
async fn run_check(paths: Vec<PathBuf>, cli_config: CliConfig) -> (CheckReport, bool) {
    let policy = cli_config.policy;
    let ecosystem_runtime = EcosystemRuntime::from_policy(&policy);
    let cache = Arc::new(HttpCache::with_policy(Arc::clone(
        &ecosystem_runtime.policy,
    )));
    // FR-013/SC-004: blocks every outbound request at the shared HTTP cache itself, so
    // `fetch_latest_versions_parallel` and the OSV client naturally degrade to
    // already-cached-only data instead of `check_manifest` needing its own offline
    // short-circuit around each call site.
    cache.set_offline(policy.network.offline);
    let ecosystem_registry = EcosystemRegistry::new();
    let _workspace_registry_ecosystems =
        register_ecosystems(&ecosystem_registry, Arc::clone(&cache), &ecosystem_runtime);

    let ctx = CheckContext {
        cache: Arc::clone(&cache),
        osv: Arc::new(OsvClient::new(Arc::clone(&cache))),
        lockfile_cache: Arc::new(deps_core::lockfile::LockFileCache::new()),
        policy,
    };

    let walk_outcome = walk::walk(&paths, &ecosystem_registry);
    let mut had_execution_error = false;
    for error in &walk_outcome.walk_errors {
        eprintln!("deps-cli: warning: {error}");
        // S2 (spec 062 review): an unreadable path during the walk means the report may be
        // missing manifests the run should have seen — that must not silently exit 0.
        had_execution_error = true;
    }
    if walk_outcome.truncated {
        eprintln!(
            "deps-cli: warning: walk truncated at {} entries; some manifests may be missing from this report",
            walk::MAX_WALKED_FILES
        );
        had_execution_error = true;
    }
    for path in &walk_outcome.unrecognized_explicit_paths {
        // M4 (spec 062 review), spec §6: not fatal, and does not affect the exit code — the
        // rest of the run proceeds normally.
        eprintln!(
            "deps-cli: warning: {} is not recognized by any ecosystem",
            path.display()
        );
    }

    let mut findings = Vec::new();

    // TODO(deviation #4, spec 062 tasks.md T024 / spec.md NFR-004): manifests are processed
    // sequentially here, not fanned out via `futures::stream::buffer_unordered` as T024's own
    // checklist item still names. Deliberately deferred, not an oversight — per-manifest
    // dependency-fetch concurrency is already bounded by `fetch_latest_versions_parallel`
    // (`deps_engine::classify::fetch`), which is what NFR-004 actually gates; this only
    // affects wall-clock time on a true monorepo-of-monorepos (hundreds of manifests), out of
    // scope for this PR's target use case (perf-reviewed and signed off as non-blocking:
    // single-repo CI runs, ~37 manifests in this workspace's own self-check).
    for manifest in walk_outcome.manifests {
        match deps_core::fs_probe::read_to_string_capped(&manifest.path, MAX_MANIFEST_FILE_SIZE) {
            Ok(Some(content)) => {
                match check_manifest(
                    &manifest.ecosystem,
                    &manifest.path,
                    &manifest.display_path,
                    &content,
                    &ctx,
                )
                .await
                {
                    Ok(result) => {
                        had_execution_error |= result.registry_unreachable;
                        findings.extend(result.findings);
                    }
                    Err(error) => {
                        eprintln!("deps-cli: warning: {error}");
                        had_execution_error = true;
                    }
                }
            }
            Ok(None) => {
                eprintln!(
                    "deps-cli: warning: {} exceeds the manifest size cap, skipping",
                    manifest.display_path.display()
                );
                had_execution_error = true;
            }
            Err(error) => {
                eprintln!(
                    "deps-cli: warning: could not read {}: {error}",
                    manifest.display_path.display()
                );
                had_execution_error = true;
            }
        }
    }

    (CheckReport { findings }, had_execution_error)
}

/// Directory `config::load` resolves its default `deps.toml` lookup against when `--config`
/// is not given (FR-014's "at the walked root", spec 062 review S4).
///
/// `paths` is [`deps_cli::cli::CheckArgs::walk_paths`]'s output, so it is never empty. Exactly
/// one path resolves unambiguously (its own directory, or its parent when it is a file
/// itself); multiple paths have no single "the walked root" to pick, so this falls back to
/// the current directory, matching this crate's pre-S4 behavior for that case.
fn config_default_dir(paths: &[PathBuf]) -> PathBuf {
    match paths {
        [only] if only.is_dir() => only.clone(),
        [only] => only
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf),
        _ => PathBuf::from("."),
    }
}
