//! `deps-cli`: dependency-health checks for CI, pre-commit hooks, and shell workflows.
//!
//! Wires the `check` subcommand end to end: loads config, walks the target path(s),
//! classifies every discovered manifest through the same pipeline `deps-lsp` uses, applies
//! the `--fail-on` policy, prints the selected format, and exits with the mapped code.
//!
//! Also wires `update` (spec 068, #1329): plans and writes back version-requirement edits
//! for one manifest's outdated or vulnerable dependencies.

use clap::Parser;
use deps_cli::MAX_MANIFEST_FILE_SIZE;
use deps_cli::analyze::analyze_manifest;
use deps_cli::cli::{Cli, Command, OutputFormat, UpdateArgs, UpdateOutputFormat};
use deps_cli::config::{self, CliConfig};
use deps_cli::exit::{ExecutionOutcome, exit_code};
use deps_cli::report::{CheckContext, CheckReport, FailOnPolicy, check_manifest};
use deps_cli::update::ignore::IgnoreRules;
use deps_cli::update::{self, UpdatePlan};
use deps_cli::{format, walk};
use deps_core::osv::OsvClient;
use deps_core::policy_config::PolicyConfig;
use deps_core::{EcosystemRegistry, HttpCache, NetworkMode};
use deps_engine::setup::{EcosystemRuntime, register_ecosystems};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

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

    match cli.command {
        Command::Check(args) => run_check_command(&runtime, &args),
        Command::Update(args) => run_update_command(&runtime, &args),
    }
}

/// Shared per-run handles: HTTP cache, OSV client, lock-file cache, and the ecosystem
/// registry — built identically for `check` and `update`.
struct RuntimeHandles {
    osv: Arc<OsvClient>,
    lockfile_cache: Arc<deps_core::lockfile::LockFileCache>,
    cache: Arc<HttpCache>,
    ecosystem_registry: EcosystemRegistry,
}

fn build_runtime_handles(policy: &PolicyConfig) -> RuntimeHandles {
    // Shared with `ecosystem_runtime` below (impl-critic #4 follow-up to #1212's S3 fix) so
    // Composer's classification-time `composer.lock` read and this run's own in-use-version
    // resolution hit the same mtime-keyed cache instance, instead of each parsing the lock
    // file independently — the same double-parse `deps-lsp`'s `ServerState` avoids.
    let lockfile_cache = Arc::new(deps_core::lockfile::LockFileCache::new());
    let ecosystem_runtime =
        EcosystemRuntime::from_policy(policy).with_lockfile_cache(Arc::clone(&lockfile_cache));
    let cache = Arc::new(HttpCache::with_policy(Arc::clone(
        &ecosystem_runtime.policy,
    )));
    // FR-013/SC-004: offline gate lives at the shared cache, so callers degrade to
    // cached-only data without their own per-call short-circuit.
    cache.set_offline(NetworkMode::from_offline_flag(policy.network.offline));
    let ecosystem_registry = EcosystemRegistry::new();
    let _workspace_registry_ecosystems =
        register_ecosystems(&ecosystem_registry, Arc::clone(&cache), &ecosystem_runtime);

    RuntimeHandles {
        osv: Arc::new(OsvClient::new(Arc::clone(&cache))),
        lockfile_cache,
        cache,
        ecosystem_registry,
    }
}

fn run_check_command(
    runtime: &tokio::runtime::Runtime,
    args: &deps_cli::cli::CheckArgs,
) -> ExitCode {
    let walk_paths = args.walk_paths();
    let default_config_dir = config_default_dir(&walk_paths);
    let cli_config = match config::load(args.config.as_deref(), &default_config_dir) {
        Ok(config) => config::apply_overrides(
            config,
            NetworkMode::from_offline_flag(args.offline),
            args.cooldown,
        ),
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

    let (report, had_execution_error) = runtime.block_on(run_check(
        walk_paths,
        cli_config,
        args.gitignore_policy(),
        args.symlink_policy(),
    ));

    let rendered = match args.format {
        OutputFormat::Table => format::table::render(&report),
        OutputFormat::Json => match format::json::render(&report) {
            Ok(json) => json,
            Err(error) => {
                eprintln!("deps-cli: failed to render JSON report: {error}");
                return ExitCode::from(2);
            }
        },
        OutputFormat::Sarif => match format::sarif::render(&report) {
            Ok(sarif) => sarif,
            Err(error) => {
                eprintln!("deps-cli: failed to render SARIF report: {error}");
                return ExitCode::from(2);
            }
        },
    };
    print!("{rendered}");

    ExitCode::from(
        u8::try_from(exit_code(
            &report,
            &fail_on,
            ExecutionOutcome::from_had_execution_error(had_execution_error),
        ))
        .unwrap_or(2),
    )
}

/// Builds the shared runtime handles, walks `paths`, and classifies every discovered
/// manifest, returning the assembled [`CheckReport`] and whether any manifest's registry
/// fetch failed (offline excluded) or failed to parse — either of which makes the report
/// incomplete, independent of `--fail-on` (FR-012).
async fn run_check(
    paths: Vec<PathBuf>,
    cli_config: CliConfig,
    gitignore_policy: walk::GitignorePolicy,
    symlink_policy: walk::SymlinkPolicy,
) -> (CheckReport, bool) {
    let policy = cli_config.policy;
    let handles = build_runtime_handles(&policy);
    let ctx = CheckContext {
        cache: Arc::clone(&handles.cache),
        osv: handles.osv,
        lockfile_cache: handles.lockfile_cache,
        policy,
    };

    let walk_outcome = walk::walk(
        &paths,
        &handles.ecosystem_registry,
        gitignore_policy,
        symlink_policy,
    );
    let mut had_execution_error = false;
    for error in walk_outcome.walk_errors() {
        eprintln!("deps-cli: warning: {error}");
        // S2 (spec 062 review): an unreadable path means the report may be incomplete — must not silently exit 0.
        had_execution_error = true;
    }
    if walk_outcome.truncated {
        eprintln!(
            "deps-cli: warning: walk truncated at {} entries; some manifests may be missing from this report",
            walk::MAX_WALKED_FILES
        );
        had_execution_error = true;
    }
    for path in walk_outcome.unrecognized_explicit_paths() {
        // M4 (spec 062 review), spec §6: not fatal, does not affect the exit code.
        // #1299 round 2: `path` is already display-sanitized by `walk::walk` at push time —
        // `main.rs` prints every `WalkOutcome` path as-is, on the strength of that boundary
        // invariant, not a per-print-site sanitizer call.
        eprintln!(
            "deps-cli: warning: {} is not recognized by any ecosystem",
            path.display()
        );
    }
    for path in walk_outcome.ignored_manifests() {
        // #1109 / reviewer follow-up / #1112: a manifest an ecosystem would have claimed was
        // excluded from the scan without being asked to — an ignore rule under
        // --respect-gitignore, a PRUNED_DIRECTORIES match in any mode, or a symlink reachable
        // only by passing --follow-symlinks. Either way the report is incomplete, so this must
        // not silently exit 0.
        eprintln!(
            "deps-cli: warning: {} looks like a manifest but was excluded from the scan (a .gitignore/.ignore rule, a pruned directory such as vendor/build/dist, or a symlink not followed — see --follow-symlinks)",
            path.display()
        );
        had_execution_error = true;
    }
    for path in walk_outcome.broken_manifest_symlinks() {
        // #1124: distinct from `ignored_manifests` — this path produced no manifest at all
        // (unresolvable or non-regular-file target), a stronger tampering signal.
        eprintln!(
            "deps-cli: warning: {} is a manifest-shaped symlink whose target could not be resolved (does not exist, a broken chain, is unreadable, or is not a regular file) — this is stronger evidence of tampering than an ordinary excluded manifest",
            path.display()
        );
        had_execution_error = true;
    }
    if walk_outcome.manifests().is_empty() {
        // Defensive visibility (#1108, reviewer follow-up #1): zero manifests discovered at
        // all is operationally different from manifests found but clean — the former is far
        // more likely to be a walk/routing bug (wrong root, every manifest pruned) than a
        // genuinely dependency-free tree, and must not look identical to a clean exit 0 to a
        // CI system gating on exit code alone. Must set had_execution_error, not just warn —
        // otherwise this is the exact "broken scan looks like a clean one" failure #1108 was
        // about, just reached a different way.
        eprintln!("deps-cli: warning: no manifests were discovered under the given path(s)");
        had_execution_error = true;
    }

    let mut findings = Vec::new();

    // TODO(deviation #4, spec 062 tasks.md T024 / spec.md NFR-004): manifests are processed
    // sequentially, not fanned out via `buffer_unordered`, deliberately — per-manifest fetch
    // concurrency is already bounded by `fetch_latest_versions_parallel`, which is what NFR-004
    // gates; only affects wall-clock time on monorepo-of-monorepos scale (perf-reviewed, non-blocking).
    for manifest in walk_outcome.manifests() {
        match deps_core::fs_probe::read_to_string_capped(&manifest.path, MAX_MANIFEST_FILE_SIZE) {
            Ok(Some(content)) => {
                // Review finding M2: `check_manifest`'s `manifest_path` drives URI derivation
                // for both parsing and lockfile/in-use-version discovery — it must be
                // `uri_path` (the manifest's encountered path), not `manifest.path` (the
                // resolved real path used only for the read above), or lockfile lookup under
                // `--follow-symlinks` silently anchors at the symlink target's directory
                // instead of the symlink's own.
                match check_manifest(
                    &manifest.ecosystem,
                    &manifest.uri_path,
                    &manifest.display_path,
                    &content,
                    &ctx,
                )
                .await
                {
                    Ok(result) => {
                        // Both name genuinely different subsystems (the version registry vs.
                        // a tier-3 license source) but feed the same exit-2 "incomplete
                        // report" signal — see `ManifestCheckResult::license_fetch_incomplete`'s
                        // doc (issue #1133 code-review finding #1).
                        had_execution_error |=
                            result.registry_unreachable || result.license_fetch_incomplete;
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

/// Loads [`CliConfig`] for `update` (FR-007): only from an explicit `--config <path>`, never
/// auto-discovered — `update` never even looks for a default-location `deps.toml`, unlike
/// `check`'s [`config::load`] with `explicit_path: None`.
fn load_update_config(explicit_path: Option<&Path>) -> Result<CliConfig, config::ConfigError> {
    match explicit_path {
        Some(path) => config::load(Some(path), Path::new(".")),
        None => Ok(CliConfig::default()),
    }
}

fn run_update_command(runtime: &tokio::runtime::Runtime, args: &UpdateArgs) -> ExitCode {
    let cli_config = match load_update_config(args.config.as_deref()) {
        Ok(config) => config::apply_overrides(
            config,
            NetworkMode::from_offline_flag(args.offline),
            args.cooldown,
        ),
        Err(error) => {
            eprintln!("deps-cli: {error}");
            return ExitCode::from(2);
        }
    };
    let policy = cli_config.policy;

    // FR-014 (M6: covers both clauses in one check, not just `--cooldown`): a non-default
    // `freshness.cooldown_secs` — whether it came from `--cooldown` or from a `[freshness]`
    // section in an explicit `--config` file — has no effect under `--security-only`, since
    // the fix target comes from the advisory's `recommended_fix()`, never the
    // freshness-filtered registry pick. Warn, don't reject; comparing the final resolved
    // `policy` value (after `apply_overrides`) against the default catches both sources
    // uniformly instead of checking `args.cooldown` alone.
    if args.security_only
        && policy.freshness.cooldown_secs != PolicyConfig::default().freshness.cooldown_secs
    {
        eprintln!(
            "deps-cli: warning: a non-default freshness cooldown has no effect under --security-only (the fix target comes from the advisory, not the freshness-filtered registry pick)"
        );
    }

    // FR-015: hard-error rather than silently scanning zero dependencies and exiting 0.
    if args.security_only && (policy.network.offline || !policy.diagnostics.vulnerabilities_enabled)
    {
        eprintln!(
            "deps-cli: error: --security-only requires network access and vulnerability scanning to be enabled (network.offline and diagnostics.vulnerabilities_enabled)"
        );
        return ExitCode::from(2);
    }

    // FR-007: `[update].ignore` rules are honored only when loaded from an explicit
    // `--config <path>` — `cli_config.update.ignore` is already empty when `args.config` is
    // `None` (`load_update_config` never auto-discovers), but this stays explicit rather than
    // relying on that being true by construction.
    let ignore_config = args
        .config
        .is_some()
        .then(|| cli_config.update.ignore.clone());

    match runtime.block_on(run_update(args, policy, ignore_config)) {
        Ok(plan) => {
            let rendered = match args.format {
                UpdateOutputFormat::Table => {
                    format::table::render_update(&plan, format::DryRun::from_flag(args.dry_run))
                }
                UpdateOutputFormat::Json => {
                    match format::json::render_update(
                        &plan,
                        format::DryRun::from_flag(args.dry_run),
                    ) {
                        Ok(json) => json,
                        Err(error) => {
                            eprintln!("deps-cli: failed to render JSON report: {error}");
                            return ExitCode::from(2);
                        }
                    }
                }
            };
            print!("{rendered}");
            ExitCode::from(u8::try_from(deps_cli::exit::update_exit_code(&plan)).unwrap_or(2))
        }
        Err(message) => {
            eprintln!("deps-cli: error: {message}");
            ExitCode::from(2)
        }
    }
}

/// Walks (single-path routing, FR-002), analyzes, plans, and applies one `update` run.
///
/// `ignore_config` is `Some(rules)` only when an explicit `--config` supplied `[update].ignore`
/// rules (FR-007) — `None` means no rules were loaded at all, resolving to
/// [`IgnoreRules::empty`] once the manifest's ecosystem (and therefore its
/// `normalize_package_name`) is known.
async fn run_update(
    args: &UpdateArgs,
    policy: PolicyConfig,
    ignore_config: Option<Vec<deps_cli::config::IgnoreRule>>,
) -> Result<UpdatePlan, String> {
    let handles = build_runtime_handles(&policy);

    let walk_outcome = walk::walk(
        std::slice::from_ref(&args.manifest),
        &handles.ecosystem_registry,
        walk::GitignorePolicy::Ignore,
        walk::SymlinkPolicy::Skip,
    );
    if walk_outcome.manifests().len() != 1
        || !walk_outcome.unrecognized_explicit_paths().is_empty()
        || !walk_outcome.broken_manifest_symlinks().is_empty()
        || !walk_outcome.ignored_manifests().is_empty()
        || !walk_outcome.walk_errors().is_empty()
    {
        return Err(format!(
            "{} is not a single recognized manifest",
            args.manifest.display()
        ));
    }
    let Some(manifest) = walk_outcome.manifests().first() else {
        return Err(format!(
            "{} is not a single recognized manifest",
            args.manifest.display()
        ));
    };

    // N1 (critic re-review): spec §8's Never clause forbids reading manifest content before
    // FR-017's symlink refusal passes — `write_atomic`'s own refusal only fires at write time,
    // which left a symlinked manifest argument fully read, parsed, and its dependency names
    // sent to the registry/OSV before the existing write-time check ever ran (US-006's
    // *observable* contract — nothing gets written — still held, but the spec's stricter
    // read-time boundary did not). `manifest.path` is the encountered, unresolved argument
    // path for an explicit single-file root (`walk_with_limit`'s `root.is_file()` branch calls
    // `route_file(&absolute_root, &absolute_root, ...)` — `std::path::absolute` never resolves
    // symlinks), so this read and `write_atomic`'s later write both operate on the same path.
    //
    // Code review finding 2: a separate `symlink_metadata` check followed by a plain,
    // symlink-following read left a check-then-open TOCTOU gap of its own. Closed by
    // `read_to_string_capped_no_follow`, which passes `O_NOFOLLOW` to the single `open(2)`
    // call itself on Linux/macOS — see that function's doc for the narrower (documented, not
    // fully closed) fallback on other platforms.
    let content = match deps_core::fs_probe::read_to_string_capped_no_follow(
        &manifest.path,
        MAX_MANIFEST_FILE_SIZE,
    ) {
        Ok(Some(content)) => content,
        Ok(None) => {
            return Err(format!(
                "{} exceeds the manifest size cap",
                manifest.display_path.display()
            ));
        }
        // `read_to_string_capped_no_follow`'s own error message already names the symlink
        // refusal specifically (mirroring how `ApplyError::Write`'s `{source}` Display already
        // carries `write_atomic`'s equivalent message) — no need to re-detect it by `ErrorKind`
        // here, just propagate `error`'s own `Display`.
        Err(error) => {
            return Err(format!(
                "could not read {}: {error}",
                manifest.display_path.display()
            ));
        }
    };

    let ctx = CheckContext {
        cache: Arc::clone(&handles.cache),
        osv: Arc::clone(&handles.osv),
        lockfile_cache: handles.lockfile_cache,
        policy,
    };

    // Code review finding 6: `update` never reads `ManifestAnalysis::licenses` in either mode,
    // and its default mode never reads `vulnerabilities` either — declaring the narrower scope
    // here (vs. `check`'s `AnalysisScope::all()`) skips a wasted network round trip per
    // dependency (license prefetch) and, for the common default-mode case, the OSV scan too.
    let scope = if args.security_only {
        deps_cli::analyze::AnalysisScope::vulnerabilities_only()
    } else {
        deps_cli::analyze::AnalysisScope::none()
    };
    let analysis = analyze_manifest(
        &manifest.ecosystem,
        &manifest.uri_path,
        &content,
        &ctx,
        scope,
    )
    .await
    .map_err(|error| error.to_string())?;
    // S2 (critic finding): a total registry outage must not silently yield an empty plan and
    // exit 0 — spec §5's exit table lists "registry unreachable" under exit 2, and `check`
    // already honors this same signal (see `run_check`). Aborts before planning/writing
    // rather than proceeding on partial registry data, since an "up to date" verdict built
    // from an incomplete fetch is actively misleading, not merely incomplete. Deliberately
    // does not also gate on `analysis.license_fetch_incomplete`: unlike `check`, `update`'s
    // planners never read license data at all, so that signal has no bearing on plan
    // correctness here.
    if analysis.registry_unreachable {
        return Err(format!(
            "a registry required to classify {} was unreachable; the plan would be based on \
             incomplete data",
            manifest.display_path.display()
        ));
    }
    let formatter = manifest.ecosystem.formatter();
    let ignore_rules = match ignore_config {
        Some(rules) => IgnoreRules::new(rules, formatter),
        None => IgnoreRules::empty(),
    };

    let mut plan = if args.security_only {
        update::security::plan_security_updates(
            &analysis,
            manifest.ecosystem.as_ref(),
            &ctx.osv,
            &args.package,
            &ignore_rules,
            ctx.policy.cache.fetch_timeout_secs,
        )
        .await
    } else {
        update::plan_updates(&analysis, &content, formatter, &args.package, &ignore_rules)
    };
    // M2: must run before the plan is reported/rendered — `plan_security_updates` does not
    // dedup its own `Applied` items, so this demotes any edit that would be dropped by
    // `apply_plan`'s own dedup pass to `Skipped(OverlapsAnotherEdit)` first, so a reported
    // `applied` outcome always matches what actually gets written.
    update::dedup_applied_items(&mut plan.items);

    update::apply_plan(
        &plan,
        &manifest.path,
        &content,
        format::DryRun::from_flag(args.dry_run),
    )
    .map_err(|error| error.to_string())?;

    Ok(plan)
}
