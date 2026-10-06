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
        .fmt_fields(sanitizing_field_format())
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

/// Sink-level defense-in-depth against CWE-117 log forging (#1505): every field value
/// (and the log message itself) is rendered via `Debug`, then swept for control/invisible
/// characters via [`deps_core::redact::sanitize_invisible`], before being written to the log
/// line — closing the class for every `tracing` call site, including third-party error
/// `Display` text this crate does not control, not just the ones fixed individually.
///
/// Skips `log.*` fields entirely (critic S1): `.init()` installs `tracing-log`'s `LogTracer`
/// bridge for the `log` crate's own events (e.g. from `reqwest`), which attaches metadata
/// fields (`log.file`, `log.line`, `log.module_path`, `log.target`) that the default
/// formatter hides but a custom one must hide explicitly, or every bridged event grows a
/// `log.file="/abs/path/to/.cargo/registry/..."` suffix leaking the build machine's path.
///
/// Exercised by this module's own `tests` module (critic S2) rather than
/// `deps_core::test_util::capture_tracing_output_at`, which installs its own formatter and so
/// can't observe this one.
fn sanitizing_field_format()
-> impl for<'writer> tracing_subscriber::fmt::FormatFields<'writer> + 'static {
    use tracing_subscriber::field::MakeExt;

    tracing_subscriber::fmt::format::debug_fn(|writer, field, value| {
        if field.name().starts_with("log.") {
            return Ok(());
        }
        let rendered = format!("{value:?}");
        let sanitized = deps_core::redact::sanitize_invisible(&rendered);
        if field.name() == "message" {
            write!(writer, "{sanitized}")
        } else {
            write!(writer, "{}={sanitized}", field.name())
        }
    })
    .delimited(" ")
}

/// Shared per-run handles: HTTP cache, OSV client, deps.dev (GOSSIP) client, lock-file
/// cache, and the ecosystem registry — built identically for `check` and `update`.
struct RuntimeHandles {
    osv: Arc<OsvClient>,
    /// Always constructed (spec 074 FR-001) — construction alone makes no network call, so
    /// there is no cost to building this unconditionally. Every call site threads it as
    /// `Option<&Arc<DepsDevClient>>`, `None` when `!policy.gossip.enabled`, and the reused
    /// `deps_core::lsp_helpers::fetch_gossip_findings_batch` helper short-circuits before
    /// any HTTP request on `None` (mirrors `deps-lsp`'s own always-built `DocumentState::deps_dev`).
    deps_dev: Arc<deps_core::DepsDevClient>,
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
        deps_dev: Arc::new(deps_core::DepsDevClient::new(Arc::clone(&cache))),
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
        deps_dev: handles.deps_dev,
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

    // Deviation #4 (spec 062 tasks.md T024 / spec.md NFR-004): manifests are processed
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
    let freshness_non_default =
        policy.freshness.cooldown_secs != PolicyConfig::default().freshness.cooldown_secs;
    if args.security_only {
        // Spec 074 FR-006: GOSSIP's fetch-level cooldown exclusion (FR-003) is, for the exact
        // same reason, equally without effect under `--security-only` — extended here rather
        // than as a second independent warning so both no-op cooldown sources are named in one
        // place when both apply.
        let gossip_enabled = policy.gossip.enabled;
        let source = match (freshness_non_default, gossip_enabled) {
            (true, true) => Some("a non-default freshness cooldown and GOSSIP"),
            (true, false) => Some("a non-default freshness cooldown"),
            (false, true) => Some("GOSSIP"),
            (false, false) => None,
        };
        if let Some(source) = source {
            eprintln!(
                "deps-cli: warning: {source} has no effect under --security-only (the fix target comes from the advisory, not the freshness/GOSSIP-filtered registry pick)"
            );
        }
    } else if freshness_non_default && !policy.freshness.enabled {
        // Critique M4: a non-default `freshness.cooldown_secs` (from `--cooldown` or an
        // explicit `--config`'s `[freshness]` section) is silently a no-op once
        // `[freshness].enabled = false` — `to_freshness()` yields `FreshnessSettings::Disabled`
        // in that case, and every cooldown-evaluating call site (`cooldown_disposition` et al.)
        // short-circuits on it before ever reading the configured window. Consistent with
        // `check`'s existing `enabled`-gated cooldown badge, but an explicit override having
        // zero effect with no signal at all is surprising enough to warn about, unlike
        // `--security-only`'s structural (never-applicable) case above.
        eprintln!(
            "deps-cli: warning: a non-default freshness cooldown has no effect because [freshness].enabled is false"
        );
    }

    // FR-015: hard-error rather than silently scanning zero dependencies and exiting 0.
    if args.security_only && !policy.osv_checks().is_active() {
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
        deps_dev: Arc::clone(&handles.deps_dev),
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
        deps_cli::analyze::AnalysisScope::update_default()
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
    // Issue #1517: an unverified (never checked, timed out, or failed) OSV latest-check for
    // an outdated dependency must abort the whole run the same way a registry outage does —
    // silently omitting just that dependency from the plan could look like "nothing to do"
    // when the truth is "this could not be confirmed safe to write." Critique S4: scoped to
    // default mode only, and to dependencies actually in scope for this run's plan
    // (`--package`/`[update].ignore`) — `--security-only` never reads the default-mode plan
    // this check exists to protect, and an unrelated, unrequested dependency's transient OSV
    // timeout must not block it from applying fixes it already independently verified.
    if !args.security_only
        && analysis.has_unverified_latest_check(formatter, &args.package, &ignore_rules)
    {
        return Err(format!(
            "the OSV.dev latest-version check for one or more dependencies in {} could not be \
             completed (timeout or query failure); the plan would be based on unverified data",
            manifest.display_path.display()
        ));
    }

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
        // Spec 076 FR-024/T004: production `ManifestReparse`, driving the fallback-edit guard's
        // re-parse through the same resolved ecosystem/URI this analysis already used.
        let reparse = deps_core::edit::EcosystemReparse {
            ecosystem: manifest.ecosystem.as_ref(),
            uri: &analysis.uri,
        };
        update::plan_updates(
            &analysis,
            &content,
            formatter,
            &reparse,
            &args.package,
            &ignore_rules,
            ctx.policy.freshness.to_freshness(),
            // Fix-cycle item 9/security L3: reuses the SAME `now` `analyze_manifest`'s own
            // fallback-OSV-round gate evaluated against — never a second, independent
            // `PublishTime::now()` call that backward clock skew could desync from it.
            analysis.now,
        )
    };
    // M2: must run before the plan is reported/rendered — `plan_security_updates` does not
    // dedup its own `Applied` items, so this demotes any edit that would be dropped by
    // `apply_plan`'s own dedup pass to `Skipped(OverlapsAnotherEdit)` first, so a reported
    // `applied` outcome always matches what actually gets written.
    update::dedup_applied_items(&mut plan.items);

    // Issue #1517 critique S3: `analysis.latest_status.is_none()` means the OSV latest-check
    // did not run at all for this manifest — a *deliberate* offline/disabled skip (see
    // `analyze_manifest`'s `run_latest_check` gate), not a transient per-dependency failure
    // (those still fail closed via `has_unverified_latest_check`/`collect_update_candidates`'s
    // own gate above and below). `latest_verdict` degrades that to `NotApplicable`, so default
    // mode still writes the cached `latest` — silently, unless warned here. `--security-only`
    // never reads a cached `latest` at all (its fix targets come from advisories), so this
    // warning is default-mode only.
    if !args.security_only
        && analysis.latest_status.is_none()
        && plan
            .items
            .iter()
            .any(|item| matches!(item.outcome, update::Outcome::Applied { .. }))
    {
        let reason = if ctx.policy.network.offline {
            "network.offline is set"
        } else {
            "diagnostics.vulnerabilities_enabled is disabled"
        };
        eprintln!(
            "deps-cli: warning: the latest version(s) applied to {} were not checked against \
             OSV.dev ({reason}); this update proceeded on unverified data",
            manifest.display_path.display()
        );
    }

    update::apply_plan(
        &plan,
        &manifest.path,
        &content,
        format::DryRun::from_flag(args.dry_run),
    )
    .map_err(|error| error.to_string())?;

    Ok(plan)
}

#[cfg(test)]
mod sanitizing_field_format_tests {
    use super::sanitizing_field_format;
    use std::io;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct BufWriter(Arc<Mutex<Vec<u8>>>);

    impl io::Write for BufWriter {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BufWriter {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Installs a scoped subscriber using the real `sanitizing_field_format()`, runs `f`, and
    /// returns everything written to its buffer as a `String`.
    fn capture(f: impl FnOnce()) -> String {
        let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(BufWriter(Arc::clone(&buf)))
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .with_level(false)
            .fmt_fields(sanitizing_field_format())
            .finish();

        let guard = tracing::subscriber::set_default(subscriber);
        f();
        drop(guard);

        let captured = buf.lock().unwrap().clone();
        String::from_utf8(captured).expect("log output is valid utf8")
    }

    /// #1505: a `%`-sigil field and the message text itself must both be swept of
    /// control/invisible characters (`\n`, `\r`, ESC, U+2028), collapsing to a single line.
    #[test]
    fn sanitizes_percent_field_and_message_control_chars() {
        let payload = "evil\r\x1b[31mred\u{2028}line";

        let log = capture(|| {
            tracing::warn!(field = %payload, "message with \nnewline");
        });

        assert_eq!(
            log.lines().count(),
            1,
            "a crafted field/message must not forge an extra log line: {log:?}"
        );
        assert!(!log.contains('\r'), "raw CR must not survive: {log:?}");
        assert!(!log.contains('\x1b'), "raw ESC must not survive: {log:?}");
        assert!(
            !log.contains('\u{2028}'),
            "raw line separator must not survive: {log:?}"
        );
    }

    /// #1505 critic S1 regression: `tracing-log`'s `LogTracer` bridge (installed by `.init()`
    /// in `main()`) attaches `log.*` metadata fields to every `log`-crate event. These must
    /// be skipped entirely, not merely sanitized, or every bridged event (e.g. from
    /// `reqwest`) leaks the build machine's absolute source path via `log.file`.
    #[test]
    fn skips_log_crate_bridge_fields() {
        let log = capture(|| {
            tracing::warn!(
                log.file = "/home/builder/.cargo/registry/src/foo/connect.rs",
                log.line = 929,
                log.module_path = "reqwest::connect",
                log.target = "reqwest::connect",
                "bridged log-crate event"
            );
        });

        assert!(
            !log.contains("log.file"),
            "log.* bridge fields must be skipped, not rendered: {log:?}"
        );
        assert!(
            !log.contains(".cargo/registry"),
            "the build machine's absolute path must not leak: {log:?}"
        );
        assert!(
            log.contains("bridged log-crate event"),
            "the event's own message must still render: {log:?}"
        );
    }

    /// #1505: a span's own fields are rendered through the same `FormatFields` when the span
    /// context is printed alongside an event inside it, so they must be sanitized too.
    #[test]
    fn sanitizes_span_field_control_chars() {
        let log = capture(|| {
            let span = tracing::info_span!("crafted-span", value = %"evil\nvalue");
            let _enter = span.enter();
            tracing::warn!("event inside span");
        });

        assert_eq!(
            log.lines().count(),
            1,
            "a crafted span field must not forge an extra log line: {log:?}"
        );
    }
}
