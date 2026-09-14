---
aliases:
  - deps-engine Boundary Design
  - LSP/CLI/MCP Architecture Decision
tags:
  - sdd
  - architecture
  - decision-record
  - cli
created: 2026-09-14
status: accepted
related:
  - "[[spec]]"
  - "[[plan]]"
  - "[[tasks]]"
  - "[[constitution]]"
---

> [!info] Provenance
> Produced during implementation of [[plan]] PR 1 (spec 062, issue #711), when
> extracting `register_ecosystems`/`EcosystemRuntime` into `deps-core` (the
> original T002) hit a hard Cargo circular-dependency wall. Two rounds of
> architect → adversarial-critic review followed (round 1: `significant`
> verdict, 4 structural gaps; round 2: `minor` verdict, one mandatory ~150-line
> scope correction). This document is the architect's v2, carried into
> [[plan]] and [[tasks]] verbatim by `/sdd`. Moved here from the transient,
> gitignored `.local/arch/711-boundary-design.md` so the design rationale
> survives worktree cleanup and stays reviewable in PRs, per this project's
> `specs/` tracking convention (`.claude/rules/specs.md`).
>
> The user confirmed the core recommendation (a new `deps-engine` leaf crate)
> after asking why `deps-core` itself could not host this; the only
> alternative — merging all 14 ecosystem crates into `deps-core` — was
> assessed as a far larger, architecture-destroying change.

# Architecture: LSP / CLI / MCP boundary for `deps-lsp`

**Version**: v2 (2026-09-14). Revised in response to the critic's `significant` verdict
(round-1 review).
**Status**: accepted — critic verdict `minor` on round 2, proceeding to implementation via [[tasks]].
**Supersedes**: [[plan]] §1 "Ecosystem registration location" (original decision) and
[[tasks]]'s original T002/T004.

> **v2 change log.** §1, §2, §5.1–5.4 and §6 survive the critique intact. Rewritten:
> §1.5 (split target is `ServerState`, not `DocumentState` — S1); §3.2 and §5.6 (capability B
> is now a **classification-layer extraction**, not a `resolve_manifest` aggregate — S4;
> `ManifestAnalysis`/`resolve_manifest` are **withdrawn**); §3.5 (progress and staleness
> designed explicitly — S3); §4 (fabricated justification removed — M1); §7 (semver gate
> replaced, public-dependency cost named — M3/M4/M5); §8 (six-step sequencing with an honest
> per-step gate — S2/M2); §9 (assumptions resolved, new open questions).
>
> One critic finding is **contested with evidence**: S2 ("PR 1c's tests get rewritten, not
> relocated") correctly demolished v1's `resolve_manifest` design, but does **not** apply to
> the design that replaces it — see §5.6.3 for the measurements.
>
> **Round-2 amendment (critic verdict `minor`)**: N3 moves the classification boundary ~150
> lines earlier than v2's first draft had it — `merge_registry_fetch_result`'s pure half and
> two `diff.rs` helpers must move too, or `deps-cli`'s orchestrator has no shared code for
> building `DependencyOutcomes` correctly, which is exactly the FR-005 hole Option F exists to
> close. PR 1c is therefore **four** steps and **~950** lines, not three/~800. N1 and N2 are
> smaller corrections (a feature-unification note; `ProgressSender` needs a `pub` constructor,
> not a verbatim move). N4 corrects three miscounted verification numbers. N5 reparameterizes
> `load_resolved_versions` to take `&Arc<LockFileCache>` only (not `&ServerState`) and bumps
> `build_scan_targets`'s visibility. Every correction makes the existing conclusion stronger or
> leaves it unchanged, none flips a decision. See
> [[#9-assumptions-open-questions-risks]] and [[tasks]] for how N1/N2/N3/N4/N5 are carried into
> the task breakdown.

---

## 0. Executive summary

The circular-dependency wall hit at T002 is the symptom of `deps-lsp` silently holding
**three front-end-agnostic responsibilities** that it owned only because it was the only
front end. One is blocked by a Cargo cycle, one is a bigger reuse surface than the plan
accounted for, and one is already resolved.

**Recommendation**: introduce one new leaf crate, **`deps-engine`**, depending on `deps-core`
+ all 14 ecosystem crates and on nothing else in the workspace. Every driving adapter
(`deps-lsp`, `deps-cli`, future `deps-mcp`) depends on `deps-engine` and on none of the
others. This is **hexagonal (ports & adapters)** with one Rust amendment: the composition
root is a *crate*, not a function, because Cargo's acyclic package graph makes "the outermost
main wires everything" impossible with three mains.

Into `deps-engine` go (A) ecosystem composition, verbatim, and (B) **the pure
verdict-classification layer only** — ~950 lines (round-2 corrected; see N3) that are already
`ServerState`-free and `Client`-free. Orchestration (progress lifecycle, mid-flight staleness
rejection, incremental diffing, document lifecycle) stays per-adapter, by design and not by
omission.

`PolicyConfig` stays where the developer already put it (`deps-core`). T001/T003 stand.

---

## 1. Verified facts (read from the code, not from the plan)

### 1.1 Actual crate graph

```
deps-core                        ← leaf; already depends on tower-lsp-server,
   ↑                                reqwest, tokio, futures, dashmap
   ├── deps-cargo, deps-npm, deps-pypi, deps-go, deps-bundler, deps-dart,
   │   deps-maven, deps-gradle(→deps-maven), deps-swift, deps-composer,
   │   deps-nuget, deps-deno(→deps-npm), deps-github-actions, deps-gitlab-ci
   │        ↑
   └────────┴── deps-lsp   (14 optional deps + tower-lsp-server transport)
```

Verified by grepping every `crates/*/Cargo.toml`: no ecosystem crate depends on `deps-lsp`,
and all 14 depend on `deps-core`.

**T002 as written is therefore impossible.** Cargo rejects package-level cycles
unconditionally — optional and feature-gated dependencies are not an exception (only
`[dev-dependencies]` are). `deps-core` can never name `deps-cargo`.

### 1.2 The plan's stated motive for avoiding `deps-cli → deps-lsp` is factually wrong

`plan.md` §1 says that alternative "pulls in `tower-lsp-server` and the whole LSP transport
stack for no reason". But `crates/deps-core/Cargo.toml` lists `tower-lsp-server` as a
**non-optional** dependency and `deps-core/src/lib.rs:149` does `pub use tower_lsp_server;`.
`ls_types::{Diagnostic, Hover, CodeAction, Position, Range, Uri, DiagnosticSeverity}` appear
in `deps-core`'s public trait signatures, and `deps_core::policy_config` imports
`DiagnosticSeverity` on line 2.

`deps-cli` links `tower-lsp-server` regardless of which option is chosen. The option is still
rejected, for the reasons in §5.3 — but the bad argument must not survive into the spec.

### 1.3 Three distinct capabilities are trapped in `deps-lsp`

| # | Capability | Where today | Cycle-blocked? | CLI | MCP |
|---|---|---|---|---|---|
| A | **Composition**: `register_ecosystems`, `EcosystemRuntime`, the `ecosystem!`/`register!` macros | `deps-lsp/src/lib.rs:39-522` | **Yes** — constructs `deps_cargo::parser::CargoParseContext`, `deps_npm::config::NpmParseContext`, `deps_go::config::GoParseContext`, `deps_nuget::config::NuGetParseContext` + 10 more | Yes | Yes |
| B | **Verdict classification**: decide yanked / deprecated / fetch-failed / in-use-version / OSV key per package | `document/{fetch,resolved,osv_scan}.rs` | No | **Yes** | **Yes** |
| C | **Policy config** | already in `deps-core/src/policy_config.rs` (shipped) | No | Yes | Yes |

The plan addresses only A and C. **B is what makes FR-005 (`spec.md:151` — "run the identical
`Ecosystem::generate_diagnostics` path … so CLI and LSP verdicts cannot structurally drift")
true rather than aspirational.** (v1 mis-cited SC-001 here; SC-001 at `spec.md:205` is the
*measurement* — "100% agreement in the cross-ecosystem regression suite" — while FR-005 is
the structural requirement.)

### 1.4 Why B is unavoidable: `generate_diagnostics` resolves nothing

`Ecosystem::generate_diagnostics` (`deps-core/src/ecosystem.rs:1071`) takes
`versions: VersionData<'a>` — a *borrowed view over already-populated maps*, not a resolver.
`handlers/diagnostics.rs:181-242` shows what must exist before that call:

```
parse_result, cached_versions, resolved_versions, resolved_version_candidates,
vulnerabilities, outcomes, licenses   (+ license_policy, offline, ecosystem_id)
```

`plan.md`'s claim that `deps-cli` merely "calls that ecosystem's `generate_diagnostics` — the
identical call the LSP's `handlers/diagnostics.rs` makes" skips the entire body of work that
produces the inputs.

### 1.5 The coupling is `ServerState`, not `DocumentState` *(rewritten — critic S1)*

v1 analysed `DocumentState` and stopped one level short. `ServerState`
(`document/state.rs:582-641`) is the actual blocker, and it mixes two unrelated concerns in
11 public fields:

| Engine handles (front-end-agnostic) | Editor state (LSP-only) |
|---|---|
| `cache: Arc<HttpCache>` | `documents: DashMap<Uri, DocumentState>` |
| `osv: Arc<OsvClient>` | `cold_start_limiter: ColdStartLimiter` |
| `deps_dev: Arc<DepsDevClient>` | |
| `lockfile_cache: Arc<LockFileCache>` | |
| `ecosystem_registry: Arc<EcosystemRegistry>` | |
| `registry_policy: Arc<RegistryAccessPolicy>` | |
| `nuget_user_profile_sources`, `gitlab_instance_host` | |
| `license_policy: RwLock<Arc<LicensePolicy>>` | |

All three capability-B modules take `&ServerState` or its fields (`resolved.rs:170`,
`fetch.rs:757`, `fetch.rs:875`, `osv_scan.rs:191,311,447`).

**But — critically — they take it only at their orchestration entry points.** §5.6 shows the
classification bodies beneath those entry points are already clean. This is what makes the
revised design possible without splitting `ServerState` at all.

`DocumentState`'s own split (8 domain fields vs. 4 editor-only: `parsed_at`, `loading_state`,
`loading_started_at`, `version`) remains a true observation, but v2 no longer acts on it —
see §5.6.2.

---

## 2. Evaluating the three framings *(unchanged from v1 — confirmed sound)*

### 2.1 Hexagonal / ports & adapters — **best fit, adopt**

The codebase is already 80 % hexagonal and nobody named it:

| Hexagonal concept | Already exists as |
|---|---|
| Driven port (outbound) | `deps_core::registry::Registry`, `LockFileProvider`, `EcosystemFormatter` |
| Driven adapter | each `deps-<ecosystem>` crate's registry client + parser + formatter |
| Driving adapter | `deps-lsp` (the only one so far) |
| Anti-corruption layer | each ecosystem's parser/formatter mapping a foreign registry model onto `PackageName`/`ConcreteVersion`/`VersionReq` |
| Application / use-case layer | **missing** — `document/` + `handlers/` play it by accident |
| Composition root | **missing** — `register_ecosystems` plays it by accident |

Those two accidents are the two things that broke.

**The Rust amendment the pattern literature does not cover.** Classic hexagonal puts the
composition root in the outermost ring (`main`). Cargo's package graph is a hard DAG, so a
composition root that instantiates every driven adapter must be a *package* depending on all
of them, with every `main` depending on *it*. The composition root therefore sits
structurally *below* the adapters — inverted from the usual diagram, identical in effect.
Any design that does not say this out loud will rediscover the T002 wall.

### 2.2 Onion — **reject**

Onion's defining rule is a *pure* innermost domain ring with zero I/O. `deps-core` violates
this by construction and correctly so: it owns `HttpCache` (`reqwest`), the OSV and deps.dev
clients, `fs_probe`, `net_policy`, `mtime_cache`. Purifying it means splitting `deps-core`
into `deps-domain` + `deps-infra` and inverting `HttpCache` behind a trait — thousands of
lines whose only payoff is testability `mockito` already provides. Onion's one useful idea
over hexagonal (dependencies point inward) is already satisfied.

### 2.3 DDD — **vocabulary only**

*Tactical* DDD: the value objects already exist and are good (`PackageName`,
`ConcreteVersion`, `VersionReq`, `Redacted<T>`, `EcosystemId`); `Registry` is a Repository in
all but name. What DDD would add — aggregate roots enforcing invariants, domain events,
application services as classes — has nothing to bite on in an *integration* domain with thin
business rules.

*Strategic* DDD is the useful lens: **each ecosystem crate is a bounded context** with its
own ubiquitous language (a "yank" in Cargo, a "deprecation" in npm, an "abandoned" package in
Composer), its formatter/parser the anti-corruption layer; `deps-core` is the **shared
kernel**. Good description of what exists; prescribes no change. Use the vocabulary in docs,
add no structure.

### 2.4 Verdict

**Hexagonal, with the composition-root-is-a-crate amendment.** Name the rings in the
project's existing vocabulary (`deps-core` / ecosystem crates / `deps-engine` / adapter
crates) rather than importing `domain`/`application`/`infrastructure` module names that would
collide with the `deps-<name>` convention and mean nothing to a contributor reading `crates/`.

---

## 3. Recommended target architecture

### 3.1 Crate map

```
┌─────────────────────────────────────────────────────────────┐
│ DRIVING ADAPTERS (one per protocol; none depends on another)│
│  deps-lsp        deps-cli        deps-mcp (future, #710)    │
│  transport       clap + walk     rmcp stdio                 │
│  document/       format/         tool schemas               │
│  handlers/       exit codes      path allowlist             │
│  ── each owns its own orchestration: when to fetch, how to  │
│     report progress, how to handle input changing mid-flight│
└───────────┬─────────────┬──────────────┬────────────────────┘
            ▼             ▼              ▼
┌─────────────────────────────────────────────────────────────┐
│ COMPOSITION ROOT + CLASSIFICATION — deps-engine  (NEW)      │
│   ::setup       register_ecosystems, EcosystemRuntime,      │
│                 ecosystem! re-exports, from_policy          │
│   ::classify    the verdict-deciding layer (~950 lines)     │
│   ::progress    ProgressSender (designed mpsc port)         │
└───────────┬─────────────────────────────────────────────────┘
            ▼  (depends on all 14, feature-gated)
┌─────────────────────────────────────────────────────────────┐
│ DRIVEN ADAPTERS — 14× deps-<ecosystem>                      │
└───────────┬─────────────────────────────────────────────────┘
            ▼
┌─────────────────────────────────────────────────────────────┐
│ SHARED KERNEL + PORTS — deps-core                           │
│  Ecosystem/Registry/LockFileProvider/EcosystemFormatter,    │
│  EcosystemRegistry, lsp_helpers, osv, deps_dev, net_policy, │
│  fs_probe, policy_config                                    │
└─────────────────────────────────────────────────────────────┘
```

**The invariant to enforce forever**: no driving-adapter crate may appear in another
driving-adapter crate's dependency tree. CI-guarded (§7.4).

### 3.2 `deps-engine` module contents *(rewritten — critic S4; boundary corrected — critic N3)*

`ManifestAnalysis` and `resolve_manifest` from v1 are **withdrawn**. What moves is the
classification layer — the code that *decides a verdict* — and nothing that orchestrates.

| Module | Contents | Moved from |
|---|---|---|
| `deps_engine::setup` | `EcosystemRuntime`, `register_ecosystems`, the `ecosystem!`/`register!` macros and the ~110 concrete-type re-exports; plus **new** `EcosystemRuntime::from_policy(&PolicyConfig) -> EcosystemRuntime` | `deps-lsp/src/lib.rs:39-522`, verbatim |
| `deps_engine::classify::fetch` | `dedup_dependencies_by_source`, `composer_minimum_stability`, `FetchResult`, `fetch_latest_versions_parallel`, `fetch_and_classify_package`, **plus (N3) the pure half of `merge_registry_fetch_result`** — raw→normalized re-keying (`fetch.rs:896-903`) and the `set_fetch_failure_if_absent` collision rule (`:905-913`, "impl-critic M2") | `fetch.rs:29-716`, and the pure slice of `:874-934` |
| `deps_engine::classify::resolved` | `collect_in_use_versions`, `dependency_version_map`, `cached_versions_from_lockfile`, `split_resolved_packages`, and `load_resolved_versions` reparameterized from `&ServerState` to **`&Arc<LockFileCache>` only** (critic N5 correction — `resolved.rs:208-210` is its sole `state` touch; the ecosystem itself arrives as `&dyn Ecosystem`) | `resolved.rs:50,93,114,137,168` |
| `deps_engine::classify::osv` | `build_scan_targets` (visibility bumped from private per N5), `resolve_fix_target`, `collect_fix_target_resolutions`, `apply_live_fix_target_statuses` | `osv_scan.rs:66,635,685,721` |
| `deps_engine::classify::diff` | **(N3, new)** `merge_deprecations_after_fetch` and `merge_no_comparable_versions_after_fetch` (the "I2" normalized-dedup + "fetched and clean" S1 rule), reparameterized from `doc: &mut DocumentState` to `&mut deps_core::lsp_helpers::DependencyOutcomes` | `diff.rs:106-155`, `:156+` |
| `deps_engine::progress` | `ProgressSender` + `ProgressUpdate` + a new `pub fn channel(total: usize) -> (ProgressSender, Receiver<ProgressUpdate>)` factory (critic N2 — **not** a verbatim move: `progress.rs:40-48`'s fields are private, so a `pub` constructor is required at the boundary) | `deps-lsp/src/progress.rs:36-62` |

**Explicitly staying in `deps-lsp`** — orchestration, by design:

- `fetch.rs:749-874` — `fetch_registry_versions_for_change` (`&ServerState`, `&Client`),
  `fetch_failure_toast`; and the **~12-line remainder** of `merge_registry_fetch_result`
  (`:874-934` minus the N3 pure slice) — the `state.documents.get_mut(...)` lookup and
  `set_loaded()`/`set_failed()` calls, which are genuinely `DocumentState` mutation and do not
  move
- `osv_scan.rs` — `run_osv_scan_phase_a`, `run_license_prefetch`,
  `run_osv_phase_b_and_commit`, `run_osv_fix_target_verification`, and the
  `doc.content == snapshot` staleness commit guards at **`:378` and `:532`** (critic N4
  correction — `:197`/`:320` are snapshot *captures*, not guards, and `:274` is a doc comment)
- `resolved.rs:26-36` — `RefetchPolicy` (an editor-only reparse concept; note it does **not**
  travel with the rest of `resolved.rs`, and `fetch.rs:9` imports it)
- `progress.rs` — `RegistryProgress` (owns the `Client` and the LSP progress lifecycle;
  constructs `deps_engine::progress::channel(total)` instead of the struct literals it uses
  today)
- `diff.rs`'s `preserve_cache` and `drop_cache_for_forced_refetch` only — editor-only cache
  reconciliation, genuinely `DocumentState`-mutating. **Explicitly not staying**:
  `merge_deprecations_after_fetch` and `merge_no_comparable_versions_after_fetch` — these move
  to `deps_engine::classify::diff` per N3 above; do not read "diff.rs stays in deps-lsp" as
  applying to the whole file
- `lifecycle.rs`, `loader.rs`, `reparse.rs` — unchanged, no capability-B code in these files
- `ServerState`, `DocumentState`, `ColdStartLimiter`, all of `handlers/`

**The split rule, stated once so it is testable**: *`deps-engine` decides what a dependency's
verdict is; the adapter decides when to ask and what to do while waiting.* Concretely —
`deps-engine` may not know that its input can change under it, may not own a progress
lifecycle, and may not reach a transport client.

### 3.3 Why `deps-engine` and not another `deps-core` module

Only because Cargo forbids it (§1.1). Say this plainly in the spec: `deps-engine` is
`deps-core`'s composition half, separated by a toolchain constraint, not a conceptual one.
That framing also yields a mechanical placement rule a contributor can apply without asking:
**if it must name a concrete ecosystem type, it goes in `deps-engine`; otherwise `deps-core`.**

### 3.4 Naming

`deps-engine` matches the `deps-<name>` convention and matches issue #710's own words ("the
same dependency-health engine"). Risk: a reader may expect `deps-<name>` to mean "an
ecosystem" — mitigated by the crate description and by it being the only non-ecosystem,
non-adapter crate. Rejected alternatives: `deps-composition` (inaccurate once `classify`
lands), `deps-app` (vague), `deps-runtime` (collides with `EcosystemRuntime`).
**Settled**: the name is unclaimed on crates.io (critic-verified).

### 3.5 Progress and staleness, designed rather than dropped *(new — critic S3; N2 correction)*

v1's `resolve_manifest(...)` signature silently deleted two live behaviours. Both are
resolved by the §3.2 boundary, not papered over:

**(a) Progress reporting.** `ProgressSender` threads into the innermost per-package fetch
(`fetch.rs:239 → 277 → 294 → 411 → 703`), which is inside the region that moves. `progress.rs`'s
fields and `ProgressUpdate` are private today (constructed only at `RegistryProgress::start`
`:137` and at `:286`/`:300`, all staying in `deps-lsp`), so — correcting v2's first draft —
this is **not** a verbatim move: `deps_engine::progress` needs `ProgressUpdate` made `pub` and
a `pub fn channel(total)` factory. `RegistryProgress` (which holds the `Client` and runs
begin→report→end) stays in `deps-lsp` and calls that factory. The parameter stays
`Option<ProgressSender>`, so `deps-cli` passes `None` — or, for free, drains the receiver to
render a terminal progress bar, and `deps-mcp` ignores it. This is a small, designed port
promotion, not an invented abstraction.

**(b) Mid-flight staleness rejection.** `osv_scan.rs:378,532` snapshot-compare-commit guards
discard a result if the document changed during an await. The critic is right that this
cannot live inside `deps-engine` under §3.2's split rule — and right that v1 made it
structurally inexpressible. v2 resolves it by *not moving it*: the staleness guard is part of
the `run_*` orchestrators, which stay in `deps-lsp` (§3.2's "explicitly staying" list). The
already-existing phase-A / await / phase-B-commit shape of `osv_scan.rs` is exactly the right
seam — phase A's pure target-building (`build_scan_targets`) and phase B's pure
status-application (`apply_live_fix_target_statuses`) move; the snapshot-compare-commit
between them stays. **This is not a concurrency-model change; it is a decision to leave the
concurrency model where it is.** `deps-cli` and `deps-mcp` need no equivalent: their input is
a file read once per run that cannot mutate mid-analysis.

---

## 4. Config composition — no change needed *(justification corrected — critic M1)*

**Recommendation: leave `PolicyConfig` in `deps-core` exactly as the WIP has it.**

v1 justified this by claiming `deps-core::lsp_helpers` consumes `PolicyConfig`. **That was
fabricated** — verified: `policy_config` is referenced from nowhere else inside
`crates/deps-core/src/`. The conclusion is unchanged but rests on §3.3's mechanical rule
alone: `policy_config.rs` names no concrete ecosystem type (it needs only `serde` and
`tower_lsp_server::ls_types::DiagnosticSeverity`), so it hits no cycle and has no reason to
sit in the composition crate. Placing it in `deps-engine` would be arbitrary and would
force `deps-cli` to depend on the composition crate merely to parse a config file.

Two properties of the shipped shape are correct and should be made *deliberate* in the spec:

1. **Each front end owns its own outer struct and its own `deny_unknown_fields`.**
   `deps-lsp::config::DepsConfig` = editor sections + `#[serde(flatten)] policy`;
   `deps-cli::config::CliConfig` = CLI-only keys + the same flatten; a future
   `deps-mcp::config::McpConfig` likewise. Shared sections cannot drift; adapter-specific
   ones cannot leak into each other.
2. **`PolicyConfig` is format-agnostic** — plain `Deserialize`, so JSON
   (`initializationOptions`) and TOML (`deps.toml`) both work with no second schema.

**The `flatten` asymmetry is intended, tested, and should be written down as such** (was
assumption A-2, now settled): `config.rs`'s `test_flatten_preserves_deny_unknown_fields_rejection`
asserts an unknown *top-level* key rejects the whole payload; its companion
`test_flatten_still_tolerates_unknown_key_nested_inside_a_known_section` asserts an unknown
key *nested inside* a known section is deliberately tolerated, for forward-compat.
`deny_unknown_fields` was only ever top-level. Not a risk to monitor — a documented contract,
and one `deps-cli` must reproduce exactly.

---

## 5. Options considered

### 5.1 Option A — new leaf crate `deps-engine` — **RECOMMENDED** *(for capability A)*

- Resolves the cycle by construction; the graph stays a DAG with one new node.
- One registration list, one `EcosystemRuntime`, shared by three adapters (principle 1).
- The 14 ecosystem feature flags move to `deps-engine`; each adapter forwards them
  (`cargo = ["deps-engine/cargo"]`), so `--no-default-features --features npm` keeps working
  for `deps-lsp` and works for free for new adapters.
- `deps-lsp` drops 14 optional dependencies and its
  `[package.metadata.cargo-machete] ignored` list — a net simplification.
- **Cost**: a 17th published crate on the principle-8 contract (18th with `deps-cli`), and
  §7.3's public-dependency coupling.

### 5.2 Option B — each front end re-registers — **reject**

`register_ecosystems` is 140 lines of *non-uniform* wiring: `cargo`, `npm`, `deno`, `pypi`,
`go`, `nuget`, `gitlab-ci` each need a different context object threaded in; npm+deno must
share one `NpmRegistry` instance (#312); and the return value is the single source of truth
for `config::reparse_scope`'s policy-reparse set (#592 security M1, with a dedicated
anti-drift test). Three hand-maintained copies is a security regression waiting to happen.

### 5.3 Option C — adapters depend on `deps-lsp` as a library — **reject**

Not for `plan.md`'s reason (§1.2). Reject because it makes `deps-lsp`'s `pub` surface the
de-facto SDK for two unrelated protocols — every internal LSP refactor becomes a principle-8
break for CLI and MCP too; it forces `deps-cli` to link `tokio` `io-std`,
`tracing-subscriber` `env-filter` and the `tower-lsp-server` *server runtime* into a CI
binary; and it leaves the boundary undefined, guaranteeing the question returns at #710.

### 5.4 Option D — `inventory`/`linkme` self-registration — **reject**

(a) Both rely on link-section/`unsafe` machinery, against the spirit of workspace-wide
`unsafe_code = "forbid"`, for a build-time convenience. (b) Registration order becomes
link-order-dependent, and `EcosystemRegistry::for_uri`'s ordered routing has a *known live
bug class* depending on deterministic precedence — see the `.gitlab/ci/action.yml` regression
test at `deps-lsp/src/lib.rs:718-744`. (c) The non-uniform per-ecosystem context threading
(§5.2) cannot be a uniform factory without inventing a second config-plumbing mechanism.
(d) It destroys the compile-time "every `EcosystemId::ALL` variant is registered" check
(#758) that principle 2 depends on.

### 5.5 Option E — `deps-engine` for capability A only, B stays in `deps-lsp` — **reject as an endpoint**

`deps-cli` would write its own classification to satisfy FR-005, which is the drift principle
1 forbids, and #710's `check_manifest`/`suggest_update` would need a third. Acceptable only
as sequencing, never as the final shape.

### 5.6 Option F — classification-layer-only extraction — **RECOMMENDED** *(for capability B; adopted from critic S4, boundary corrected by N3)*

Move the pure verdict-deciding code; leave all orchestration per-adapter.

#### 5.6.1 The evidence that it is cleanly separable

Verified directly against the production regions (everything below the `#[cfg(test)]` marker
is excluded):

| Module | Production lines | Coupling found |
|---|---|---|
| `fetch.rs` | 1–935 | `ServerState` at **:757, :875 only**; `Client` at **:758 only**. Lines 29–716 — `dedup_dependencies_by_source`, `FetchResult`, `fetch_latest_versions_parallel`, `fetch_and_classify_package` — are entirely free of both. `merge_registry_fetch_result` (`:874-934`) splits: `:896-913` pure, the remaining ~12 lines touch `state.documents`. |
| `resolved.rs` | 1–227 | 4 of 5 production functions pure; only `load_resolved_versions:168` takes `&ServerState`, and only for `lockfile_cache` (its type already lives in `deps-core`). `RefetchPolicy:26` is editor-only and stays. |
| `osv_scan.rs` | 1–736 | 3 production `ServerState` references (`:191,:311,:447`), all inside the four `run_*` orchestrators; `build_scan_targets:66`, `resolve_fix_target:635`, `collect_fix_target_resolutions:685`, `apply_live_fix_target_statuses:721` are pure. |
| `diff.rs` | — | `merge_deprecations_after_fetch` (`:106-155`) and `merge_no_comparable_versions_after_fetch` (`:156+`) are pure except for a `doc: &mut DocumentState` parameter that only touches `doc.outcomes` (`deps_core::lsp_helpers::DependencyOutcomes`). |

So ~950 pure lines (N3-corrected) carry the verdict-deciding logic, and the
`ServerState`/`Client` coupling lives in a small, well-bounded set of orchestration lines that
v1 already planned to leave behind. **`ServerState` never needs to be split** — which
dissolves critic S1's blocker rather than merely answering it.

#### 5.6.2 What this gives up versus v1, honestly

`deps-cli` and `deps-mcp` each write their own thin orchestrator: call
`load_resolved_versions`, call `build_scan_targets` + the OSV client, call
`fetch_latest_versions_parallel`, call the N3-extracted pure `merge_registry_fetch_result`
half to assemble `DependencyOutcomes` correctly, assemble `VersionData`, call
`generate_diagnostics`. Estimated 100–150 lines of straight-line code per adapter (revised up
slightly from v2's first-draft 80–150 to account for N3's added call), with no staleness
guard, no incremental diff, and no progress lifecycle to reproduce.

Is that drift risk? The drift-prone part — *is this version yanked / deprecated /
fetch-failed, which version is actually in use, which OSV key identifies it, and how do raw
fetch results normalize into `DependencyOutcomes`* — is shared. The per-adapter part is
loop-and-store. That is the honest boundary, and it is where a concurrency model that exists
only because documents can be edited mid-flight naturally ends. **Backstop**: the FR-005
parity test specified in PR 2 (§8) runs one fixture through both the LSP and CLI paths and
asserts identical findings — cheap, because both now share the classification layer.

Also given up: `ManifestAnalysis` as a named aggregate, and therefore §7.2's former need to
reshape `DocumentState`. That is a simplification, not a loss.

#### 5.6.3 Why critic S2 does not apply to this design *(contested, with measurements; N4-corrected)*

S2 argued PR 1c's test suite gets rewritten rather than relocated, because it constructs
`ServerState::new()` and drives URI-keyed document mutation — so it is not the safety net §8
claimed. **That is a correct demolition of v1's `resolve_manifest` design**, which inverted
control flow through exactly those tests.

It does not hold for Option F. Measured (N4-corrected — the round-2 review re-derived these
directly from source; the round-1 draft's raw `fn ` counts were inflated by mock trait impls,
helpers, and closures in the test region):

- `fetch.rs`: **51** test functions (10 `#[test]` + 41 `#[tokio::test]`); **46 of 51**
  reference the moving functions (`fetch_and_classify_package`,
  `fetch_latest_versions_parallel`, `dedup_dependencies_by_source`); only **2** construct
  `ServerState`.
- `osv_scan.rs`: 1 import + 3 production `ServerState` signatures (`:191,:311,:447`) + **7**
  test-function references (`:786,:811,:835,:877,:919,:966,:1011`) — all attached to the
  `run_*` orchestrators, which stay.

So the overwhelming majority of these tests target the pure layer and relocate with it; the
handful that build a `ServerState` stay in `deps-lsp` alongside the orchestrators they test,
and keep passing unchanged. The safety net is real for Option F — but §8 states the gate per
step rather than as one blanket claim, since S2's underlying demand (stop asserting "tests
move unchanged" without per-step evidence) is legitimate regardless.

---

## 6. Designing for the MCP adapter (#710) now *(unchanged from v1 — confirmed sound)*

Issue #710's tool surface is strictly *more* demanding than the CLI's, which makes it the
right forcing function:

| #710 tool | Needs | Provided by |
|---|---|---|
| `check_manifest` | full per-dependency verdict set | `deps_engine::classify` + `Ecosystem::generate_diagnostics` — the same calls LSP and CLI make |
| `resolve_latest` | latest + latest-satisfying + publish date + cooldown | `Ecosystem::registry()` + `deps_core::freshness` — already reachable, no new surface |
| `suggest_update` | *the exact edit the code action would apply* | `Ecosystem::generate_code_actions(parse_result, position, uri, version_data, content)` — needs the same classified `VersionData`. **This is the tool that proves capability B must be shared**: without it, MCP could suggest a different bump than the LSP's own quickfix on the same file. |
| `explain_advisory` | OSV id → summary/severity/fixed versions | `deps_core::osv` directly |

A future `deps-mcp` is therefore: `Cargo.toml` (deps-core + deps-engine + `rmcp` + 14
forwarded features) + a transport module + JSON schemas + a path-allowlist guard reusing
`fs_probe::read_to_string_capped` + the ~100-150-line orchestrator of §5.6.2. **Zero changes
to `deps-engine`, `deps-core`, or any ecosystem crate.** That is the test this design must
pass, and it does.

**Open question (O-2)**: #710 proposes `deps-lsp --mcp` (one binary, convenient for the Zed
extension). Under this boundary that is backwards — the LSP adapter hosting the MCP adapter.
Recommendation: a separate `deps-mcp` binary, with the Zed extension declaring
`language_server_command` and `context_server_command` pointing at two binaries in one
release archive (`zed_extension_api` 0.7 supports exactly this). If single-binary
distribution proves to be a hard requirement, the fallback is a trivial `deps-tools` crate
whose `main` dispatches to the three as libraries — still no adapter-to-adapter dependency.
**Do not decide here**; it belongs to #710's own `/sdd specify`.

---

## 7. Impact on `deps-lsp` (the shipped, 1.0.0-tagged adapter)

### 7.1 A compile-only local check complements (not replaces) CI's `cargo-semver-checks` gate *(rewritten — critic M3; corrected — reviewer 2026-09-14)*

v1 proposed `cargo-semver-checks` as the gate and `#[deprecated]` on re-exports as the
migration path. The `#[deprecated]` part is wrong outright — it's a known rustc no-op on a
`pub use` re-export for downstream consumers. The `cargo-semver-checks` part needs a more
careful split between two distinct environments, not a blanket "cannot run" claim:

- **Local dev sandbox**: running the `cargo-semver-checks` CLI directly against this
  environment's toolchain fails — installed 0.45.0 errors with
  `error: unsupported rustdoc format v60`. This is a real, documented limitation for anyone
  trying to run the tool by hand before pushing, and is the reason a fast, local,
  pre-push check is worth adding.
- **CI's actual gate is live and functioning**: `ci.yml`'s `semver` job (`ci.yml:239-263`)
  does not invoke the local CLI at all — it uses the `obi1kenobi/cargo-semver-checks-action`,
  which provisions its own isolated `stable` toolchain via rustup regardless of this
  workspace's pinned nightly, and (per that job's own comments) auto-installs
  cargo-semver-checks v0.50.0+, which added rustdoc v61 support — so it never hits the local
  format-v60 mismatch. It blocks on every PR/push (`continue-on-error` applies only to the
  separate *scheduled* run); it is not advisory. Live runs confirm the signal is real: it
  passed on ordinary PR/push runs and caught a genuine breaking change in the 2026-09-13
  scheduled run (issue #904 — `LineOffsetTable` lost auto-trait impls, `HostClass` gained
  `#[non_exhaustive]`, `CharOffsets` was removed). (Note separately:
  `specs/constitution.md` principle 8's parenthetical calling this gate "advisory/
  `continue-on-error` on normal PR/push runs" is **stale and should be corrected** in a
  follow-up to this spec revision; see [[tasks]]'s handoff note.)

**Additional local check**: a compile-only test in `deps-lsp` (`tests/public_api_paths.rs`)
that `use`s every previously-public path — `deps_lsp::{EcosystemRuntime,
register_ecosystems}`, `deps_lsp::config::{CacheConfig, DiagnosticsConfig, …}`, and each of
the ~110 `ecosystem!`-generated type paths. If a path stops resolving, the workspace stops
compiling. This is a fast, local, pre-push check that catches simple path-removal breakage
for a contributor who cannot run the real `cargo-semver-checks` CLI locally — it does not
replace CI's `semver` job, which remains the authoritative, blocking non-breakage gate. It
costs one file.

### 7.2 Phase-by-phase breakage

**Capability A move**: `deps_lsp::EcosystemRuntime` and `deps_lsp::register_ecosystems` are
`pub` at the crate root, so relocating them breaks unless re-exported:

```rust
pub use deps_engine::setup::{EcosystemRuntime, register_ecosystems};
```

Same technique the developer already used for the config section types
(`deps-lsp/src/config.rs:4-7`). The ~110 `ecosystem!`-generated re-exports move to
`deps-engine` and must be forwarded identically, or their removal is breaking. Recommend
forwarding them and scheduling removal for the next major (a consumer wanting
`CargoEcosystem` should depend on `deps-cargo`) — tracked as a follow-up issue rather than a
`#[deprecated]` attribute that does nothing.

**Capability B move (Option F)**: everything moving is `pub(crate)` today
(`fetch.rs`, `resolved.rs`, `osv_scan.rs`, `diff.rs` expose nothing public) except
`ProgressSender`, which is `pub` in `deps_lsp::progress` and is re-exported the same way.
`DocumentState` and `ServerState` are untouched — v1's §7.2 field-reshape problem no longer
exists.

**Net**: the redesign ships without a `deps-lsp` major bump, gated by §7.1's compile test
rather than asserted. `CHANGELOG.md` entries belong under "Changed".

**Settled** (was assumption A-1): `deps-lsp` has **0 reverse dependencies** on crates.io
(1 079 downloads total, critic-verified) — so even if a break were unavoidable, its blast
radius is nil. This lowers the stakes; it does not remove the principle-8 obligation.

### 7.3 Costs this creates that v1 did not name *(critic M4, M5)*

**Public-dependency coupling.** Every `deps-lsp` re-export of a `deps-engine` type means a
`deps-engine` major forces a `deps-lsp` major. `deps-engine` in turn re-exports ecosystem
crate types, so an ecosystem-crate major propagates through two hops. This is precisely
**issue #851's open question** ("are third-party/dependency types wrapped or exposed directly
in the public API"), now replicated at a new internal boundary. It should be named as such in
the spec and routed to #851 rather than re-litigated — but it is a real cost of choosing
re-export-for-non-breakage over a clean break.

**`deps-engine`'s public surface is ~115 items, not ~5.** v1's risk table claimed a ~5-item
surface while §3.2 puts the ~110 `ecosystem!`-generated re-exports inside `deps-engine`.
Correcting the claim: the surface is `EcosystemRuntime`, `register_ecosystems`,
`from_policy`, `FetchResult`, `ProgressSender`/`ProgressUpdate`/`channel`, the `classify::*`
functions, **plus** ~110 forwarded ecosystem types. The mitigation is not "keep it to 5
items" but "the ~110 are pass-through re-exports whose semver risk is already owned by the
ecosystem crates".

**`policy_config`'s exhaustive structs make config growth a `deps-core` break.** Verified:
**none** of `PolicyConfig`, `DiagnosticsConfig`, `CacheConfig`, `FreshnessConfig`,
`SupplyChainConfig`, `RegistriesConfig`, `NetworkConfig`, `LicensePolicyConfig` is
`#[non_exhaustive]` — only `WorkspaceRegistriesSetting` is, deliberately, for the
`config::reparse_scope` exhaustive-destructuring security guard (issue #592 M1) documented in
`policy_config.rs`'s own module doc comment. The consequence, which the WIP did not originally
state: **adding a config field, previously a `deps-lsp`-internal edit, is now a breaking
change to `deps-core` under principle 8.** Given how often config sections grow in this
project, that is a recurring tax. Not a reason to reverse the extraction — but it must be a
stated, accepted trade-off in the spec, with the alternative (`#[non_exhaustive]` +
constructors, which the developer deliberately rejected for the reason above) recorded
alongside its rationale. See O-6.

### 7.4 New CI guards this design requires

1. Extend the `test-util` leak guard (`cargo tree -p deps-lsp -e features,no-dev`) to
   `deps-engine`, `deps-cli` and later `deps-mcp`. `deps-engine` sits between the adapters
   and the ecosystem crates, a new leak path for `deps-core/test-util` and for
   `deps-cargo`/`deps-npm`'s own `test-util` http carve-outs. This is a **security** gate —
   those features relax the HTTPS-only registry check.
2. New: assert no driving adapter appears in another's tree (`cargo tree -p deps-cli -e
   no-dev` must not mention `deps-lsp`). The machine-checkable form of §3.1's invariant;
   without it the boundary is a convention that erodes.
3. `deps-engine` must carry `#![recursion_limit = "256"]` (as `deps-lsp/src/lib.rs:8` and
   `deps-core/src/lib.rs:9` do) — it will host the same boxed-future `Send`-bound proving that
   triggered rust-lang/rust#159228 in both.
4. **Flag for the spec**: `config::reparse_scope` (`config.rs:442`) relies on
   `register_ecosystems`'s return value as its single source of truth for the
   workspace-registry reparse set (#592 security M1, guarded by the #758 completeness test).
   After the move this becomes a **cross-crate** invariant (`deps-lsp` ↔ `deps-engine`) —
   still testable, but call it out so nobody "simplifies" `deps-engine`'s return type later
   without noticing it is a security boundary.
5. **New (N1)**: `composer_minimum_stability` (`fetch.rs:111-119`) is
   `#[cfg(feature = "composer")]` and downcasts `crate::ComposerParseResult`. Once it lives in
   `deps-engine`, that `cfg` reads *deps-engine's* feature flag, so under Cargo's workspace
   feature unification, another adapter's build can switch on a code path a
   `--no-default-features` `deps-lsp` build previously compiled out on its own. Benign or
   arguably better (more consistent behavior across adapters sharing one process), but it is
   not a byte-for-byte "verbatim" move and should be noted, not silently assumed away.

---

## 8. Revised sequencing *(rewritten — critic S2, M2; step count corrected — critic N3)*

`tasks.md`'s T002/T004 are unimplementable as written. Replacement, with an explicit gate per
step rather than one blanket "tests move unchanged" claim:

| Step | Scope | Gate |
|---|---|---|
| **PR 1a** (in flight, developer-implemented) | `deps_core::policy_config` + `DepsConfig` composes it via `#[serde(flatten)]`. **Keep as is.** | The two flatten tests in `config.rs` (`test_flatten_preserves_deny_unknown_fields_rejection`, `test_flatten_still_tolerates_unknown_key_nested_inside_a_known_section`) |
| **PR 1b-i** | Create `deps-engine`; move capability A **verbatim**; `deps-lsp` re-exports; features forward; add §7.4 guards 1–3 and the §7.1 compile-only path test | Full LSP suite unchanged; §7.1 compile test; adapter-isolation guard |
| **PR 1b-ii** | Add `EcosystemRuntime::from_policy` and use it at `server.rs:712`. **Scoped down from v1**: it constructs the runtime only. The duplicated blocks at `server.rs:524-546`/`:712-755` also write `state.cache` and `state.cold_start_limiter` and call `warn_if_gitlab_instance_host_invalid(&self.client, …)` under ordering constraints documented in comments tagged "M4"/"critic M5" — that remainder is genuinely LSP business and stays. v1's `apply_policy` is **withdrawn** as wrong-arity. | Config-reload behaviour tests unchanged; the ordering comments preserved verbatim |
| **PR 1c-i** | Move `deps_engine::progress` (`ProgressUpdate` made `pub`, `pub fn channel(total)` factory added — N2, not a verbatim move) + `resolved.rs`'s 4 pure helpers + `load_resolved_versions` reparameterized to `&Arc<LockFileCache>` only (N5). `RefetchPolicy` explicitly stays. | The moved functions' own unit tests move with them and pass; `fetch.rs:9`'s import of `RefetchPolicy` still resolves |
| **PR 1c-ii** | Move `osv_scan.rs`'s 4 pure helpers (`build_scan_targets` visibility bumped per N5). Staleness guards (`:378`,`:532`) and all four `run_*` orchestrators stay. | The 7 `ServerState`-referencing `osv_scan` test functions (N4-corrected) stay in `deps-lsp` and pass **unchanged** — they test the orchestrators, which did not move |
| **PR 1c-iii** | Move `fetch.rs:29-716`. `fetch_registry_versions_for_change`, `fetch_failure_toast` stay. | 46 of `fetch.rs`'s 51 test functions (N4-corrected) relocate with the moved code; the 2 `ServerState`-constructing tests stay and pass unchanged |
| **PR 1c-iv** *(new — critic N3, mandatory)* | Extract `merge_registry_fetch_result`'s pure half (`fetch.rs:896-913`) into `deps_engine::classify::fetch`; reparameterize `diff.rs`'s `merge_deprecations_after_fetch`/`merge_no_comparable_versions_after_fetch` to `&mut DependencyOutcomes`; leave the ~12-line `state.documents.get_mut` + `set_loaded()`/`set_failed()` shell in `deps-lsp`. Without this step, `deps-cli`'s "assemble `VersionData`" (PR 2) has no shared code for building `DependencyOutcomes` correctly. | The two `diff.rs` functions' existing unit tests pass against the new `&mut DependencyOutcomes` signature; `fetch.rs`'s remaining ~12-line shell still compiles and its own tests (the 2 `ServerState`-constructing ones from PR 1c-iii) pass unchanged |
| **PR 2** | `deps-cli`: clap, walk, `table`/`json`, exit codes, plus its own ~100-150-line orchestrator (§5.6.2) calling `deps_engine::classify` | **FR-005 parity test**: one fixture through both the LSP and CLI paths, asserting identical findings |
| **PR 3** | SARIF + pre-commit + GitHub Action (unchanged from `plan.md` §9) | As specified |

**Revert independence, stated accurately** (v1 over-claimed): each 1c step is behaviour-
neutral and independently revertable *at the time it lands*, but once a later step builds on
an earlier one's relocated helpers, reverting the earlier one in isolation no longer
compiles. Under Option F this is much weaker coupling than under v1 — there is no shared
growing aggregate, only four independent function groups — but "independently revertable"
should be written as "independently reviewable and behaviour-neutral", which is what actually
matters.

**Trade-off to surface to the user**: PR 1c (four steps, ~950 production lines relocated) is
work `plan.md` did not budget for and it delays `deps-cli`. The alternative — ship `deps-cli`
with its own classification and extract later — is faster but converts FR-005 from a
structural property into a manual regression suite, and pays the extraction cost anyway at
#710 with two consumers to migrate instead of one. Recommend paying it now. **Option F makes
this materially cheaper than v1's estimate**: no `ServerState` split, no `DocumentState`
reshape, no wholesale test rewrites, no new concurrency model.

---

## 9. Assumptions, open questions, risks

### Settled since v1

- **A-1 → settled**: `deps-lsp` has 0 crates.io reverse dependencies (1 079 downloads).
  Breakage blast radius is nil; the principle-8 obligation still stands.
- **A-2 → settled, opposite to expectation**: the `flatten`/`deny_unknown_fields`
  asymmetry is deliberate and tested both ways. Documented contract, not a risk (§4).
- **A-3 → resolved by measurement**: `fetch.rs`'s production half touches
  `tower_lsp_server::Client` at exactly one line (`:758`) and `ServerState` at two
  (`:757`, `:875`) — all in the orchestration lines that stay. This was v1's biggest
  estimation risk; it is now the design's foundation (§5.6.1).
- **O-3 → settled**: `deps-engine` is unclaimed on crates.io.

### Open questions

- **O-1**: keep `deps_lsp::config`'s re-export of the moved section types permanently, or
  remove at the next major? (`#[deprecated]` is a no-op on re-exports — §7.1 — so this is a
  plain keep-or-break decision plus a follow-up issue.)
- **O-2** (§6): `deps-mcp` as its own binary vs `deps-lsp --mcp`. Defer to #710.
- **O-4**: should `Category`/`Finding` (the CLI's `CheckFinding.category`, and the same
  classification MCP will need) live in a new `deps_core::finding` module next to the
  diagnostic codes it maps from (`UNSATISFIABLE_DIAGNOSTIC_CODE`,
  `LICENSE_POLICY_VIOLATION_DIAGNOSTIC_CODE`, …) rather than in `deps-cli::report` as
  `plan.md` §3 has it? Recommendation: **yes, `deps-core`** — the code→category mapping is
  minted there, so a copy per adapter is exactly the duplication principle 1 exists to stop.
  **Not decided here** because it widens `deps-core`'s published surface (and see §7.3's
  exhaustive-struct tax) — carried into [[plan]] as `[NEEDS CLARIFICATION: O-4]`.
- **O-5**: FR-016 makes the CLI fail closed on a bad config where the LSP keeps its
  last-known-good. That asymmetry is deliberate and lives in the adapter — write it down.
- **O-6**: given §7.3, should `policy_config`'s structs gain `#[non_exhaustive]` +
  constructors after all, trading struct-literal ergonomics for the ability to add config
  fields without a `deps-core` major? The developer's rationale for exhaustive is sound on
  its own terms; it was decided before the principle-8 cost was on the table. **Route to the
  user, not a guess** — carried into [[plan]] as `[NEEDS CLARIFICATION: O-6]`.
- **O-7**: `specs/constitution.md` principle 8's parenthetical describing
  `cargo-semver-checks` as advisory is stale — `ci.yml:239-263` blocks on it for PR/push.
  Correct it in a follow-up to this spec revision, and record that the tool currently cannot
  run locally (rustdoc format v60). Flagged separately for the team lead to action —
  `constitution.md` is not edited by this revision.

### Risks

| Risk | Impact | Mitigation |
|---|---|---|
| `deps-engine` becomes a dumping ground | Erodes the boundary | §3.3's mechanical placement rule + §3.2's split rule + §7.4 guards |
| Adapter-isolation invariant is convention-only | Rediscovered at #710 | §7.4 guard 2 — machine-checked in CI |
| Per-adapter orchestrators drift despite a shared classification layer | FR-005 regression | The PR-2 parity test; cheap now that both share `classify` |
| Public-dependency coupling forces cascading majors (§7.3) | More majors over time | Name it, route to #851, do not re-litigate here |
| Config growth now breaks `deps-core` (§7.3) | Recurring tax | Stated trade-off; O-6 offers the alternative |
| `cargo-semver-checks` CLI unusable in local dev sandbox | A contributor cannot self-check before pushing | CI's `semver` job is the real, blocking gate; §7.1's compile-only path test adds a fast local pre-push supplement |
| PR 1c-iv (N3) skipped or under-scoped | FR-005 hole reopens exactly where Option F exists to close it | Sequenced as a mandatory 4th step in §8, not optional cleanup |

## See Also

- [[spec]] — feature specification (WHAT/WHY, largely unaffected by this revision)
- [[plan]] — technical plan (revised to carry this design)
- [[tasks]] — implementation tasks (revised to carry this design)
- [[constitution]] — principle 8's `cargo-semver-checks` parenthetical needs a separate
  correction (O-7); principle 1 and principle 8's crate count both apply directly here
- `crates/deps-core/src/policy_config.rs` — the already-shipped module this design leaves
  untouched
