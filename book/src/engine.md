# The deps-engine crate

`deps-engine` is the workspace's composition root: the one place that wires all 14
`deps-<ecosystem>` crates into a running `EcosystemRegistry`, and the one place that decides
what a dependency's status actually is — outdated, yanked, vulnerable, unsatisfiable,
deprecated, or fetch-failed. `deps-lsp` and `deps-cli` both depend on it instead of
reimplementing either piece themselves.

## Why this crate exists

Cargo's dependency graph forbids a cycle: `deps-core` cannot depend on any `deps-<ecosystem>`
crate, since all 14 already depend on `deps-core`. Something still has to know about all 14
crates at once to register them — before `deps-engine` existed, that something was
`deps-lsp` itself, which meant a second driving adapter (`deps-cli`, added to check
dependencies from the command line and in CI) would have had to either depend on the LSP
binary crate or duplicate its registration and classification code. Neither is acceptable:
depending on a binary crate is not idiomatic Rust, and a duplicated copy drifts.

`deps-engine` was carved out of `deps-lsp` (issues #1058/#1059) specifically to be the shared
answer. Both `deps-lsp`'s LSP handlers and `deps-cli`'s `check` command call into the exact
same functions here, so an editor's inline diagnostics and a CI job's SARIF findings for the
same manifest can never disagree — there is only one place either could compute a different
answer, and both call it.

## Three modules

### `setup` — the composition root

[`EcosystemRuntime`](https://bug-ops.github.io/deps-lsp/deps_engine/setup/struct.EcosystemRuntime.html)
bundles the live-updatable settings a running instance threads into every ecosystem that
needs them: the `registries.workspace_registries` reachability policy, NuGet's
`registries.nuget_user_profile_sources` flag, GitLab's `registries.gitlab_instance_host`, and
a shared lock-file memoization cache. `register_ecosystems` takes one `EcosystemRuntime` and
returns a fully populated `deps_core::EcosystemRegistry` — every feature-enabled
`deps-<ecosystem>` crate's `Ecosystem` implementation constructed with its registry client and
formatter, ready to route manifests to. This is the ~110-line function (moved verbatim from
`deps-lsp/src/lib.rs`) that both `deps-lsp`'s `initialize` handler and `deps-cli`'s startup
path call.

### `classify` — pure verdict logic

The `classify` module (submodules `diff`, `fetch`, `license`, `osv`, `resolved`) answers "what
is true about this dependency" from data already in hand: in-use-version/lockfile resolution,
which dependencies need an OSV scan and which OSV findings still apply after a fix, registry
fetch fan-out, and outcome-merging. It deliberately knows nothing about *when* to ask a
registry, *how* to report progress to a caller, or what to do if input changes mid-flight —
those are each driving adapter's own orchestration concern. This split (moved from
`deps-lsp`'s `document/` module, issue #1059) is what lets `deps-cli` reach identical verdicts
to `deps-lsp` without reimplementing any classification of its own; see
[`specs/062-cli-check-mode/architecture-decision.md`](https://github.com/bug-ops/deps-lsp/blob/main/specs/062-cli-check-mode/architecture-decision.md)
in the repository for the full design rationale.

### `progress` — a driving-adapter-agnostic port

Fetch tasks report progress through this module's types rather than calling an LSP-specific
`$/progress` notification or a CLI-specific stderr line directly — each adapter supplies its
own implementation of the port. `deps-lsp` reports through LSP work-done progress; `deps-cli`
reports differently (or not at all, in a non-interactive CI run).

## How this fits the rest of the architecture

`deps-engine` sits between `deps-core` (the trait definitions) and the two driving adapters:

```text
deps-core            — Ecosystem trait, Registry trait, shared LSP-response generation
   ↑
deps-cargo, deps-npm, ...   — 14 ecosystem crates, each implementing deps-core's traits
   ↑
deps-engine           — registers all 14, classifies verdicts, reports progress
   ↑              ↑
deps-lsp        deps-cli   — driving adapters: LSP server, CLI
```

See [Architecture Overview](architecture.md) for the `Ecosystem` trait and registry routing
this crate wires up, and [deps-cli](cli.md) for the other consumer of this shared
classification layer.
