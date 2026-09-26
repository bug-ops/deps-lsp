# deps.dev GOSSIP Signals (issue #1456)

Sources hover's and diagnostics' outdated-release-cooldown callout from deps.dev's
authoritative GOSSIP (Google Open Source Security Intelligence Platform) Dynamic Cooldown
signal, and adds a live hover low-usage/slopsquatting-risk callout — on top of, never
replacing, the existing local cooldown heuristic.

## How It Works

For a declared dependency in one of the seven [deps.dev](https://deps.dev)-covered
ecosystems (Cargo, npm, PyPI, Go, Bundler, Maven, NuGet), `deps-lsp` batch-fetches
GOSSIP findings for every dependency in a document via deps.dev's v3alpha
`GetFindingsBatch` endpoint (one POST per document, not one call per dependency), through a
background, per-document pre-fetch mirroring the typosquat pre-fetch's design.

- **Cooldown**: hover's "Latest" callout and diagnostics' outdated-dependency message read
  the prefetched result synchronously — no live network wait. The GOSSIP-sourced answer is
  used only when its own recorded version exactly matches the version being displayed;
  otherwise `deps-lsp` falls back to the existing local heuristic
  (`freshness.cooldown_secs`) unchanged. A GOSSIP-sourced cooldown callout is worded
  distinctly ("deps.dev/GOSSIP reports...") so its source is never ambiguous with the local
  heuristic's own wording.
- **Low usage**: hover additionally makes one live, version-scoped `GetFindings` call for
  the pinned/resolved version (not necessarily the package's default version, so the
  document-level batch can't cover it), flagging a version deps.dev considers suspiciously
  low-usage — a slopsquatting/LLM-hallucinated-name risk signal — as a non-blocking,
  low-severity invitation to double-check the package identity. Skipped entirely when no
  concrete in-use version can be resolved (a range-only requirement with no lock file).
- **Completion** gets its own, GOSSIP-free local cooldown baseline: every version
  candidate's relative-age label is badged (⏳) when it falls within the configured
  cooldown window, using the same locally-known publish timestamps completion already
  collects. This works for all 14 ecosystems, including the seven GOSSIP doesn't cover, and
  needs no network call.

Composer, GitHub Actions, GitLab CI/CD, Dart, Swift, Gradle, and Deno have no
[deps.dev](https://deps.dev) coverage — completion's local baseline still covers them,
hover/diagnostics fall back to the local heuristic exactly as they did before this feature.

## Configuration

Ships **disabled by default** — enable via `gossip.enabled` (see the
[Configuration reference](../configuration.md#configuration-reference)). Opt-in for the
same reason the [typosquat diagnostic](typosquat-detection.md) is: the per-document batch
prefetch discloses every declared dependency's name to deps.dev. Completion's local
cooldown baseline is unaffected by this flag — it never reads GOSSIP data and is always on
(subject to the existing `freshness.enabled`/`freshness.cooldown_secs` settings).

## Known Limitations

- Findings are cached per-package for up to an hour; an idle, unedited document can show a
  GOSSIP answer that is up to an hour stale before the next natural prefetch trigger (an
  edit, a reopen, or a config change) refreshes it.
- `deps-cli` has no GOSSIP integration (dropped from this issue's scope — near-zero
  practical value there, since cooldown only affects a diagnostic message's wording, never
  `--fail-on`/exit-code behavior). A `[gossip]` section in an auto-discovered `deps.toml`
  surfaces a warning instead of silently having no effect.
- The GOSSIP API is still `v3alpha` (no GA designation) — same provisional-integration
  posture as the typosquat diagnostic.
