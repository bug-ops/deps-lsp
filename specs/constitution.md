---
aliases:
  - Project Constitution
tags:
  - sdd
  - constitution
created: 2026-09-12
status: active
---

# Constitution

> [!abstract]
> Non-negotiable principles for `deps-lsp`. These are the constraints every
> spec, plan, and implementation must satisfy — not a restatement of
> `.claude/CLAUDE.md` or `.claude/rules/*.md`, which hold the full day-to-day
> conventions this constitution distills from.

## Principles

1. **One fix, one place.** A behavior shared by more than one ecosystem crate
   belongs in `deps-core`, not duplicated per crate. A feature or bugfix
   landing in only one ecosystem when the same defect class applies to others
   is treated as incomplete, not merely a follow-up.

2. **`EcosystemId` matches are exhaustive.** Code that branches on ecosystem
   identity must match `EcosystemId` exhaustively so adding a 15th ecosystem
   is a compile error at every call site, not a silent fallthrough — an
   incomplete match on ecosystem identity was a real bug class (issue #118).
   Whether any *other* enum should be exhaustive or `#[non_exhaustive]` is a
   case-by-case call, not a blanket rule — see `deps-core`'s own
   per-enum API-stability policy (`deps-core/src/lib.rs`, issue #769).

3. **Non-blocking LSP surface.** Hover, completion, and other latency-critical
   handlers must return from cached/pre-fetched state; registry I/O is
   delegated to background tasks, never awaited inline on the request path.

4. **No hand-rolled version comparison.** Version parsing and ordering use an
   ecosystem-appropriate maintained crate (`semver`, `node-semver`,
   `pep440_rs`, ...) or an explicitly documented algorithm modeled on the
   registry's own real semantics — never ad hoc string/lexicographic
   comparison.

5. **Verify live, not just in CI.** Passing unit/integration tests are
   necessary but not sufficient for a feature to be considered working;
   nontrivial behavior is confirmed against a real registry and a real LSP
   client interaction before being called done.

6. **Secrets never touch plaintext at rest or in Debug output.** Tokens and
   credentials are held behind `Redacted<T>`/`expose_secret()`; a
   secret-holding type never exposes a plain string accessor, and `Debug`
   always redacts.

7. **Pre-1.0 means clean breaks.** Before v1.0.0, correctness and clarity win
   over backward compatibility — breaking changes are made directly and
   documented in `CHANGELOG.md`, not hidden behind deprecation shims.

## See Also

- [[MOC-specs]] — all specifications
- `.claude/CLAUDE.md`, `.claude/rules/*.md` — full conventions these
  principles are distilled from
