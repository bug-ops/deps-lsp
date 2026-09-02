---
aliases:
  - saphyr migration evaluation
  - yaml-rust2 successor research
tags:
  - sdd
  - spec
  - research
  - dependencies
  - deps-dart
created: 2026-08-19
status: draft
related:
  - "[[constitution]]"
---

# Feature: Evaluate saphyr as eventual successor to yaml-rust2

> [!info] Metadata
> **Author**: rust-researcher (research session, 2026-08-19)
> **Branch**: N/A (research finding, no implementation branch)

## 1. Overview

### Problem Statement

`crates/deps-dart` depends on `yaml-rust2` (workspace-pinned `"0.11"`, root
`Cargo.toml:52`) to parse `pubspec.yaml` and `pubspec.lock`. The yaml-rust2
maintainers have publicly declared
([issue #26](https://github.com/Ethiraric/yaml-rust2/issues/26)) that the
crate will receive only basic maintenance going forward, and that all future
API evolution and features will land exclusively in a sibling project,
[`saphyr`](https://github.com/saphyr-rs/saphyr). This creates ambiguity about
which crate the project should standardize on long-term, and the existing
project rule (`.claude/rules/dependencies.md`) still names `yaml-rust2` as the
canonical choice without acknowledging this split.

This is not a bug — it is an open question about dependency direction that
needs a documented decision so future dependency-monitoring sessions do not
re-litigate it from scratch.

### Goal

Produce a documented, evidence-based decision on whether/when to migrate
`deps-dart`'s YAML parsing from `yaml-rust2` to `saphyr`, backed by a concrete
compatibility assessment, so the decision is a first-class, revisitable
artifact rather than tribal knowledge.

### Out of Scope

- Actually performing the migration (no code changes — this is a `specify`-only
  research spec; no `/sdd plan` or `/sdd tasks` phase).
- Evaluating other YAML crates not in the yaml-rust2 lineage (e.g. `marked-yaml`,
  `noyalib`, `serde-saphyr`) — out of scope unless a future scan reopens the
  YAML-parser-choice question entirely.
- Changing `.claude/rules/dependencies.md` (project rule files are not touched
  by research sessions; a follow-up team decision is needed to update it if the
  recommendation below is accepted).

## 2. User Stories

### US-001: Researcher tracks dependency direction risk
AS A rust-researcher agent running periodic dependency-monitoring scans
I WANT a recorded decision on the yaml-rust2 vs saphyr question
SO THAT I don't re-research the same ecosystem split every cycle and can
instead just check the stated re-evaluation triggers

**Acceptance criteria:**
```
GIVEN a future research session scans crates.io for yaml-rust2/saphyr updates
WHEN saphyr has not yet reached the re-evaluation trigger conditions (see FR-003)
THEN the session records "no change" against this spec instead of re-deriving
     the full compatibility analysis
```

### US-002: Maintainer decides whether to accept migration risk now
AS A project maintainer reviewing research findings
I WANT a clear effort estimate and blocking-API-differences list
SO THAT I can decide immediately whether this is worth scheduling, without
having to read yaml-rust2/saphyr source myself

**Acceptance criteria:**
```
GIVEN this spec and its linked GitHub issue
WHEN the maintainer reads the Functional Requirements and Data Model sections
THEN they can determine the call-site count, the nature of the breaking
     changes, and the recommended timeline without further investigation
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN a research session evaluates the yaml-rust2 dependency THE SYSTEM (research process) SHALL record whether saphyr has reached API stability (1.0) or yaml-rust2 has stopped receiving maintenance releases | must |
| FR-002 | WHEN neither trigger in FR-001 has occurred THE SYSTEM SHALL classify this finding as "monitor only, no migration" and skip re-deriving the compatibility analysis | must |
| FR-003 | WHEN either trigger in FR-001 occurs THE SYSTEM SHALL re-open this spec, re-verify the call-site list against current `deps-dart` source (line numbers drift with unrelated changes), and produce an updated effort estimate before recommending migration | must |
| FR-004 | WHEN this spec is superseded by a migration decision THE SYSTEM SHALL update `.claude/rules/dependencies.md` as part of that decision (not as part of this research spec) | should |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Stability | Any adopted YAML parsing dependency must not require re-validating parsing correctness on every patch release; a crate shipping breaking changes in `0.0.x`/`0.x` releases at the observed cadence (yaml-rust2 issue #26: "rapidly...API-breaking changes...multiple times in a short timespan"; saphyr CHANGELOG: breaking changes in 0.0.5, 0.0.7, 0.0.9) does not meet this bar yet |
| NFR-002 | Security | The chosen crate must have no open, unpatched RUSTSEC advisory (verified: neither yaml-rust2 nor saphyr currently has one) |
| NFR-003 | MSRV | The chosen crate's MSRV must not exceed the project's MSRV (1.91, per `.claude/rules/rust-code.md`). Both yaml-rust2 and saphyr currently require 1.85.0 — not a blocker either way |

## 5. Data Model

Not applicable in the traditional sense (no persisted entities) — this section
instead documents the concrete API surface delta between the two crates, since
that delta *is* the decision-relevant "data."

| Concept | yaml-rust2 (current, pinned `0.11`, latest `0.12.0`) | saphyr (`0.0.12`, pre-1.0) |
|---|---|---|
| Top-level type | Owned `Yaml` enum | `Yaml<'input>` — lifetime-parameterized, borrows from input; separate `YamlOwned` exists for fully-owned use |
| Loader entry point | `YamlLoader::load_from_str(&str) -> Result<Vec<Yaml>, ScanError>` | `Yaml::load_from_str(&str)` via `LoadableYamlNode` trait (loader is now a trait method on the node type, not a separate struct) |
| Mapping variant | `Yaml::Hash(LinkedHashMap<Yaml, Yaml>)` | `Yaml::Mapping(Mapping<'input>)` — renamed, still `hashlink::LinkedHashMap`-backed |
| String scalar variant | `Yaml::String(String)` — direct match | No direct `String` variant. Either `Yaml::Representation(Cow<'input,str>, ScalarStyle, Option<Cow<Tag>>)` (raw/lazy) or `Yaml::Value(Scalar::String(Cow<str>))` (resolved) — a new `Scalar` enum (`String`/`Integer`/`FloatingPoint`/`Boolean`/`Null`) sits between `Yaml` and the primitive value |
| Error type | `ScanError` | `LoadError`, `#[non_exhaustive]` since 0.0.7 |
| Index access (`doc["key"]`) | Implemented via `Index`/`IndexMut`, returns `Yaml::BadValue` on miss | Present in saphyr too, but interacts with the `Representation`/`Value` split above |

### Current `yaml-rust2` call sites in `deps-dart` (would all require rewriting)

| File | Lines | Pattern |
|---|---|---|
| `crates/deps-dart/src/parser.rs` | 7 | `use yaml_rust2::{Yaml, YamlLoader};` |
| `crates/deps-dart/src/parser.rs` | 52-53 | `YamlLoader::load_from_str(content)` |
| `crates/deps-dart/src/parser.rs` | 84, 138, 175 | `Yaml::Hash(map)` pattern match |
| `crates/deps-dart/src/parser.rs` | 127, 144, 153, 155, 168 | `Yaml::String(ver)` pattern match |
| `crates/deps-dart/src/parser.rs` | 144, 149, 153, 155, 177-187 | `Yaml::String("key".into())` map-key construction, `Yaml::as_str` |
| `crates/deps-dart/src/lockfile.rs` | 10 | `use yaml_rust2::{Yaml, YamlLoader};` |
| `crates/deps-dart/src/lockfile.rs` | 46 | `YamlLoader::load_from_str(content)` |
| `crates/deps-dart/src/lockfile.rs` | 56 | `Yaml::Hash(pkgs)` pattern match |
| `crates/deps-dart/src/lockfile.rs` | 56-98 | `doc["packages"]`, `entry["version"]`, `entry["description"]["url"]` chained indexing |
| Root `Cargo.toml` | 52 | `yaml-rust2 = "0.11"` workspace pin |
| `crates/deps-dart/Cargo.toml` | 25 | `yaml-rust2 = { workspace = true }` |

~15+ call sites across 2 source files, plus 2 manifest entries.

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| saphyr reaches 1.0 before yaml-rust2 is deprecated | Re-open FR-003, re-run the call-site audit (line numbers will have drifted), produce a fresh effort estimate before recommending migration |
| yaml-rust2 stops receiving maintenance/security releases (no commits/releases for an extended period, or a RUSTSEC advisory is filed with no fix) | Treat as urgent — re-open FR-003 immediately regardless of saphyr's stability, and evaluate all YAML-parser alternatives (not just saphyr) |
| A future `yaml-rust2` release changes MSRV above the project's MSRV | File a separate, standard dependency-update finding (not this spec — MSRV bumps are routine dependency monitoring, see `.claude/rules/continuous-improvement.md`) |
| saphyr's `Representation`/`Value` lazy model turns out to require schema resolution the current code doesn't anticipate (e.g. `pubspec.lock` version strings that look numeric, like `"1.2"` unquoted) | Flag as an additional migration risk in the FR-003 re-audit — the resolved-vs-raw distinction did not exist in yaml-rust2 and needs explicit test coverage for pubspec's mixed quoted/unquoted scalar style |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Time to re-derive a migration decision when a trigger fires | Re-audit re-uses this spec's call-site table as a starting point rather than a from-scratch grep — should take materially less time than the original ~1 research session that produced this spec |
| SC-002 | False re-migration attempts avoided | 0 migration PRs opened against this dependency before FR-001's trigger condition is met |

## 8. Agent Boundaries

### Always (without asking)
- Re-verify crates.io versions and RUSTSEC status for both crates on each periodic dependency scan
- Update this spec's Data Model table if the call-site line numbers have drifted due to unrelated `deps-dart` changes

### Ask First
- Proposing a `/sdd plan` phase for this spec (only once FR-001's trigger condition is met)
- Changing `.claude/rules/dependencies.md`'s YAML parser recommendation

### Never
- Modify `crates/deps-dart/src/parser.rs`, `crates/deps-dart/src/lockfile.rs`, or any `Cargo.toml` as part of this research spec — this is a decision record only, per the research-protocol hard rule (researcher agents never modify source code)

## 9. Open Questions

- [NEEDS CLARIFICATION: Should the team pre-emptively adopt `saphyr-parser` (the lower-level event-stream crate) instead of `saphyr` (the high-level `Yaml` object crate) if/when migration happens, to sidestep the `Representation`/`Value` lazy-resolution complexity entirely? This would mean building a custom YAML-to-`Yaml`-like mapping layer atop parser events — a materially different design than either full crate offers today, and is a decision for the eventual `/sdd plan` phase, not this `specify` phase.]

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [yaml-rust2 issue #26 — "Status of this crate"](https://github.com/Ethiraric/yaml-rust2/issues/26)
- [saphyr GitHub repository](https://github.com/saphyr-rs/saphyr)
- [saphyr CHANGELOG](https://github.com/saphyr-rs/saphyr/blob/master/saphyr/CHANGELOG.md)
- [yaml-rust2 CHANGELOG](https://github.com/Ethiraric/yaml-rust2/blob/master/CHANGELOG.md)
- `.claude/rules/dependencies.md` — current project rule naming yaml-rust2 as the standard
