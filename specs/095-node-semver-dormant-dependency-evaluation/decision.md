---
aliases:
  - node-semver decision record
tags:
  - sdd
  - decision
  - dependencies
  - deps-npm
  - deps-deno
created: 2026-11-08
status: provisional
related:
  - "[[spec]]"
  - "[[MOC-specs]]"
---

# Decision record: node-semver 2.2 vs nodejs-semver 7.0.0 (issue #1928)

> [!warning] Provisional
> Outcome: **keep `node-semver` 2.2** (gate FR-011, no eligible candidate). Items marked `provisional, needs user review` are policy defaults chosen in the stricter-gate direction; the spec's `[NEEDS CLARIFICATION]` markers are not closed by this record.

## 1. Method

- Snapshot: `git archive a2a20c639` extracted in the session scratchpad. Nothing was built from the worktree and nothing under `crates/` changed.
- Corpus (not committed, regenerated from the commands in section 7): 57,243 unique ranges (a curated list of a few hundred grammar edge cases plus grammar-generated clean and noisy ranges), 281 versions, 354,648 (range, version) pairs, 30,000 range pairs for `allows_any`; real-world: 21,882 distinct ranges (dependencies, peerDependencies, optionalDependencies, devDependencies, engines) and 29,440 versions from 60+ npm packuments.
- Three columns on every case: current engine, candidate, and the reference oracle (npm's own `semver` 7.8.5).
- Two levels:
  - Engine level: bare `node-semver` 2.2.0 vs `nodejs-semver` 7.0.0 (`Range::parse`, `Version::parse`, `satisfies`, `allows_any`).
  - Wrapper level ("current engine" per the plan): the snapshot's project entry points, built twice, once as-is and once with `node-semver = { package = "nodejs-semver", version = "=7.0.0" }` in the root `[workspace.dependencies]`.
    - `deps_npm::parse_range_safe` (MAX_REQUIREMENT_LEN guard, #1639/#1646 token rewrites, `catch_unwind`).
    - `NpmFormatter::compile_bounded_requirement` giving `RequirementMatcher::matches` and `explicitly_excludes` (the `||` gap check that probes `allows_any`; this is the only "range-to-interval" use of the engine in npm, `deps-core::interval` is not driven by `node_semver`).
    - `NpmFormatter::is_bounded_requirement_up_to_date`.
    - `node_semver::Version::parse` as used by the registry, lockfile and `is_prerelease` sites.
    - Deno routes through the same `compile_node_semver_range`, so it is covered by this corpus.

## 2. Results

### 2.1 Real-world corpus (wrapper level)

One divergence in 313,906 records: the empty requirement `""` (current: unparseable, candidate and npm: `*`). Everything else is identical, including #1639 wildcard forms, prerelease exclusion (#299) and the `MAX_REQUIREMENT_LEN` guard (it lives in the wrapper).

### 2.2 Synthetic corpus, wrapper level (users would see these)

| Class | Example (minimal, probe-verified) | Current | Candidate | npm |
|---|---|---|---|---|
| C1 candidate bug: `<=` with wildcard operand combined with another comparator | `>=X <=X` vs `3.0.0`; `*.x <=x` vs `3.0.0` | true | false | true |
| C2 candidate bug: empty intersection reported satisfiable | `<=0 1` vs `0.0.1`; `>1 <=1` vs `1.2.3` | false | true | false |
| C3 candidate bug: `Version::parse` ignores trailing junk | `1.2.3-`, `1.2.3+`, `1.2.3.4`, `1.2.3 abc` (accepted as `1.2.3`) | Err | Ok | Err |
| C4 candidate bug: invalid range accepted (old engine panicked, wrapper turned that into Err) | `=x.4.0 ^1`, `10<TAB>=*.2` (868 of 57k) | Err | Ok | Err |
| C5 current bug fixed by candidate: partial `<=` | `<=1`, `<=0`, `<=1.x`, `<=1.2` vs `1.2.3` | false | true | true |
| C6 candidate matches npm | `""`, `||`, leading/trailing whitespace, `~v1.x.1`, `1.2.3\n` as a version | Err | Ok | Ok |
| C7 both wrong vs npm (not a divergence) | `<=*`, `<=x` vs `5.0.0` | false | false | true |

C5 is a latent user-visible bug today (`<=1` marks `1.2.3` unsatisfied), outside this decision's scope.

### 2.3 Engine level, panics

- Fuzz, bare engines, 2 MiB stack thread, seed 11, 120 s each: `nodejs-semver` 7.0.0: 5,658,870 iterations, 0 panics, no abort; `node-semver` 2.2.0: 1,735,712 iterations, 246,324 caught panics (the #1630/#1646 class; the wrapper contains them).
- Wrapper-level fuzz (shared entry points, 2 MiB stack, seeds 31-33, 800,000 records per seed (400k range/version pairs plus 400k range-only), inputs up to about 2.4 KB; the wrapper rejects over 256 bytes first): both builds complete every record on every seed with exit 0 and no abort. A caught panic is invisible at this level (it surfaces as Err), so this checks survival only.

### 2.4 Criteria (FR-008)

| Criterion | node-semver 2.2.0 | nodejs-semver 7.0.0 |
|---|---|---|
| (a) maintenance | last release and push 2025-02-07; 5 open issues; 19 stars; original author inactive | last release 2026-09-25, push 2026-10-04; 0 open issues; 8 stars; contributors: cijiugechu 100 commits, zkat 29 (the original `node-semver` author, no recent activity), 3 others with 1-2 commits, i.e. one active maintainer |
| (b) MSRV | 1.70 | 1.85, both at or below 1.98 |
| (c) weight | 7 crates unique to it: `bytecount`, `miette`, `miette-derive`, `minimal-lexical`, `nom 7`, `unicode-width 0.1`, itself | adds `nodejs-semver` only (`smallvec`, `thiserror 2` already present). Whole-workspace normal tree: 207 -> 201 unique crate versions |
| (d) `unsafe` (lines containing the keyword in each crate's `src/`) | own: 0; deps: `bytecount` 43, `miette` 66, `nom` 6, `minimal-lexical` 42 | own: 0; deps: `smallvec` 80 |
| (e) license | Apache-2.0 | Apache-2.0, `cargo deny check licenses bans sources` ok (evaluated on a variant with all three engine swaps of #1928/#1929), advisories ok |
| (f) panics | see 2.3 | see 2.3 |
| (g) differential | baseline | C1-C4 are candidate bugs |
| (h) API stability | no breaking change since 2022 | majors 5.0.0 (2026-06-20), 6.0.0 (2026-09-19), 7.0.0 (2026-09-25); 7.0.0's changelog states callers relying on the exact accepted/rejected set may observe differences |

API surface for the swap: 3 call-site edits in `deps-npm/src/formatter.rs` (`Version::major`/`minor` became methods); `cargo check -p deps-npm -p deps-deno --all-targets` passes afterwards.

Benchmarks (`crates/deps-npm/benches/npm_benchmarks.rs`, groups `version_matching` and `registry_parsing`, criterion 1 s warm-up, 3 s measurement, no LTO): two runs each, with 2-3x run-to-run noise because of concurrent builds on the machine. Inconclusive; no regression shown (100-version registry parse 27-34 us candidate vs 38-48 us current). Rerun on a quiet machine before any adoption.

## 3. Findings against the issue text

> [!warning] Correction
> The issue and spec state node-semver is the only source of `thiserror 1.0.69` in the normal tree. Measured with `cargo tree --workspace -e normal -i thiserror@1.0.69`: it is also pulled by `pep508_rs 0.9.2`. Replacing node-semver alone removes `unicode-width 0.1.14` but not `thiserror 1`; NFR-003 / SC-003 are reachable only together with the `pep508_rs` replacement of #1929 (with all three swaps the tree has no `thiserror 1` and no `unicode-width 0.1`).

## 4. Gate (FR-011) outcome

Gate reading used here and in the 096 record (stricter direction, provisional): every non-intentional divergence where the candidate is wrong (a "candidate bug") blocks eligibility until fixed upstream, guarded in the wrapper, or accepted by the user as an intentional difference; a divergence where the current engine is wrong (C5) does not block; a new crate with `unsafe` needs user approval. The `unsafe` rule does not block `nodejs-semver`: its only `unsafe`-bearing dependency, `smallvec`, is already in the current tree.

- FR-001..FR-006 with zero unclassified divergences: not met (C1-C4 are non-intentional candidate differences).
- Maintenance bar (provisional default below): not met (single active maintainer; two majors in six days).
- Outcome: **keep** `node-semver` 2.2 with the existing mitigations (`parse_range_safe` panic guard, `MAX_REQUIREMENT_LEN`, token rewrites).

## 5. Open clarifications (provisional values, `provisional, needs user review`)

| Marker | Provisional value (stricter direction) | Basis |
|---|---|---|
| Benchmark regression threshold (NFR-004) | 0 %: any statistically significant slowdown on `version_matching`/`registry_parsing` blocks adoption | Current data shows no slowdown, so this costs nothing now |
| `unsafe` in a dependency's normal tree | Not allowed beyond crates already in the tree today; any new crate with `unsafe` needs explicit approval | Candidate adds none (`smallvec` is already in the tree) |
| Minimum maintenance bar | Release or commit within 12 months and at least two contributors active in that window | Candidate fails the second clause |
| Deno reference semantics | npm's semantics for every specifier form; Deno goes through the same `compile_node_semver_range`; no divergence found | Corpus covers it via the shared entry point |
| Tracking issue number | #1928 | Answered, issue exists |
| Right benchmark baseline | Yes: `crates/deps-npm/benches/npm_benchmarks.rs`; only the `version_matching` and `registry_parsing` groups touch the engine | Verified by reading the bench |

## 6. Re-evaluation triggers (FR-012)

- A RUSTSEC advisory against `node-semver`, `miette` 7, `nom` 7 or `thiserror 1` that is not already ignorable.
- An unfixable panic not contained by `parse_range_safe`.
- A toolchain or edition break (MSRV above 1.98 for `node-semver` is not expected).
- `nodejs-semver` fixing C1-C4 upstream, tagged, and staying on one major for at least 3 months with a second active maintainer; then rerun section 7 and revisit.
- Another dependency swap (#1929) that makes the `thiserror 1` duplicate attributable solely to `node-semver`.

If the outcome is later flipped to "replace": record it as a conditional outcome; implementation goes to a separate issue with the C1-C4 wrapper guards (or upstream fixes) and the C5 behavior change listed in CHANGELOG.

## 7. Commands (inline evidence)

```
git archive a2a20c639 | tar -x -C <scratch>/snap          # snapshot
engines node-corpus 1 60000 corpus.jsonl                    # synthetic corpus, seed 1
engines node-eval old|new corpus.jsonl out.jsonl            # bare engines
node oracle-node.js corpus.jsonl ref.jsonl                  # npm semver 7.8.5
wh-node corpus.jsonl out.jsonl                              # wrapper level, built per snapshot
engines node-fuzz old|new 11 120                            # 2 MiB stack thread
engines fuzz-corpus node 31..33 400000 f.jsonl; wh-node f.jsonl o.out
cargo tree --workspace -e normal --prefix none              # per variant
cargo deny check licenses bans sources; cargo deny check advisories
cargo bench -p deps-npm --bench npm_benchmarks -- 'version_matching|registry_parsing'
```
