---
aliases:
  - Operator advisory exemptions
  - Advisory exemptions
tags:
  - sdd
  - spec
  - enhancement
  - security
  - deps-core
  - deps-lsp
  - deps-cli
  - priority/p3
created: 2026-11-17
status: implemented
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[094-lsp-per-package-diagnostic-suppression/spec|094 Per-package diagnostic suppression]]"
  - "[[084-unified-registry-trust-rule/spec|084 Unified registry trust rule]]"
---

# Feature: Operator-controlled advisory exemptions that a repository cannot grant

> [!info] Metadata
> **Type / priority**: enhancement / security, P3 (`deps-core`, `deps-lsp`, `deps-cli`)
> **Issue**: #1964
> **Phase**: specify, implemented in the same PR. Open `[NEEDS CLARIFICATION]`: 0.

> [!abstract]
> An operator can exempt a specific advisory id from vulnerability diagnostics, with a reason and an optional expiry. The exemption file is read only from the operator's own user config directory (editor) or from an explicit `--advisory-exemptions <PATH>` argument (CLI). A repository-controlled `deps.toml`, LSP workspace settings, or any file inside an open workspace cannot exempt an advisory. Every exemption stays visible as one informational notice per dependency.

## 1. Overview

Spec 094 deliberately left the `vulnerability` kind out of per-package suppression: workspace settings (`.vscode/settings.json`, `.zed/settings.json`) can be controlled by the repository being opened, so a repository-supplied rule must never hide a security advisory. Its open question Q4 deferred suppression by advisory id to a separate spec. This is that spec.

Scope of the claim: a repository-controlled `deps.toml`, LSP workspace settings, or a file inside an open workspace cannot exempt an advisory. `diagnostics.vulnerabilities_enabled = false` is a separate, known gap (a repository setting can turn the whole vulnerability check off) and is out of scope here.

### Trust model

| Source | Honored | Why |
|--------|---------|-----|
| `<user config dir>/deps-lsp/advisory-exemptions.toml`, outside every workspace root | yes | operator-owned location |
| same file, inside a workspace root | no (warning, fail closed) | a repository can point `XDG_CONFIG_HOME` into itself |
| `--advisory-exemptions <PATH>` (deps-cli) | yes | operator-typed argument |
| `deps.toml`, LSP `initializationOptions` / workspace settings | no | repository-controlled; there is no such key |
| any auto-discovered file in the scanned tree | no | never discovered |

The type system carries the boundary: `OperatorExemptions` implements neither `Deserialize` nor `Default`. The only constructors are `none()` and `load(&ExemptionFile)`, and an `ExemptionFile` is only obtainable from `ExemptionFile::user_config_default` / `under_config_dir` (containment-checked), `from_command_line` (banned by a `clippy.toml` `disallowed-methods` entry except at the one deps-cli call site), or a test-only constructor. A compile_fail doctest documents the missing `DeserializeOwned` impl; it is documentation, the constructors are the gate.

## 2. Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-001 | WHEN an advisory's id or any alias equals the `id` of a non-expired entry, the advisory SHALL NOT be emitted as a vulnerability diagnostic. | must |
| FR-002 | The advisory severity `Malicious` (including an advisory that aliases a `MAL-` record) SHALL never be exemptible. The rule is an exhaustive `const fn` over `VulnSeverity`. | must |
| FR-003 | Expiry (`expires = "YYYY-MM-DD"`) SHALL be inclusive and compared with the UTC date of the evaluation instant. An expired entry is inert. | must |
| FR-004 | For every dependency with at least one exempted advisory, exactly one `AdvisoryExempted` diagnostic (code `advisory-exempted`, severity Information) SHALL list the count and up to 5 ids, sorted. | must |
| FR-005 | The "+N more" total SHALL shrink only by fetched records that matched; unfetched records (beyond `MAX_ADVISORY_RECORDS`, or an at-least total) stay counted so the overflow entry keeps flagging them. | must |
| FR-006 | The editor SHALL read the file once in `initialize`; a change needs a server restart. A missing file means no exemptions; a malformed file means no exemptions plus a `window/showMessage` warning. | must |
| FR-007 | The CLI SHALL accept `check --advisory-exemptions <PATH>`. A missing or invalid file is a config error (exit 2) that names the path and never echoes file content. | must |
| FR-008 | File format: `[[advisory]]` with `id` (valid OSV id), `reason` (trimmed, 1..=500 characters, no control characters), optional `expires`. Unknown fields rejected, duplicate ids rejected, at most 1024 entries, at most 64 KiB. | must |

## 3. Editor lookup and containment

The file is `<user config dir>/deps-lsp/advisory-exemptions.toml` (`dirs::config_dir()`: `$XDG_CONFIG_HOME` or `~/.config` on Linux, `~/Library/Application Support` on macOS, `%APPDATA%` on Windows). Order of checks in `ExemptionFile::under_config_dir`:

1. Canonicalize the file path. NotFound means `Absent`, quietly: no containment check, no warning.
   The file read later must be a regular file (checked before and after opening): a symlink to a FIFO, a tty or `/dev/stdin` would block `initialize` or consume the editor transport. The CLI `--advisory-exemptions` source keeps allowing pipes (`<(cmd)`).
2. Any other canonicalize error fails closed: the file is returned as `Located` and its load reports the error, so the result is `none()` plus a warning. It is never `Absent` and never silently honored.
3. If any of these paths equals or sits below an effective workspace root (component-wise `Path::starts_with`), the lookup is `InsideWorkspace`: `none()` plus a warning naming the reason and the root, never the file content. The paths are the canonical file, the canonical config directory, and the canonical parent folder joined with the file name. Together they catch a committed symlink at the file or at `deps-lsp/` that lives in the workspace but resolves outside it.
4. Otherwise `Located`.

Workspace roots come from `initialize`: `workspaceFolders`, `rootUri`, the deprecated `rootPath`, and the server's current directory. `WorkspaceRoots::new` canonicalizes them and drops roots that fail to canonicalize, filesystem roots (`cwd = /` for a macOS GUI launch or a client without a cwd), and every root equal to or an ancestor of the canonical home directory (`cwd = $HOME`, Neovim's default, or the home folder opened as a workspace). A root below home, where direnv/mise `.envrc` and devcontainer `remoteEnv` point `XDG_CONFIG_HOME=$PWD/...`, is enforced.

Each kept root is also extended to its enclosing git repository top level: the outermost ancestor holding a `.git` entry, found by walking up while the candidate is neither the filesystem root nor home or above. A monorepo opened at `repo/app` with a repository-root `.envrc` pointing at `repo/.config` is therefore refused. A repository whose top level is home or above does not widen the root.

### Residual risks

- **R1, `HOME` override.** A repository `.envrc` exporting `HOME=<any path in the workspace>` (`HOME=$PWD`, or a subfolder such as `$PWD/.home`) makes the workspace equal to or a parent of the home directory, so it is dropped as a root, and `dirs::config_dir()` follows `$HOME`, so a repository file can become `Located`. This is the same residual the project already accepts for operator-home trust (`~/.npmrc`, `~/.cargo/config`, see [[084-unified-registry-trust-rule/spec|spec 084]]): a process whose environment the repository controls is already granted more than this feature can protect. Out of scope; do not rely on exemptions in an environment a repository can configure.
- **R2, later folders.** Workspace folders added after `initialize` are not re-checked (deps-lsp does not track workspace folders).
- **R3, hostile client settings.** A client that lets repository settings choose the server binary, arguments or environment already grants code execution.
- **Limit.** Opening `~/.config` (or the config directory's own parent below home) as a workspace disables exemptions (fail closed).

For the CLI there is no containment check: a committed exemption file is the legitimate pattern on trusted branches. Under `pull_request_target` and other fork-PR workflows a path inside the checked-out tree is attacker-controlled, so keep the file outside the checkout there.

The editor reads the user config directory automatically while the CLI needs the flag. That asymmetry is intended: CI needs explicit, reproducible input. For local parity run `deps-cli check --advisory-exemptions <the same path>`.

## 4. Behavior and display

- Exempted records are removed from the item list and from the total before `advisories_for_display()`, after the user's `deprecated` suppression. The notice only counts advisories that would otherwise have been shown.
- The rule returns the unfiltered `DependencyVulnerabilities` to its callers (suppression `hides`, the outdated rule, the `FlaggedLatest` dedup). When the in-use version equals the latest and every advisory on it is exempted, `FlaggedLatest` stays deduplicated and hidden. When the latest differs from the in-use version, flagged-latest and candidate checks ignore exemptions (out of scope).
- Hover, inlay hints and code actions still show the raw advisories; only the diagnostics rule and the `deps-cli check` report apply exemptions.
- deps-cli classifies `AdvisoryExempted` as `Category::Other`. `--fail-on other` therefore fails on a visible exemption, and SARIF emits a `note`-level result per dependency. `--fail-on vulnerable` passes when every advisory of a dependency is exempted. This is intended: an exemption is a decision someone should be able to audit.

## 5. Acceptance tests

- `crates/deps-core/tests/operator_exemptions_file.rs`: file format and limits.
- `crates/deps-core/tests/operator_exemptions_containment.rs`: layouts (a)-(e), symlink, prefix sibling, non-NotFound fail-closed, property test.
- `crates/deps-core/tests/deserialize_toml_checked.rs`: shared TOML helper (redaction, bounds, nesting).
- `crates/deps-cli/tests/check_advisory_exemptions.rs`: end-to-end `check` and the flag.
- In-module tests in `deps-core` `diagnostics.rs`: overflow total (FR-005) and the flagged-latest dedup.

## 6. Decisions

| # | Decision |
|---|----------|
| D1 | Per-package narrowing, reload without restart, and a GitHub Action input are out of scope (follow-ups). |
| D2 | The deserialize helper keeps deps-cli's redaction. For `invalid type: string "..."` mismatches where credential redaction changed nothing, the string payload is dropped so an operator-file value never reaches a log. Required by the protected acceptance test `deserialize_toml_checked_messages_do_not_echo_input_values`; a deviation from plan N2, approved by team-lead (2026-11-17). |
| D4 | A reason is validated (required, 1..=500 characters, no control characters) but not retained: no code path reads it. |
| D3 | `vulnerabilities_enabled` settable by a repository is a separate known gap (follow-up). |
