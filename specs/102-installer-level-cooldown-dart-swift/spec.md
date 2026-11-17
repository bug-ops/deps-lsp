---
aliases:
  - Installer-level cooldown for Dart and Swift
tags:
  - sdd
  - spec
  - research
  - ecosystem/dart
  - ecosystem/swift
  - deps-core
  - priority/p4
created: 2026-11-17
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[099-honor-native-package-manager-cooldown/spec|099 Honor native package-manager cooldown]]"
  - "[[076-cli-update-cooldown-fallback-no-lockfile/spec|076 CLI update cooldown fallback, no lockfile]]"
  - "[[020-freshness-cooldown-diagnostics-blind/spec|020 Freshness cooldown diagnostics]]"
---

# Feature: Installer-level cooldown findings for Dart and Swift

> [!info] Metadata
> **Type / priority**: research finding, P4, `deps-core` / `deps-dart` / `deps-swift`
> **Issue**: #1569 (this spec closes it; surfacing for Cargo, npm and uv is tracked in #1982 and [[099-honor-native-package-manager-cooldown/spec|spec 099]])
> **Phase**: specify. Open `[NEEDS CLARIFICATION]`: 0.

> [!abstract]
> #1569 asked whether an installer-level release-age gate exists for ecosystems whose manifest requirement auto-follows new releases, so `deps-cli update` need not write an exact pin ([[076-cli-update-cooldown-fallback-no-lockfile/spec|076]] section 8). Cargo, npm and uv now have one (answered in the issue comment and covered by spec 099). As of 2026-11-17, neither pub (Dart) nor SwiftPM has a shipped gate, so there is nothing to surface for them. Existing fail-closed behavior stays; no code change.

## 1. Findings

Checked 2026-11-17 against primary sources.

| Ecosystem | Native release-age gate | Evidence |
|-----------|-------------------------|----------|
| Cargo | Yes: `registry.global-min-publish-age`, `registries.<name>.min-publish-age`, `resolver.incompatible-publish-age` (Rust 1.100) | #1569 comment; `rust-lang/cargo#17335`, RFC 3923; surfacing in spec 099 |
| npm / pnpm / uv | Yes: `min-release-age`, `minimumReleaseAge`, `exclude-newer` | #1569 comment; spec 099 |
| Dart (pub) | **No** | dart.dev pub dependency docs document no age setting, only version constraints and `--enforce-lockfile`. The feature request `dart-lang/pub#4791` ("Support a minimum package age (cooldown) for dependency resolution") is still open (checked via `gh api`, updated 2026-11-10); it proposes a `dependency_resolution.minimum_release_age` pubspec key and a `--minimum-release-age` flag, neither shipped |
| Swift (SwiftPM) | **No** | `swift package resolve --help` and `swift package update --help` (Swift 6.4.2, swift-driver 1.168.6) list no age, cooldown or exclude-newer option; a web search found no SwiftPM proposal or changelog entry for one |

Dart and Swift are the "no native gate" remainder from the #1569 comment; this spec records that verification (also answering spec 099 item 8 for these two ecosystems; Maven, Gradle, NuGet, Composer, Bundler and Go remain covered by that item).

## 2. Outcome

- No native window exists for Dart or Swift, so deps-lsp and deps-cli have nothing to read and surface; the project-wide `freshness.cooldown_secs` stays the only window.
- The fail-closed behavior for these ecosystems in [[076-cli-update-cooldown-fallback-no-lockfile/spec|076]] (OQ-C: Dart, Swift `from:`) is unchanged. In particular, no manifest-level exact pin is introduced to emulate a gate.

## 3. Sketch if a gate ships later

Should `dart-lang/pub#4791` or a SwiftPM equivalent land, treat it as a new row of spec 099's per-ecosystem phase table, not as a new mechanism:

- `deps-core`: reuse the effective-window input spec 099 introduces; add a reader per ecosystem behind the shared `fs_probe::read_to_string_capped` path (Dart: `pubspec.yaml` and any pub config; Swift: `Package.swift` or SwiftPM configuration).
- `deps-lsp`: the hover callout and update code actions name the native source, through the existing `lsp_helpers` formatter contract.
- `deps-cli`: `update` and `check` use the same effective window, so no recommendation or edit proposes a version the installer rejects.
- Trust model: a repository-controlled window may delay an upgrade recommendation but never hides a vulnerability diagnostic ([[099-honor-native-package-manager-cooldown/spec|spec 099]] US-005).

## 4. Out of Scope

- Any code change; implementing a Dart or Swift reader before a gate exists.
- Cargo, npm and uv surfacing: [[099-honor-native-package-manager-cooldown/spec|spec 099]], #1982.

## 5. See Also

- [[099-honor-native-package-manager-cooldown/spec|099]] — surfacing native gates for Cargo, npm, pnpm, uv
- [[076-cli-update-cooldown-fallback-no-lockfile/spec|076]] — fail-closed fallback and why an exact pin was rejected
- Issue #1569; `dart-lang/pub#4791`
