//! Compile-only non-breakage gate (issue #1058, `deps-engine` composition-root extraction).
//!
//! `EcosystemRuntime`/`register_ecosystems` and every `ecosystem!`-generated ecosystem type
//! moved from `deps-lsp`'s own crate root into `deps-engine::setup`, re-exported back at
//! `deps-lsp`'s crate root unchanged (`src/lib.rs`'s `pub use deps_engine::setup::*;`). This
//! `use`s every one of those paths, plus every `deps_lsp::config` type: if a path stops
//! resolving, the workspace stops compiling. CI's `cargo-semver-checks` gate is
//! advisory-only on ordinary PR/push runs (see `specs/062-cli-check-mode/
//! architecture-decision.md` §7.1), so this test — run in the ordinary, blocking test job —
//! is the actual enforcement for this specific claim.
//!
//! This proves only that these *type paths* still resolve — it does not prove no field
//! layout changed on an existing type (see the architecture decision doc's own account of a
//! real field-layout break this style of test cannot catch).

#![allow(unused_imports)]

use deps_lsp::config::{
    CodeLensConfig, ColdStartConfig, DepsConfig, InlayHintsConfig, LoadingIndicatorConfig,
};
use deps_lsp::{EcosystemRuntime, register_ecosystems};

#[cfg(feature = "cargo")]
use deps_lsp::{
    CargoDependency, CargoDependencySection, CargoEcosystem, CargoFormatter, CargoLockParser,
    CargoParseResult, CargoParser, CargoRegistry, CargoVersion, CrateInfo, CratesIoRegistry,
    parse_cargo_toml,
};

#[cfg(feature = "npm")]
use deps_lsp::{
    NpmDependency, NpmDependencySection, NpmEcosystem, NpmFormatter, NpmLockParser, NpmPackage,
    NpmParseResult, NpmRegistry, NpmVersion, parse_package_json,
};

#[cfg(feature = "pypi")]
use deps_lsp::{
    PypiDependency, PypiDependencySection, PypiEcosystem, PypiFormatter, PypiLockParser,
    PypiParser, PypiRegistry, PypiVersion,
};

#[cfg(feature = "go")]
use deps_lsp::{
    GoDependency, GoDirective, GoEcosystem, GoFormatter, GoParseResult, GoRegistry, GoSumParser,
    GoVersion, parse_go_mod,
};

#[cfg(feature = "bundler")]
use deps_lsp::{
    BundlerDependency, BundlerEcosystem, BundlerFormatter, BundlerParseResult, BundlerVersion,
    DependencyGroup, GemInfo, GemfileLockParser, RubyGemsRegistry, parse_gemfile,
};

#[cfg(feature = "dart")]
use deps_lsp::{
    DartDependency, DartEcosystem, DartFormatter, DartParseResult, DartVersion, PackageInfo,
    PubDevRegistry, PubspecLockParser, parse_pubspec_yaml,
};

#[cfg(feature = "maven")]
use deps_lsp::{
    ArtifactInfo, MavenCentralRegistry, MavenDependency, MavenEcosystem, MavenFormatter,
    MavenParseResult, MavenVersion, parse_pom_xml,
};

#[cfg(feature = "gradle")]
use deps_lsp::{
    GradleDependency, GradleEcosystem, GradleFormatter, GradleParseResult, GradleVersion,
    parse_gradle,
};

#[cfg(feature = "swift")]
use deps_lsp::{
    SwiftDependency, SwiftEcosystem, SwiftFormatter, SwiftLockParser, SwiftPackage,
    SwiftParseResult, SwiftRegistry, SwiftVersion, parse_package_swift,
};

#[cfg(feature = "composer")]
use deps_lsp::{
    ComposerDependency, ComposerEcosystem, ComposerFormatter, ComposerLockParser, ComposerPackage,
    ComposerParseResult, ComposerSection, ComposerVersion, PackagistRegistry, parse_composer_json,
};

#[cfg(feature = "nuget")]
use deps_lsp::{
    NuGetDependency, NuGetEcosystem, NuGetFormatter, NuGetLockParser, NuGetParseResult,
    NuGetRegistry, NuGetVersion, parse_project_file,
};

#[cfg(feature = "deno")]
use deps_lsp::{
    DenoDependency, DenoDependencySection, DenoEcosystem, DenoFormatter, DenoMetadata,
    DenoParseResult, DenoRegistry, JsrPackage, JsrRegistry, JsrVersion, parse_deno_json,
};

#[cfg(feature = "github-actions")]
use deps_lsp::{
    GithubActionsDependency, GithubActionsEcosystem, GithubActionsFormatter,
    GithubActionsParseResult, GithubActionsRegistry, GithubActionsVersion, parse_workflow_yaml,
};

#[cfg(feature = "gitlab-ci")]
use deps_lsp::{
    GitlabCiDependency, GitlabCiEcosystem, GitlabCiFormatter, GitlabCiParseResult,
    GitlabCiRegistry, GitlabCiVersion, parse_gitlab_ci_yaml,
};

/// Does not need to execute anything — a successful compilation of the `use` statements above
/// is the actual assertion. Deliberately breaking one re-export locally (e.g. commenting out
/// one `pub use` in `deps-lsp/src/lib.rs`) must fail this test file to compile.
#[test]
fn public_api_paths_still_resolve() {}
