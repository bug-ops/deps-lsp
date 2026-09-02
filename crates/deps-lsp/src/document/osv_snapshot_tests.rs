//! `insta` snapshots pinning the OSV vulnerability-diagnostic shape across
//! every ecosystem, per `architecture.md` §9 (NFR-003/SC-004 enforcement):
//! since no ecosystem crate overrides `generate_diagnostics`, a divergence
//! introduced by an ecosystem-specific formatter shows up here as a
//! snapshot diff rather than needing a manual comparison pass.
//!
//! Hover is intentionally not snapshotted per ecosystem: `generate_hover`
//! makes a real registry network call (`registry.get_versions`), which is
//! ecosystem-specific and would require mocking eleven different
//! registries. The shared hover-rendering logic (the part this feature
//! actually adds) is already covered deterministically, with a mock
//! registry, in `deps_core::lsp_helpers`'s own test suite.

#![cfg(test)]

use std::collections::HashMap;
use std::sync::Arc;

use deps_core::VersionData;
use deps_core::osv::{
    Advisory, Capped, DependencyVulnerabilities, ScanOutcome, UpgradeStatus, VulnSeverity,
    VulnerabilityMap,
};

use super::ServerState;

fn sample_advisory() -> Arc<Advisory> {
    Arc::new(Advisory {
        id: "GHSA-xxxx-yyyy-zzzz".to_string(),
        modified: "2023-01-01T00:00:00Z".to_string(),
        summary: Some("Example vulnerability for snapshot testing".to_string()),
        aliases: vec!["CVE-2023-00000".to_string()],
        severity: VulnSeverity::High,
        cvss_vector: None,
        fixed_versions: vec!["9.9.9".to_string()],
        url: "https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz".to_string(),
    })
}

/// Runs the shared scenario for one ecosystem: parse `content`, flag the
/// single dependency named `dep_key` (after normalization) as vulnerable,
/// generate diagnostics, and return a snapshot-stable rendering.
async fn diagnostics_snapshot_for(
    ecosystem_id: &str,
    manifest_filename: &str,
    content: &str,
) -> String {
    let state = ServerState::new();
    let uri = deps_core::test_util::test_uri(&format!("/test/{manifest_filename}"));
    let ecosystem = state
        .ecosystem_registry
        .get(ecosystem_id)
        .unwrap_or_else(|| panic!("{ecosystem_id} ecosystem not registered"));

    let parse_result = ecosystem
        .parse_manifest(content, &uri)
        .await
        .unwrap_or_else(|e| panic!("{ecosystem_id} manifest failed to parse: {e}"));

    let deps = parse_result.dependencies();
    assert_eq!(
        deps.len(),
        1,
        "{ecosystem_id} fixture must parse to exactly one dependency, got {}",
        deps.len()
    );
    let normalized_key = ecosystem.formatter().normalize_package_name(deps[0].name());

    let mut vulnerabilities = VulnerabilityMap::new();
    vulnerabilities.insert(
        normalized_key,
        ScanOutcome::Vulnerable(DependencyVulnerabilities {
            advisories: Capped::new(vec![sample_advisory()], 6),
            fix_target_status: UpgradeStatus::NotChecked,
            upgrade_status: UpgradeStatus::NotChecked,
        }),
    );

    let cached = HashMap::new();
    let resolved = HashMap::new();
    let diagnostics = ecosystem
        .generate_diagnostics(
            parse_result.as_ref(),
            VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities),
            &uri,
            deps_core::FreshnessSettings::default(),
            deps_core::DiagnosticSeverities::default(),
        )
        .await;

    // Render deterministically: severity, message, and whether a code
    // (clickable advisory id) is present. Ranges/URIs are excluded since
    // they are not the property under test here.
    diagnostics
        .iter()
        .map(|d| {
            format!(
                "{:?} | {} | code={}",
                d.severity,
                d.message,
                d.code.is_some()
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

macro_rules! ecosystem_snapshot_test {
    ($test_name:ident, $feature:literal, $ecosystem_id:literal, $manifest_filename:literal, $content:expr) => {
        #[cfg(feature = $feature)]
        #[tokio::test]
        async fn $test_name() {
            let rendered =
                diagnostics_snapshot_for($ecosystem_id, $manifest_filename, $content).await;
            insta::assert_snapshot!(rendered);
        }
    };
}

ecosystem_snapshot_test!(
    cargo_vulnerable_diagnostic,
    "cargo",
    "cargo",
    "Cargo.toml",
    "[dependencies]\ntime = \"0.1.43\"\n"
);

ecosystem_snapshot_test!(
    npm_vulnerable_diagnostic,
    "npm",
    "npm",
    "package.json",
    r#"{"dependencies": {"lodash": "4.17.15"}}"#
);

ecosystem_snapshot_test!(
    pypi_vulnerable_diagnostic,
    "pypi",
    "pypi",
    "pyproject.toml",
    "[project]\ndependencies = [\n    \"django==3.0.0\",\n]\n"
);

ecosystem_snapshot_test!(
    go_vulnerable_diagnostic,
    "go",
    "go",
    "go.mod",
    "module example.com/myapp\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.6.0\n"
);

ecosystem_snapshot_test!(
    bundler_vulnerable_diagnostic,
    "bundler",
    "bundler",
    "Gemfile",
    "source \"https://rubygems.org\"\ngem \"rack\", \"2.0.5\""
);

ecosystem_snapshot_test!(
    dart_vulnerable_diagnostic,
    "dart",
    "dart",
    "pubspec.yaml",
    "dependencies:\n  http: 0.12.0\n"
);

ecosystem_snapshot_test!(
    maven_vulnerable_diagnostic,
    "maven",
    "maven",
    "pom.xml",
    r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
  </dependencies>
</project>"#
);

ecosystem_snapshot_test!(
    gradle_vulnerable_diagnostic,
    "gradle",
    "gradle",
    "build.gradle",
    "dependencies {\n    implementation 'org.apache.logging.log4j:log4j-core:2.14.1'\n}\n"
);

ecosystem_snapshot_test!(
    swift_vulnerable_diagnostic,
    "swift",
    "swift",
    "Package.swift",
    "\nlet package = Package(\n    dependencies: [\n        .package(url: \"https://github.com/apple/swift-nio.git\", from: \"2.29.0\"),\n    ]\n)\n"
);

ecosystem_snapshot_test!(
    composer_vulnerable_diagnostic,
    "composer",
    "composer",
    "composer.json",
    r#"{"require": {"symfony/http-kernel": "4.4.0"}}"#
);

ecosystem_snapshot_test!(
    nuget_vulnerable_diagnostic,
    "nuget",
    "nuget",
    "App.csproj",
    r#"<Project>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
  </ItemGroup>
</Project>"#
);
