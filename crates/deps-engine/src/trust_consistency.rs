#![cfg(all(
    feature = "cargo",
    feature = "go",
    feature = "npm",
    feature = "nuget",
    feature = "swift"
))]
//! Cross-ecosystem consistency of the URL-alone registry trust rule (spec 084, #1822).
//!
//! Go, npm, NuGet and Swift each read an operator-owned file, and all four must give the same
//! answer for the same scenario: a URL the operator declared is `Trusted` (Baseline egress,
//! workspace policy skipped, even `off`); a URL only the repository declared is
//! `WorkspaceDeclared` (Guarded egress, blocked under `off`); and equality is per URL, so the
//! operator's host with a different path is not trusted. Cargo is the documented exception: its
//! trust follows alias provenance because it also gates a credential.

use std::sync::Arc;

use deps_core::EgressTier;
use deps_core::config_trust::OperatorPath;
use deps_core::net_policy::{RegistryAccessPolicy, RegistryTrust, WorkspaceRegistryAccess};
use deps_core::policy_config::{AtomicToggle, UserProfileSources};

const OPERATOR_URL: &str = "https://registry.corp.example/pkgs";
const REPO_URL: &str = "https://repo-chosen.example/pkgs";
const SIBLING_PATH_URL: &str = "https://registry.corp.example/other";

fn policy(level: WorkspaceRegistryAccess) -> RegistryAccessPolicy {
    RegistryAccessPolicy::new(level)
}

/// What one ecosystem made of a repository-declared `repo_url` while the operator declared
/// `OPERATOR_URL`, under `level`: its trust and egress, or `None` when it was refused.
type Observed = Option<(RegistryTrust, EgressTier)>;

fn observed(trust: RegistryTrust) -> Observed {
    Some((trust, trust.egress()))
}

fn go(repo_url: &str, level: WorkspaceRegistryAccess) -> Observed {
    // Go's only source is the operator's `$GOENV`, so a "repository" URL cannot exist there:
    // the scenario is the operator declaring `repo_url` itself.
    let content = format!("GOPROXY={repo_url}\n");
    let config = deps_go::config::GoEnvConfig::parse(
        &content,
        &OperatorPath::for_test("/home/me/go/env"),
        &policy(level),
    );
    let chain = config.goproxy_chain()?;
    match chain.hops.first()? {
        deps_go::config::GoProxyHop::Url(url) => observed(url.trust()),
        _ => None,
    }
}

fn npm(repo_url: &str, level: WorkspaceRegistryAccess) -> Observed {
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join(".npmrc"),
        format!("registry={repo_url}\n"),
    )
    .unwrap();
    std::fs::write(
        home.path().join(".npmrc"),
        format!("registry={OPERATOR_URL}\n"),
    )
    .unwrap();
    let config = deps_npm::config::resolve_with_home(
        project.path(),
        &deps_npm::NpmConfigCache::new(),
        &policy(level),
        Some(OperatorPath::for_test(home.path())),
    );
    let registries = config.resolved_registries();
    let declared = registries.first()?;
    observed(declared.trust())
}

fn nuget(repo_url: &str, level: WorkspaceRegistryAccess) -> Observed {
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let config_xml = |url: &str| {
        format!(
            r#"<configuration><packageSources><add key="Corp" value="{url}/index.json" /></packageSources></configuration>"#
        )
    };
    std::fs::write(repo.join("NuGet.Config"), config_xml(repo_url)).unwrap();
    let user_profile = root.path().join("user.NuGet.Config");
    std::fs::write(&user_profile, config_xml(OPERATOR_URL)).unwrap();
    let config = deps_nuget::config::resolve_with_context(
        &repo,
        &deps_nuget::config::NuGetConfigCache::new(),
        &policy(level),
        Some(&OperatorPath::for_test(&user_profile)),
        &AtomicToggle::new(UserProfileSources::Disabled),
    );
    let chains = config.resolved_chains();
    let hop = chains.first()?.hops.first()?;
    observed(hop.url.trust())
}

fn swift(repo_url: &str, level: WorkspaceRegistryAccess) -> Observed {
    let dir = tempfile::tempdir().unwrap();
    let registries = |url: &str| {
        format!(r#"{{"registries": {{"[default]": {{"url": "{url}"}}}}, "version": 1}}"#)
    };
    let project_file = dir.path().join(".swiftpm/configuration/registries.json");
    std::fs::create_dir_all(project_file.parent().unwrap()).unwrap();
    std::fs::write(&project_file, registries(repo_url)).unwrap();
    let user_file = dir.path().join("user-registries.json");
    std::fs::write(&user_file, registries(OPERATOR_URL)).unwrap();

    let context = deps_swift::SwiftParseContext::new(
        Arc::new(policy(level)),
        Arc::default(),
        deps_swift::config::UserConfigPath::Path(OperatorPath::for_test(&user_file)),
        None,
    );
    let uri = url::Url::from_file_path(dir.path().join("Package.swift")).unwrap();
    let parsed = deps_swift::parse_package_swift_with_context(
        r#".package(id: "acme.net", from: "1.0.0")"#,
        &uri,
        &context,
    )
    .unwrap();
    let url = &parsed.resolved_registries.first()?.url;
    observed(url.trust())
}

type Probe = fn(&str, WorkspaceRegistryAccess) -> Observed;

const PROBES: [(&str, Probe); 3] = [("npm", npm), ("nuget", nuget), ("swift", swift)];

/// The operator's own URL is Trusted on the Baseline egress under every policy, `off` included.
#[test]
fn operator_declared_url_is_trusted_on_every_ecosystem_even_under_off() {
    let expected = Some((RegistryTrust::Trusted, EgressTier::Baseline));
    assert_eq!(
        go(OPERATOR_URL, WorkspaceRegistryAccess::Off),
        expected,
        "go"
    );
    for (name, probe) in PROBES {
        assert_eq!(
            probe(OPERATOR_URL, WorkspaceRegistryAccess::Off),
            expected,
            "{name}"
        );
    }
}

/// A repository-only URL is refused under `off` and Guarded-egress workspace-declared otherwise.
#[test]
fn repo_only_url_is_blocked_under_off_and_guarded_otherwise() {
    for (name, probe) in PROBES {
        assert_eq!(
            probe(REPO_URL, WorkspaceRegistryAccess::Off),
            None,
            "{name}"
        );
        assert_eq!(
            probe(REPO_URL, WorkspaceRegistryAccess::PublicOnly),
            Some((RegistryTrust::WorkspaceDeclared, EgressTier::Guarded)),
            "{name}"
        );
    }
}

/// Equality is per URL: the operator's host with a different path is not trusted.
#[test]
fn operator_host_with_a_different_path_is_not_trusted_on_any_ecosystem() {
    for (name, probe) in PROBES {
        assert_eq!(
            probe(SIBLING_PATH_URL, WorkspaceRegistryAccess::Off),
            None,
            "{name}"
        );
        assert_eq!(
            probe(SIBLING_PATH_URL, WorkspaceRegistryAccess::PublicOnly),
            Some((RegistryTrust::WorkspaceDeclared, EgressTier::Guarded)),
            "{name}"
        );
    }
}

/// Cargo's documented exception: trust follows alias provenance, so a workspace alias naming the
/// same URL as a `$CARGO_HOME` registry stays workspace-declared (blocked under `off`), while
/// the egress of each trust is still the core `RegistryTrust::egress`.
#[test]
fn cargo_trust_follows_provenance_not_url_equality() {
    use deps_cargo::config::RegistryIndex;

    let off = policy(WorkspaceRegistryAccess::Off);
    let trusted = RegistryIndex::new(OPERATOR_URL, RegistryTrust::Trusted, &off).unwrap();
    assert_eq!(trusted.trust().egress(), EgressTier::Baseline);

    let same_url_from_workspace =
        RegistryIndex::new(OPERATOR_URL, RegistryTrust::WorkspaceDeclared, &off);
    assert!(
        same_url_from_workspace.is_err(),
        "Cargo does not lift a workspace alias to Trusted by URL equality"
    );
}
