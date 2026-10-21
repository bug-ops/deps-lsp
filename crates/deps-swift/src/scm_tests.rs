//! End-to-end tests of SCM-to-registry swizzling (spec 088): parser, decision, probe, notices.

use std::assert_matches;
use std::sync::Arc;

use deps_core::Ecosystem;
use deps_core::config_trust::OperatorPath;
use deps_core::lsp_helpers::{ProbeEffect, ProbePhase, ProbeReport};
use deps_core::net_policy::{RegistryAccessPolicy, WorkspaceRegistryAccess};
use deps_core::parser::DependencySource;
use deps_core::policy_config::ScmToRegistry;
use mockito::{Matcher, Mock, ServerGuard};
use url::Url;

use crate::config::{SwiftParseContext, TrustedLookupRegistry, UserConfigPath};
use crate::ecosystem::SwiftEcosystem;
use crate::parser::SwiftParseResult;
use crate::registry::SwiftRegistry;
use crate::scm::{
    IdentityLookup, MemoKey, ScmLookupUrl, ScmToRegistryHandle, SwiftForm, SwiftOrigin,
    SwiftRequirementForm, SwizzleInput, swizzle_decision,
};
use crate::types::SwiftDependency;

pub(crate) const NIO: &str =
    r#".package(url: "https://github.com/apple/swift-nio", from: "2.0.0")"#;

fn registries(default: Option<&str>, scoped: &[(&str, &str)]) -> String {
    let mut entries: Vec<String> = default
        .iter()
        .map(|url| format!(r#""[default]": {{"url": "{url}"}}"#))
        .collect();
    entries.extend(
        scoped
            .iter()
            .map(|(scope, url)| format!(r#""{scope}": {{"url": "{url}"}}"#)),
    );
    format!(
        r#"{{"registries": {{{}}}, "version": 1}}"#,
        entries.join(", ")
    )
}

/// A manifest directory with optional user-tier and project-tier `registries.json`, and a Swift
/// ecosystem reading them.
pub(crate) struct Fixture {
    _dir: tempfile::TempDir,
    pub registry: Arc<SwiftRegistry>,
    pub ecosystem: SwiftEcosystem,
    pub mode: Arc<ScmToRegistryHandle>,
    pub uri: Url,
    /// The user-tier `[default]` registry URL, when the fixture declares one.
    pub default_url: String,
}

impl Fixture {
    pub(crate) fn new(user: Option<String>, project: Option<String>, mode: ScmToRegistry) -> Self {
        let dir = tempfile::tempdir().unwrap();
        if let Some(project) = project {
            let file = dir.path().join(".swiftpm/configuration/registries.json");
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, project).unwrap();
        }
        let user_config = match user {
            Some(user) => {
                let file = dir.path().join("user-registries.json");
                std::fs::write(&file, user).unwrap();
                UserConfigPath::Path(OperatorPath::for_test(&file))
            }
            None => UserConfigPath::NoUserTier,
        };
        let mode = Arc::new(ScmToRegistryHandle::new(mode));
        let context = SwiftParseContext::new(
            Arc::new(RegistryAccessPolicy::new(WorkspaceRegistryAccess::All)),
            Arc::default(),
            user_config,
            None,
        )
        .with_scm_to_registry(Arc::clone(&mode));
        let registry = Arc::new(SwiftRegistry::new(Arc::new(deps_core::HttpCache::new())));
        Self {
            uri: Url::from_file_path(dir.path().join("Package.swift")).unwrap(),
            ecosystem: SwiftEcosystem::with_context(Arc::clone(&registry), context),
            registry,
            mode,
            default_url: String::new(),
            _dir: dir,
        }
    }

    /// A fixture whose user tier declares `default` as its `[default]` registry.
    pub(crate) fn with_default(default: &str, mode: ScmToRegistry) -> Self {
        let mut fixture = Self::new(Some(registries(Some(default), &[])), None, mode);
        fixture.default_url = default.to_string();
        fixture
    }

    /// The memo key of `scm` under the fixture's default registry.
    pub(crate) fn key(&self, scm: &ScmLookupUrl) -> MemoKey {
        let registry = crate::config::SwiftRegistryUrl::for_test(
            &self.default_url,
            deps_core::net_policy::RegistryTrust::Trusted,
        );
        MemoKey::new(&registry, scm)
    }

    pub(crate) async fn parse(&self, manifest: &str) -> SwiftParseResult {
        let parsed = self
            .ecosystem
            .parse_manifest(manifest, &self.uri)
            .await
            .unwrap();
        let any = parsed.as_any();
        let parsed = any.downcast_ref::<SwiftParseResult>().unwrap();
        SwiftParseResult {
            dependencies: parsed.dependencies.clone(),
            uri: parsed.uri.clone(),
            dependency_truncation: parsed.dependency_truncation,
            resolved_registries: parsed.resolved_registries.clone(),
            blocked_registries: parsed.blocked_registries.clone(),
            rejected_registries: parsed.rejected_registries.clone(),
        }
    }

    pub(crate) async fn prefetch(&self, parsed: &SwiftParseResult) -> ProbeReport {
        self.ecosystem
            .background_probes(parsed, ProbePhase::PreFetch)
            .await
    }
}

fn identifiers(server: &mut ServerGuard, written: &str, body: &str, status: usize) -> Mock {
    server
        .mock("GET", "/identifiers")
        .match_query(Matcher::UrlEncoded("url".into(), written.into()))
        .match_header("accept", "application/vnd.swift.registry.v1+json")
        .with_status(status)
        .with_body(body)
        .create()
}

const NIO_URL: &str = "https://github.com/apple/swift-nio";
const UNIQUE: &str = r#"{"identifiers": ["apple.swift-nio"]}"#;

fn dependency(parsed: &SwiftParseResult) -> &SwiftDependency {
    &parsed.dependencies[0]
}

#[tokio::test]
async fn test_prefetch_warms_the_memo_then_the_reparse_swaps_the_dependency() {
    let mut server = mockito::Server::new_async().await;
    let lookup = identifiers(&mut server, NIO_URL, UNIQUE, 200).expect(1);
    let fixture = Fixture::with_default(&server.url(), ScmToRegistry::Replace);

    let first = fixture.parse(NIO).await;
    assert_eq!(dependency(&first).origin, SwiftOrigin::Declared);
    assert_eq!(dependency(&first).source, DependencySource::Registry);

    let report = fixture.prefetch(&first).await;
    assert_eq!(report.effect, ProbeEffect::Reparse);
    assert_eq!((report.issued, report.incomplete_identity_lookups), (1, 0));

    let second = fixture.parse(NIO).await;
    let swapped = dependency(&second);
    assert_eq!(swapped.name, "apple.swift-nio");
    assert_eq!(
        swapped.source,
        DependencySource::AlternateRegistry {
            index: server.url(),
            mirrors_crates_io: false,
        }
    );
    assert_matches!(&swapped.origin, SwiftOrigin::Swizzled { scm } if scm.wire() == NIO_URL);
    assert_eq!(swapped.url, NIO_URL);
    assert_eq!(swapped.name_range, dependency(&first).name_range);
    assert_eq!(swapped.version_range, dependency(&first).version_range);
    assert_eq!(swapped.version_req, dependency(&first).version_req);
    assert_eq!(second.resolved_registries.len(), 1);

    assert_eq!(
        fixture.prefetch(&second).await.effect,
        ProbeEffect::Unchanged
    );
    lookup.assert();
}

#[tokio::test]
async fn test_a_disabled_mode_changes_nothing_and_sends_nothing() {
    let mut server = mockito::Server::new_async().await;
    let lookup = identifiers(&mut server, NIO_URL, UNIQUE, 200).expect(0);
    let fixture = Fixture::with_default(&server.url(), ScmToRegistry::Disabled);

    let parsed = fixture.parse(NIO).await;
    assert_eq!(fixture.prefetch(&parsed).await, ProbeReport::default());
    assert_eq!(dependency(&parsed).origin, SwiftOrigin::Declared);
    lookup.assert();
}

#[tokio::test]
async fn test_each_registry_answer_maps_to_its_form() {
    let cases: [(&str, usize, bool); 5] = [
        (UNIQUE, 200, true),
        (
            r#"{"identifiers": ["apple.swift-nio", "other.nio"]}"#,
            200,
            false,
        ),
        (r#"{"identifiers": []}"#, 200, false),
        (r#"{"identifiers": ["not an identity"]}"#, 200, false),
        ("", 404, false),
    ];
    for (body, status, swapped) in cases {
        let mut server = mockito::Server::new_async().await;
        let _lookup = identifiers(&mut server, NIO_URL, body, status);
        let fixture = Fixture::with_default(&server.url(), ScmToRegistry::Replace);

        let report = fixture.prefetch(&fixture.parse(NIO).await).await;
        let reparsed = fixture.parse(NIO).await;
        assert_eq!(
            matches!(dependency(&reparsed).origin, SwiftOrigin::Swizzled { .. }),
            swapped,
            "{status} {body}"
        );
        assert_eq!(
            report.effect == ProbeEffect::Reparse,
            swapped,
            "{status} {body}"
        );
        assert_eq!(report.incomplete_identity_lookups, 0, "{status} {body}");
    }
}

#[tokio::test]
async fn test_a_failed_lookup_keeps_source_control_and_adds_a_notice() {
    let mut server = mockito::Server::new_async().await;
    let _lookup = identifiers(&mut server, NIO_URL, "boom", 500);
    let fixture = Fixture::with_default(&server.url(), ScmToRegistry::Replace);

    let parsed = fixture.parse(NIO).await;
    let report = fixture.prefetch(&parsed).await;
    assert_eq!(report.effect, ProbeEffect::Unchanged);
    assert_eq!(report.incomplete_identity_lookups, 1);

    let notices = fixture.ecosystem.lookup_failed_notices(&parsed);
    assert_eq!(notices.len(), 1);
    assert_eq!(
        notices[0].message(),
        "registry identity lookup failed; showing source-control versions"
    );
    assert_eq!(
        notices[0].severity,
        Some(deps_core::diagnostic::Severity::Information)
    );
    assert_eq!(
        dependency(&fixture.parse(NIO).await).source,
        DependencySource::Registry
    );
}

#[tokio::test]
async fn test_a_not_registered_url_gets_no_notice() {
    let mut server = mockito::Server::new_async().await;
    let _lookup = identifiers(&mut server, NIO_URL, "", 404);
    let fixture = Fixture::with_default(&server.url(), ScmToRegistry::Replace);

    let parsed = fixture.parse(NIO).await;
    fixture.prefetch(&parsed).await;
    assert!(fixture.ecosystem.lookup_failed_notices(&parsed).is_empty());
}

#[tokio::test]
async fn test_written_url_is_sent_first_and_the_canonical_form_once_on_not_registered() {
    let mut server = mockito::Server::new_async().await;
    let written = identifiers(
        &mut server,
        "https://github.com/apple/swift-nio.git",
        "",
        404,
    )
    .expect(1);
    let canonical = identifiers(&mut server, NIO_URL, UNIQUE, 200).expect(1);
    let fixture = Fixture::with_default(&server.url(), ScmToRegistry::Replace);
    let manifest = r#".package(url: "https://github.com/apple/swift-nio.git", from: "2.0.0")"#;

    let report = fixture.prefetch(&fixture.parse(manifest).await).await;
    assert_eq!(report.effect, ProbeEffect::Reparse);
    written.assert();
    canonical.assert();
}

#[tokio::test]
async fn test_credentials_in_the_written_url_never_reach_the_registry() {
    let mut server = mockito::Server::new_async().await;
    let leak = server
        .mock("GET", "/identifiers")
        .match_query(Matcher::Regex("TOKEN|private_token|oauth2".into()))
        .with_status(200)
        .with_body(UNIQUE)
        .expect(0)
        .create();
    let stripped =
        identifiers(&mut server, "https://gitlab.example.com/x.git", UNIQUE, 200).expect(1);
    let fixture = Fixture::with_default(&server.url(), ScmToRegistry::Replace);
    let manifest = r#".package(url: "https://oauth2:TOKEN@gitlab.example.com/x.git?private_token=y", from: "1.0.0")"#;

    let report = fixture.prefetch(&fixture.parse(manifest).await).await;
    assert_eq!(report.effect, ProbeEffect::Reparse);
    stripped.assert();
    leak.assert();

    let swapped = fixture.parse(manifest).await;
    assert!(!format!("{:?}", dependency(&swapped)).contains("TOKEN"));
}

#[tokio::test]
async fn test_only_version_requirements_on_http_urls_are_eligible() {
    let mut server = mockito::Server::new_async().await;
    let lookup = server
        .mock("GET", "/identifiers")
        .match_query(Matcher::Any)
        .with_status(200)
        .with_body(UNIQUE)
        .expect(0)
        .create();
    let fixture = Fixture::with_default(&server.url(), ScmToRegistry::Replace);
    let manifest = r#"
        .package(url: "https://github.com/apple/swift-nio", branch: "main"),
        .package(url: "https://github.com/apple/swift-log", revision: "abc"),
        .package(url: "git@github.com:apple/swift-metrics.git", from: "1.0.0"),
        .package(url: "ssh://git@github.com/apple/swift-numerics.git", from: "1.0.0"),
        .package(path: "../local"),
        .package(id: "acme.net", from: "1.0.0")
    "#;

    let parsed = fixture.parse(manifest).await;
    assert_eq!(fixture.prefetch(&parsed).await, ProbeReport::default());
    assert!(
        parsed
            .dependencies
            .iter()
            .all(|dep| dep.origin == SwiftOrigin::Declared)
    );
    lookup.assert();
}

#[tokio::test]
async fn test_a_project_tier_default_is_never_asked() {
    let mut server = mockito::Server::new_async().await;
    let lookup = identifiers(&mut server, NIO_URL, UNIQUE, 200).expect(0);
    let fixture = Fixture::new(
        None,
        Some(registries(Some(&server.url()), &[])),
        ScmToRegistry::Replace,
    );

    let parsed = fixture.parse(NIO).await;
    assert_eq!(fixture.prefetch(&parsed).await, ProbeReport::default());
    assert_eq!(
        dependency(&fixture.parse(NIO).await).source,
        DependencySource::Registry
    );
    lookup.assert();
}

#[tokio::test]
async fn test_a_project_tier_default_cannot_redirect_a_user_tier_lookup() {
    let mut operator = mockito::Server::new_async().await;
    let mut attacker = mockito::Server::new_async().await;
    let asked = identifiers(&mut operator, NIO_URL, UNIQUE, 200).expect(1);
    let untouched = identifiers(&mut attacker, NIO_URL, UNIQUE, 200).expect(0);
    let fixture = Fixture::new(
        Some(registries(Some(&operator.url()), &[])),
        Some(registries(Some(&attacker.url()), &[])),
        ScmToRegistry::Replace,
    );

    fixture.prefetch(&fixture.parse(NIO).await).await;
    let swapped = fixture.parse(NIO).await;
    assert_eq!(
        dependency(&swapped).source,
        DependencySource::AlternateRegistry {
            index: operator.url(),
            mirrors_crates_io: false,
        }
    );
    asked.assert();
    untouched.assert();
}

#[tokio::test]
async fn test_the_identity_scope_routes_through_the_user_tier_table() {
    let mut default = mockito::Server::new_async().await;
    let scoped = mockito::Server::new_async().await;
    let _lookup = identifiers(&mut default, NIO_URL, UNIQUE, 200);
    let fixture = Fixture::new(
        Some(registries(
            Some(&default.url()),
            &[("apple", &scoped.url())],
        )),
        None,
        ScmToRegistry::Replace,
    );

    fixture.prefetch(&fixture.parse(NIO).await).await;
    let swapped = fixture.parse(NIO).await;
    assert_eq!(
        dependency(&swapped).source,
        DependencySource::AlternateRegistry {
            index: scoped.url(),
            mirrors_crates_io: false,
        }
    );
}

#[tokio::test]
async fn test_removing_the_trusted_default_converges_without_reparse_or_events() {
    let mut server = mockito::Server::new_async().await;
    let _lookup = identifiers(&mut server, NIO_URL, UNIQUE, 200);
    let warm = Fixture::with_default(&server.url(), ScmToRegistry::Replace);
    warm.prefetch(&warm.parse(NIO).await).await;
    assert_matches!(
        dependency(&warm.parse(NIO).await).origin,
        SwiftOrigin::Swizzled { .. }
    );

    let context = SwiftParseContext::default().with_scm_to_registry(Arc::clone(&warm.mode));
    let without_default = SwiftEcosystem::with_context(Arc::clone(&warm.registry), context);
    let mut events = warm.registry.identity_memo().subscribe();
    for _ in 0..3 {
        let parsed = without_default
            .parse_manifest(NIO, &warm.uri)
            .await
            .unwrap();
        let report = without_default
            .background_probes(parsed.as_ref(), ProbePhase::PreFetch)
            .await;
        assert_eq!(report.effect, ProbeEffect::Unchanged);
        let any = parsed.as_any();
        let parsed = any.downcast_ref::<SwiftParseResult>().unwrap();
        assert_eq!(dependency(parsed).source, DependencySource::Registry);
    }
    assert!(events.try_recv().is_err());
}

#[tokio::test]
async fn test_a_stale_entry_is_served_and_refreshed_in_the_background() {
    let mut server = mockito::Server::new_async().await;
    let lookup = identifiers(&mut server, NIO_URL, r#"{"identifiers": []}"#, 200).expect(1);
    let fixture = Fixture::with_default(&server.url(), ScmToRegistry::Replace);
    let scm = ScmLookupUrl::parse(NIO_URL).unwrap();
    let long_ago = std::time::Instant::now()
        .checked_sub(crate::scm_memo::IDENTITY_TTL * 2)
        .unwrap();
    let known = IdentityLookup::Unique(
        crate::package_location::RegistryIdentityBuf::parse("apple.swift-nio").unwrap(),
    );
    fixture
        .registry
        .identity_memo()
        .record(&fixture.key(&scm), known, long_ago);

    let parsed = fixture.parse(NIO).await;
    assert_matches!(dependency(&parsed).origin, SwiftOrigin::Swizzled { .. });
    let report = fixture.prefetch(&parsed).await;
    assert_eq!(report.effect, ProbeEffect::Unchanged);
    assert_eq!(report.issued, 1);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !lookup.matched() && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    lookup.assert();
}

#[test]
fn test_swizzle_decision_truth_table() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("user.json");
    std::fs::write(&file, registries(Some("https://swift.acme.dev/api"), &[])).unwrap();
    let context = SwiftParseContext::new(
        Arc::default(),
        Arc::default(),
        UserConfigPath::Path(OperatorPath::for_test(&file)),
        None,
    );
    let config = context.resolve_user_tier();
    let lookup = config.trusted_lookup().unwrap();
    let scm = ScmLookupUrl::parse(NIO_URL).unwrap();
    let unique = IdentityLookup::Unique(
        crate::package_location::RegistryIdentityBuf::parse("apple.swift-nio").unwrap(),
    );

    fn decide<'a>(
        mode: ScmToRegistry,
        lookup: Option<&'a TrustedLookupRegistry<'a>>,
        form: SwiftRequirementForm,
        scm: Option<&'a ScmLookupUrl>,
        answer: Option<&'a IdentityLookup>,
    ) -> SwiftForm {
        swizzle_decision(SwizzleInput {
            mode,
            lookup,
            form,
            scm,
            answer,
        })
    }
    let swapped = decide(
        ScmToRegistry::Replace,
        Some(&lookup),
        SwiftRequirementForm::Version,
        Some(&scm),
        Some(&unique),
    );
    assert_matches!(swapped, SwiftForm::RegistryIdentity { .. });

    assert_eq!(
        decide(
            ScmToRegistry::Disabled,
            Some(&lookup),
            SwiftRequirementForm::Version,
            Some(&scm),
            Some(&unique)
        ),
        SwiftForm::Scm
    );
    assert_eq!(
        decide(
            ScmToRegistry::Replace,
            None,
            SwiftRequirementForm::Version,
            Some(&scm),
            Some(&unique)
        ),
        SwiftForm::Scm
    );
    for form in [
        SwiftRequirementForm::Branch,
        SwiftRequirementForm::Revision,
        SwiftRequirementForm::Path,
    ] {
        assert_eq!(
            decide(
                ScmToRegistry::Replace,
                Some(&lookup),
                form,
                Some(&scm),
                Some(&unique)
            ),
            SwiftForm::Scm
        );
    }
    assert_eq!(
        decide(
            ScmToRegistry::Replace,
            Some(&lookup),
            SwiftRequirementForm::Version,
            None,
            Some(&unique)
        ),
        SwiftForm::Scm
    );
    for answer in [
        None,
        Some(IdentityLookup::Ambiguous),
        Some(IdentityLookup::NotRegistered),
        Some(IdentityLookup::Rejected),
        Some(IdentityLookup::Failed),
    ] {
        assert_eq!(
            decide(
                ScmToRegistry::Replace,
                Some(&lookup),
                SwiftRequirementForm::Version,
                Some(&scm),
                answer.as_ref()
            ),
            SwiftForm::Scm,
            "{answer:?}"
        );
    }
}

/// NFR-004: a run that waits for every miss ends on the same forms however many misses there
/// are, instead of giving up after a fixed wait and swapping them later.
#[tokio::test]
async fn test_many_misses_are_all_answered_within_the_live_concurrency_limit() {
    const COUNT: usize = 30;
    let mut server = mockito::Server::new_async().await;
    let lookups = server
        .mock("GET", "/identifiers")
        .match_query(Matcher::Any)
        .with_status(200)
        .with_body(UNIQUE)
        .expect(COUNT)
        .create();
    let fixture = Fixture::with_default(&server.url(), ScmToRegistry::Replace);
    fixture.mode.set_fetch_limits(
        deps_core::policy_config::FetchTimeout::DEFAULT,
        deps_core::policy_config::FetchConcurrency::try_new(4).unwrap(),
    );
    let manifest = (0..COUNT)
        .map(|i| format!(r#".package(url: "https://github.com/acme/pkg{i}", from: "1.0.0"),"#))
        .collect::<Vec<_>>()
        .concat();

    let parsed = fixture.parse(&manifest).await;
    let report = fixture.prefetch(&parsed).await;

    assert_eq!(report.issued, COUNT);
    assert_eq!(report.incomplete_identity_lookups, 0);
    assert_eq!(report.effect, ProbeEffect::Reparse);
    lookups.assert();
}

#[test]
fn test_a_reverted_swizzled_dependency_is_exactly_the_declared_one() {
    let uri = Url::parse("file:///x/Package.swift").unwrap();
    let declared = crate::parser::parse_package_swift(NIO, &uri)
        .unwrap()
        .dependencies
        .remove(0);
    let mut swizzled = declared.clone();
    swizzled.name = "apple.swift-nio".into();
    swizzled.source = DependencySource::AlternateRegistry {
        index: "https://registry.example".into(),
        mirrors_crates_io: false,
    };
    swizzled.origin = SwiftOrigin::Swizzled {
        scm: ScmLookupUrl::parse(&declared.url).unwrap(),
    };

    swizzled.revert_to_scm();

    assert_eq!(swizzled, declared);
}

const SCM_PIN: &str = r#"{"version": 2, "pins": [{"identity": "swift-nio", "kind": "remoteSourceControl",
    "location": "https://github.com/Apple/Swift-NIO.git", "state": {"version": "2.65.0", "revision": "abc"}}]}"#;

/// FR-018: a swapped dependency finds the version a source-control pin recorded, matched by the
/// canonical repository URL however the pin spells it.
#[tokio::test]
async fn test_a_source_control_pin_is_named_by_the_identity_the_memo_maps_it_to() {
    let mut server = mockito::Server::new_async().await;
    let _lookup = identifiers(&mut server, NIO_URL, UNIQUE, 200);
    let fixture = Fixture::with_default(&server.url(), ScmToRegistry::Replace);
    let lockfile = fixture
        .uri
        .to_file_path()
        .unwrap()
        .with_file_name("Package.resolved");
    std::fs::write(&lockfile, SCM_PIN).unwrap();
    let provider = fixture.ecosystem.lockfile_provider().unwrap();

    let parsed = provider.parse_lockfile(&lockfile).await.unwrap();
    assert!(
        provider.derived_packages(&parsed).is_empty(),
        "cold memo: nothing to name"
    );

    fixture.prefetch(&fixture.parse(NIO).await).await;
    let derived = provider.derived_packages(&parsed);

    assert_eq!(derived.len(), 1);
    assert_eq!(derived[0].name, "apple.swift-nio");
    assert_eq!(derived[0].version, "2.65.0");
}

#[tokio::test]
async fn test_no_pin_is_named_when_the_mode_is_disabled() {
    let mut server = mockito::Server::new_async().await;
    let _lookup = identifiers(&mut server, NIO_URL, UNIQUE, 200);
    let fixture = Fixture::with_default(&server.url(), ScmToRegistry::Replace);
    let lockfile = fixture
        .uri
        .to_file_path()
        .unwrap()
        .with_file_name("Package.resolved");
    std::fs::write(&lockfile, SCM_PIN).unwrap();
    let provider = fixture.ecosystem.lockfile_provider().unwrap();
    fixture.prefetch(&fixture.parse(NIO).await).await;
    let parsed = provider.parse_lockfile(&lockfile).await.unwrap();

    fixture.mode.set(ScmToRegistry::Disabled);

    assert!(provider.derived_packages(&parsed).is_empty());
}
