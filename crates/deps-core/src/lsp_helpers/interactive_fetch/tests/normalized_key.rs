//! The interactive request is keyed by the formatter's normalized spelling, not the declared one.

use super::*;
use crate::NormalizedName;
use crate::test_util::StubFormatter;

fn hover_request<'a>(
    outcomes: &'a DependencyOutcomes,
    maps: (
        &'a HashMap<PackageName, crate::PackageVersions>,
        &'a HashMap<PackageName, ConcreteVersion>,
    ),
    manifest: &'a url::Url,
    key: PackageKey,
) -> InteractiveFetchRequest<'a> {
    InteractiveFetchRequest::from_parts(
        VersionData::new(maps.0, maps.1)
            .with_ecosystem(EcosystemId::Pypi)
            .with_outcomes(outcomes),
        manifest,
        key,
        DependencySource::Registry,
        FetchContext::Hover,
    )
}

#[test]
fn the_background_seed_is_found_under_the_formatter_normalized_key_only() {
    let formatter = StubFormatter::new().with_lowercase_names();
    let package = PackageName::new("My_Pkg");
    let key = PackageKey::new(&package, &formatter);
    assert_eq!(key.normalized().as_str(), "my_pkg");
    let (cached, resolved) = (HashMap::new(), HashMap::new());
    let manifest = manifest("/project/pyproject.toml");

    let seeded_normalized = DependencyOutcomes::new()
        .with_fetch_failure(key.normalized().clone(), FetchFailure::Transient);
    let seeded_declared = DependencyOutcomes::new()
        .with_fetch_failure(NormalizedName::for_test("My_Pkg"), FetchFailure::Transient);

    let by_normalized = hover_request(
        &seeded_normalized,
        (&cached, &resolved),
        &manifest,
        key.clone(),
    );
    let by_declared = hover_request(&seeded_declared, (&cached, &resolved), &manifest, key);

    assert!(by_normalized.background_failure_known(LookupKind::VersionList));
    assert!(
        !by_declared.background_failure_known(LookupKind::VersionList),
        "a seed under the declared spelling must not be found"
    );
}
