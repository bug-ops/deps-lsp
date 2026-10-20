//! The interactive request is keyed by the formatter's normalized spelling, not the declared one.

use super::*;
use crate::NormalizedName;
use crate::lsp_helpers::NormalizeName;
use crate::test_util::StubFormatter;

fn hover_request<'a>(
    outcomes: &'a DependencyOutcomes,
    maps: (
        &'a HashMap<PackageName, crate::PackageVersions>,
        &'a HashMap<PackageName, ConcreteVersion>,
    ),
    manifest: &'a url::Url,
    package: &'a PackageName,
    key: &'a NormalizedName,
    source: &'a DependencySource,
) -> InteractiveFetchRequest<'a> {
    InteractiveFetchRequest::new(
        VersionData::new(maps.0, maps.1)
            .with_ecosystem(EcosystemId::Pypi)
            .with_outcomes(outcomes),
        manifest,
        package,
        key,
        source,
        FetchContext::Hover,
    )
}

#[test]
fn the_background_seed_is_found_under_the_formatter_normalized_key_only() {
    let formatter = StubFormatter::new().with_lowercase_names();
    let package = PackageName::new("My_Pkg");
    let normalized = formatter.normalize_package_name(&package);
    assert_eq!(normalized.as_str(), "my_pkg");
    let outcomes =
        DependencyOutcomes::new().with_fetch_failure(normalized.clone(), FetchFailure::Transient);
    let (cached, resolved) = (HashMap::new(), HashMap::new());
    let source = DependencySource::Registry;
    let manifest = manifest("/project/pyproject.toml");
    let declared_spelling = NormalizedName::for_test("My_Pkg");

    let by_normalized = hover_request(
        &outcomes,
        (&cached, &resolved),
        &manifest,
        &package,
        &normalized,
        &source,
    );
    let by_declared = hover_request(
        &outcomes,
        (&cached, &resolved),
        &manifest,
        &package,
        &declared_spelling,
        &source,
    );

    assert!(by_normalized.background_failure_known(LookupKind::VersionList));
    assert!(
        !by_declared.background_failure_known(LookupKind::VersionList),
        "the declared spelling must miss the seed the normalized key finds"
    );
}
