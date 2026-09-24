//! Version formatting for Maven ecosystem.

use deps_core::lsp_helpers::{
    DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
    RequirementMatcher, RequirementResolution, SourcePolicy, compile_requirement_unless,
    requirement_contains_template_placeholder,
};
use deps_core::{
    ConcreteVersion, InvalidPackageName, PackageName, VersionReq, is_safe_maven_coordinate_segment,
};

/// [`EcosystemFormatter`](deps_core::lsp_helpers::EcosystemFormatter) implementation for Maven.
pub struct MavenFormatter;

/// Unexpanded `${property}` interpolation (missing from `<properties>`), an unresolved
/// `@property@` resource-filtering placeholder (`maven-resources-plugin` filtering, or a
/// `pom.xml` generated from an archetype, e.g. `@project.version@`), or any other
/// cross-ecosystem external-templating shape — delegates fully to
/// [`requirement_contains_template_placeholder`] (#1384), the same shared predicate
/// npm/Cargo/PyPI/Dart/Deno/Go/Composer/GitLab CI's equivalent guards use (#1383's
/// generalization), which already covers `${...}`/`$(...)` (its own `$`-prefixed check)
/// alongside `@VAR@`, `%VAR%`, `{{ }}`, `{% %}`, and `<%= %>`.
fn is_unresolved(requirement: &str) -> bool {
    requirement_contains_template_placeholder(requirement)
}

/// Maven's `LATEST`/`RELEASE` metadata keywords (case-sensitive per Maven's own grammar):
/// "resolve to whatever `<latest>`/`<release>` in maven-metadata.xml currently designates".
/// That designation is a side channel [`MavenMatcher`] has no access to (the same
/// `<release>`-side-channel limitation `MavenCentralRegistry::select_latest_matching`
/// documents), so — like an unresolved `${property}` — the requirement can't be checked
/// literally against `available` and must be treated as always satisfied.
fn is_latest_keyword(requirement: &str) -> bool {
    matches!(requirement, "LATEST" | "RELEASE")
}

/// A `-SNAPSHOT` pin (e.g. `7.0.0-SNAPSHOT`) is a normal, common requirement in real dev
/// manifests, but `MavenCentralRegistry` only ever fetches the release-repo
/// `maven-metadata.xml` — which never lists snapshot versions, those live in a separate
/// snapshot repository this registry client doesn't query. `available` can therefore never
/// contain one, so — like `LATEST`/`RELEASE` and an unresolved `${property}` — it must be
/// treated as always satisfied rather than scanned.
fn is_snapshot(requirement: &str) -> bool {
    requirement.ends_with("-SNAPSHOT")
}

/// A resolved timestamped-snapshot deployment (e.g. `1.0-20260101.120000-1`) — the form a
/// `-SNAPSHOT` version takes once actually deployed to the snapshot repository, replacing
/// the `-SNAPSHOT` suffix with a `-<yyyyMMdd>.<HHmmss>-<buildNumber>` unique-version stamp.
/// Same undecidable case as [`is_snapshot`]: this registry client never queries the
/// snapshot repository, so `available` can never contain one.
fn is_timestamped_snapshot(requirement: &str) -> bool {
    let mut segments = requirement.rsplitn(3, '-');
    let Some(build_number) = segments.next() else {
        return false;
    };
    let Some(timestamp) = segments.next() else {
        return false;
    };
    if segments.next().is_none() {
        return false;
    }
    if build_number.is_empty() || !build_number.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Some((date, time)) = timestamp.split_once('.') else {
        return false;
    };
    date.len() == 8
        && date.bytes().all(|b| b.is_ascii_digit())
        && time.len() == 6
        && time.bytes().all(|b| b.is_ascii_digit())
}

/// Precise Maven version/range matcher, compiled once per dependency by
/// [`MavenFormatter::compile_requirement`] — the range union (if any) is parsed once into
/// [`crate::interval::VersionRange`]s here rather than being re-parsed for every candidate
/// version scanned. Deliberately more precise than the loose `version_satisfies_requirement`
/// in two ways it does not need for its own "treat as up to date" question: it recognizes the
/// `LATEST`/`RELEASE` keywords, and its exact-match branch uses qualifier-aware
/// `compare_versions_for_range` instead of raw string equality, so `1.0` correctly matches a
/// published `1.0.0` (equal under Maven's own `ComparableVersion`) rather than reporting a
/// false WARNING.
enum MavenMatcher {
    /// Unresolved `${property}`/`@property@`, `LATEST`/`RELEASE`, or a `-SNAPSHOT` pin — see
    /// [`is_unresolved`], [`is_latest_keyword`], [`is_snapshot`].
    AlwaysSatisfied,
    /// A range/union, pre-parsed by [`crate::range::parse_range`].
    Ranges(Vec<crate::interval::VersionRange>),
    /// A bare "soft" recommended version, compared with qualifier-aware equality.
    Exact(String),
}

impl RequirementMatcher for MavenMatcher {
    fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
        let version = version.as_str();
        Some(match self {
            Self::AlwaysSatisfied => true,
            Self::Ranges(ranges) => crate::range::satisfies_ranges(version, ranges),
            Self::Exact(target) => {
                crate::version::compare_versions_for_range(version, target)
                    == std::cmp::Ordering::Equal
            }
        })
    }
}

impl PackageNaming for MavenFormatter {
    /// Validates a Maven coordinate's `groupId:artifactId` shape and character set.
    ///
    /// Mirrors the gate `crate::registry::metadata_urls` applies before building a
    /// registry request URL ([`is_safe_maven_coordinate_segment`] on each split
    /// coordinate segment), so a coordinate rejected here would also be rejected there —
    /// letting the "Invalid package name" diagnostic (deps-core's
    /// `formatter.validate_package_name` gate) surface the accurate reason instead of the
    /// generic "Unknown package" a registry-side rejection produces (#369).
    ///
    /// An unresolved `${property}`/`@property@` groupId/artifactId (e.g. a multi-module
    /// POM's `<groupId>${project.groupId}</groupId>`, see `is_unresolved` — which, via the
    /// shared `requirement_contains_template_placeholder`, also accepts a `%VAR%`/`{{ }}`/
    /// `{% %}`/`<%= %>`-shaped groupId/artifactId defensively, though Maven's own tooling
    /// never produces those) is valid Maven, not a malformed coordinate — checked first and
    /// always accepted, the same undecidable treatment `is_unresolved` already gets in
    /// [`version_satisfies_requirement`](Self::version_satisfies_requirement) and
    /// [`compile_requirement`](Self::compile_requirement).
    ///
    /// The missing-`:` branch is defensive: `crate::parser` always builds a
    /// dependency's name as `format!("{group_id}:{artifact_id}")`, so a real coordinate
    /// reaching this method already contains exactly one `:`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPackageName`] if `name` has no `:` separator, or if either the
    /// `groupId` or `artifactId` segment fails [`is_safe_maven_coordinate_segment`] — but
    /// never when `name` contains an unresolved `${property}`/`@property@` placeholder,
    /// which is accepted instead.
    fn validate_package_name(&self, name: &str) -> Result<(), InvalidPackageName> {
        if is_unresolved(name) {
            return Ok(());
        }
        let Some((group_id, artifact_id)) = name.split_once(':') else {
            return Err(InvalidPackageName::new(
                "coordinate must be in 'groupId:artifactId' form",
            ));
        };
        if !is_safe_maven_coordinate_segment(group_id) {
            return Err(InvalidPackageName::new(
                "groupId contains invalid characters",
            ));
        }
        if !is_safe_maven_coordinate_segment(artifact_id) {
            return Err(InvalidPackageName::new(
                "artifactId contains invalid characters",
            ));
        }
        Ok(())
    }
}

impl PackageRendering for MavenFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        let version = version.as_str();
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        crate::registry::package_url(name.as_str())
    }
}

impl RequirementResolution for MavenFormatter {
    // #249 review (M4): this branch order (unresolved → range → exact) is a separate copy
    // from `compile_requirement`'s below — kept apart deliberately (see `MavenMatcher`'s
    // docs for the two precision differences), but any reordering here must be checked
    // against `compile_requirement`'s malformed-range guard placement too, since S1/S2
    // happened in `deps-gradle` from exactly this kind of drift between two copies.
    fn version_satisfies_requirement(&self, version: &ConcreteVersion, requirement: &str) -> bool {
        let version = version.as_str();
        // Unresolved ${property}/@property@ (or another shared-predicate template
        // placeholder shape) — skip comparison
        if is_unresolved(requirement) {
            return true;
        }
        if crate::range::is_range(requirement) {
            return crate::range::satisfies(version, requirement);
        }
        version == requirement
    }

    // #1370/#1384/#1391: Maven's `is_unresolved` fully delegates to the shared
    // `requirement_contains_template_placeholder` — the same detector
    // `RequirementResolution::requirement_is_placeholder`'s shared default calls — so it
    // covers `${property}`/`@property@` (the two forms Maven's own tooling actually
    // produces) plus the other four cross-ecosystem shapes (`%VAR%`, `{{ }}`, `{% %}`,
    // `<%= %>`) defensively, with no override needed here.

    /// Uses [`compile_requirement_unless`] (see that function and
    /// [`deps_core::lsp_helpers::RequirementResolution::compile_requirement`] for the shared "undecidable" contract).
    ///
    /// The undecidable predicate rejects a malformed range (`is_range` true but
    /// `crate::range::parse_range` fails) — checked unconditionally, first, before any other
    /// branch: without this guard ahead of the `AlwaysSatisfied` short-circuits below, a
    /// range that happens to also end in `-SNAPSHOT` or contain `${` would be misclassified
    /// as always-satisfied instead of rejected, and a fail-closed `false` on every candidate
    /// would otherwise produce a false "unsatisfiable" verdict for a typo instead of
    /// correctly suppressing the check.
    ///
    /// #249 review (M4): this is a separate branch-order copy from `version_satisfies_requirement`
    /// above — see the note on that method before reordering either one.
    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
        compile_requirement_unless(
            requirement.as_str(),
            |r| crate::range::is_range(r) && crate::range::parse_range(r).is_none(),
            |r| {
                if is_unresolved(&r)
                    || is_latest_keyword(&r)
                    || is_snapshot(&r)
                    || is_timestamped_snapshot(&r)
                {
                    return MavenMatcher::AlwaysSatisfied;
                }
                // The undecidable guard above already ensures `parse_range` succeeds here.
                if crate::range::is_range(&r)
                    && let Some(ranges) = crate::range::parse_range(&r)
                {
                    return MavenMatcher::Ranges(ranges);
                }
                MavenMatcher::Exact(r)
            },
        )
    }
}

impl DiagnosticMessages for MavenFormatter {}

impl DiagnosticPolicy for MavenFormatter {}

impl SourcePolicy for MavenFormatter {}

impl OsvNaming for MavenFormatter {}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::lsp_helpers::RequirementStatus;

    #[test]
    fn test_format_version() {
        let f = MavenFormatter;
        assert_eq!(
            f.format_version_for_text_edit(&ConcreteVersion::new("3.14.0")),
            "3.14.0"
        );
        assert_eq!(
            f.format_version_for_text_edit(&ConcreteVersion::new("1.0.0-SNAPSHOT")),
            "1.0.0-SNAPSHOT"
        );
    }

    // #758: exact-value `EcosystemFormatter` conformance, replacing test_package_url,
    // test_version_satisfies, test_version_satisfies_range, test_version_satisfies_maven_property,
    // test_validate_package_name_accepts_valid_coordinate,
    // test_validate_package_name_rejects_invalid_group_id,
    // test_validate_package_name_rejects_invalid_artifact_id,
    // test_validate_package_name_rejects_missing_colon, and
    // test_validate_package_name_accepts_unresolved_property. The unresolved-`${property}`
    // acceptance (impl-critic S2: valid Maven, not a malformed coordinate) and the
    // `${property}`-requirement always-satisfied cases both fit this macro's literal lists.
    deps_core::formatter_conformance! {
        mod maven_formatter_conformance;
        build: MavenFormatter;
        package_url: {
            "org.apache.commons:commons-lang3" => "https://central.sonatype.com/artifact/org.apache.commons/commons-lang3",
        };
        accepts: [
            "org.apache.commons:commons-lang3",
            "${project.groupId}:my-module",
            "org.example:${artifact.name}",
            "@project.groupId@:my-module",
            "org.example:@artifact.name@",
        ];
        rejects: [
            "commons</artifactId><parent>:commons-lang3",
            "org.apache.commons:..",
            "org.apache.commons",
        ];
        version_roundtrip: [
            "3.14.0", "3.14.0" => true,
            "3.14.0", "3.13.0" => false,
            "3.14.0", "3.14.1" => false,
            "1.5.0", "[1.0,2.0)" => true,
            "2.0.0", "[1.0,2.0)" => false,
            "1.0.0", "[1.0.0]" => true,
            "1.0.1", "[1.0.0]" => false,
            "7.1.1", "${woodstoxVersion}" => true,
            "2.0.17", "${slf4j.version}" => true,
            "1.0.0", "${project.version}" => true,
            "1.0.0", "@project.version@" => true
        ];
    }

    // #782 gap 1: the former hand-written test_package_url_hostile_display_link_payload_is_safe
    // is now generated unconditionally by `formatter_conformance!` above
    // (`formatter_package_url_hostile_input_safe`), reachable by `cargo nextest run -p
    // deps-maven` alone, same as before.

    #[test]
    fn test_normalize_is_identity() {
        let f = MavenFormatter;
        assert_eq!(
            f.normalize_package_name(&PackageName::new("org.apache.commons:commons-lang3")),
            "org.apache.commons:commons-lang3"
        );
    }

    #[test]
    fn test_requirement_status_unresolved_property() {
        let f = MavenFormatter;
        assert_eq!(
            f.requirement_status(
                &VersionReq::new("${woodstoxVersion}"),
                &ConcreteVersion::new("7.1.1")
            ),
            RequirementStatus::Unresolved
        );
        assert_eq!(
            f.requirement_status(
                &VersionReq::new("${project.version}"),
                &ConcreteVersion::new("1.0.0")
            ),
            RequirementStatus::Unresolved
        );
    }

    /// #1384: `@project.version@` (Maven's `@VAR@` resource-filtering placeholder) must be
    /// classified `Unresolved`, the same as its `${property}` counterpart above.
    #[test]
    fn test_requirement_status_unresolved_at_placeholder() {
        let f = MavenFormatter;
        assert_eq!(
            f.requirement_status(
                &VersionReq::new("@project.version@"),
                &ConcreteVersion::new("1.0.0")
            ),
            RequirementStatus::Unresolved
        );
    }

    #[test]
    fn test_requirement_status_up_to_date() {
        let f = MavenFormatter;
        assert_eq!(
            f.requirement_status(&VersionReq::new("3.14.0"), &ConcreteVersion::new("3.14.0")),
            RequirementStatus::UpToDate
        );
    }

    #[test]
    fn test_requirement_status_outdated() {
        let f = MavenFormatter;
        assert_eq!(
            f.requirement_status(&VersionReq::new("3.13.0"), &ConcreteVersion::new("3.14.0")),
            RequirementStatus::Outdated
        );
    }

    #[test]
    fn test_osv_version_to_native_round_trips_through_own_parser() {
        // Critic S2 gate: `osv_version_to_native` is identity for Maven (OSV
        // records use Maven's own version syntax verbatim), so the version
        // it hands to `format_version_for_text_edit` must itself satisfy the
        // requirement text that edit produces — proving the default hook is
        // safe for this ecosystem rather than merely assumed so.
        let f = MavenFormatter;
        let osv_version = "1.2.3";
        let native = f.osv_version_to_native(osv_version);
        assert_eq!(native, osv_version);
        let native = ConcreteVersion::new(native);
        let edit_text = f.format_version_for_text_edit(&native);
        assert!(f.version_satisfies_requirement(&native, &edit_text));
    }

    #[test]
    fn test_compile_requirement_exact() {
        let f = MavenFormatter;
        let matcher = f
            .compile_requirement(&VersionReq::new("3.14.0"))
            .expect("Maven requirement always compiles");
        assert_eq!(matcher.matches(&ConcreteVersion::new("3.14.0")), Some(true));
        assert_eq!(
            matcher.matches(&ConcreteVersion::new("3.13.0")),
            Some(false)
        );
    }

    #[test]
    fn test_compile_requirement_range() {
        let f = MavenFormatter;
        let matcher = f
            .compile_requirement(&VersionReq::new("[1.0,2.0)"))
            .unwrap();
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.5.0")), Some(true));
        assert_eq!(matcher.matches(&ConcreteVersion::new("2.0.0")), Some(false));
    }

    #[test]
    fn test_compile_requirement_malformed_range_returns_none() {
        let f = MavenFormatter;
        assert!(
            f.compile_requirement(&VersionReq::new("[1.0,2.0"))
                .is_none()
        );
    }

    /// #1347 S1 deferral rationale: an unresolved `${property}` compiles to
    /// `MavenMatcher::AlwaysSatisfied`, which reports `Some(true)` against *any* candidate —
    /// including a vulnerability's fix target. Since #1391, the actual guard against a
    /// destructive rewrite is [`deps_core::edit::replacement_text`]'s central placeholder gate
    /// (backed by `RequirementResolution::requirement_is_placeholder`, which composes the
    /// shared generic-template detector for Maven's `${property}` form) — this
    /// `AlwaysSatisfied` classification now only feeds `requirement_already_resolves_to`'s
    /// secondary no-op check, not the sole line of defense `deps-cli`'s
    /// `requirement_already_admits_fix` originally relied on.
    #[test]
    fn test_compile_requirement_unresolved_property_always_satisfied() {
        let f = MavenFormatter;
        let matcher = f
            .compile_requirement(&VersionReq::new("${undefined.property}"))
            .expect("an unresolved property must be decidable (always-satisfied), not undecidable");
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.2.0")), Some(true));
        assert_eq!(
            matcher.matches(&ConcreteVersion::new("99.99.99")),
            Some(true)
        );
    }

    /// #1384: an unresolved `@property@` resource-filtering placeholder must compile to
    /// `AlwaysSatisfied`, exactly like `${property}` above.
    #[test]
    fn test_compile_requirement_at_placeholder_always_satisfied() {
        let f = MavenFormatter;
        let matcher = f
            .compile_requirement(&VersionReq::new("@project.version@"))
            .expect("an unresolved @property@ placeholder must be decidable (always-satisfied)");
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.2.0")), Some(true));
        assert_eq!(
            matcher.matches(&ConcreteVersion::new("99.99.99")),
            Some(true)
        );
    }

    /// M2: `<version>1.0</version>` and a published `1.0.0` are equal under Maven's own
    /// `ComparableVersion` (trailing zero segments don't matter) — the exact-match branch
    /// must not fall back to raw string equality and report a false WARNING.
    #[test]
    fn test_compile_requirement_trailing_zero_segments_are_equal() {
        let f = MavenFormatter;
        let matcher = f.compile_requirement(&VersionReq::new("1.0")).unwrap();
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.0.0")), Some(true));
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.1.0")), Some(false));
    }

    /// M2: `LATEST`/`RELEASE` resolve against maven-metadata.xml's `<latest>`/`<release>`
    /// elements, a side channel this matcher has no access to — must be treated as always
    /// satisfied, like an unresolved property, not compared literally against `available`.
    #[test]
    fn test_compile_requirement_latest_keyword_always_satisfied() {
        let f = MavenFormatter;
        let matcher = f.compile_requirement(&VersionReq::new("LATEST")).unwrap();
        assert_eq!(matcher.matches(&ConcreteVersion::new("3.14.0")), Some(true));

        let matcher = f.compile_requirement(&VersionReq::new("RELEASE")).unwrap();
        assert_eq!(matcher.matches(&ConcreteVersion::new("3.14.0")), Some(true));
    }

    /// S6: a `-SNAPSHOT` pin resolves against the snapshot repository, which this registry
    /// never queries — release-repo metadata never lists snapshot versions, so this must be
    /// treated as always satisfied rather than reported unsatisfiable.
    #[test]
    fn test_compile_requirement_snapshot_always_satisfied() {
        let f = MavenFormatter;
        let matcher = f
            .compile_requirement(&VersionReq::new("7.0.0-SNAPSHOT"))
            .unwrap();
        assert_eq!(matcher.matches(&ConcreteVersion::new("6.9.0")), Some(true));
        assert_eq!(matcher.matches(&ConcreteVersion::new("7.0.0")), Some(true));
    }

    /// #249 review regression: a malformed range that also happens to end in `-SNAPSHOT` or
    /// contain `${` must still be rejected (`None`), not misclassified as always-satisfied by
    /// checking the `AlwaysSatisfied` short-circuits before the malformed-range guard.
    #[test]
    fn test_compile_requirement_malformed_range_rejected_even_with_snapshot_or_property_suffix() {
        let f = MavenFormatter;
        assert!(
            f.compile_requirement(&VersionReq::new("[1.0,2.0-SNAPSHOT"))
                .is_none()
        );
        assert!(
            f.compile_requirement(&VersionReq::new("[1.0,${max}"))
                .is_none()
        );
        assert!(
            f.compile_requirement(&VersionReq::new("[1.0,@max@"))
                .is_none()
        );
    }

    /// A resolved timestamped-snapshot deployment (the form `-SNAPSHOT` takes once
    /// actually published to the snapshot repository) is subject to the same
    /// never-queried-repository limitation as the plain `-SNAPSHOT` pin above.
    #[test]
    fn test_compile_requirement_timestamped_snapshot_always_satisfied() {
        let f = MavenFormatter;
        let matcher = f
            .compile_requirement(&VersionReq::new("1.0-20260101.120000-1"))
            .unwrap();
        assert_eq!(matcher.matches(&ConcreteVersion::new("6.9.0")), Some(true));

        // A version with a trailing numeric qualifier that merely looks similar but isn't
        // a `yyyyMMdd.HHmmss-N` stamp must still be compared normally.
        let matcher = f.compile_requirement(&VersionReq::new("1.0-1-2")).unwrap();
        assert_eq!(
            matcher.matches(&ConcreteVersion::new("1.0-1-2")),
            Some(true)
        );
        assert_eq!(
            matcher.matches(&ConcreteVersion::new("1.0-1-3")),
            Some(false)
        );
    }

    /// #1353: an unresolved `${property}` must be classified as unresolved directly (not
    /// just observed as a side effect of `requirement_status`) — the same predicate
    /// `requirement_status`, `requirement_is_unsatisfiable`, and `format_version_replacing`
    /// all key off. Mirrors `deps-nuget`'s equivalent `$(...)`-property test.
    #[test]
    fn test_requirement_is_unresolved_property_placeholder() {
        let f = MavenFormatter;
        assert!(f.requirement_is_unresolved(&VersionReq::new("${ver}")));
        assert!(f.requirement_is_unresolved(&VersionReq::new("${project.version}")));
    }

    /// #1384: `@project.version@` (and other `@property@`-shaped tokens) must be classified
    /// unresolved by both `requirement_is_unresolved` and the central `requirement_is_placeholder`
    /// gate, exactly like `${property}` above.
    #[test]
    fn test_requirement_is_unresolved_at_placeholder() {
        let f = MavenFormatter;
        assert!(f.requirement_is_unresolved(&VersionReq::new("@project.version@")));
        assert!(f.requirement_is_unresolved(&VersionReq::new("@maven.build.timestamp@")));
        assert!(f.requirement_is_placeholder(&VersionReq::new("@project.version@")));
    }

    /// #1384: `is_unresolved` now delegates fully to
    /// `requirement_contains_template_placeholder`, so Maven also inherits guard coverage
    /// for the shared predicate's other external-templating shapes — `%VAR%`, `{{ VAR }}`,
    /// `{% ... %}`, `<%= VAR %>` — even though `pom.xml` itself never produces these
    /// (`@property@`/`${property}` are the only forms Maven's own tooling emits). Defense in
    /// depth: a `pom.xml` mangled by an unrelated external templating step before this crate
    /// ever sees it must still be refused a destructive rewrite.
    #[test]
    fn test_requirement_is_unresolved_other_template_placeholder_forms() {
        let f = MavenFormatter;
        assert!(f.requirement_is_unresolved(&VersionReq::new("%VERSION%")));
        assert!(f.requirement_is_unresolved(&VersionReq::new("{{ version }}")));
        assert!(f.requirement_is_unresolved(&VersionReq::new("{% version %}")));
        assert!(f.requirement_is_unresolved(&VersionReq::new("<%= version %>")));
    }

    /// #1353 counterpart: an ordinary requirement must never be misclassified as unresolved.
    #[test]
    fn test_requirement_is_unresolved_false_for_ordinary_requirements() {
        let f = MavenFormatter;
        assert!(!f.requirement_is_unresolved(&VersionReq::new("3.14.0")));
        assert!(!f.requirement_is_unresolved(&VersionReq::new("[1.0,2.0)")));
    }

    /// A minimal [`crate::types::MavenDependency`] for probing
    /// [`deps_core::edit::replacement_text`] directly — its identity is irrelevant to the
    /// placeholder gate, which checks `current`/`version_literal()` only.
    fn placeholder_probe_dependency() -> crate::types::MavenDependency {
        crate::types::MavenDependency {
            group_id: "com.example".into(),
            artifact_id: "probe".into(),
            name: PackageName::new("com.example:probe"),
            name_range: deps_core::position::Range::default(),
            version_req: None,
            version_range: None,
            scope: crate::types::MavenScope::default(),
            source: deps_core::parser::DependencySource::Registry,
        }
    }

    /// #1353/#1391: `deps_core::edit::replacement_text` — the sole production rewrite path —
    /// must leave an unresolved `${property}` unrewritten rather than substituting the
    /// fix/latest version — mirrors `deps-nuget`'s `$(...)`-property equivalent
    /// (#1347/#1352). This is what actually closes the gap the default
    /// `requirement_already_resolves_to`/`compile_requirement` pairing misses for a
    /// requirement that is *both* unresolved and an undecidable malformed range (see the
    /// malformed-range test below) — `compile_requirement` returns `None` for that shape,
    /// not `MavenMatcher::AlwaysSatisfied`, making the pairing inert.
    #[test]
    fn test_replacement_text_unresolved_property_is_none() {
        use deps_core::edit::replacement_text;

        let f = MavenFormatter;
        let dep = placeholder_probe_dependency();
        assert_eq!(
            replacement_text(&f, &dep, &ConcreteVersion::new("1.2.0"), "${ver}"),
            None
        );
    }

    /// #1384: the same guarantee must hold for an unresolved `@property@`
    /// resource-filtering placeholder — this is the exact reproduction from issue #1384,
    /// where a real (non-dry-run) `deps-cli update` rewrote `@project.version@` to a
    /// literal fix version.
    #[test]
    fn test_replacement_text_at_placeholder_is_none() {
        use deps_core::edit::replacement_text;

        let f = MavenFormatter;
        let dep = placeholder_probe_dependency();
        assert_eq!(
            replacement_text(
                &f,
                &dep,
                &ConcreteVersion::new("1.2.0"),
                "@project.version@"
            ),
            None
        );
    }

    /// #1353 S1: `[1.0,${hi}` is classified unresolved (`is_unresolved` delegates to
    /// `requirement_contains_template_placeholder`, which detects the embedded `${hi}`), but
    /// it is *also* a malformed range — `is_range` is true and `crate::range::parse_range`
    /// fails on it, so `compile_requirement`'s malformed-range guard returns `None` (not
    /// `MavenMatcher::AlwaysSatisfied`), making the default `requirement_already_resolves_to`
    /// inert. `RequirementResolution::requirement_is_placeholder`'s direct `is_unresolved`
    /// check — consulted by `deps_core::edit::replacement_text` before ever calling into the
    /// formatter's rewrite logic — is what actually closes this gap.
    #[test]
    fn test_replacement_text_unresolved_malformed_range_is_none() {
        use deps_core::edit::replacement_text;

        let f = MavenFormatter;
        let dep = placeholder_probe_dependency();
        assert!(
            f.compile_requirement(&VersionReq::new("[1.0,${hi}"))
                .is_none(),
            "expected the malformed range to be undecidable"
        );
        assert_eq!(
            replacement_text(&f, &dep, &ConcreteVersion::new("1.2.0"), "[1.0,${hi}"),
            None
        );
    }

    /// #1384 counterpart to the test above: the same malformed-range-with-embedded-placeholder
    /// gap, for the `@property@` grammar instead of `${property}`.
    #[test]
    fn test_replacement_text_unresolved_malformed_range_at_placeholder_is_none() {
        use deps_core::edit::replacement_text;

        let f = MavenFormatter;
        let dep = placeholder_probe_dependency();
        assert!(
            f.compile_requirement(&VersionReq::new("[1.0,@hi@"))
                .is_none(),
            "expected the malformed range to be undecidable"
        );
        assert_eq!(
            replacement_text(&f, &dep, &ConcreteVersion::new("1.2.0"), "[1.0,@hi@"),
            None
        );
    }

    /// Positive control for the two tests above: a resolved, well-formed requirement must
    /// still be rewritten — the guard must not over-broadly suppress legitimate fixes.
    #[test]
    fn test_format_version_replacing_resolved_requirement_still_rewritten() {
        let f = MavenFormatter;
        assert_eq!(
            f.format_version_replacing(&ConcreteVersion::new("1.2.0"), "1.0.0"),
            "1.2.0"
        );
    }

    fn vuln_fix_dv(fixed_version: &str) -> deps_core::osv::DependencyVulnerabilities {
        use deps_core::osv::{
            Advisory, Capped, DependencyVulnerabilities, UpgradeStatus, VulnSeverity,
        };
        use std::sync::Arc;

        let advisory = Arc::new(
            Advisory::new(
                "GHSA-0000-0000-0000".to_string(),
                "2024-01-01T00:00:00Z".to_string(),
                VulnSeverity::High,
            )
            .expect("valid osv id")
            .with_fixed_versions(vec![fixed_version.to_string()]),
        );
        DependencyVulnerabilities::new(Capped::new(vec![advisory], 1)).with_fix_target_status(
            UpgradeStatus::CandidateClean {
                version: fixed_version.to_string(),
            },
        )
    }

    /// Positive control for the placeholder cases the `unresolved_requirement_conformance!`
    /// macro invocation in `ecosystem.rs` covers (#1353/#1370/#1372: `${property}` and
    /// `[1.0,${hi}` must never be rewritten by `plan_vulnerability_fix`) — a resolved,
    /// well-formed requirement on the same dependency shape must still be rewritten.
    #[test]
    fn test_plan_vulnerability_fix_resolved_requirement_still_returns_planned_edit() {
        use crate::types::{MavenDependency, MavenScope};
        use deps_core::edit::plan_vulnerability_fix;
        use deps_core::parser::DependencySource;
        use deps_core::position::{Position, Range};

        let version_range = Range::new(Position::new(0, 20), Position::new(0, 26));
        let dep = MavenDependency {
            group_id: "com.example".into(),
            artifact_id: "some-lib".into(),
            name: PackageName::new("com.example:some-lib"),
            name_range: Range::default(),
            version_req: Some(VersionReq::new("1.0.0")),
            version_range: Some(version_range),
            scope: MavenScope::Compile,
            source: DependencySource::Registry,
        };

        let dv = vuln_fix_dv("1.2.0");
        let planned = plan_vulnerability_fix(&dep, version_range, "1.0.0", &dv, &MavenFormatter)
            .expect("a resolved requirement must still be rewritten to the fix version");
        assert_eq!(planned.edit.new_text, "1.2.0");
    }
}
