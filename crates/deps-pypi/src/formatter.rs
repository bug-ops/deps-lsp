use deps_core::ConcreteVersion;
use deps_core::Dependency;
use deps_core::InvalidPackageName;
use deps_core::PackageName;
use deps_core::VersionReq;
use deps_core::lsp_helpers::{
    DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
    RequirementMatcher, RequirementResolution, SourcePolicy,
};
use pep440_rs::{Version, VersionSpecifiers};
use std::str::FromStr;
use tower_lsp_server::ls_types::Position;

/// Precise PEP 440 specifier-set matcher, compiled once per dependency by
/// [`PypiFormatter::compile_requirement`].
struct Pep440Matcher(VersionSpecifiers);

impl RequirementMatcher for Pep440Matcher {
    fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
        let version = version.as_str();
        Version::from_str(version).ok().map(|v| self.0.contains(&v))
    }
}

pub struct PypiFormatter;

impl PackageNaming for PypiFormatter {
    fn normalize_package_name(&self, name: &PackageName) -> String {
        crate::name::normalize(name.as_str())
    }

    fn validate_package_name(&self, name: &str) -> Result<(), InvalidPackageName> {
        // PEP 508: ^([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9])$
        let valid = !name.is_empty()
            && name
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric())
            && name
                .chars()
                .last()
                .is_some_and(|c| c.is_ascii_alphanumeric())
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));

        if valid {
            Ok(())
        } else {
            Err(InvalidPackageName::new(
                "must match PEP 508 name pattern ^([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9])$",
            ))
        }
    }
}

impl PackageRendering for PypiFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        let version = version.as_str();
        let next_major = version
            .split('.')
            .next()
            .and_then(|s| s.parse::<u32>().ok())
            .and_then(|v| v.checked_add(1))
            .unwrap_or(1);

        format!(">={version},<{next_major}")
    }

    fn format_version_replacing(&self, version: &ConcreteVersion, current: &str) -> String {
        let version = version.as_str();
        let terms: Vec<&str> = current.trim().split(',').map(str::trim).collect();

        if terms.iter().any(|t| t.starts_with("===")) {
            return format!("==={version}");
        }

        if let Some(term) = terms.iter().find(|t| t.starts_with("==")) {
            return match term.strip_prefix("==").and_then(|r| r.strip_suffix(".*")) {
                Some(base) => {
                    let candidate = truncate_release_to_match(base, version)
                        .map(|truncated| format!("=={truncated}.*"))
                        .unwrap_or_else(|| format!("=={version}"));
                    // Truncating `version` back down to the wildcard's own
                    // precision can reproduce `current` byte-for-byte (e.g.
                    // `==1.0.*` stays `==1.0.*` for a 1.0.2 fix) even though
                    // the wildcard still admits the vulnerable range it
                    // started from — fall back to the untruncated exact pin
                    // rather than silently no-oping a live finding.
                    if candidate == *term {
                        format!("=={version}")
                    } else {
                        candidate
                    }
                }
                None => format!("=={version}"),
            };
        }

        if let Some(term) = terms.iter().find(|t| t.starts_with("~=")) {
            let rest = term.strip_prefix("~=").unwrap_or_default().trim();
            let release_len = Version::from_str(rest)
                .map(|v| v.release().len())
                .unwrap_or(0);
            return if release_len >= 2 {
                let candidate = truncate_release_to_match(rest, version)
                    .map(|truncated| format!("~={truncated}"))
                    .unwrap_or_else(|| format!("~={version}"));
                // Same no-op fallback as the `==` wildcard case above.
                if candidate == *term {
                    format!("~={version}")
                } else {
                    candidate
                }
            } else {
                // `~=3` has a single release segment, which is not valid PEP 440
                // on its own — don't emit another invalid pin.
                self.format_version_for_text_edit(&ConcreteVersion::new(version))
            };
        }

        self.format_version_for_text_edit(&ConcreteVersion::new(version))
    }

    fn package_url(&self, name: &PackageName) -> String {
        crate::registry::package_url(name.as_str())
    }

    fn is_position_on_dependency(&self, dep: &dyn Dependency, position: Position) -> bool {
        let name_range = dep.name_range();

        if position.line != name_range.start.line {
            return false;
        }

        let end_char = dep
            .version_range()
            .map_or(name_range.end.character, |r| r.end.character);

        let start_char = name_range.start.character.saturating_sub(2);
        let end_char = end_char.saturating_add(2);

        position.character >= start_char && position.character <= end_char
    }

    /// FR-009/validator finding #2: suppresses the hover heading's `pypi.org` project link
    /// for anything but plain public-registry content. Without this override (the trait
    /// default is unconditionally `false`), a private-index dependency's hover would render
    /// a `pypi.org` link right next to its actual private-index version data — once live
    /// data renders alongside it, an unrelated `pypi.org` link reads as false confirmation
    /// the link is real. Mirrors `NpmFormatter`'s/`CargoFormatter`'s identical override,
    /// reusing `SourcePolicy::source_is_public_registry_content`'s default (`Registry` only
    /// — PyPI has no crates.io-style verified-mirror concept for `AlternateRegistry` to
    /// except).
    fn suppress_package_url(&self, source: &deps_core::DependencySource) -> bool {
        !self.source_is_public_registry_content(source)
    }
}

impl RequirementResolution for PypiFormatter {
    fn version_satisfies_requirement(&self, version: &ConcreteVersion, requirement: &str) -> bool {
        let version = version.as_str();
        let Ok(ver) = Version::from_str(version) else {
            return false;
        };

        let Ok(specs) = VersionSpecifiers::from_str(requirement) else {
            return false;
        };

        specs.contains(&ver)
    }

    /// Compiles `requirement` via `pep440_rs::VersionSpecifiers` — the same crate and the
    /// same precise contains-check `version_satisfies_requirement` above already uses, so
    /// this is not a new comparator, just its result cached across candidates instead of
    /// reparsed per call.
    ///
    /// Returns `None` when any specifier pins a PEP 440 [local version identifier]
    /// (e.g. `torch==2.0.1+cu118`). Local versions are conventionally published only on
    /// custom/alternate indexes (e.g. the PyTorch wheel index), not the default registry
    /// this matcher checks candidates against — so an empty match set there does not mean
    /// the requirement is unsatisfiable everywhere, and the diagnostic would be a false
    /// positive.
    ///
    /// [local version identifier]: https://peps.python.org/pep-0440/#local-version-identifiers
    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
        let specs = VersionSpecifiers::from_str(requirement.as_str()).ok()?;
        if specs.iter().any(|spec| spec.version().is_local()) {
            return None;
        }
        Some(Box::new(Pep440Matcher(specs)))
    }
}

impl DiagnosticMessages for PypiFormatter {}

impl DiagnosticPolicy for PypiFormatter {}

impl SourcePolicy for PypiFormatter {
    /// FR-009: gates hover/diagnostics/code-actions on a resolved `AlternateRegistry`
    /// (private-index) source, in addition to the plain public `Registry` default —
    /// mirrors `NpmFormatter::can_resolve_source` exactly. `CustomRegistry` (an unresolved
    /// or invalid explicit index — FR-006) is deliberately not accepted here: it falls
    /// through to the default `is_version_resolvable() == false`, keeping the existing
    /// fail-closed gate intact.
    ///
    /// Known cosmetic limitation (M1, not fixed): a plain dependency in an extras-only file
    /// (FR-005(b)) is classified `AlternateRegistry` at parse time, before the winning hop
    /// is known — if it actually resolves via the implicit public fallback, its `pypi.org`
    /// hover link is still suppressed by `PackageRendering::suppress_package_url` (correct
    /// for the private-index case this feature exists for, cosmetically over-cautious only
    /// for this one edge case). Accepted for phase 1; documented in `ECOSYSTEM_GUIDE.md`.
    fn can_resolve_source(&self, source: &deps_core::DependencySource) -> bool {
        matches!(
            source,
            deps_core::DependencySource::Registry
                | deps_core::DependencySource::AlternateRegistry { .. }
        )
    }
}

impl OsvNaming for PypiFormatter {}

/// Truncates `latest`'s PEP 440 release segments to the same segment count
/// as `source_version`'s release, joined with `.`. Returns `None` if either
/// fails to parse, or `latest` has fewer release segments than
/// `source_version` (in which case the caller falls back to the untruncated
/// version rather than losing precision).
fn truncate_release_to_match(source_version: &str, latest: &str) -> Option<String> {
    let source_release_len = Version::from_str(source_version).ok()?.release().len();
    let latest_release = Version::from_str(latest).ok()?;
    let latest_release = latest_release.release();
    if latest_release.len() < source_release_len {
        return None;
    }
    Some(
        latest_release[..source_release_len]
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join("."),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FR-009: `Registry` and `AlternateRegistry` both resolve; `CustomRegistry` and every
    /// non-registry source stay fail-closed via the default `is_version_resolvable()`.
    #[test]
    fn test_can_resolve_source() {
        let formatter = PypiFormatter;
        assert!(formatter.can_resolve_source(&deps_core::DependencySource::Registry));
        assert!(
            formatter.can_resolve_source(&deps_core::DependencySource::AlternateRegistry {
                index: "pypi-chain:deadbeef".to_string(),
                mirrors_crates_io: false,
            })
        );
        assert!(
            !formatter.can_resolve_source(&deps_core::DependencySource::CustomRegistry {
                url: "https://pypi.mycorp.example/simple".to_string(),
            })
        );
    }

    /// Validator finding #2 (security H2): a private-index (`AlternateRegistry`) dependency's
    /// hover must suppress the `pypi.org` project link; a plain public-registry dependency
    /// must not.
    #[test]
    fn test_suppress_package_url() {
        let formatter = PypiFormatter;
        assert!(!formatter.suppress_package_url(&deps_core::DependencySource::Registry));
        assert!(
            formatter.suppress_package_url(&deps_core::DependencySource::AlternateRegistry {
                index: "pypi-chain:deadbeef".to_string(),
                mirrors_crates_io: false,
            })
        );
        assert!(
            formatter.suppress_package_url(&deps_core::DependencySource::CustomRegistry {
                url: "https://pypi.mycorp.example/simple".to_string(),
            })
        );
    }

    #[test]
    fn test_normalize_package_name() {
        let formatter = PypiFormatter;
        assert_eq!(
            formatter.normalize_package_name(&PackageName::new("requests")),
            "requests"
        );
        assert_eq!(
            formatter.normalize_package_name(&PackageName::new("Django-REST-Framework")),
            "django-rest-framework"
        );
        assert_eq!(
            formatter.normalize_package_name(&PackageName::new("My-Package")),
            "my-package"
        );
        assert_eq!(
            formatter.normalize_package_name(&PackageName::new("zope.interface")),
            "zope-interface"
        );
    }

    #[test]
    fn test_format_version() {
        let formatter = PypiFormatter;
        assert_eq!(
            formatter.format_version_for_text_edit(&ConcreteVersion::new("1.2.3")),
            ">=1.2.3,<2"
        );
        assert_eq!(
            formatter.format_version_for_text_edit(&ConcreteVersion::new("2.28.0")),
            ">=2.28.0,<3"
        );
        assert_eq!(
            formatter.format_version_for_text_edit(&ConcreteVersion::new("0.1.0")),
            ">=0.1.0,<1"
        );
    }

    #[test]
    fn test_format_version_overflow_protection() {
        let formatter = PypiFormatter;
        // u32::MAX should not overflow, checked_add returns None
        assert_eq!(
            formatter.format_version_for_text_edit(&ConcreteVersion::new("4294967295.0.0")),
            ">=4294967295.0.0,<1"
        );
    }

    #[test]
    fn test_package_url() {
        let formatter = PypiFormatter;
        assert_eq!(
            formatter.package_url(&PackageName::new("requests")),
            "https://pypi.org/project/requests"
        );
        assert_eq!(
            formatter.package_url(&PackageName::new("django")),
            "https://pypi.org/project/django"
        );
    }

    #[test]
    fn test_version_satisfies_pep440() {
        let formatter = PypiFormatter;

        assert!(
            formatter.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), ">=1.0,<2")
        );
        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("2.28.0"), ">=2.0"));
        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("1.0.0"), "==1.0.0"));
        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("1.2.0"), "~=1.2.0"));

        assert!(
            !formatter.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), ">=1.0,<2")
        );
        assert!(!formatter.version_satisfies_requirement(&ConcreteVersion::new("0.9.0"), ">=1.0"));
    }

    #[test]
    fn test_version_satisfies_invalid_version() {
        let formatter = PypiFormatter;
        assert!(
            !formatter
                .version_satisfies_requirement(&ConcreteVersion::new("not-a-version"), ">=1.0")
        );
    }

    #[test]
    fn test_version_satisfies_invalid_specifier() {
        let formatter = PypiFormatter;
        assert!(
            !formatter
                .version_satisfies_requirement(&ConcreteVersion::new("1.0.0"), "not-a-specifier")
        );
    }

    #[test]
    fn test_compile_requirement_satisfiable() {
        let formatter = PypiFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new(">=1.0,<2.0"))
            .expect("valid PEP 440 specifier must compile");
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.5.0")), Some(true));
        assert_eq!(matcher.matches(&ConcreteVersion::new("2.0.0")), Some(false));
    }

    #[test]
    fn test_compile_requirement_unparseable_requirement_returns_none() {
        let formatter = PypiFormatter;
        assert!(
            formatter
                .compile_requirement(&VersionReq::new("not-a-specifier"))
                .is_none()
        );
    }

    #[test]
    fn test_compile_requirement_local_version_returns_none() {
        let formatter = PypiFormatter;
        assert!(
            formatter
                .compile_requirement(&VersionReq::new("==2.0.1+cu118"))
                .is_none()
        );
    }

    #[test]
    fn test_compile_requirement_unparseable_candidate_is_skipped() {
        let formatter = PypiFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new(">=1.0"))
            .unwrap();
        assert_eq!(matcher.matches(&ConcreteVersion::new("2011k")), None);
    }

    #[test]
    fn test_default_yanked_message() {
        let formatter = PypiFormatter;
        assert_eq!(formatter.yanked_message(), "This version has been yanked");
        assert_eq!(formatter.yanked_label(), "*(yanked)*");
    }

    #[test]
    fn test_osv_version_to_native_round_trips_through_own_parser() {
        // Critic S2 gate: `osv_version_to_native` is identity for PyPI (OSV
        // records use PEP 440 verbatim), so the version it hands to
        // `format_version_for_text_edit` — which expands it into a
        // `>=v,<next-major` range, unlike the identity edit most other
        // ecosystems use — must itself satisfy the requirement text that
        // edit produces.
        let formatter = PypiFormatter;
        let osv_version = "2.28.0";
        let native = formatter.osv_version_to_native(osv_version);
        assert_eq!(native, osv_version);
        let native = ConcreteVersion::new(native);
        let edit_text = formatter.format_version_for_text_edit(&native);
        assert!(formatter.version_satisfies_requirement(&native, &edit_text));
    }

    #[test]
    fn test_osv_version_to_native_round_trips_through_format_version_replacing() {
        // Critic M2: the vulnerability-fix `TextEdit` is now built via
        // `format_version_replacing`, not `format_version_for_text_edit` —
        // the round-trip gate above no longer guards the code it was
        // written for. Same property, retargeted at the method the fix
        // path actually calls, across every `current` shape it recognizes.
        let formatter = PypiFormatter;
        let osv_version = "2.28.0";
        let native = formatter.osv_version_to_native(osv_version);
        assert_eq!(native, osv_version);
        let native = ConcreteVersion::new(native);

        for current in ["==2.20.0", "==2.20.*", "~=2.20", "~=2.20.0", ">=2.20,<2.21"] {
            let edit_text = formatter.format_version_replacing(&native, current);
            assert!(
                formatter.version_satisfies_requirement(&native, &edit_text),
                "current={current:?} produced edit_text={edit_text:?}, which does not admit {native:?}"
            );
        }
    }

    #[test]
    fn test_normalize_fast_path() {
        let formatter = PypiFormatter;
        // Already lowercase, no hyphens - should hit fast path
        assert_eq!(
            formatter.normalize_package_name(&PackageName::new("requests")),
            "requests"
        );
        assert_eq!(
            formatter.normalize_package_name(&PackageName::new("flask")),
            "flask"
        );
        assert_eq!(
            formatter.normalize_package_name(&PackageName::new("numpy")),
            "numpy"
        );
    }

    #[test]
    fn test_validate_package_name_accepts_valid_names() {
        let formatter = PypiFormatter;
        assert!(formatter.validate_package_name("zope.interface").is_ok());
        assert!(formatter.validate_package_name("Django").is_ok());
        assert!(formatter.validate_package_name("a").is_ok());
        assert!(formatter.validate_package_name("my-package_1.0").is_ok());
    }

    #[test]
    fn test_validate_package_name_rejects_invalid_names() {
        let formatter = PypiFormatter;
        assert!(formatter.validate_package_name("---").is_err());
        assert!(formatter.validate_package_name("-x").is_err());
        assert!(formatter.validate_package_name("x-").is_err());
        assert!(formatter.validate_package_name("a b").is_err());
        assert!(formatter.validate_package_name("").is_err());
    }

    #[test]
    fn test_format_version_replacing_table() {
        let formatter = PypiFormatter;

        // starts `===`
        assert_eq!(
            formatter.format_version_replacing(&ConcreteVersion::new("1.2"), "===1.0"),
            "===1.2"
        );

        // starts `==`, no wildcard
        assert_eq!(
            formatter.format_version_replacing(&ConcreteVersion::new("1.2"), "==1.0"),
            "==1.2"
        );

        // starts `==`, wildcard, latest has enough segments
        assert_eq!(
            formatter.format_version_replacing(&ConcreteVersion::new("1.6.2"), "==1.4.*"),
            "==1.6.*"
        );

        // `~=` with >=2 release segments truncates, never over-specifies
        assert_eq!(
            formatter.format_version_replacing(&ConcreteVersion::new("1.26.4"), "~=1.24"),
            "~=1.26"
        );

        // `~=` with a single release segment is invalid PEP 440 on its own; default
        assert_eq!(
            formatter.format_version_replacing(&ConcreteVersion::new("4.0.0"), "~=3"),
            ">=4.0.0,<5"
        );

        // multi-specifier collapse: any comma-separated term starting with `==` wins,
        // regardless of position (N1 fix — pep440_rs sorts specifiers by version, so
        // `!=0.9,==1.0` in source may render sorted either way)
        assert_eq!(
            formatter.format_version_replacing(&ConcreteVersion::new("1.2"), "==1.0, !=1.0.1"),
            "==1.2"
        );
        assert_eq!(
            formatter.format_version_replacing(&ConcreteVersion::new("1.2"), "!=0.9, ==1.0"),
            "==1.2"
        );

        // comma-separated, no `==`/`===`/`~=` term -> default range
        assert_eq!(
            formatter
                .format_version_replacing(&ConcreteVersion::new("2.0.0"), ">=1.0, !=1.5, <2.0"),
            ">=2.0.0,<3"
        );

        // anything else -> default
        assert_eq!(
            formatter.format_version_replacing(&ConcreteVersion::new("2.0.0"), ">=1.0"),
            ">=2.0.0,<3"
        );
    }

    #[test]
    fn test_format_version_replacing_wildcard_pin_no_op_falls_back_to_exact_fix() {
        // Critic S1: truncating the fix version back down to the pin's own
        // precision can reproduce `current` byte-for-byte even though the
        // pin still admits the vulnerable range it started from (`~=1.0`
        // and `==1.0.*` both still match 1.0.0/1.0.1). If that happens, the
        // untruncated exact version must be emitted instead, or the N1
        // no-op guard in `deps-core` silently drops the vulnerability
        // quickfix entirely.
        let formatter = PypiFormatter;

        assert_eq!(
            formatter.format_version_replacing(&ConcreteVersion::new("1.0.2"), "~=1.0"),
            "~=1.0.2"
        );
        assert_eq!(
            formatter.format_version_replacing(&ConcreteVersion::new("1.0.2"), "==1.0.*"),
            "==1.0.2"
        );

        // `~=`'s floor equals the fix version's own precision: the
        // untruncated fallback text is identical to the truncated one, so
        // this is a genuine no-op either way (unaffected by the fallback).
        assert_eq!(
            formatter.format_version_replacing(&ConcreteVersion::new("1.0.2"), "~=1.0.2"),
            "~=1.0.2"
        );
        // `==V.*` has no floor semantics (it is a release-prefix match, not
        // a lower bound), so there is no textually-identical "genuine
        // no-op" fallback for it — the wildcard is narrowed to an exact pin
        // instead, which is always at least as safe as leaving it alone.
        assert_eq!(
            formatter.format_version_replacing(&ConcreteVersion::new("1.0.2"), "==1.0.2.*"),
            "==1.0.2"
        );
    }

    mod is_position_on_dependency_tests {
        use super::*;
        use deps_core::parser::DependencySource;
        use std::any::Any;
        use tower_lsp_server::ls_types::Range;

        struct MockDep {
            name_range: Range,
            version_range: Option<Range>,
        }

        impl deps_core::Dependency for MockDep {
            fn name(&self) -> &deps_core::PackageName {
                static NAME: std::sync::LazyLock<deps_core::PackageName> =
                    std::sync::LazyLock::new(|| deps_core::PackageName::new("test-package"));
                &NAME
            }
            fn name_range(&self) -> Range {
                self.name_range
            }
            fn version_requirement(&self) -> Option<&deps_core::VersionReq> {
                static VERSION_REQ: std::sync::LazyLock<deps_core::VersionReq> =
                    std::sync::LazyLock::new(|| deps_core::VersionReq::new(">=1.0"));
                Some(&VERSION_REQ)
            }
            fn version_range(&self) -> Option<Range> {
                self.version_range
            }
            fn source(&self) -> DependencySource {
                DependencySource::Registry
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        #[test]
        fn test_position_on_name() {
            let formatter = PypiFormatter;
            let dep = MockDep {
                name_range: Range::new(Position::new(5, 10), Position::new(5, 20)),
                version_range: Some(Range::new(Position::new(5, 25), Position::new(5, 35))),
            };
            // Position on package name
            assert!(formatter.is_position_on_dependency(&dep, Position::new(5, 15)));
        }

        #[test]
        fn test_position_in_padding_before() {
            let formatter = PypiFormatter;
            let dep = MockDep {
                name_range: Range::new(Position::new(5, 10), Position::new(5, 20)),
                version_range: Some(Range::new(Position::new(5, 25), Position::new(5, 35))),
            };
            // Position in padding before name (character - 2)
            assert!(formatter.is_position_on_dependency(&dep, Position::new(5, 8)));
        }

        #[test]
        fn test_position_after_version_padding() {
            let formatter = PypiFormatter;
            let dep = MockDep {
                name_range: Range::new(Position::new(5, 10), Position::new(5, 20)),
                version_range: Some(Range::new(Position::new(5, 25), Position::new(5, 35))),
            };
            // Position after version range (character + 2)
            assert!(formatter.is_position_on_dependency(&dep, Position::new(5, 37)));
        }

        #[test]
        fn test_position_too_far_before() {
            let formatter = PypiFormatter;
            let dep = MockDep {
                name_range: Range::new(Position::new(5, 10), Position::new(5, 20)),
                version_range: Some(Range::new(Position::new(5, 25), Position::new(5, 35))),
            };
            // Position too far before (outside padding)
            assert!(!formatter.is_position_on_dependency(&dep, Position::new(5, 5)));
        }

        #[test]
        fn test_position_too_far_after() {
            let formatter = PypiFormatter;
            let dep = MockDep {
                name_range: Range::new(Position::new(5, 10), Position::new(5, 20)),
                version_range: Some(Range::new(Position::new(5, 25), Position::new(5, 35))),
            };
            // Position too far after (outside padding)
            assert!(!formatter.is_position_on_dependency(&dep, Position::new(5, 40)));
        }

        #[test]
        fn test_position_different_line() {
            let formatter = PypiFormatter;
            let dep = MockDep {
                name_range: Range::new(Position::new(5, 10), Position::new(5, 20)),
                version_range: Some(Range::new(Position::new(5, 25), Position::new(5, 35))),
            };
            // Different line
            assert!(!formatter.is_position_on_dependency(&dep, Position::new(4, 15)));
            assert!(!formatter.is_position_on_dependency(&dep, Position::new(6, 15)));
        }

        #[test]
        fn test_position_without_version_range() {
            let formatter = PypiFormatter;
            let dep = MockDep {
                name_range: Range::new(Position::new(5, 10), Position::new(5, 20)),
                version_range: None,
            };
            // Should use name_range.end for calculation
            assert!(formatter.is_position_on_dependency(&dep, Position::new(5, 22)));
            assert!(!formatter.is_position_on_dependency(&dep, Position::new(5, 25)));
        }

        #[test]
        fn test_saturating_sub_at_column_zero() {
            let formatter = PypiFormatter;
            // Edge case: character 0 with saturating_sub(2)
            let dep = MockDep {
                name_range: Range::new(Position::new(5, 0), Position::new(5, 10)),
                version_range: None,
            };
            // saturating_sub(2) should give 0, not underflow
            assert!(formatter.is_position_on_dependency(&dep, Position::new(5, 0)));
        }
    }
}
