use deps_core::Dependency;
use deps_core::InvalidPackageName;
use deps_core::PackageName;
use deps_core::lsp_helpers::EcosystemFormatter;
use pep440_rs::{Version, VersionSpecifiers};
use std::str::FromStr;
use tower_lsp_server::ls_types::Position;

pub struct PypiFormatter;

impl EcosystemFormatter for PypiFormatter {
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

    fn format_version_for_text_edit(&self, version: &str) -> String {
        let next_major = version
            .split('.')
            .next()
            .and_then(|s| s.parse::<u32>().ok())
            .and_then(|v| v.checked_add(1))
            .unwrap_or(1);

        format!(">={version},<{next_major}")
    }

    fn format_version_replacing(&self, version: &str, current: &str) -> String {
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
                self.format_version_for_text_edit(version)
            };
        }

        self.format_version_for_text_edit(version)
    }

    fn version_satisfies_requirement(&self, version: &str, requirement: &str) -> bool {
        let Ok(ver) = Version::from_str(version) else {
            return false;
        };

        let Ok(specs) = VersionSpecifiers::from_str(requirement) else {
            return false;
        };

        specs.contains(&ver)
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
}

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
            formatter.format_version_for_text_edit("1.2.3"),
            ">=1.2.3,<2"
        );
        assert_eq!(
            formatter.format_version_for_text_edit("2.28.0"),
            ">=2.28.0,<3"
        );
        assert_eq!(
            formatter.format_version_for_text_edit("0.1.0"),
            ">=0.1.0,<1"
        );
    }

    #[test]
    fn test_format_version_overflow_protection() {
        let formatter = PypiFormatter;
        // u32::MAX should not overflow, checked_add returns None
        assert_eq!(
            formatter.format_version_for_text_edit("4294967295.0.0"),
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

        assert!(formatter.version_satisfies_requirement("1.2.3", ">=1.0,<2"));
        assert!(formatter.version_satisfies_requirement("2.28.0", ">=2.0"));
        assert!(formatter.version_satisfies_requirement("1.0.0", "==1.0.0"));
        assert!(formatter.version_satisfies_requirement("1.2.0", "~=1.2.0"));

        assert!(!formatter.version_satisfies_requirement("2.0.0", ">=1.0,<2"));
        assert!(!formatter.version_satisfies_requirement("0.9.0", ">=1.0"));
    }

    #[test]
    fn test_version_satisfies_invalid_version() {
        let formatter = PypiFormatter;
        assert!(!formatter.version_satisfies_requirement("not-a-version", ">=1.0"));
    }

    #[test]
    fn test_version_satisfies_invalid_specifier() {
        let formatter = PypiFormatter;
        assert!(!formatter.version_satisfies_requirement("1.0.0", "not-a-specifier"));
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
            formatter.format_version_replacing("1.2", "===1.0"),
            "===1.2"
        );

        // starts `==`, no wildcard
        assert_eq!(formatter.format_version_replacing("1.2", "==1.0"), "==1.2");

        // starts `==`, wildcard, latest has enough segments
        assert_eq!(
            formatter.format_version_replacing("1.6.2", "==1.4.*"),
            "==1.6.*"
        );

        // `~=` with >=2 release segments truncates, never over-specifies
        assert_eq!(
            formatter.format_version_replacing("1.26.4", "~=1.24"),
            "~=1.26"
        );

        // `~=` with a single release segment is invalid PEP 440 on its own; default
        assert_eq!(
            formatter.format_version_replacing("4.0.0", "~=3"),
            ">=4.0.0,<5"
        );

        // multi-specifier collapse: any comma-separated term starting with `==` wins,
        // regardless of position (N1 fix — pep440_rs sorts specifiers by version, so
        // `!=0.9,==1.0` in source may render sorted either way)
        assert_eq!(
            formatter.format_version_replacing("1.2", "==1.0, !=1.0.1"),
            "==1.2"
        );
        assert_eq!(
            formatter.format_version_replacing("1.2", "!=0.9, ==1.0"),
            "==1.2"
        );

        // comma-separated, no `==`/`===`/`~=` term -> default range
        assert_eq!(
            formatter.format_version_replacing("2.0.0", ">=1.0, !=1.5, <2.0"),
            ">=2.0.0,<3"
        );

        // anything else -> default
        assert_eq!(
            formatter.format_version_replacing("2.0.0", ">=1.0"),
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
            formatter.format_version_replacing("1.0.2", "~=1.0"),
            "~=1.0.2"
        );
        assert_eq!(
            formatter.format_version_replacing("1.0.2", "==1.0.*"),
            "==1.0.2"
        );

        // `~=`'s floor equals the fix version's own precision: the
        // untruncated fallback text is identical to the truncated one, so
        // this is a genuine no-op either way (unaffected by the fallback).
        assert_eq!(
            formatter.format_version_replacing("1.0.2", "~=1.0.2"),
            "~=1.0.2"
        );
        // `==V.*` has no floor semantics (it is a release-prefix match, not
        // a lower bound), so there is no textually-identical "genuine
        // no-op" fallback for it — the wildcard is narrowed to an exact pin
        // instead, which is always at least as safe as leaving it alone.
        assert_eq!(
            formatter.format_version_replacing("1.0.2", "==1.0.2.*"),
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
