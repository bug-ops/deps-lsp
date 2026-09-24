//! `[update].ignore` rule evaluation (#1119, spec 068).

use deps_core::edit::UpdateKind;
use deps_core::lsp_helpers::EcosystemFormatter;

use crate::config::IgnoreRule;
use crate::update::SkipReason;

/// Normalized, ready-to-evaluate `[update].ignore` rules.
///
/// Built once per run via [`Self::new`] (normal mode, honoring an explicit `--config`'s
/// rules) or [`Self::empty`] (no `--config` given — FR-007: `update` never auto-discovers a
/// `deps.toml`, so there are never any rules to evaluate in that case).
#[derive(Debug, Default)]
pub struct IgnoreRules {
    rules: Vec<(String, Option<Vec<crate::config::UpdateTypeToken>>)>,
}

impl IgnoreRules {
    /// No rules — every dependency is eligible (FR-007's no-`--config` case).
    #[must_use]
    pub const fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    /// Normalizes `rules`' names via `formatter.normalize_package_name` once, up front, so
    /// [`Self::skip_reason`] never has to.
    #[must_use]
    pub fn new(rules: Vec<IgnoreRule>, formatter: &dyn EcosystemFormatter) -> Self {
        let rules = rules
            .into_iter()
            .map(|rule| {
                let normalized =
                    formatter.normalize_package_name(&deps_core::PackageName::new(rule.name));
                (normalized, rule.update_types)
            })
            .collect();
        Self { rules }
    }

    /// Whether any rule names `normalized_name` at all, regardless of its `update_types`
    /// scope — used only by `--security-only`'s FR-008 override report (never to suppress a
    /// candidate there), since an overridden rule is reported as "would have applied"
    /// independent of whether its scope would actually have matched this update's kind.
    #[must_use]
    pub fn matches_name(&self, normalized_name: &str) -> bool {
        self.rules.iter().any(|(name, _)| name == normalized_name)
    }

    /// Whether a dependency named `normalized_name` (already normalized), classified `kind`,
    /// should be skipped — `Some(SkipReason::IgnoreRule)` when a rule matches, `None`
    /// otherwise.
    ///
    /// A rule with no `update_types` matches every kind, including [`UpdateKind::Unknown`]. A
    /// rule with `update_types` matches its listed kinds **and** `Unknown` — fail-closed
    /// (FR-006): a rule that cannot confirm an update is below its stated threshold treats it
    /// as if it met the threshold.
    #[must_use]
    pub fn skip_reason(&self, normalized_name: &str, kind: UpdateKind) -> Option<SkipReason> {
        let (_, update_types) = self
            .rules
            .iter()
            .find(|(name, _)| name == normalized_name)?;

        let matches = match update_types {
            None => true,
            Some(types) => kind == UpdateKind::Unknown || types.iter().any(|t| t.matches(kind)),
        };
        matches.then_some(SkipReason::IgnoreRule)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::UpdateTypeToken;

    const STUB_FORMATTER: deps_core::test_util::StubFormatter =
        deps_core::test_util::StubFormatter::new().with_package_url_prefix("");

    #[test]
    fn test_empty_rules_never_skip() {
        let rules = IgnoreRules::empty();
        assert_eq!(rules.skip_reason("tokio", UpdateKind::Major), None);
    }

    #[test]
    fn test_rule_with_no_update_types_matches_every_kind() {
        let rules = IgnoreRules::new(
            vec![IgnoreRule {
                name: "legacy-thing".to_string(),
                update_types: None,
            }],
            &STUB_FORMATTER,
        );
        assert_eq!(
            rules.skip_reason("legacy-thing", UpdateKind::Patch),
            Some(SkipReason::IgnoreRule)
        );
        assert_eq!(
            rules.skip_reason("legacy-thing", UpdateKind::Unknown),
            Some(SkipReason::IgnoreRule)
        );
    }

    #[test]
    fn test_scoped_rule_only_matches_listed_kind() {
        let rules = IgnoreRules::new(
            vec![IgnoreRule {
                name: "tokio".to_string(),
                update_types: Some(vec![UpdateTypeToken::Major]),
            }],
            &STUB_FORMATTER,
        );
        assert_eq!(
            rules.skip_reason("tokio", UpdateKind::Major),
            Some(SkipReason::IgnoreRule)
        );
        assert_eq!(rules.skip_reason("tokio", UpdateKind::Minor), None);
        assert_eq!(rules.skip_reason("tokio", UpdateKind::Patch), None);
    }

    /// FR-006 fail-closed clause: a scoped rule still skips an `Unknown`-classified update,
    /// even though `unknown` is not itself a listed token.
    #[test]
    fn test_scoped_rule_fail_closed_on_unknown_kind() {
        let rules = IgnoreRules::new(
            vec![IgnoreRule {
                name: "tokio".to_string(),
                update_types: Some(vec![UpdateTypeToken::Major]),
            }],
            &STUB_FORMATTER,
        );
        assert_eq!(
            rules.skip_reason("tokio", UpdateKind::Unknown),
            Some(SkipReason::IgnoreRule)
        );
    }

    #[test]
    fn test_non_matching_name_is_never_skipped() {
        let rules = IgnoreRules::new(
            vec![IgnoreRule {
                name: "tokio".to_string(),
                update_types: None,
            }],
            &STUB_FORMATTER,
        );
        assert_eq!(rules.skip_reason("serde", UpdateKind::Major), None);
    }
}
