//! `--group` selection (#1118): which planned updates belong to the selected
//! `[update.groups.<name>]` rule, and the post-plan pass that demotes the rest.

use deps_core::edit::UpdateKind;
use deps_core::lsp_helpers::{EcosystemFormatter, NormalizeName};
use deps_core::{DependencyKind, NormalizedName, PackageName};

use super::{Outcome, PlannedUpdateItem, SkipReason};
use crate::config::{DependencyTypeToken, GroupName, GroupRule, UpdateTypeToken};

/// A group rule with its dependency names normalized once for the ecosystem at hand.
#[derive(Debug, Clone)]
pub struct UpdateGroup {
    name: GroupName,
    dependencies: Option<Vec<NormalizedName>>,
    patterns: Option<Vec<NormalizedName>>,
    update_types: Option<Vec<UpdateTypeToken>>,
    dependency_type: Option<DependencyTypeToken>,
}

impl DependencyTypeToken {
    /// Whether a dependency of role `kind` is inside a group with this `dependency_type`.
    const fn admits(self, kind: DependencyKind) -> bool {
        match self {
            Self::Production => !matches!(kind, DependencyKind::Development),
            Self::Development => matches!(kind, DependencyKind::Development),
            Self::Build => matches!(kind, DependencyKind::Build),
            Self::Peer => matches!(kind, DependencyKind::Peer),
            Self::Optional => matches!(kind, DependencyKind::Optional),
        }
    }
}

impl UpdateGroup {
    /// Builds the group from its config rule, normalizing names with `formatter`.
    #[must_use]
    pub fn new(name: GroupName, rule: GroupRule, formatter: &dyn EcosystemFormatter) -> Self {
        Self {
            name,
            dependencies: rule.dependencies.map(|names| {
                names
                    .into_iter()
                    .map(|name| formatter.normalize_package_name(&PackageName::new(name)))
                    .collect()
            }),
            patterns: rule.patterns.map(|patterns| {
                patterns
                    .iter()
                    .map(|pattern| {
                        formatter.normalize_package_name(&PackageName::new(pattern.as_str()))
                    })
                    .collect()
            }),
            update_types: rule.update_types,
            dependency_type: rule.dependency_type,
        }
    }

    /// The group's name.
    #[must_use]
    pub const fn name(&self) -> &GroupName {
        &self.name
    }

    /// Whether an update of `name` of the given `kind` and role `dependency` is inside the group.
    ///
    /// A name selector (`dependencies` and/or `patterns`) admits a name listed in either; a group
    /// without one admits every name. `update_types` and `dependency_type` must each admit the
    /// update when present. An unclassifiable `kind` ([`UpdateKind::Unknown`]) matches no
    /// `update_types` token, and an unknown `dependency` (`None`) matches no `dependency_type`;
    /// both are inside only a group without the respective field.
    #[must_use]
    pub fn contains(
        &self,
        name: &NormalizedName,
        kind: UpdateKind,
        dependency: Option<DependencyKind>,
    ) -> bool {
        self.admits_name(name)
            && self
                .update_types
                .as_ref()
                .is_none_or(|tokens| tokens.iter().any(|token| token.matches(kind)))
            && self
                .dependency_type
                .is_none_or(|token| dependency.is_some_and(|dependency| token.admits(dependency)))
    }

    fn admits_name(&self, name: &NormalizedName) -> bool {
        if self.dependencies.is_none() && self.patterns.is_none() {
            return true;
        }
        self.dependencies
            .as_ref()
            .is_some_and(|names| names.contains(name))
            || self.patterns.as_ref().is_some_and(|patterns| {
                patterns
                    .iter()
                    .any(|pattern| deps_core::star_glob::matches(pattern.as_str(), name.as_str()))
            })
    }
}

/// Demotes every `Applied` item outside `group` to `Skipped { reason: NotInGroup }`.
///
/// Other outcomes are left alone: only an `Applied` edit would be written, and an item that
/// already is skipped or needs a lock file change keeps its own, more specific, explanation.
pub fn demote_outside_group(
    items: &mut [PlannedUpdateItem],
    group: &UpdateGroup,
    formatter: &dyn EcosystemFormatter,
) {
    for item in items {
        let Outcome::Applied { target, .. } = &item.outcome else {
            continue;
        };
        let normalized = formatter.normalize_package_name(&PackageName::new(item.name.as_str()));
        if group.contains(
            &normalized,
            item.current.update_kind_to(target),
            item.dependency_kind,
        ) {
            continue;
        }
        item.outcome = Outcome::Skipped {
            reason: SkipReason::NotInGroup,
            target: Some(target.clone()),
        };
    }
}
