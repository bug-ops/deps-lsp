//! `--group` selection (#1118): which planned updates belong to the selected
//! `[update.groups.<name>]` rule, and the post-plan pass that demotes the rest.

use deps_core::edit::UpdateKind;
use deps_core::lsp_helpers::{EcosystemFormatter, NormalizeName};
use deps_core::{NormalizedName, PackageName};

use super::{Outcome, PlannedUpdateItem, SkipReason};
use crate::config::{GroupName, GroupRule, UpdateTypeToken};

/// A group rule with its dependency names normalized once for the ecosystem at hand.
#[derive(Debug, Clone)]
pub struct UpdateGroup {
    name: GroupName,
    dependencies: Option<Vec<NormalizedName>>,
    update_types: Option<Vec<UpdateTypeToken>>,
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
            update_types: rule.update_types,
        }
    }

    /// The group's name.
    #[must_use]
    pub const fn name(&self) -> &GroupName {
        &self.name
    }

    /// Whether an update of `name` of the given `kind` is inside the group.
    ///
    /// Both lists must admit the update when present; an absent list admits everything. An
    /// unclassifiable `kind` ([`UpdateKind::Unknown`]) matches no `update_types` token, so it is
    /// inside only a group without `update_types`.
    #[must_use]
    pub fn contains(&self, name: &NormalizedName, kind: UpdateKind) -> bool {
        self.dependencies
            .as_ref()
            .is_none_or(|names| names.contains(name))
            && self
                .update_types
                .as_ref()
                .is_none_or(|tokens| tokens.iter().any(|token| token.matches(kind)))
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
        if group.contains(&normalized, item.current.update_kind_to(target)) {
            continue;
        }
        item.outcome = Outcome::Skipped {
            reason: SkipReason::NotInGroup,
            target: Some(target.clone()),
        };
    }
}
