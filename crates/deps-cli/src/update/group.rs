//! `--group` selection (#1118): which planned updates belong to the selected
//! `[update.groups.<name>]` rule, and the post-plan pass that demotes the rest.

use deps_core::NormalizedName;
use deps_core::edit::UpdateKind;
use deps_core::lsp_helpers::EcosystemFormatter;

use super::PlannedUpdateItem;
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
    pub fn new(_name: GroupName, _rule: GroupRule, _formatter: &dyn EcosystemFormatter) -> Self {
        todo!()
    }

    /// The group's name.
    #[must_use]
    pub const fn name(&self) -> &GroupName {
        &self.name
    }

    /// Whether an update of `name` of the given `kind` is inside the group.
    #[must_use]
    pub fn contains(&self, _name: &NormalizedName, _kind: UpdateKind) -> bool {
        let _ = (&self.dependencies, &self.update_types);
        todo!()
    }
}

/// Demotes every `Applied` item outside `group` to `Skipped { reason: NotInGroup }`.
pub fn demote_outside_group(
    _items: &mut [PlannedUpdateItem],
    _group: &UpdateGroup,
    _formatter: &dyn EcosystemFormatter,
) {
    todo!()
}
