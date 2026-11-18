//! Regeneration for Dart and Flutter `pubspec.lock` (#2083).

use deps_core::parser::DependencySource;

use super::command::NonEmpty;
use super::command::dart::{PubPackageArg, PubTool};
use super::lockers::Located;
use super::{
    Invocation, LockfileOutcome, NotApplicableReason, PinCheck, RegenerationError, Session,
    UnsupportedReason, unsupported,
};

impl Session<'_> {
    pub(super) async fn dart(&self) -> Result<LockfileOutcome, RegenerationError> {
        let located = match self.lockfile_beside_manifest().await? {
            Located::Beside(path) => path,
            Located::Stop(outcome) => return Ok(outcome),
        };
        let reparse_failed = || RegenerationError::ManifestReparseFailed {
            path: self.target.display_path.to_path_buf(),
        };
        let text = deps_core::fs_probe::read_to_string_capped_no_follow(
            self.target.manifest_path,
            crate::MAX_MANIFEST_FILE_SIZE,
        )
        .ok()
        .flatten()
        .ok_or_else(reparse_failed)?;
        if declares_workspace_resolution(&text) {
            return Ok(unsupported(
                Some(self.display_lock_path(&located)),
                UnsupportedReason::WorkspaceMemberLockfile,
            ));
        }
        if let Some(outcome) = self.cooldown_refusal(&located) {
            return Ok(outcome);
        }
        if let Some(outcome) = self.placement_refusal(&located) {
            return Ok(outcome);
        }

        let names = self.lockfile_only_args(PubPackageArg::parse)?;
        if self.pins.is_empty() {
            return Ok(LockfileOutcome::NotApplicable(
                NotApplicableReason::NothingApplied,
            ));
        }
        let parsed =
            deps_core::ecosystem::parse_manifest_now(self.target.ecosystem, &text, self.target.uri)
                .ok_or_else(reparse_failed)?;
        let tool = if parsed.dependencies().iter().any(
            |dependency| matches!(dependency.source(), DependencySource::Sdk { sdk } if sdk == "flutter"),
        ) {
            PubTool::Flutter
        } else {
            PubTool::Dart
        };

        self.capture(&[&located])?;
        if self.pins.iter().any(|pin| !pin.is_lockfile_only()) {
            self.runner
                .run(&Invocation::pub_get(self.manifest_dir, tool), self.deadline)
                .await?;
        }
        if let Some(names) = NonEmpty::new(names) {
            self.runner
                .run(
                    &Invocation::pub_upgrade(self.manifest_dir, tool, &names),
                    self.deadline,
                )
                .await?;
        }
        self.verified(tool.program(), &located, PinCheck::SatisfiesInLock)
            .await
    }
}

/// Whether a `pubspec.yaml` has a top-level `resolution` key. Pub requires
/// `resolution: workspace` in a workspace member and resolves the whole workspace from the
/// root, so a member's own stray `pubspec.lock` is not the file `pub` would write. Text that
/// does not parse as a YAML mapping counts as declaring it.
fn declares_workspace_resolution(text: &str) -> bool {
    use deps_core::yaml_rust2::{Yaml, YamlLoader};

    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    if deps_core::check_yaml_bounds(text, "pubspec.yaml").is_err() {
        return true;
    }
    match YamlLoader::load_from_str(text).as_deref() {
        Ok([]) => false,
        Ok([Yaml::Hash(root), ..]) => root.contains_key(&Yaml::String("resolution".to_owned())),
        Ok(_) | Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_level_resolution_key_marks_a_workspace_member() {
        for text in [
            "name: a\nresolution: workspace\n",
            "name: a\n\"resolution\": workspace\n",
            "name: a\n'resolution': workspace\n",
            "name: a\nresolution : workspace\n",
            "name: a\nresolution:   workspace   # member\n",
            "\u{feff}name: a\nresolution: workspace\n",
            "resolution: workspace\r\nname: a\r\n",
            "{name: a, resolution: workspace}\n",
            "---\nname: a\nresolution: workspace\n",
            "name: a\nresolution: [\n",
        ] {
            assert!(declares_workspace_resolution(text), "{text:?}");
        }
    }

    #[test]
    fn other_pubspecs_are_not_workspace_members() {
        for text in [
            "name: a\ndependencies:\n  resolution: ^1.0.0\n",
            "name: a\n# resolution: workspace\n",
            "name: a\ndescription: \"resolution: workspace\"\n",
            "name: a\n",
            "",
        ] {
            assert!(!declares_workspace_resolution(text), "{text:?}");
        }
    }
}
