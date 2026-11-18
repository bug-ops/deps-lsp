//! Regeneration for the Bundler and Deno lockers (#2046).

use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::command::NonEmpty;
use super::command::lockers::DenoFilter;
use super::fallback::{DescriptorLock, ExactPinRun, Relax};
use super::{
    ArgComponent, Invocation, LockfileOutcome, NotApplicableReason, NpmClient, PinCheck, Program,
    RegenerationError, Session, UnsupportedReason, declares_workspace, same_file, unsupported,
};

/// The lock file beside the manifest, or the outcome that ends the run before any spawn.
pub(super) enum Located {
    Beside(PathBuf),
    Stop(LockfileOutcome),
}

impl Session<'_> {
    /// The ecosystem provider's lock file when it sits in the manifest's own directory; a lock
    /// file in an ancestor means the manifest is a member of a workspace the tool would lock
    /// from its root.
    pub(super) async fn lockfile_beside_manifest(&self) -> Result<Located, RegenerationError> {
        let Some(located) = self.locate().await? else {
            return Ok(Located::Stop(LockfileOutcome::NotApplicable(
                NotApplicableReason::NoLockfilePresent,
            )));
        };
        if same_file(located.parent(), Some(self.manifest_dir)) {
            Ok(Located::Beside(located))
        } else {
            Ok(Located::Stop(unsupported(
                Some(self.display_lock_path(&located)),
                UnsupportedReason::WorkspaceMemberLockfile,
            )))
        }
    }

    /// Whether any strict ancestor directory satisfies `declares`.
    ///
    /// Fails closed: a manifest directory that cannot be canonicalized, or an ancestor chain
    /// longer than the config-walk depth cap, counts as declaring.
    pub(super) fn ancestor_declares(&self, declares: impl Fn(&Path) -> bool) -> bool {
        let Ok(physical) = std::fs::canonicalize(self.manifest_dir) else {
            return true;
        };
        let ancestors: Vec<&Path> = deps_core::fs_probe::config_ancestors(&physical)
            .skip(1)
            .collect();
        let depth_exhausted = ancestors.len() + 1 == deps_core::fs_probe::MAX_CONFIG_ANCESTOR_DEPTH
            && ancestors.last().is_some_and(|dir| dir.parent().is_some());
        depth_exhausted || ancestors.into_iter().any(declares)
    }

    pub(super) async fn bundler(&self) -> Result<LockfileOutcome, RegenerationError> {
        let located = match self.lockfile_beside_manifest().await? {
            Located::Beside(path) => path,
            Located::Stop(outcome) => return Ok(outcome),
        };
        if let Some(outcome) = self.placement_refusal(&located) {
            return Ok(outcome);
        }

        if self.has_fallback_pins() {
            let names = NonEmpty::new(self.update_only_args(ArgComponent::parse)?);
            let install = Invocation::bundle_lock(self.manifest_dir);
            let update = names
                .as_ref()
                .map(|names| Invocation::bundle_lock_update(self.manifest_dir, names));
            return self
                .run_with_exact_pins(ExactPinRun {
                    tool: Program::Bundle,
                    lockfile: &located,
                    manifest: self.target.manifest_path,
                    install: &install,
                    update: update.as_ref(),
                    relax: Relax::Reinstall,
                    siblings: &[],
                })
                .await;
        }
        let lockfile_only = self.lockfile_only_args(ArgComponent::parse)?;

        self.capture(&[&located])?;
        if self.pins.iter().any(|pin| !pin.is_lockfile_only()) {
            self.runner
                .run(&Invocation::bundle_lock(self.manifest_dir), self.deadline)
                .await?;
        }
        if let Some(names) = NonEmpty::new(lockfile_only) {
            self.runner
                .run(
                    &Invocation::bundle_lock_update(self.manifest_dir, &names),
                    self.deadline,
                )
                .await?;
        }
        self.verified(Program::Bundle, &located, PinCheck::SatisfiesInLock)
            .await
    }

    pub(super) async fn deno(&self) -> Result<LockfileOutcome, RegenerationError> {
        let located = match self.lockfile_beside_manifest().await? {
            Located::Beside(path) => path,
            Located::Stop(outcome) => return Ok(outcome),
        };
        let display = self.display_lock_path(&located);
        if self.ancestor_declares(|dir| {
            file_declares(dir, "deno.json", declares_deno_workspace)
                || dir.join("deno.jsonc").try_exists().unwrap_or(true)
                || declares_workspace(dir, NpmClient::Npm)
        }) {
            return Ok(unsupported(
                Some(display),
                UnsupportedReason::WorkspaceMemberLockfile,
            ));
        }
        if let Some(outcome) = self.placement_refusal(&located) {
            return Ok(outcome);
        }

        if self.has_fallback_pins() {
            let filters = NonEmpty::new(self.update_only_args(DenoFilter::parse)?);
            let install = Invocation::deno_install_lockfile_only(self.manifest_dir);
            let update = filters
                .as_ref()
                .map(|filters| Invocation::deno_update_lockfile_only(self.manifest_dir, filters));
            return self
                .run_with_exact_pins(ExactPinRun {
                    tool: Program::Deno,
                    lockfile: &located,
                    manifest: self.target.manifest_path,
                    install: &install,
                    update: update.as_ref(),
                    relax: Relax::Rekey(DescriptorLock::Deno),
                    siblings: &[],
                })
                .await;
        }
        let lockfile_only = self.lockfile_only_args(DenoFilter::parse)?;

        self.capture(&[&located])?;
        if self.pins.iter().any(|pin| !pin.is_lockfile_only()) {
            self.runner
                .run(
                    &Invocation::deno_install_lockfile_only(self.manifest_dir),
                    self.deadline,
                )
                .await?;
        }
        if let Some(filters) = NonEmpty::new(lockfile_only) {
            self.runner
                .run(
                    &Invocation::deno_update_lockfile_only(self.manifest_dir, &filters),
                    self.deadline,
                )
                .await?;
        }
        self.verified(Program::Deno, &located, PinCheck::SatisfiesInLock)
            .await
    }
}

/// Whether `dir/name` makes `declares` true; an unreadable, oversized or symlinked file counts
/// as declaring, a missing one does not.
pub(super) fn file_declares(dir: &Path, name: &str, declares: impl Fn(&str) -> bool) -> bool {
    match deps_core::fs_probe::read_to_string_capped_no_follow(
        &dir.join(name),
        crate::MAX_MANIFEST_FILE_SIZE,
    ) {
        Ok(Some(text)) => declares(&text),
        Ok(None) => true,
        Err(error) => error.kind() != std::io::ErrorKind::NotFound,
    }
}

#[derive(Deserialize)]
struct DenoJson {
    workspace: Option<serde::de::IgnoredAny>,
}

/// Whether a `deno.json` has a top-level `workspace`; unparsable text counts as yes.
fn declares_deno_workspace(text: &str) -> bool {
    serde_json::from_str::<DenoJson>(text).map_or(true, |config| config.workspace.is_some())
}
