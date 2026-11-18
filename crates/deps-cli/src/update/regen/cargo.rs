//! Regeneration for Cargo workspaces.

use std::path::Path;

use super::command::compat_class;
use super::{
    Invocation, LockfileOutcome, NotApplicableReason, PinCheck, Program, RegenerationError,
    Session, arg_pair, unsafe_argument,
};

impl Session<'_> {
    pub(super) async fn cargo(&self) -> Result<LockfileOutcome, RegenerationError> {
        let manifest = self.target.manifest_path;
        let probe = Invocation::cargo_locate_workspace(self.manifest_dir, manifest);
        let root_manifest = self.runner.probe(&probe, self.deadline).await?;
        let root_dir = (!root_manifest.is_empty())
            .then(|| self.manifest_dir.join(&root_manifest))
            .and_then(|path| path.parent().map(Path::to_path_buf))
            .ok_or(RegenerationError::UnexpectedProbeOutput {
                program: Program::Cargo,
            })?;
        let owned = root_dir.join("Cargo.lock");
        if !owned.is_file() {
            return Ok(LockfileOutcome::NotApplicable(
                NotApplicableReason::NoLockfilePresent,
            ));
        }
        if let Some(outcome) = self.ownership_refusal(&owned).await? {
            return Ok(outcome);
        }

        let mut updates = Vec::with_capacity(self.pins.len());
        for pin in self.pins {
            let class = compat_class(pin.compat_basis()).ok_or_else(|| unsafe_argument(pin))?;
            let (name, version) = arg_pair(pin)?;
            updates.push(Invocation::cargo_update_precise(
                self.manifest_dir,
                manifest,
                &name,
                &class,
                &version,
            ));
        }

        self.capture(&[&owned])?;
        if self.pins.iter().any(|pin| !pin.is_lockfile_only()) {
            self.runner
                .run(
                    &Invocation::cargo_update_workspace(self.manifest_dir, manifest),
                    self.deadline,
                )
                .await?;
        }
        for (pin, update) in self.pins.iter().zip(&updates) {
            match self.runner.run(update, self.deadline).await {
                Err(RegenerationError::ToolFailed { code, .. }) if pin.cooldown_fallback => {
                    return Err(RegenerationError::FallbackPinRejected {
                        package: pin.package.clone(),
                        target: pin.target.clone(),
                        code,
                    });
                }
                other => other?,
            }
        }
        self.verified(Program::Cargo, &owned, PinCheck::ExactInLock)
            .await
    }
}
