//! Regeneration for Go modules.

use super::command::GoWork;
use super::{
    Invocation, LockfileOutcome, NotApplicableReason, PinCheck, Program, RegenerationError,
    Session, UnsupportedReason, arg_pair, unsupported,
};

impl Session<'_> {
    pub(super) async fn go(&self) -> Result<LockfileOutcome, RegenerationError> {
        if self.manifest_dir.join("vendor/modules.txt").is_file() {
            return Ok(unsupported(None, UnsupportedReason::GoVendored));
        }
        let workspace = self
            .runner
            .probe(&Invocation::go_env_gowork(self.manifest_dir), self.deadline)
            .await?;
        let work = if workspace.is_empty() || workspace == "off" {
            GoWork::Inherit
        } else {
            GoWork::Off
        };
        let owned = self.manifest_dir.join("go.sum");
        if !owned.is_file() {
            return Ok(LockfileOutcome::NotApplicable(
                NotApplicableReason::NoLockfilePresent,
            ));
        }
        if let Some(outcome) = self.ownership_refusal(&owned).await? {
            return Ok(outcome);
        }

        let modules = self
            .pins
            .iter()
            .map(arg_pair)
            .collect::<Result<Vec<_>, _>>()?;
        self.capture(&[&self.manifest_dir.join("go.mod"), &owned])?;
        self.runner
            .run(
                &Invocation::go_get(self.manifest_dir, &modules, work),
                self.deadline,
            )
            .await?;
        self.verified(Program::Go, &owned, PinCheck::ExactInLock)
            .await
    }
}
