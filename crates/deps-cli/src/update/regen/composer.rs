//! Regeneration for Composer (#2082).

use super::command::NonEmpty;
use super::command::composer::ComposerPackageArg;
use super::lockers::Located;
use super::{
    Invocation, LockfileOutcome, NotApplicableReason, PinCheck, Program, RegenerationError,
    Session, unsafe_argument,
};

impl Session<'_> {
    pub(super) async fn composer(&self) -> Result<LockfileOutcome, RegenerationError> {
        let located = match self.lockfile_beside_manifest().await? {
            Located::Beside(path) => path,
            Located::Stop(outcome) => return Ok(outcome),
        };
        if let Some(outcome) = self.cooldown_refusal(&located) {
            return Ok(outcome);
        }
        if let Some(outcome) = self.placement_refusal(&located) {
            return Ok(outcome);
        }

        let names = self
            .pins
            .iter()
            .map(|pin| {
                ComposerPackageArg::parse(pin.package.as_str()).map_err(|_| unsafe_argument(pin))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let Some(names) = NonEmpty::new(names) else {
            return Ok(LockfileOutcome::NotApplicable(
                NotApplicableReason::NothingApplied,
            ));
        };

        self.capture(&[&located])?;
        self.runner
            .run(
                &Invocation::composer_update(self.manifest_dir, &names),
                self.deadline,
            )
            .await?;
        self.verified(Program::Composer, &located, PinCheck::SatisfiesInLock)
            .await
    }
}
