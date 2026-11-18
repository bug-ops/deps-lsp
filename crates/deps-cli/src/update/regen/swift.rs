//! Regeneration for SwiftPM `Package.resolved` (#2086).

use super::command::NonEmpty;
use super::command::swift::SwiftIdentityArg;
use super::lockers::Located;
use super::{Invocation, LockfileOutcome, PinCheck, Program, RegenerationError, Session};

impl Session<'_> {
    /// `swift package resolve` after a manifest edit, then `swift package update <identities>`
    /// for lock-only pins.
    ///
    /// Refuses a cooldown-fallback target: `resolve` picks the newest version the edited
    /// requirement admits, which is the release the cooldown excluded.
    pub(super) async fn swift(&self) -> Result<LockfileOutcome, RegenerationError> {
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

        let lockfile_only = self.lockfile_only_args(SwiftIdentityArg::parse)?;

        self.capture(&[&located])?;
        if self.pins.iter().any(|pin| !pin.is_lockfile_only()) {
            self.runner
                .run(
                    &Invocation::swift_package_resolve(self.manifest_dir),
                    self.deadline,
                )
                .await?;
        }
        if let Some(identities) = NonEmpty::new(lockfile_only) {
            self.runner
                .run(
                    &Invocation::swift_package_update(self.manifest_dir, &identities),
                    self.deadline,
                )
                .await?;
        }
        self.verified(Program::Swift, &located, PinCheck::SatisfiesInLock)
            .await
    }
}
