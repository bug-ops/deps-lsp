//! Regeneration for Gradle; not implemented yet.

use deps_core::EcosystemId;

use super::{
    LockfileOutcome, LockfileSupport, RegenerationError, Session, UnsupportedReason, unsupported,
};

pub(super) const SUPPORT: LockfileSupport = LockfileSupport::Deferred;
pub(super) const TOOLS: &[&str] = &[];

impl Session<'_> {
    pub(super) fn gradle(&self, id: EcosystemId) -> Result<LockfileOutcome, RegenerationError> {
        Ok(unsupported(None, UnsupportedReason::EcosystemDeferred(id)))
    }
}
