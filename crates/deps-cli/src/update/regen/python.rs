//! Regeneration for the Python lockers (uv today).

use serde::Deserialize;

use super::command::NonEmpty;
use super::lockers::{Located, file_declares};
use super::{
    Invocation, LockfileOutcome, LockfileSupport, NotApplicableReason, PinCheck, Program,
    PythonLocker, RegenerationError, Session, UnsupportedReason, arg_pair, unsupported,
};

pub(super) const SUPPORT: LockfileSupport = LockfileSupport::Regenerates;
pub(super) const TOOLS: &[&str] = &["uv"];

impl Session<'_> {
    pub(super) async fn pypi(&self) -> Result<LockfileOutcome, RegenerationError> {
        let located = match self.lockfile_beside_manifest().await? {
            Located::Beside(path) => path,
            Located::Stop(outcome) => return Ok(outcome),
        };
        let display = self.display_lock_path(&located);
        let locker = located
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .and_then(PythonLocker::from_lockfile_name);
        match locker {
            Some(PythonLocker::Uv) => {}
            Some(deferred @ (PythonLocker::Poetry | PythonLocker::Pdm | PythonLocker::Pipenv)) => {
                return Ok(unsupported(
                    Some(display),
                    UnsupportedReason::PythonLockerDeferred(deferred),
                ));
            }
            None => {
                return Err(RegenerationError::UnrecognizedLockfile {
                    path: display.shown,
                });
            }
        }
        if self.target.manifest_path.file_name() != Some(std::ffi::OsStr::new("pyproject.toml")) {
            return Ok(unsupported(
                Some(display),
                UnsupportedReason::LockfileOwnershipMismatch,
            ));
        }
        if self.ancestor_declares(|dir| file_declares(dir, "pyproject.toml", declares_uv_workspace))
        {
            return Ok(unsupported(
                Some(display),
                UnsupportedReason::WorkspaceMemberLockfile,
            ));
        }
        if let Some(outcome) = self.placement_refusal(&located) {
            return Ok(outcome);
        }

        let pins = self
            .pins
            .iter()
            .map(arg_pair)
            .collect::<Result<Vec<_>, _>>()?;
        let Some(pins) = NonEmpty::new(pins) else {
            return Ok(LockfileOutcome::NotApplicable(
                NotApplicableReason::NothingApplied,
            ));
        };

        self.capture(&[&located])?;
        self.runner
            .run(
                &Invocation::uv_lock(self.manifest_dir, &pins),
                self.deadline,
            )
            .await?;
        self.verified(Program::Uv, &located, PinCheck::ExactInLock)
            .await
    }
}

#[derive(Deserialize)]
struct PyProject {
    tool: Option<PyProjectTool>,
}

#[derive(Deserialize)]
struct PyProjectTool {
    uv: Option<PyProjectUv>,
}

#[derive(Deserialize)]
struct PyProjectUv {
    workspace: Option<serde::de::IgnoredAny>,
}

/// Whether a `pyproject.toml` declares `[tool.uv.workspace]`; unparsable text counts as yes.
fn declares_uv_workspace(text: &str) -> bool {
    deps_core::parser::deserialize_toml_checked::<PyProject>(text).map_or(true, |project| {
        project
            .tool
            .and_then(|tool| tool.uv)
            .is_some_and(|uv| uv.workspace.is_some())
    })
}
