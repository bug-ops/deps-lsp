//! Regeneration for the Python lockers: uv, Poetry, PDM and Pipenv.

use std::path::Path;

use serde::Deserialize;

use super::command::NonEmpty;
use super::command::python::PoetryLockStyle;
use super::lockers::{Located, file_declares};
use super::{
    ArgComponent, Invocation, LockfileOutcome, NotApplicableReason, PinCheck, Program,
    PythonLocker, RegenerationError, Session, UnsupportedReason, arg_pair, unsafe_argument,
    unsupported,
};

impl Session<'_> {
    pub(super) async fn pypi(&self) -> Result<LockfileOutcome, RegenerationError> {
        let located = match self.lockfile_beside_manifest().await? {
            Located::Beside(path) => path,
            Located::Stop(outcome) => return Ok(outcome),
        };
        let locker = located
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .and_then(PythonLocker::from_lockfile_name);
        match locker {
            Some(PythonLocker::Uv) => self.uv(&located).await,
            Some(PythonLocker::Poetry) => self.poetry(&located).await,
            Some(PythonLocker::Pdm) => self.pdm(&located).await,
            Some(PythonLocker::Pipenv) => self.pipenv(&located).await,
            None => Err(RegenerationError::UnrecognizedLockfile {
                path: self.display_lock_path(&located).shown,
            }),
        }
    }

    /// `Some(Unsupported)` unless the manifest is the file named `expected`, the one the locker
    /// reads.
    fn manifest_name_refusal(&self, located: &Path, expected: &str) -> Option<LockfileOutcome> {
        (self.target.manifest_path.file_name() != Some(std::ffi::OsStr::new(expected))).then(|| {
            unsupported(
                Some(self.display_lock_path(located)),
                UnsupportedReason::LockfileOwnershipMismatch,
            )
        })
    }

    fn pyproject_refusal(&self, located: &Path) -> Option<LockfileOutcome> {
        self.manifest_name_refusal(located, "pyproject.toml")
    }

    /// The refusals Poetry and PDM share; each runs before any spawn.
    fn pyproject_locker_refusal(&self, located: &Path) -> Option<LockfileOutcome> {
        self.pyproject_refusal(located)
            .or_else(|| self.cooldown_refusal(located))
            .or_else(|| self.placement_refusal(located))
    }

    async fn uv(&self, located: &Path) -> Result<LockfileOutcome, RegenerationError> {
        if let Some(outcome) = self.pyproject_refusal(located) {
            return Ok(outcome);
        }
        if self.ancestor_declares(|dir| file_declares(dir, "pyproject.toml", declares_uv_workspace))
        {
            return Ok(unsupported(
                Some(self.display_lock_path(located)),
                UnsupportedReason::WorkspaceMemberLockfile,
            ));
        }
        if let Some(outcome) = self.placement_refusal(located) {
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

        self.capture(&[located])?;
        self.runner
            .run(
                &Invocation::uv_lock(self.manifest_dir, &pins),
                self.deadline,
            )
            .await?;
        self.verified(Program::Uv, located, PinCheck::ExactInLock)
            .await
    }

    async fn poetry(&self, located: &Path) -> Result<LockfileOutcome, RegenerationError> {
        if let Some(outcome) = self.pyproject_locker_refusal(located) {
            return Ok(outcome);
        }
        let names = self.lockfile_only_args(ArgComponent::parse)?;
        if self.pins.is_empty() {
            return Ok(LockfileOutcome::NotApplicable(
                NotApplicableReason::NothingApplied,
            ));
        }

        // Poetry before 1.2 rejects `--no-plugins`, so a failing probe means "too old". No
        // plugin-loading fallback probe is run: plugins are repository-controlled code.
        let printed = match self
            .runner
            .probe(
                &Invocation::poetry_version(self.manifest_dir),
                self.deadline,
            )
            .await
        {
            Ok(printed) => printed,
            Err(RegenerationError::ToolFailed {
                program: Program::Poetry,
                ..
            }) => {
                return Ok(unsupported(
                    Some(self.display_lock_path(located)),
                    UnsupportedReason::ToolTooOld(Program::Poetry),
                ));
            }
            Err(error) => return Err(error),
        };
        let style = match PoetryEra::from_version_output(&printed) {
            Some(PoetryEra::TooOld) => {
                return Ok(unsupported(
                    Some(self.display_lock_path(located)),
                    UnsupportedReason::ToolTooOld(Program::Poetry),
                ));
            }
            Some(PoetryEra::One) => PoetryLockStyle::NoUpdateFlag,
            Some(PoetryEra::TwoOrNewer) => PoetryLockStyle::KeepsLocked,
            None => {
                return Err(RegenerationError::UnexpectedProbeOutput {
                    program: Program::Poetry,
                });
            }
        };

        let update = NonEmpty::new(names)
            .map(|names| Invocation::poetry_update_lock(self.manifest_dir, &names));
        self.run_locker(
            Program::Poetry,
            located,
            &Invocation::poetry_lock(self.manifest_dir, style),
            update,
        )
        .await
    }

    async fn pdm(&self, located: &Path) -> Result<LockfileOutcome, RegenerationError> {
        if let Some(outcome) = self.pyproject_locker_refusal(located) {
            return Ok(outcome);
        }
        let names = self.lockfile_only_args(ArgComponent::parse)?;
        if self.pins.is_empty() {
            return Ok(LockfileOutcome::NotApplicable(
                NotApplicableReason::NothingApplied,
            ));
        }

        let update = NonEmpty::new(names)
            .map(|names| Invocation::pdm_update_no_sync(self.manifest_dir, &names));
        self.run_locker(
            Program::Pdm,
            located,
            &Invocation::pdm_lock(self.manifest_dir),
            update,
        )
        .await
    }

    /// `Some(Unsupported)` when `<manifest dir>/.venv` is a file or symlink: Pipenv reads it
    /// as the path of a virtualenv whose `python` it then runs, and `PIPENV_VENV_IN_PROJECT=0`
    /// does not stop that. A `.venv` directory is ignored under that variable.
    fn saved_virtualenv_refusal(&self, located: &Path) -> Option<LockfileOutcome> {
        let selects_interpreter = std::fs::symlink_metadata(self.manifest_dir.join(".venv"))
            .is_ok_and(|metadata| !metadata.file_type().is_dir());
        selects_interpreter.then(|| {
            unsupported(
                Some(self.display_lock_path(located)),
                UnsupportedReason::SavedVirtualenv,
            )
        })
    }

    /// Pipenv has no manifest-preserving lock command, so one `pipenv upgrade --lock-only` over
    /// every pinned package moves just those packages against the (possibly edited) `Pipfile`;
    /// the exact target is not requestable, so [`PinCheck::SatisfiesInLock`] proves each pin.
    async fn pipenv(&self, located: &Path) -> Result<LockfileOutcome, RegenerationError> {
        if let Some(outcome) = self
            .manifest_name_refusal(located, "Pipfile")
            .or_else(|| self.cooldown_refusal(located))
            .or_else(|| self.placement_refusal(located))
            .or_else(|| self.saved_virtualenv_refusal(located))
        {
            return Ok(outcome);
        }
        let names = self
            .pins
            .iter()
            .map(|pin| ArgComponent::parse(pin.package.as_str()).map_err(|_| unsafe_argument(pin)))
            .collect::<Result<Vec<_>, _>>()?;
        let Some(names) = NonEmpty::new(names) else {
            return Ok(LockfileOutcome::NotApplicable(
                NotApplicableReason::NothingApplied,
            ));
        };

        let manifest = self.target.manifest_path;
        self.capture(&[located, manifest])?;
        let original = self.read_manifest(manifest)?;
        self.runner
            .run(
                &Invocation::pipenv_upgrade_lock_only(self.manifest_dir, &names),
                self.deadline,
            )
            .await?;
        // A Pipfile the tool rewrote (older releases turn ranges into "*") fails the run as
        // `ManifestChanged`; the snapshot restore then puts the original bytes back.
        self.restore_formatting([&original])?;
        self.verified(Program::Pipenv, located, PinCheck::SatisfiesInLock)
            .await
    }

    /// Captures the lock file, runs `lock` when the manifest was edited and `update` when some
    /// pin is lock-only, then verifies every pin against the lock file.
    async fn run_locker(
        &self,
        tool: Program,
        located: &Path,
        lock: &Invocation,
        update: Option<Invocation>,
    ) -> Result<LockfileOutcome, RegenerationError> {
        self.capture(&[located])?;
        if self.pins.iter().any(|pin| !pin.is_lockfile_only()) {
            self.runner.run(lock, self.deadline).await?;
        }
        if let Some(update) = update {
            self.runner.run(&update, self.deadline).await?;
        }
        self.verified(tool, located, PinCheck::SatisfiesInLock)
            .await
    }
}

/// Which Poetry generation is installed, as far as the flags regeneration needs differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PoetryEra {
    /// Before 1.2, which lacks `--no-plugins`.
    TooOld,
    /// 1.2 up to 2.0: `poetry lock` re-resolves everything unless `--no-update` is given.
    One,
    /// 2.0 and later: `poetry lock` keeps locked versions.
    TwoOrNewer,
}

impl PoetryEra {
    /// Reads the first `major.minor` number out of `poetry --version` output
    /// (`Poetry (version 1.8.3)`); `None` when there is none.
    fn from_version_output(output: &str) -> Option<Self> {
        let token = output
            .split(|c: char| c.is_whitespace() || c == '(' || c == ')')
            .find(|token| token.starts_with(|c: char| c.is_ascii_digit()))?;
        let mut parts = token.split('.');
        let mut leading_number = || {
            let digits: String = parts
                .next()?
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            digits.parse::<u32>().ok()
        };
        let major = leading_number()?;
        let minor = leading_number()?;
        Some(match (major, minor) {
            (0, _) | (1, 0 | 1) => Self::TooOld,
            (1, _) => Self::One,
            _ => Self::TwoOrNewer,
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poetry_version_output_selects_the_flag_style() {
        for (output, era) in [
            ("Poetry (version 1.8.3)", Some(PoetryEra::One)),
            ("Poetry (version 1.2.0rc1)", Some(PoetryEra::One)),
            ("Poetry (version 1.1.15)", Some(PoetryEra::TooOld)),
            ("Poetry (version 1.0.10)", Some(PoetryEra::TooOld)),
            ("Poetry (version 2.0.0)", Some(PoetryEra::TwoOrNewer)),
            ("Poetry (version 2.1.3)", Some(PoetryEra::TwoOrNewer)),
            ("Poetry (version 10.0.1)", Some(PoetryEra::TwoOrNewer)),
            ("Poetry", None),
            ("", None),
            ("Poetry (version x.y)", None),
        ] {
            assert_eq!(PoetryEra::from_version_output(output), era, "{output}");
        }
    }
}
