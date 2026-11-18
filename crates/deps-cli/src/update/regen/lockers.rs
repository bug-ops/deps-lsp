//! Regeneration for the uv, Bundler and Deno lockers (#2046).

use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::command::lockers::{DenoFilter, NonEmpty};
use super::{
    ArgComponent, Invocation, LockfileOutcome, NotApplicableReason, NpmClient, PinCheck, Program,
    PythonLocker, RegenerationError, Session, UnsupportedReason, arg_pair, declares_workspace,
    same_file, unsupported,
};

/// The lock file beside the manifest, or the outcome that ends the run before any spawn.
enum Located {
    Beside(PathBuf),
    Stop(LockfileOutcome),
}

impl Session<'_> {
    /// The ecosystem provider's lock file when it sits in the manifest's own directory; a lock
    /// file in an ancestor means the manifest is a member of a workspace the tool would lock
    /// from its root.
    async fn lockfile_beside_manifest(&self) -> Result<Located, RegenerationError> {
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
    fn ancestor_declares(&self, declares: impl Fn(&Path) -> bool) -> bool {
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
            None => return Err(RegenerationError::UnrecognizedLockfile { path: display.0 }),
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
        if let Some(outcome) = self.symlink_refusal(&located) {
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

    pub(super) async fn bundler(&self) -> Result<LockfileOutcome, RegenerationError> {
        let located = match self.lockfile_beside_manifest().await? {
            Located::Beside(path) => path,
            Located::Stop(outcome) => return Ok(outcome),
        };
        if let Some(outcome) = self.cooldown_refusal(&located) {
            return Ok(outcome);
        }
        if let Some(outcome) = self.symlink_refusal(&located) {
            return Ok(outcome);
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
        if let Some(outcome) = self.cooldown_refusal(&located) {
            return Ok(outcome);
        }
        if let Some(outcome) = self.symlink_refusal(&located) {
            return Ok(outcome);
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
fn file_declares(dir: &Path, name: &str, declares: impl Fn(&str) -> bool) -> bool {
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

#[derive(Deserialize)]
struct DenoJson {
    workspace: Option<serde::de::IgnoredAny>,
}

/// Whether a `deno.json` has a top-level `workspace`; unparsable text counts as yes.
fn declares_deno_workspace(text: &str) -> bool {
    serde_json::from_str::<DenoJson>(text).map_or(true, |config| config.workspace.is_some())
}
