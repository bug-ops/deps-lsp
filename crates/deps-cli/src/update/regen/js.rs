//! Regeneration for the JavaScript lockfile owners: npm, pnpm (workspace members included) and
//! Yarn 2+ (#2047).

use std::path::{Path, PathBuf};

use super::command::WorkspaceMember;
use super::{
    Invocation, LockfileOutcome, NotApplicableReason, NpmClient, NpmPackageArg, PinCheck, Program,
    RegenerationError, Session, UnsupportedReason, WorkspaceMembers, declares_workspace,
    inside_workspace, same_file, unsupported, workspace_dir_env_set,
};

/// Where a JavaScript tool has to run to update the located lockfile.
enum Layout {
    /// The lockfile sits beside the manifest; the tool runs there.
    Standalone,
    /// The manifest is a member of the workspace whose root owns the lockfile.
    Member {
        root: PathBuf,
        member: WorkspaceMember,
    },
    Refused(UnsupportedReason),
}

impl Session<'_> {
    pub(super) async fn npm_family(&self) -> Result<LockfileOutcome, RegenerationError> {
        let Some(located) = self.locate().await? else {
            return Ok(LockfileOutcome::NotApplicable(
                NotApplicableReason::NoLockfilePresent,
            ));
        };
        let display = self.display_lock_path(&located);
        let client = located
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .and_then(NpmClient::from_lockfile_name);
        match client {
            Some(client @ (NpmClient::Npm | NpmClient::Pnpm)) => {
                self.npm_or_pnpm(&located, client).await
            }
            Some(NpmClient::Yarn) => self.yarn(&located).await,
            Some(deferred @ NpmClient::Bun) => Ok(unsupported(
                Some(display),
                UnsupportedReason::NpmClientDeferred(deferred),
            )),
            None => Err(RegenerationError::UnrecognizedLockfile { path: display.0 }),
        }
    }

    async fn npm_or_pnpm(
        &self,
        located: &Path,
        client: NpmClient,
    ) -> Result<LockfileOutcome, RegenerationError> {
        let display = self.display_lock_path(located);
        let (root, member) = match self.layout(located, client).await? {
            Layout::Standalone => (self.manifest_dir.to_path_buf(), None),
            Layout::Member { root, member } => (root, Some(member)),
            Layout::Refused(reason) => return Ok(unsupported(Some(display), reason)),
        };
        if let Some(outcome) = self.cooldown_refusal(located) {
            return Ok(outcome);
        }
        if let Some(outcome) = self.symlink_refusal(located) {
            return Ok(outcome);
        }

        let names = self.lockfile_only_args(NpmPackageArg::parse)?;
        let (program, install, update): (_, _, fn(&Path, &[_], Option<&_>) -> Invocation) =
            match client {
                NpmClient::Pnpm => (
                    Program::Pnpm,
                    Invocation::pnpm_lock(&root),
                    Invocation::pnpm_update,
                ),
                NpmClient::Npm | NpmClient::Yarn | NpmClient::Bun => (
                    Program::Npm,
                    Invocation::npm_lock(&root),
                    Invocation::npm_update,
                ),
            };

        self.capture(&[located])?;
        if self.pins.iter().any(|pin| !pin.is_lockfile_only()) {
            self.runner.run(&install, self.deadline).await?;
        }
        if !names.is_empty() {
            self.runner
                .run(&update(&root, &names, member.as_ref()), self.deadline)
                .await?;
        }
        self.verified(program, located, PinCheck::SatisfiesInLock)
            .await
    }

    /// Decides where the tool must run, probing the tool for the workspace root only for a
    /// manifest below a lockfile whose directory declares a workspace.
    async fn layout(&self, located: &Path, client: NpmClient) -> Result<Layout, RegenerationError> {
        let lock_dir = located.parent();
        if same_file(lock_dir, Some(self.manifest_dir)) {
            return Ok(
                if inside_workspace(self.manifest_dir, client, |name| std::env::var_os(name)) {
                    Layout::Refused(UnsupportedReason::WorkspaceMemberLockfile)
                } else {
                    Layout::Standalone
                },
            );
        }
        let member_of_lock_dir = lock_dir.is_some_and(|dir| {
            self.members == WorkspaceMembers::Allowed
                && !workspace_dir_env_set(client, |name| std::env::var_os(name))
                && declares_workspace(dir, client)
                && std::fs::canonicalize(self.manifest_dir)
                    .ok()
                    .zip(std::fs::canonicalize(dir).ok())
                    .is_some_and(|(manifest, root)| manifest.starts_with(root))
        });
        let Some(lock_dir) = lock_dir.filter(|_| member_of_lock_dir) else {
            return Ok(Layout::Refused(UnsupportedReason::WorkspaceMemberLockfile));
        };

        let probe = match client {
            NpmClient::Pnpm => Invocation::pnpm_workspace_root(self.manifest_dir),
            NpmClient::Npm | NpmClient::Yarn | NpmClient::Bun => {
                Invocation::npm_prefix(self.manifest_dir)
            }
        };
        let program = probe.program();
        let printed = self.runner.probe(&probe, self.deadline).await?;
        let root = match client {
            NpmClient::Pnpm => Path::new(&printed).parent().map(Path::to_path_buf),
            NpmClient::Npm | NpmClient::Yarn | NpmClient::Bun => {
                (!printed.is_empty()).then(|| PathBuf::from(&printed))
            }
        }
        .ok_or(RegenerationError::UnexpectedProbeOutput { program })?;
        if !same_file(Some(root.as_path()), Some(lock_dir)) {
            return Ok(Layout::Refused(
                UnsupportedReason::LockfileOwnershipMismatch,
            ));
        }

        let relative = std::fs::canonicalize(self.manifest_dir)
            .ok()
            .zip(std::fs::canonicalize(lock_dir).ok())
            .and_then(|(manifest, root)| manifest.strip_prefix(root).map(Path::to_path_buf).ok());
        let Some(member) = relative.and_then(|relative| WorkspaceMember::parse(&relative).ok())
        else {
            return Ok(Layout::Refused(UnsupportedReason::WorkspaceMemberLockfile));
        };
        if client == NpmClient::Pnpm && !self.pnpm_lists_member(lock_dir, &member).await? {
            return Ok(Layout::Refused(UnsupportedReason::WorkspaceMemberLockfile));
        }
        Ok(Layout::Member {
            root: lock_dir.to_path_buf(),
            member,
        })
    }

    /// Whether pnpm's workspace has exactly one project at the member path.
    ///
    /// `pnpm root -w` answers for any directory below the root, and `pnpm update --filter`
    /// matching nothing exits 0 without touching the lockfile, so membership is proven here,
    /// before any writing spawn.
    async fn pnpm_lists_member(
        &self,
        root: &Path,
        member: &WorkspaceMember,
    ) -> Result<bool, RegenerationError> {
        #[derive(serde::Deserialize)]
        struct Project {
            path: PathBuf,
        }
        let probe = Invocation::pnpm_list_member(root, member);
        let printed = self.runner.probe(&probe, self.deadline).await?;
        let projects: Vec<Project> = serde_json::from_str(&printed).map_err(|_| {
            RegenerationError::UnexpectedProbeOutput {
                program: Program::Pnpm,
            }
        })?;
        Ok(matches!(
            projects.as_slice(),
            [only] if same_file(Some(only.path.as_path()), Some(self.manifest_dir))
        ))
    }

    /// Yarn 2+ (berry) beside its manifest; members and Yarn Classic are refused.
    async fn yarn(&self, located: &Path) -> Result<LockfileOutcome, RegenerationError> {
        let display = self.display_lock_path(located);
        if !same_file(located.parent(), Some(self.manifest_dir))
            || inside_workspace(self.manifest_dir, NpmClient::Yarn, |name| {
                std::env::var_os(name)
            })
        {
            return Ok(unsupported(
                Some(display),
                UnsupportedReason::WorkspaceMemberLockfile,
            ));
        }
        if let Some(outcome) = self.cooldown_refusal(located) {
            return Ok(outcome);
        }
        if let Some(outcome) = self.symlink_refusal(located) {
            return Ok(outcome);
        }
        let names = self.lockfile_only_args(NpmPackageArg::parse)?;

        let version = self
            .runner
            .probe(&Invocation::yarn_version(self.manifest_dir), self.deadline)
            .await?;
        let major = version
            .split('.')
            .next()
            .and_then(|major| major.parse::<u32>().ok())
            .ok_or(RegenerationError::UnexpectedProbeOutput {
                program: Program::Yarn,
            })?;
        if major < 2 {
            return Ok(unsupported(Some(display), UnsupportedReason::YarnClassic));
        }

        self.capture(&[located])?;
        if self.pins.iter().any(|pin| !pin.is_lockfile_only()) {
            self.runner
                .run(&Invocation::yarn_lock(self.manifest_dir), self.deadline)
                .await?;
        }
        if !names.is_empty() {
            self.runner
                .run(
                    &Invocation::yarn_update(self.manifest_dir, &names),
                    self.deadline,
                )
                .await?;
        }
        self.verified(Program::Yarn, located, PinCheck::SatisfiesInLock)
            .await
    }
}
