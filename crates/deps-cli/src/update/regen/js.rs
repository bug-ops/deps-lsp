//! Regeneration for the JavaScript lockfile owners: npm, pnpm (workspace members included),
//! Yarn 2+ (#2047, #2080) and Bun.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};

use ignore::overrides::OverrideBuilder;
use serde::Deserialize;
use serde::de::{DeserializeOwned, Deserializer, IgnoredAny, MapAccess, Visitor};

use super::command::WorkspaceMember;
use super::fallback::{DescriptorLock, ExactPinRun, Relax};
use super::run::Probed;
use super::{
    Invocation, LockfileOutcome, NotApplicableReason, NpmClient, NpmPackageArg, PinCheck, Program,
    RegenerationError, Session, UnsupportedReason, declares_workspace, inside_workspace, same_file,
    unsupported, workspace_dir_env_set,
};

/// Most workspaces one Yarn run captures.
const MAX_YARN_WORKSPACES: usize = 512;

/// Largest `yarn workspaces list --json` output read: room for [`MAX_YARN_WORKSPACES`] lines of
/// the longest location and name; anything longer is refused, never truncated.
const WORKSPACE_LIST_CAP: u64 = 512 * 1024;

/// The manifests a Yarn run must keep, or why the run is refused.
enum Siblings {
    Found(Vec<PathBuf>),
    Refused(UnsupportedReason),
}

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

#[derive(Deserialize)]
#[serde(untagged)]
enum WorkspacePatterns {
    List(Vec<String>),
    Object { packages: Vec<String> },
}

impl WorkspacePatterns {
    fn as_slice(&self) -> &[String] {
        match self {
            Self::List(patterns) | Self::Object { packages: patterns } => patterns,
        }
    }
}

#[derive(Deserialize)]
struct RootPackage {
    workspaces: Option<WorkspacePatterns>,
}

/// The keys of a lock file's `packages` object, without its values.
struct PackageKeys(BTreeSet<String>);

impl<'de> Deserialize<'de> for PackageKeys {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Keys;

        impl<'de> Visitor<'de> for Keys {
            type Value = PackageKeys;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a map of package paths")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<PackageKeys, A::Error> {
                let mut keys = BTreeSet::new();
                while let Some((key, IgnoredAny)) = map.next_entry::<String, IgnoredAny>()? {
                    keys.insert(key);
                }
                Ok(PackageKeys(keys))
            }
        }

        deserializer.deserialize_map(Keys)
    }
}

#[derive(Deserialize)]
struct NpmLockMembers {
    #[serde(rename = "lockfileVersion")]
    lockfile_version: Option<u64>,
    packages: Option<PackageKeys>,
}

/// One `yarn workspaces list --json` line.
#[derive(Deserialize)]
struct YarnWorkspace {
    location: PathBuf,
}

fn read_json<T: DeserializeOwned>(path: &Path, max_bytes: u64) -> Option<T> {
    let bytes = deps_core::fs_probe::read_capped_no_follow(path, max_bytes)
        .ok()
        .flatten()?;
    serde_json::from_slice(&bytes).ok()
}

/// Whether `relative` (a `/`-separated member directory) matches one of the root manifest's
/// `workspaces` patterns.
///
/// Patterns are anchored at the root, because gitignore rules would otherwise match a bare name
/// at any depth. A negation, a `..` segment, an absolute pattern or one that does not compile
/// fails closed for the whole set.
fn workspace_patterns_match(root: &Path, patterns: &[String], relative: &str) -> bool {
    let mut builder = OverrideBuilder::new(root);
    for pattern in patterns {
        let pattern = pattern.strip_prefix("./").unwrap_or(pattern);
        let unusable = pattern.is_empty()
            || pattern.starts_with(['!', '/'])
            || pattern.split('/').any(|segment| segment == "..");
        if unusable || builder.add(&format!("/{pattern}")).is_err() {
            return false;
        }
    }
    builder
        .build()
        .is_ok_and(|overrides| overrides.matched(relative, true).is_whitelist())
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
            Some(NpmClient::Bun) => self.bun(&located).await,
            None => Err(RegenerationError::UnrecognizedLockfile {
                path: display.shown,
            }),
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
        if let Some(outcome) = self.placement_refusal(located) {
            return Ok(outcome);
        }

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

        if self.has_fallback_pins() {
            let names = self.update_only_args(NpmPackageArg::parse)?;
            let update = (!names.is_empty()).then(|| update(&root, &names, member.as_ref()));
            return self
                .run_with_exact_pins(ExactPinRun {
                    tool: program,
                    lockfile: located,
                    manifest: self.target.manifest_path,
                    install: &install,
                    update: update.as_ref(),
                    relax: Relax::Reinstall,
                    siblings: &[],
                })
                .await;
        }

        let names = self.lockfile_only_args(NpmPackageArg::parse)?;
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

    /// Whether the manifest sits beside the lockfile or below the root of a workspace that owns it.
    ///
    /// Spawns nothing; `Member` is only a candidate until the tool-specific proof.
    fn placement(&self, located: &Path, client: NpmClient) -> Layout {
        let lock_dir = located.parent();
        if same_file(lock_dir, Some(self.manifest_dir)) {
            return if inside_workspace(self.manifest_dir, client, |name| std::env::var_os(name)) {
                Layout::Refused(UnsupportedReason::WorkspaceMemberLockfile)
            } else {
                Layout::Standalone
            };
        }
        let member_of_lock_dir = lock_dir.is_some_and(|dir| {
            !workspace_dir_env_set(client, |name| std::env::var_os(name))
                && declares_workspace(dir, client)
                && std::fs::canonicalize(self.manifest_dir)
                    .ok()
                    .zip(std::fs::canonicalize(dir).ok())
                    .is_some_and(|(manifest, root)| manifest.starts_with(root))
        });
        let Some(root) = lock_dir.filter(|_| member_of_lock_dir) else {
            return Layout::Refused(UnsupportedReason::WorkspaceMemberLockfile);
        };
        let relative = std::fs::canonicalize(self.manifest_dir)
            .ok()
            .zip(std::fs::canonicalize(root).ok())
            .and_then(|(manifest, root)| manifest.strip_prefix(root).map(Path::to_path_buf).ok());
        match relative.and_then(|relative| WorkspaceMember::parse(&relative).ok()) {
            Some(member) => Layout::Member {
                root: root.to_path_buf(),
                member,
            },
            None => Layout::Refused(UnsupportedReason::WorkspaceMemberLockfile),
        }
    }

    /// Decides where an npm or pnpm tool must run, proving workspace ownership for a manifest
    /// below a lockfile whose directory declares a workspace.
    async fn layout(&self, located: &Path, client: NpmClient) -> Result<Layout, RegenerationError> {
        let (root, member) = match self.placement(located, client) {
            Layout::Member { root, member } => (root, member),
            settled @ (Layout::Standalone | Layout::Refused(_)) => return Ok(settled),
        };
        match client {
            NpmClient::Npm => Ok(if npm_lock_lists_member(located, &root, &member) {
                Layout::Member { root, member }
            } else {
                Layout::Refused(UnsupportedReason::LockfileOwnershipMismatch)
            }),
            NpmClient::Pnpm => self.pnpm_member(root, member).await,
            NpmClient::Yarn | NpmClient::Bun => {
                Ok(Layout::Refused(UnsupportedReason::WorkspaceMemberLockfile))
            }
        }
    }

    async fn pnpm_member(
        &self,
        root: PathBuf,
        member: WorkspaceMember,
    ) -> Result<Layout, RegenerationError> {
        let probe = Invocation::pnpm_workspace_root(self.manifest_dir);
        let program = probe.program();
        let printed = self.runner.probe(&probe, self.deadline).await?;
        let printed_root = Path::new(&printed)
            .parent()
            .map(Path::to_path_buf)
            .ok_or(RegenerationError::UnexpectedProbeOutput { program })?;
        if !same_file(Some(printed_root.as_path()), Some(root.as_path())) {
            return Ok(Layout::Refused(
                UnsupportedReason::LockfileOwnershipMismatch,
            ));
        }
        if !self.pnpm_lists_member(&root, &member).await? {
            return Ok(Layout::Refused(UnsupportedReason::WorkspaceMemberLockfile));
        }
        Ok(Layout::Member { root, member })
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
        #[derive(Deserialize)]
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

    /// Yarn 2+ (berry), beside its manifest or for a member of the workspace whose root owns the
    /// lockfile; Yarn Classic is a final refusal.
    async fn yarn(&self, located: &Path) -> Result<LockfileOutcome, RegenerationError> {
        let display = self.display_lock_path(located);
        let (root, member) = match self.placement(located, NpmClient::Yarn) {
            Layout::Standalone => (self.manifest_dir.to_path_buf(), None),
            Layout::Member { root, member }
                if !inside_workspace(&root, NpmClient::Yarn, |name| std::env::var_os(name)) =>
            {
                (root, Some(member))
            }
            Layout::Member { .. } => {
                return Ok(unsupported(
                    Some(display),
                    UnsupportedReason::WorkspaceMemberLockfile,
                ));
            }
            Layout::Refused(reason) => return Ok(unsupported(Some(display), reason)),
        };
        if let Some(outcome) = self.placement_refusal(located) {
            return Ok(outcome);
        }

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

        let siblings = match self.yarn_sibling_manifests(&root, member.as_ref()).await? {
            Siblings::Found(siblings) => siblings,
            Siblings::Refused(reason) => return Ok(unsupported(Some(display), reason)),
        };

        let install = Invocation::yarn_lock(&root);
        let names = self.lockfile_only_args(NpmPackageArg::parse)?;
        let mut manifests = vec![self.target.manifest_path];
        manifests.extend(siblings.iter().map(PathBuf::as_path));
        let mut guarded = vec![located];
        guarded.extend(&manifests);
        self.capture(&guarded)?;
        let captured = manifests
            .iter()
            .map(|path| self.read_manifest(path))
            .collect::<Result<Vec<_>, _>>()?;
        if self.has_fallback_pins() {
            let names = self.update_only_args(NpmPackageArg::parse)?;
            let update = (!names.is_empty()).then(|| Invocation::yarn_update(&root, &names));
            return self
                .run_with_exact_pins(ExactPinRun {
                    tool: Program::Yarn,
                    lockfile: located,
                    manifest: self.target.manifest_path,
                    install: &install,
                    update: update.as_ref(),
                    relax: Relax::Rekey(DescriptorLock::YarnBerry),
                    siblings: captured.get(1..).unwrap_or_default(),
                })
                .await;
        }
        if self.pins.iter().any(|pin| !pin.is_lockfile_only()) {
            self.runner.run(&install, self.deadline).await?;
        }
        if !names.is_empty() {
            self.runner
                .run(&Invocation::yarn_update(&root, &names), self.deadline)
                .await?;
        }
        self.restore_formatting(&captured)?;
        self.verified(Program::Yarn, located, PinCheck::SatisfiesInLock)
            .await
    }

    /// The `package.json` of every Yarn workspace other than the run's own manifest, which `yarn
    /// up` re-serializes project-wide.
    ///
    /// Paths come only from `yarn workspaces list --json`, run before any writing spawn; a
    /// location that is not `.` or a plain relative path fails closed. Asks Yarn only when the
    /// project has workspaces: a manifest that is a member, or a root that declares them.
    async fn yarn_sibling_manifests(
        &self,
        root: &Path,
        member: Option<&WorkspaceMember>,
    ) -> Result<Siblings, RegenerationError> {
        if member.is_none() && !declares_workspace(root, NpmClient::Yarn) {
            return Ok(Siblings::Found(Vec::new()));
        }
        let unexpected = || RegenerationError::UnexpectedProbeOutput {
            program: Program::Yarn,
        };
        let printed = match self
            .runner
            .probe_capped(
                &Invocation::yarn_workspaces_list(root),
                self.deadline,
                WORKSPACE_LIST_CAP,
            )
            .await?
        {
            Probed::Text(printed) => printed,
            Probed::OverCap => {
                return Ok(Siblings::Refused(UnsupportedReason::LockfileSetTooLarge));
            }
        };
        let locations = printed
            .lines()
            .map(|line| {
                let location = serde_json::from_str::<YarnWorkspace>(line)
                    .map_err(|_| unexpected())?
                    .location;
                if location == Path::new(".") {
                    Ok(None)
                } else {
                    WorkspaceMember::parse(&location)
                        .map(Some)
                        .map_err(|_| unexpected())
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        if locations.len() > MAX_YARN_WORKSPACES {
            return Ok(Siblings::Refused(UnsupportedReason::LockfileSetTooLarge));
        }
        if let Some(member) = member
            && locations
                .iter()
                .filter(|location| location.as_ref() == Some(member))
                .count()
                != 1
        {
            return Ok(Siblings::Refused(
                UnsupportedReason::WorkspaceMemberLockfile,
            ));
        }
        let mut manifests = Vec::new();
        for location in &locations {
            let dir = location
                .as_ref()
                .map_or_else(|| root.to_path_buf(), |member| root.join(member.as_str()));
            let manifest = dir.join("package.json");
            if same_file(Some(manifest.as_path()), Some(self.target.manifest_path)) {
                continue;
            }
            if !manifest.try_exists().unwrap_or(false) {
                return Ok(Siblings::Refused(
                    UnsupportedReason::LockfileOwnershipMismatch,
                ));
            }
            if let Some(LockfileOutcome::Unsupported { reason, .. }) =
                self.placement_refusal(&manifest)
            {
                return Ok(Siblings::Refused(reason));
            }
            manifests.push(manifest);
        }
        Ok(Siblings::Found(manifests))
    }

    /// Bun beside its manifest. `bun update --lockfile-only` rewrites the declared range in
    /// `package.json`, so a run with lockfile-only or fallback pins writes the captured manifest
    /// back and installs again, which keeps the locked version under the original range.
    async fn bun(&self, located: &Path) -> Result<LockfileOutcome, RegenerationError> {
        let display = self.display_lock_path(located);
        match self.placement(located, NpmClient::Bun) {
            Layout::Standalone => {}
            Layout::Member { .. } => {
                return Ok(unsupported(
                    Some(display),
                    UnsupportedReason::WorkspaceMemberLockfile,
                ));
            }
            Layout::Refused(reason) => return Ok(unsupported(Some(display), reason)),
        }
        if let Some(outcome) = self.placement_refusal(located) {
            return Ok(outcome);
        }
        let install = Invocation::bun_lock(self.manifest_dir);
        if self.has_fallback_pins() || self.pins.iter().any(|pin| pin.is_lockfile_only()) {
            let names = self.update_only_args(NpmPackageArg::parse)?;
            let update = (!names.is_empty())
                .then(|| Invocation::bun_update_lockfile_only(self.manifest_dir, &names));
            return self
                .run_with_exact_pins(ExactPinRun {
                    tool: Program::Bun,
                    lockfile: located,
                    manifest: self.target.manifest_path,
                    install: &install,
                    update: update.as_ref(),
                    relax: Relax::Reinstall,
                    siblings: &[],
                })
                .await;
        }
        self.capture(&[located])?;
        self.runner.run(&install, self.deadline).await?;
        self.verified(Program::Bun, located, PinCheck::SatisfiesInLock)
            .await
    }
}

/// Whether the workspace root's own files prove it owns `member`: no outer workspace above the
/// root, a `workspaces` pattern of the root `package.json` matching the member directory, and a
/// v2/v3 lockfile that lists it under `packages`.
///
/// Reads files only: `npm prefix` redacts UUID-like path segments, so its output cannot be
/// compared with the lockfile's directory (#2089).
fn npm_lock_lists_member(lock: &Path, root: &Path, member: &WorkspaceMember) -> bool {
    if inside_workspace(root, NpmClient::Npm, |name| std::env::var_os(name)) {
        return false;
    }
    let Some(patterns) =
        read_json::<RootPackage>(&root.join("package.json"), crate::MAX_MANIFEST_FILE_SIZE)
            .and_then(|package| package.workspaces)
    else {
        return false;
    };
    let Some(lock) = read_json::<NpmLockMembers>(lock, deps_core::lockfile::MAX_LOCKFILE_BYTES)
    else {
        return false;
    };
    lock.lockfile_version.is_some_and(|version| version >= 2)
        && lock
            .packages
            .is_some_and(|packages| packages.0.contains(member.as_str()))
        && workspace_patterns_match(root, patterns.as_slice(), member.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(patterns: &[&str], relative: &str) -> bool {
        let patterns: Vec<String> = patterns.iter().map(|p| (*p).to_owned()).collect();
        workspace_patterns_match(Path::new("/ws"), &patterns, relative)
    }

    #[test]
    fn patterns_match_direct_children_only_for_a_single_star() {
        assert!(matches(&["packages/*"], "packages/a"));
        assert!(!matches(&["packages/*"], "packages/a/b"));
        assert!(!matches(&["packages/*"], "other/a"));
    }

    #[test]
    fn patterns_are_anchored_at_the_workspace_root() {
        assert!(!matches(&["a"], "packages/a"));
        assert!(matches(&["a"], "a"));
        assert!(matches(&["./packages/a"], "packages/a"));
    }

    #[test]
    fn patterns_with_a_double_star_match_nested_members() {
        assert!(matches(&["packages/**"], "packages/team/a"));
    }

    #[test]
    fn one_unusable_pattern_fails_the_whole_set() {
        for bad in ["!packages/b", "../x", "/abs", "", "packages/[a"] {
            assert!(!matches(&["packages/*", bad], "packages/a"), "{bad}");
        }
    }

    #[test]
    fn no_patterns_match_nothing() {
        assert!(!matches(&[], "packages/a"));
    }

    #[test]
    fn workspaces_declaration_accepts_the_array_and_object_forms() {
        let list: RootPackage = serde_json::from_str(r#"{"workspaces":["a"]}"#).expect("array");
        let object: RootPackage =
            serde_json::from_str(r#"{"workspaces":{"packages":["a"]}}"#).expect("object");
        assert_eq!(list.workspaces.expect("declared").as_slice(), ["a"]);
        assert_eq!(object.workspaces.expect("declared").as_slice(), ["a"]);
    }
}
