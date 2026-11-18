//! Invocation shapes of the JavaScript package managers: npm, pnpm and Yarn.

use std::ffi::OsString;
use std::path::Path;

use super::{Invocation, NpmPackageArg, Program, WorkspaceMember};

const COREPACK_ENV: &[(&str, &str)] = &[("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0")];
const YARN_ENV: &[(&str, &str)] = &[
    ("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0"),
    ("COREPACK_ENABLE_AUTO_PIN", "0"),
    ("YARN_ENABLE_IMMUTABLE_INSTALLS", "false"),
    ("YARN_ENABLE_SCRIPTS", "false"),
];

impl Invocation {
    /// `npm install --package-lock-only --ignore-scripts --no-audit --no-fund`.
    pub(in crate::update::regen) fn npm_lock(cwd: &Path) -> Self {
        let mut invocation = Self::new(
            Program::Npm,
            cwd,
            Self::strs(&[
                "install",
                "--package-lock-only",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
            ]),
        );
        invocation.env = COREPACK_ENV;
        invocation
    }

    /// `npm update --no-save --package-lock-only --ignore-scripts --no-audit --no-fund
    /// [--workspace=<member>] <names>`: moves the named packages inside their declared ranges
    /// without editing `package.json`, for one workspace member when `member` is given.
    pub(in crate::update::regen) fn npm_update(
        cwd: &Path,
        names: &[NpmPackageArg],
        member: Option<&WorkspaceMember>,
    ) -> Self {
        let mut args = Self::strs(&[
            "update",
            "--no-save",
            "--package-lock-only",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        ]);
        args.extend(member.map(|member| format!("--workspace=./{}", member.as_str()).into()));
        args.extend(names.iter().map(|name| OsString::from(name.as_str())));
        let mut invocation = Self::new(Program::Npm, cwd, args);
        invocation.env = COREPACK_ENV;
        invocation
    }

    /// `pnpm update --lockfile-only --no-save --ignore-scripts [--filter=./<member>] <names>`.
    pub(in crate::update::regen) fn pnpm_update(
        cwd: &Path,
        names: &[NpmPackageArg],
        member: Option<&WorkspaceMember>,
    ) -> Self {
        let mut args = Self::strs(&["update", "--lockfile-only", "--no-save", "--ignore-scripts"]);
        args.extend(member.map(|member| format!("--filter=./{}", member.as_str()).into()));
        args.extend(names.iter().map(|name| OsString::from(name.as_str())));
        let mut invocation = Self::new(Program::Pnpm, cwd, args);
        invocation.env = COREPACK_ENV;
        invocation
    }

    /// `pnpm install --lockfile-only --ignore-scripts --no-frozen-lockfile`.
    pub(in crate::update::regen) fn pnpm_lock(cwd: &Path) -> Self {
        let mut invocation = Self::new(
            Program::Pnpm,
            cwd,
            Self::strs(&[
                "install",
                "--lockfile-only",
                "--ignore-scripts",
                "--no-frozen-lockfile",
            ]),
        );
        invocation.env = COREPACK_ENV;
        invocation
    }

    /// `npm prefix`: the directory npm treats as the workspace root of `cwd`.
    pub(in crate::update::regen) fn npm_prefix(cwd: &Path) -> Self {
        let mut invocation = Self::new(Program::Npm, cwd, Self::strs(&["prefix"]));
        invocation.env = COREPACK_ENV;
        invocation
    }

    /// `pnpm root -w`: the `node_modules` directory of the workspace root.
    pub(in crate::update::regen) fn pnpm_workspace_root(cwd: &Path) -> Self {
        let mut invocation = Self::new(Program::Pnpm, cwd, Self::strs(&["root", "-w"]));
        invocation.env = COREPACK_ENV;
        invocation
    }

    /// `pnpm list --filter=./<member> --depth=-1 --json`, run at the workspace root: a read-only
    /// probe that lists the workspace projects matching the member path.
    pub(in crate::update::regen) fn pnpm_list_member(
        root: &Path,
        member: &WorkspaceMember,
    ) -> Self {
        let mut invocation = Self::new(
            Program::Pnpm,
            root,
            vec![
                "list".into(),
                format!("--filter=./{}", member.as_str()).into(),
                "--depth=-1".into(),
                "--json".into(),
            ],
        );
        invocation.env = COREPACK_ENV;
        invocation
    }

    /// `yarn --version`.
    pub(in crate::update::regen) fn yarn_version(cwd: &Path) -> Self {
        let mut invocation = Self::new(Program::Yarn, cwd, Self::strs(&["--version"]));
        invocation.env = COREPACK_ENV;
        invocation
    }

    /// `yarn install --mode=update-lockfile` (Yarn 2+): resolves without linking or scripts.
    pub(in crate::update::regen) fn yarn_lock(cwd: &Path) -> Self {
        let mut invocation = Self::new(
            Program::Yarn,
            cwd,
            Self::strs(&["install", "--mode=update-lockfile"]),
        );
        invocation.env = YARN_ENV;
        invocation
    }

    /// `yarn up --recursive --mode=update-lockfile <names>` (Yarn 2+).
    pub(in crate::update::regen) fn yarn_update(cwd: &Path, names: &[NpmPackageArg]) -> Self {
        let mut args = Self::strs(&["up", "--recursive", "--mode=update-lockfile"]);
        args.extend(names.iter().map(|name| OsString::from(name.as_str())));
        let mut invocation = Self::new(Program::Yarn, cwd, args);
        invocation.env = YARN_ENV;
        invocation
    }
}
