//! Typed tool invocations for lockfile regeneration: the closed program set, validated argv
//! components, and the compatibility-class derivation `cargo update --package` needs.
//!
//! An [`Invocation`] can only be built through its named constructors, so every spawned
//! command line is one of a fixed set of shapes whose variable parts are validated.

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

use deps_core::ConcreteVersion;

/// An external tool `deps-cli` may spawn to regenerate a lockfile.
///
/// A closed set, so no program name ever originates from manifest content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Program {
    /// `cargo`.
    Cargo,
    /// `go`.
    Go,
    /// `npm` (`npm.cmd` on Windows).
    Npm,
    /// `pnpm` (`pnpm.cmd` on Windows).
    Pnpm,
}

impl Program {
    /// The stable lowercase token used in reports and JSON output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cargo => "cargo",
            Self::Go => "go",
            Self::Npm => "npm",
            Self::Pnpm => "pnpm",
        }
    }

    /// The executable file name looked up on `PATH`.
    pub(super) const fn executable(self) -> &'static str {
        match self {
            Self::Cargo | Self::Go => self.as_str(),
            #[cfg(windows)]
            Self::Npm => "npm.cmd",
            #[cfg(windows)]
            Self::Pnpm => "pnpm.cmd",
            #[cfg(not(windows))]
            Self::Npm | Self::Pnpm => self.as_str(),
        }
    }
}

impl fmt::Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The package manager that owns a JavaScript lockfile, identified by its exact file name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NpmClient {
    /// npm (`package-lock.json`).
    Npm,
    /// pnpm (`pnpm-lock.yaml`).
    Pnpm,
    /// Yarn (`yarn.lock`); regeneration is deferred.
    Yarn,
    /// Bun (`bun.lock`); regeneration is deferred.
    Bun,
}

impl NpmClient {
    /// Maps an exact lockfile file name to its client; `None` for any other name.
    #[must_use]
    pub fn from_lockfile_name(name: &str) -> Option<Self> {
        match name {
            "package-lock.json" => Some(Self::Npm),
            "pnpm-lock.yaml" => Some(Self::Pnpm),
            "yarn.lock" => Some(Self::Yarn),
            "bun.lock" => Some(Self::Bun),
            _ => None,
        }
    }

    /// The stable lowercase token used in reports and JSON output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pnpm => "pnpm",
            Self::Yarn => "yarn",
            Self::Bun => "bun",
        }
    }
}

/// A rejected [`ArgComponent`] candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("value is not safe to pass as a tool argument")]
pub(super) struct UnsafeArgument;

/// A package name or version proven safe to place in a tool's argv: non-empty, no leading `-`,
/// no `@`, and no whitespace or control characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ArgComponent(String);

impl ArgComponent {
    /// Validates `value` as an argv component.
    ///
    /// # Errors
    ///
    /// Returns [`UnsafeArgument`] for an empty value, a leading `-`, an `@`, a NUL, whitespace
    /// or any control character.
    pub(super) fn parse(value: &str) -> Result<Self, UnsafeArgument> {
        let unsafe_char = |c: char| c == '@' || c.is_whitespace() || c.is_control();
        if value.is_empty() || value.starts_with('-') || value.chars().any(unsafe_char) {
            return Err(UnsafeArgument);
        }
        Ok(Self(value.to_owned()))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

/// An npm package name proven safe for argv: `name` or `@scope/name` over npm's URL-safe
/// alphabet (letters, digits and `-_.~!'()`), so no `file:`/`npm:`/`git+` spec and no `*`
/// pattern; never a leading `-`, `.` or `!`; at most 214 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NpmPackageArg(String);

impl NpmPackageArg {
    /// Longest package name npm accepts.
    const MAX_LEN: usize = 214;

    /// Validates `value` as an npm package name argument.
    ///
    /// # Errors
    ///
    /// Returns [`UnsafeArgument`] when `value` breaks the rules above.
    pub(super) fn parse(value: &str) -> Result<Self, UnsafeArgument> {
        let url_safe = |c: char| {
            c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~' | '!' | '\'' | '(' | ')')
        };
        let well_formed_part = |part: &str| {
            !part.is_empty() && !part.starts_with(['-', '.', '!']) && part.chars().all(url_safe)
        };
        let shape_ok = match value.strip_prefix('@') {
            Some(scoped) => scoped
                .split_once('/')
                .is_some_and(|(scope, name)| well_formed_part(scope) && well_formed_part(name)),
            None => well_formed_part(value),
        };
        if value.len() > Self::MAX_LEN || !shape_ok {
            return Err(UnsafeArgument);
        }
        Ok(Self(value.to_owned()))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

/// The caret compatibility class of a concrete version, as `cargo update --package name@class`
/// expects it (`1.2.3` -> `1`, `0.2.3` -> `0.2`, `0.0.3` -> `0.0.3`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CompatClass(String);

impl fmt::Display for CompatClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Derives the [`CompatClass`] of `version`; `None` unless it is a three-part semver version.
pub(super) fn compat_class(version: &ConcreteVersion) -> Option<CompatClass> {
    let text = version.as_str();
    let core = text.split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let (major, minor, patch) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let number = |part: &str| {
        (!part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
            .then(|| part.parse::<u64>().ok())
            .flatten()
    };
    let (major, minor, patch) = (number(major)?, number(minor)?, number(patch)?);
    let class = if major > 0 {
        major.to_string()
    } else if minor > 0 {
        format!("0.{minor}")
    } else {
        format!("0.0.{patch}")
    };
    Some(CompatClass(class))
}

/// One fully formed command line: program, argv, working directory and extra environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Invocation {
    program: Program,
    args: Vec<OsString>,
    cwd: PathBuf,
    env: Option<(&'static str, &'static str)>,
}

const COREPACK_NO_PROMPT: (&str, &str) = ("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0");

impl Invocation {
    fn new(program: Program, cwd: &Path, args: Vec<OsString>) -> Self {
        Self {
            program,
            args,
            cwd: cwd.to_path_buf(),
            env: None,
        }
    }

    fn strs(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    pub(super) const fn program(&self) -> Program {
        self.program
    }

    pub(super) fn args(&self) -> &[OsString] {
        &self.args
    }

    pub(super) fn cwd(&self) -> &Path {
        &self.cwd
    }

    pub(super) const fn env(&self) -> Option<(&'static str, &'static str)> {
        self.env
    }

    /// `cargo locate-project --workspace --message-format plain --manifest-path <m>`.
    pub(super) fn cargo_locate_workspace(cwd: &Path, manifest: &Path) -> Self {
        let mut args = Self::strs(&[
            "locate-project",
            "--workspace",
            "--message-format",
            "plain",
            "--manifest-path",
        ]);
        args.push(manifest.into());
        Self::new(Program::Cargo, cwd, args)
    }

    /// `cargo update --workspace --manifest-path <m>`.
    pub(super) fn cargo_update_workspace(cwd: &Path, manifest: &Path) -> Self {
        let mut args = Self::strs(&["update", "--workspace", "--manifest-path"]);
        args.push(manifest.into());
        Self::new(Program::Cargo, cwd, args)
    }

    /// `cargo update --manifest-path <m> --package=<name>@<class> --precise=<target>`.
    pub(super) fn cargo_update_precise(
        cwd: &Path,
        manifest: &Path,
        name: &ArgComponent,
        class: &CompatClass,
        target: &ArgComponent,
    ) -> Self {
        let mut args = Self::strs(&["update", "--manifest-path"]);
        args.push(manifest.into());
        args.push(format!("--package={}@{class}", name.as_str()).into());
        args.push(format!("--precise={}", target.as_str()).into());
        Self::new(Program::Cargo, cwd, args)
    }

    /// `go env GOWORK`.
    pub(super) fn go_env_gowork(cwd: &Path) -> Self {
        Self::new(Program::Go, cwd, Self::strs(&["env", "GOWORK"]))
    }

    /// `go get -- <module>@<version>...`; `--` ends flag parsing.
    pub(super) fn go_get(cwd: &Path, modules: &[(ArgComponent, ArgComponent)]) -> Self {
        let mut args = Self::strs(&["get", "--"]);
        args.extend(
            modules.iter().map(|(module, version)| {
                format!("{}@{}", module.as_str(), version.as_str()).into()
            }),
        );
        Self::new(Program::Go, cwd, args)
    }

    /// `npm install --package-lock-only --ignore-scripts --no-audit --no-fund`.
    pub(super) fn npm_lock(cwd: &Path) -> Self {
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
        invocation.env = Some(COREPACK_NO_PROMPT);
        invocation
    }

    /// `npm update --no-save --package-lock-only --ignore-scripts --no-audit --no-fund <names>`:
    /// moves the named packages inside their declared ranges without editing `package.json`.
    pub(super) fn npm_update(cwd: &Path, names: &[NpmPackageArg]) -> Self {
        let mut args = Self::strs(&[
            "update",
            "--no-save",
            "--package-lock-only",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        ]);
        args.extend(names.iter().map(|name| OsString::from(name.as_str())));
        let mut invocation = Self::new(Program::Npm, cwd, args);
        invocation.env = Some(COREPACK_NO_PROMPT);
        invocation
    }

    /// `pnpm update --lockfile-only --no-save --ignore-scripts <names>`.
    pub(super) fn pnpm_update(cwd: &Path, names: &[NpmPackageArg]) -> Self {
        let mut args = Self::strs(&["update", "--lockfile-only", "--no-save", "--ignore-scripts"]);
        args.extend(names.iter().map(|name| OsString::from(name.as_str())));
        let mut invocation = Self::new(Program::Pnpm, cwd, args);
        invocation.env = Some(COREPACK_NO_PROMPT);
        invocation
    }

    /// `pnpm install --lockfile-only --ignore-scripts --no-frozen-lockfile`.
    pub(super) fn pnpm_lock(cwd: &Path) -> Self {
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
        invocation.env = Some(COREPACK_NO_PROMPT);
        invocation
    }
}
