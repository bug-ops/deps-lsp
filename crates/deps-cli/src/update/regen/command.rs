//! Typed tool invocations for lockfile regeneration: the closed program set, validated argv
//! components, and the compatibility-class derivation `cargo update --package` needs.
//!
//! An [`Invocation`] can only be built through its named constructors, so every spawned
//! command line is one of a fixed set of shapes whose variable parts are validated.

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

use deps_core::ConcreteVersion;

pub(super) mod composer;
pub(super) mod dart;
pub(super) mod dotnet;
pub(super) mod gradle;
mod js;
pub(super) mod lockers;
pub(super) mod python;
pub(super) mod swift;

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
    /// `yarn` (`yarn.cmd` on Windows).
    Yarn,
    /// `uv`.
    Uv,
    /// Bundler's `bundle` (`bundle.bat` on Windows).
    Bundle,
    /// `deno`.
    Deno,
    /// `bun`.
    Bun,
    /// `poetry`.
    Poetry,
    /// `pdm`.
    Pdm,
    /// `pipenv`.
    Pipenv,
    /// `composer` (`composer.bat` on Windows).
    Composer,
    /// `dart`.
    Dart,
    /// `flutter` (`flutter.bat` on Windows).
    Flutter,
    /// `dotnet`.
    Dotnet,
    /// `gradle` (`gradle.bat` on Windows).
    Gradle,
    /// `swift`.
    Swift,
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
            Self::Yarn => "yarn",
            Self::Uv => "uv",
            Self::Bundle => "bundle",
            Self::Deno => "deno",
            Self::Bun => "bun",
            Self::Poetry => "poetry",
            Self::Pdm => "pdm",
            Self::Pipenv => "pipenv",
            Self::Composer => "composer",
            Self::Dart => "dart",
            Self::Flutter => "flutter",
            Self::Dotnet => "dotnet",
            Self::Gradle => "gradle",
            Self::Swift => "swift",
        }
    }

    /// The executable file name looked up on `PATH`.
    pub(super) const fn executable(self) -> &'static str {
        match self {
            Self::Cargo
            | Self::Go
            | Self::Uv
            | Self::Deno
            | Self::Bun
            | Self::Poetry
            | Self::Pdm
            | Self::Pipenv
            | Self::Dart
            | Self::Dotnet
            | Self::Swift => self.as_str(),
            #[cfg(windows)]
            Self::Npm => "npm.cmd",
            #[cfg(windows)]
            Self::Pnpm => "pnpm.cmd",
            #[cfg(windows)]
            Self::Yarn => "yarn.cmd",
            #[cfg(windows)]
            Self::Bundle => "bundle.bat",
            #[cfg(windows)]
            Self::Composer => "composer.bat",
            #[cfg(windows)]
            Self::Gradle => "gradle.bat",
            #[cfg(windows)]
            Self::Flutter => "flutter.bat",
            #[cfg(not(windows))]
            Self::Npm
            | Self::Pnpm
            | Self::Yarn
            | Self::Bundle
            | Self::Composer
            | Self::Gradle
            | Self::Flutter => self.as_str(),
        }
    }
}

impl fmt::Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A list proven to hold at least one element, so a command that must name its targets can never
/// be built with none (`bundle lock --update` with no names would update every gem).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::update::regen) struct NonEmpty<T>(Vec<T>);

impl<T> NonEmpty<T> {
    /// `None` for an empty list.
    pub(in crate::update::regen) fn new(items: Vec<T>) -> Option<Self> {
        (!items.is_empty()).then_some(Self(items))
    }

    fn iter(&self) -> std::slice::Iter<'_, T> {
        self.0.iter()
    }
}

/// The package manager that owns a JavaScript lockfile, identified by its exact file name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NpmClient {
    /// npm (`package-lock.json`).
    Npm,
    /// pnpm (`pnpm-lock.yaml`).
    Pnpm,
    /// Yarn (`yarn.lock`).
    Yarn,
    /// Bun (`bun.lock`).
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

/// The Python lock tool that owns a lockfile, identified by its exact file name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PythonLocker {
    /// uv (`uv.lock`).
    Uv,
    /// Poetry (`poetry.lock`).
    Poetry,
    /// PDM (`pdm.lock`).
    Pdm,
    /// Pipenv (`Pipfile.lock`).
    Pipenv,
}

impl PythonLocker {
    /// Maps an exact lockfile file name to its locker; `None` for any other name.
    #[must_use]
    pub fn from_lockfile_name(name: &str) -> Option<Self> {
        match name {
            "uv.lock" => Some(Self::Uv),
            "poetry.lock" => Some(Self::Poetry),
            "pdm.lock" => Some(Self::Pdm),
            "Pipfile.lock" => Some(Self::Pipenv),
            _ => None,
        }
    }

    /// The stable lowercase token used in reports and JSON output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Uv => "uv",
            Self::Poetry => "poetry",
            Self::Pdm => "pdm",
            Self::Pipenv => "pipenv",
        }
    }
}

/// Whether a `go` invocation sees the surrounding Go workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GoWork {
    /// The inherited environment decides.
    Inherit,
    /// `GOWORK=off`: the module resolves on its own `go.mod`/`go.sum`.
    Off,
}

/// How a `go` invocation resolves modules relative to a `vendor/` directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GoModuleMode {
    /// The inherited `GOFLAGS` decide.
    Inherit,
    /// `GOFLAGS=-mod=mod`, replacing any inherited value: an inherited `-mod=vendor` would make
    /// `go get` refuse to change `go.mod`.
    ModuleCache,
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

/// A workspace member's directory relative to the workspace root, proven safe for a
/// `--workspace=<path>` / `--filter=./<path>` argument: `/`-separated normal components only, no
/// leading `-`, no whitespace or control characters, and none of `* ? [ ] { } !`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct WorkspaceMember(String);

impl WorkspaceMember {
    /// Validates `relative` (the member directory below the workspace root).
    ///
    /// # Errors
    ///
    /// Returns [`UnsafeArgument`] for an empty path, a component that is not a plain name
    /// (`.`, `..`, a prefix or a root), non-UTF-8 text, or any character the rules above reject.
    pub(super) fn parse(relative: &Path) -> Result<Self, UnsafeArgument> {
        let unsafe_char = |c: char| c.is_whitespace() || c.is_control() || "*?[]{}!".contains(c);
        let parts = relative
            .components()
            .map(|component| match component {
                std::path::Component::Normal(part) => part.to_str().ok_or(UnsafeArgument),
                std::path::Component::Prefix(_)
                | std::path::Component::RootDir
                | std::path::Component::CurDir
                | std::path::Component::ParentDir => Err(UnsafeArgument),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let joined = parts.join("/");
        if joined.is_empty() || joined.starts_with('-') || joined.chars().any(unsafe_char) {
            return Err(UnsafeArgument);
        }
        Ok(Self(joined))
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
    env: &'static [(&'static str, &'static str)],
}

const fn go_env(work: GoWork, mode: GoModuleMode) -> &'static [(&'static str, &'static str)] {
    match (work, mode) {
        (GoWork::Inherit, GoModuleMode::Inherit) => &[],
        (GoWork::Off, GoModuleMode::Inherit) => &[("GOWORK", "off")],
        (GoWork::Inherit, GoModuleMode::ModuleCache) => &[("GOFLAGS", "-mod=mod")],
        (GoWork::Off, GoModuleMode::ModuleCache) => &[("GOWORK", "off"), ("GOFLAGS", "-mod=mod")],
    }
}

impl Invocation {
    fn new(program: Program, cwd: &Path, args: Vec<OsString>) -> Self {
        Self {
            program,
            args,
            cwd: cwd.to_path_buf(),
            env: &[],
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

    pub(super) const fn env(&self) -> &'static [(&'static str, &'static str)] {
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
    pub(super) fn go_get(
        cwd: &Path,
        modules: &[(ArgComponent, ArgComponent)],
        work: GoWork,
        mode: GoModuleMode,
    ) -> Self {
        let mut args = Self::strs(&["get", "--"]);
        args.extend(
            modules.iter().map(|(module, version)| {
                format!("{}@{}", module.as_str(), version.as_str()).into()
            }),
        );
        let mut invocation = Self::new(Program::Go, cwd, args);
        invocation.env = go_env(work, mode);
        invocation
    }

    /// `go mod vendor -o <out>`: writes the vendor tree to `out` instead of `vendor/`.
    pub(super) fn go_mod_vendor(cwd: &Path, out: &Path, work: GoWork, mode: GoModuleMode) -> Self {
        let mut args = Self::strs(&["mod", "vendor", "-o"]);
        args.push(out.into());
        let mut invocation = Self::new(Program::Go, cwd, args);
        invocation.env = go_env(work, mode);
        invocation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_empty_rejects_an_empty_list() {
        assert!(NonEmpty::<u8>::new(Vec::new()).is_none());
        assert!(NonEmpty::new(vec![1_u8]).is_some());
    }
}
