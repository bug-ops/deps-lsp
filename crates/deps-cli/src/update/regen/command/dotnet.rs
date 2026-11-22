//! Invocation shapes of the .NET CLI (#2084).

use std::path::Path;

use super::{Invocation, Program, UnsafeArgument};

/// The project file name passed to `dotnet restore`: a `.csproj`, `.fsproj` or `.vbproj` file
/// name proven safe for argv, never a flag, a path or a name with control characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::update::regen) struct ProjectFileArg(String);

impl ProjectFileArg {
    const EXTENSIONS: [&'static str; 3] = [".csproj", ".fsproj", ".vbproj"];

    /// Validates `file_name` (the manifest's own file name, no directory part).
    ///
    /// # Errors
    ///
    /// [`UnsafeArgument`] for a name without a project-file extension, with a leading `-`, a
    /// path separator, or any control character.
    pub(in crate::update::regen) fn parse(file_name: &str) -> Result<Self, UnsafeArgument> {
        let lower = file_name.to_ascii_lowercase();
        let has_extension = Self::EXTENSIONS.iter().any(|ext| lower.ends_with(ext));
        let malformed = !has_extension
            || file_name.starts_with('-')
            || file_name.contains(['/', '\\'])
            || file_name.chars().any(char::is_control);
        if malformed {
            return Err(UnsafeArgument);
        }
        Ok(Self(file_name.to_owned()))
    }
}

/// No telemetry or banner output, and no MSBuild node left running after the restore.
const DOTNET_ENV: &[(&str, &str)] = &[
    ("DOTNET_CLI_TELEMETRY_OPTOUT", "1"),
    ("DOTNET_NOLOGO", "1"),
    ("MSBUILDDISABLENODEREUSE", "1"),
];

/// How a `dotnet restore` treats the lock file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::update::regen) enum RestoreMode {
    /// Re-resolves the project against the manifest and rewrites the lock file.
    Resolve,
    /// Additionally fails when the restore would change the lock file.
    Locked,
}

impl Invocation {
    /// `dotnet restore <project> --use-lock-file --no-dependencies --disable-build-servers
    /// --force`, plus `-p:RestoreLockedMode=false` for [`RestoreMode::Resolve`] or
    /// `--locked-mode` for [`RestoreMode::Locked`].
    ///
    /// The resolving restore overrides the property because a project's own
    /// `<RestoreLockedMode>true</RestoreLockedMode>` would otherwise fail it with `NU1004`
    /// (#2129); `--locked-mode` already wins over the property.
    ///
    /// `--force` makes restore re-resolve although the project looks up to date, which is how a
    /// package already locked moves to a newly pinned version. `--no-dependencies` keeps
    /// referenced projects' lock files untouched; `--force-evaluate` is deliberately never
    /// passed, because it re-resolves every floating dependency.
    pub(in crate::update::regen) fn dotnet_restore(
        cwd: &Path,
        project: &ProjectFileArg,
        mode: RestoreMode,
    ) -> Self {
        let mut args = Self::strs(&["restore"]);
        args.push(project.0.as_str().into());
        args.extend(Self::strs(&[
            "--use-lock-file",
            "--no-dependencies",
            "--disable-build-servers",
            "--force",
        ]));
        args.extend(Self::strs(&[match mode {
            RestoreMode::Resolve => "-p:RestoreLockedMode=false",
            RestoreMode::Locked => "--locked-mode",
        }]));
        let mut invocation = Self::new(Program::Dotnet, cwd, args);
        invocation.env = DOTNET_ENV;
        invocation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_file_accepts_the_three_project_extensions() {
        for name in ["App.csproj", "my app.fsproj", "X.VBPROJ"] {
            assert!(ProjectFileArg::parse(name).is_ok(), "{name}");
        }
    }

    #[test]
    fn project_file_rejects_flags_paths_and_other_files() {
        for name in [
            "",
            "-x.csproj",
            "--help.csproj",
            "a/b.csproj",
            "a\\b.csproj",
            "a\n.csproj",
            "packages.config",
            "Directory.Packages.props",
            "App.csproj.bak",
        ] {
            assert!(ProjectFileArg::parse(name).is_err(), "{name:?}");
        }
    }

    const BASE_ARGS: [&str; 6] = [
        "restore",
        "App.csproj",
        "--use-lock-file",
        "--no-dependencies",
        "--disable-build-servers",
        "--force",
    ];

    fn restore(mode: RestoreMode) -> Invocation {
        let project = ProjectFileArg::parse("App.csproj").expect("project");
        Invocation::dotnet_restore(Path::new("."), &project, mode)
    }

    #[test]
    fn resolve_restore_forces_the_lock_file_without_dependencies_or_force_evaluate() {
        let invocation = restore(RestoreMode::Resolve);

        assert_eq!(invocation.program(), Program::Dotnet);
        let mut expected = BASE_ARGS.to_vec();
        expected.push("-p:RestoreLockedMode=false");
        assert_eq!(invocation.args(), expected);
        assert!(
            invocation
                .args()
                .iter()
                .all(|arg| arg != "--force-evaluate")
        );
        assert_eq!(invocation.env(), DOTNET_ENV);
    }

    #[test]
    fn locked_restore_is_the_base_restore_plus_locked_mode_without_the_property_override() {
        let invocation = restore(RestoreMode::Locked);

        let mut expected = BASE_ARGS.to_vec();
        expected.push("--locked-mode");
        assert_eq!(invocation.args(), expected);
    }
}
