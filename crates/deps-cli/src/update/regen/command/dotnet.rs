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

impl Invocation {
    /// `dotnet restore <project> --use-lock-file --no-dependencies --disable-build-servers`.
    ///
    /// `--no-dependencies` keeps referenced projects' lock files untouched; `--force-evaluate`
    /// is deliberately never passed, because it re-resolves every floating dependency.
    pub(in crate::update::regen) fn dotnet_restore(cwd: &Path, project: &ProjectFileArg) -> Self {
        let mut args = Self::strs(&["restore"]);
        args.push(project.0.as_str().into());
        args.extend(Self::strs(&[
            "--use-lock-file",
            "--no-dependencies",
            "--disable-build-servers",
        ]));
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

    #[test]
    fn restore_uses_the_lock_file_without_dependencies_or_force_evaluate() {
        let project = ProjectFileArg::parse("App.csproj").expect("project");
        let invocation = Invocation::dotnet_restore(Path::new("."), &project);
        assert_eq!(invocation.program(), Program::Dotnet);
        assert_eq!(
            invocation.args(),
            [
                "restore",
                "App.csproj",
                "--use-lock-file",
                "--no-dependencies",
                "--disable-build-servers"
            ]
        );
        assert!(
            invocation
                .args()
                .iter()
                .all(|arg| arg != "--force-evaluate")
        );
        assert_eq!(invocation.env(), DOTNET_ENV);
    }
}
