//! Invocation shapes of Gradle (#2085).

use std::path::Path;

use super::{Invocation, NonEmpty, Program, UnsafeArgument};

/// A Gradle module coordinate `group:artifact` proven safe for `--update-locks`: two non-empty
/// parts over letters, digits and `-_.`, so no version, no `*` wildcard, no `,` (the list
/// separator) and no leading `-`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::update::regen) struct GradleCoordArg(String);

impl GradleCoordArg {
    const MAX_LEN: usize = 256;

    /// Validates `value` as a `group:artifact` coordinate.
    ///
    /// # Errors
    ///
    /// [`UnsafeArgument`] when `value` breaks the rules above.
    pub(in crate::update::regen) fn parse(value: &str) -> Result<Self, UnsafeArgument> {
        let part_ok = |part: &str| {
            !part.is_empty()
                && !part.starts_with('-')
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        };
        let well_formed = value.len() <= Self::MAX_LEN
            && value
                .split_once(':')
                .is_some_and(|(group, artifact)| part_ok(group) && part_ok(artifact));
        if !well_formed {
            return Err(UnsafeArgument);
        }
        Ok(Self(value.to_owned()))
    }
}

/// A Gradle project path derived from a project directory below the build root
/// (`libs/core` -> `:libs:core`), the root project being the empty path. Safe for argv: normal
/// UTF-8 components over letters, digits and `-_.`, never a leading `-`.
///
/// Assumes the directory name is the project name; a build that remaps `projectDir` in
/// `settings.gradle` fails verification instead of locking the wrong project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::update::regen) struct GradleProjectPath(String);

impl GradleProjectPath {
    /// Derives the project path from `relative`, the directory below the build root.
    ///
    /// # Errors
    ///
    /// [`UnsafeArgument`] for a component that is not a plain name (`.`, `..`, a root or
    /// prefix), is not UTF-8, starts with `-`, or holds a character outside `A-Za-z0-9-_.`.
    pub(in crate::update::regen) fn of(relative: &Path) -> Result<Self, UnsafeArgument> {
        let mut path = String::new();
        for component in relative.components() {
            let std::path::Component::Normal(part) = component else {
                return Err(UnsafeArgument);
            };
            let part = part.to_str().ok_or(UnsafeArgument)?;
            let well_formed = !part.starts_with('-')
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
            if !well_formed {
                return Err(UnsafeArgument);
            }
            path.push(':');
            path.push_str(part);
        }
        Ok(Self(path))
    }

    /// The `dependencies` task of this project (`:app:dependencies`, `:dependencies` for the
    /// root).
    fn task(&self) -> String {
        format!("{}:dependencies", self.0)
    }
}

impl Invocation {
    /// The first spawn of a legacy-layout migration: `--update-locks` for a module that does not
    /// exist, so Gradle writes the unified lock files without moving any real dependency.
    pub(in crate::update::regen) fn gradle_migrate_locks(
        cwd: &Path,
        projects: &NonEmpty<GradleProjectPath>,
    ) -> Self {
        Self::gradle_with_update_locks(cwd, projects, "invalid.deps-cli:lock-layout-migration")
    }

    /// `gradle --no-daemon --console=plain <:p:dependencies>... --update-locks <g:a,...>`, run at
    /// the build root: the report task runs only in the project it names, so each project that
    /// owns a lock file gets its own; only the named modules are re-resolved.
    pub(in crate::update::regen) fn gradle_update_locks(
        cwd: &Path,
        projects: &NonEmpty<GradleProjectPath>,
        coordinates: &NonEmpty<GradleCoordArg>,
    ) -> Self {
        let joined = coordinates
            .iter()
            .map(|coordinate| coordinate.0.as_str())
            .collect::<Vec<_>>()
            .join(",");
        Self::gradle_with_update_locks(cwd, projects, &joined)
    }

    fn gradle_with_update_locks(
        cwd: &Path,
        projects: &NonEmpty<GradleProjectPath>,
        modules: &str,
    ) -> Self {
        let mut args = Self::strs(&["--no-daemon", "--console=plain"]);
        args.extend(projects.iter().map(|project| project.task().into()));
        args.push("--update-locks".into());
        args.push(modules.into());
        Self::new(Program::Gradle, cwd, args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coordinate_accepts_group_and_artifact() {
        for value in ["com.google.guava:guava", "org.a_b:c-d.e", "a:b"] {
            assert!(GradleCoordArg::parse(value).is_ok(), "{value}");
        }
    }

    #[test]
    fn coordinate_rejects_versions_wildcards_lists_and_flags() {
        for value in [
            "", "a", "a:", ":b", "a:b:1.0", "a:b*", "*:b", "a:b,c:d", "-a:b", "a:-b", "a b:c",
            "a:b;c",
        ] {
            assert!(GradleCoordArg::parse(value).is_err(), "{value}");
        }
        assert!(GradleCoordArg::parse(&format!("a:{}", "b".repeat(256))).is_err());
    }

    fn project(relative: &str) -> GradleProjectPath {
        GradleProjectPath::of(Path::new(relative)).expect(relative)
    }

    #[test]
    fn project_path_is_the_colon_joined_directory() {
        assert_eq!(project("").task(), ":dependencies");
        assert_eq!(project("app").task(), ":app:dependencies");
        assert_eq!(
            project("libs/core-x_1.2").task(),
            ":libs:core-x_1.2:dependencies"
        );
    }

    #[test]
    fn project_path_rejects_unsafe_directories() {
        for relative in [
            "../x", "/abs", "./a", "a b", "-x", "a:b", "a*", "a;b", "ä", "a/../b",
        ] {
            assert!(
                GradleProjectPath::of(Path::new(relative)).is_err(),
                "{relative}"
            );
        }
    }

    #[test]
    fn migrate_locks_updates_a_module_that_does_not_exist() {
        let projects = NonEmpty::new(vec![project("app")]).expect("non-empty");
        let invocation = Invocation::gradle_migrate_locks(Path::new("."), &projects);
        assert_eq!(
            invocation.args(),
            [
                "--no-daemon",
                "--console=plain",
                ":app:dependencies",
                "--update-locks",
                "invalid.deps-cli:lock-layout-migration"
            ]
        );
    }

    #[test]
    fn update_locks_runs_every_project_task_then_names_the_modules() {
        let projects = NonEmpty::new(vec![project(""), project("app")]).expect("non-empty");
        let coordinates = NonEmpty::new(vec![
            GradleCoordArg::parse("g:a").expect("g:a"),
            GradleCoordArg::parse("h:b").expect("h:b"),
        ])
        .expect("non-empty");
        let invocation = Invocation::gradle_update_locks(Path::new("."), &projects, &coordinates);
        assert_eq!(invocation.program(), Program::Gradle);
        assert_eq!(
            invocation.args(),
            [
                "--no-daemon",
                "--console=plain",
                ":dependencies",
                ":app:dependencies",
                "--update-locks",
                "g:a,h:b"
            ]
        );
    }
}
