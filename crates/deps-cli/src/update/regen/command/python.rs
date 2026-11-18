//! Invocation shapes of the Python lockers: uv, Poetry and PDM.

use std::ffi::OsString;
use std::path::Path;

use super::{ArgComponent, Invocation, NonEmpty, Program};

/// Disables every PDM script hook (`pre_lock`, `post_lock`, ...) the repository defines.
const PDM_SKIP_HOOKS: &str = "--skip=:all";

/// Ignores a committed `.pdm-python`, which would otherwise select a repository-chosen
/// interpreter to run.
const PDM_ENV: &[(&str, &str)] = &[("PDM_IGNORE_SAVED_PYTHON", "1")];

/// How Poetry keeps unrelated pins while `poetry lock` re-resolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::update::regen) enum PoetryLockStyle {
    /// Poetry 1.x re-resolves everything unless `--no-update` is given.
    NoUpdateFlag,
    /// Poetry 2+ keeps locked versions by default.
    KeepsLocked,
}

impl Invocation {
    /// `poetry --no-plugins --version`: plugins are repository-controlled code, so even the
    /// probe runs without them.
    pub(in crate::update::regen) fn poetry_version(cwd: &Path) -> Self {
        Self::new(
            Program::Poetry,
            cwd,
            Self::strs(&["--no-plugins", "--version"]),
        )
    }

    /// `poetry lock --no-interaction --no-plugins [--no-update]`: re-resolves against the edited
    /// `pyproject.toml` while keeping every pin that still satisfies it; plugins are disabled
    /// because they execute code.
    pub(in crate::update::regen) fn poetry_lock(cwd: &Path, style: PoetryLockStyle) -> Self {
        let mut args = Self::strs(&["lock", "--no-interaction", "--no-plugins"]);
        if style == PoetryLockStyle::NoUpdateFlag {
            args.push("--no-update".into());
        }
        Self::new(Program::Poetry, cwd, args)
    }

    /// `poetry update --lock --no-interaction --no-plugins <names>`: moves only the named
    /// packages and writes no environment.
    pub(in crate::update::regen) fn poetry_update_lock(
        cwd: &Path,
        names: &NonEmpty<ArgComponent>,
    ) -> Self {
        let mut args = Self::strs(&["update", "--lock", "--no-interaction", "--no-plugins"]);
        args.extend(names.iter().map(|name| OsString::from(name.as_str())));
        Self::new(Program::Poetry, cwd, args)
    }

    /// `pdm lock --update-reuse --skip=:all`: re-resolves reusing every pin that still
    /// satisfies, without the repository's `[tool.pdm.scripts]` lock hooks.
    pub(in crate::update::regen) fn pdm_lock(cwd: &Path) -> Self {
        let mut invocation = Self::new(
            Program::Pdm,
            cwd,
            Self::strs(&["lock", "--update-reuse", PDM_SKIP_HOOKS]),
        );
        invocation.env = PDM_ENV;
        invocation
    }

    /// `pdm update --no-sync --skip=:all <names>`: moves only the named packages, installs
    /// nothing and runs no repository hooks.
    pub(in crate::update::regen) fn pdm_update_no_sync(
        cwd: &Path,
        names: &NonEmpty<ArgComponent>,
    ) -> Self {
        let mut args = Self::strs(&["update", "--no-sync", PDM_SKIP_HOOKS]);
        args.extend(names.iter().map(|name| OsString::from(name.as_str())));
        let mut invocation = Self::new(Program::Pdm, cwd, args);
        invocation.env = PDM_ENV;
        invocation
    }

    /// `uv lock --no-build --no-python-downloads` with one `--upgrade-package <name>==<version>`
    /// per pin: no sdist build, no interpreter download, exact versions only.
    pub(in crate::update::regen) fn uv_lock(
        cwd: &Path,
        pins: &NonEmpty<(ArgComponent, ArgComponent)>,
    ) -> Self {
        let mut args = Self::strs(&["lock", "--no-build", "--no-python-downloads"]);
        for (name, version) in pins.iter() {
            args.push("--upgrade-package".into());
            args.push(format!("{}=={}", name.as_str(), version.as_str()).into());
        }
        Self::new(Program::Uv, cwd, args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uv_lock_emits_one_upgrade_flag_per_pin() {
        let pin = |n: &str, v: &str| {
            (
                ArgComponent::parse(n).expect("name"),
                ArgComponent::parse(v).expect("version"),
            )
        };
        let pins = NonEmpty::new(vec![pin("a", "1.0.0"), pin("b", "2.0.0")]).expect("non-empty");
        let invocation = Invocation::uv_lock(Path::new("."), &pins);
        let args: Vec<_> = invocation
            .args()
            .iter()
            .map(|arg| arg.to_string_lossy())
            .collect();
        assert_eq!(
            args,
            [
                "lock",
                "--no-build",
                "--no-python-downloads",
                "--upgrade-package",
                "a==1.0.0",
                "--upgrade-package",
                "b==2.0.0"
            ]
        );
    }

    fn lossy(invocation: &Invocation) -> Vec<String> {
        invocation
            .args()
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    fn names(values: &[&str]) -> NonEmpty<ArgComponent> {
        NonEmpty::new(
            values
                .iter()
                .map(|value| ArgComponent::parse(value).expect("name"))
                .collect(),
        )
        .expect("non-empty")
    }

    #[test]
    fn poetry_version_probe_disables_plugins() {
        let probe = Invocation::poetry_version(Path::new("."));
        assert_eq!(lossy(&probe), ["--no-plugins", "--version"]);
    }

    #[test]
    fn poetry_lock_adds_no_update_only_for_the_one_x_style() {
        let base = ["lock", "--no-interaction", "--no-plugins"];
        let one = Invocation::poetry_lock(Path::new("."), PoetryLockStyle::NoUpdateFlag);
        let two = Invocation::poetry_lock(Path::new("."), PoetryLockStyle::KeepsLocked);
        assert_eq!(
            lossy(&one),
            ["lock", "--no-interaction", "--no-plugins", "--no-update"]
        );
        assert_eq!(lossy(&two), base);
        assert_eq!(one.program(), Program::Poetry);
    }

    #[test]
    fn poetry_update_lock_names_the_packages_last_and_never_installs() {
        let invocation = Invocation::poetry_update_lock(Path::new("."), &names(&["a", "b"]));
        assert_eq!(
            lossy(&invocation),
            [
                "update",
                "--lock",
                "--no-interaction",
                "--no-plugins",
                "a",
                "b"
            ]
        );
    }

    #[test]
    fn pdm_shapes_reuse_pins_and_skip_the_install() {
        let lock = Invocation::pdm_lock(Path::new("."));
        let update = Invocation::pdm_update_no_sync(Path::new("."), &names(&["a"]));
        assert_eq!(lossy(&lock), ["lock", "--update-reuse", "--skip=:all"]);
        assert_eq!(lossy(&update), ["update", "--no-sync", "--skip=:all", "a"]);
        for invocation in [&lock, &update] {
            assert_eq!(invocation.env(), [("PDM_IGNORE_SAVED_PYTHON", "1")]);
        }
        assert_eq!(update.program(), Program::Pdm);
    }
}
