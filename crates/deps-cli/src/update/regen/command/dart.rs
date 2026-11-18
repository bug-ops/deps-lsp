//! Invocation shapes of Dart's and Flutter's `pub`.

use std::ffi::OsString;
use std::path::Path;

use super::{Invocation, NonEmpty, Program, UnsafeArgument};

/// The front end that runs `pub` for a package: Flutter packages need `flutter pub`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::update::regen) enum PubTool {
    /// `dart pub`.
    Dart,
    /// `flutter pub`.
    Flutter,
}

impl PubTool {
    pub(in crate::update::regen) const fn program(self) -> Program {
        match self {
            Self::Dart => Program::Dart,
            Self::Flutter => Program::Flutter,
        }
    }
}

/// A pub package name proven safe for argv: lowercase letters, digits and `_`, not starting
/// with a digit (the Dart package-name grammar).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::update::regen) struct PubPackageArg(String);

impl PubPackageArg {
    /// Validates `value` as a pub package name.
    ///
    /// # Errors
    ///
    /// [`UnsafeArgument`] for an empty name, one that starts with a digit, or one with a
    /// character outside `a-z`, `0-9` and `_`.
    pub(in crate::update::regen) fn parse(value: &str) -> Result<Self, UnsafeArgument> {
        let well_formed = !value.is_empty()
            && !value.starts_with(|c: char| c.is_ascii_digit())
            && value
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if !well_formed {
            return Err(UnsafeArgument);
        }
        Ok(Self(value.to_owned()))
    }
}

/// `--no-example` keeps the run out of `example/`, whose own `pubspec.lock` is not the one
/// being regenerated (verified with Dart 3.14 and Flutter 3.44).
const PUB_FLAGS: [&str; 1] = ["--no-example"];

impl Invocation {
    /// `<tool> pub get --no-example`: re-resolves against the edited
    /// `pubspec.yaml`, keeping every locked version that still satisfies it.
    pub(in crate::update::regen) fn pub_get(cwd: &Path, tool: PubTool) -> Self {
        let mut args = Self::strs(&["pub", "get"]);
        args.extend(Self::strs(&PUB_FLAGS));
        Self::new(tool.program(), cwd, args)
    }

    /// `<tool> pub upgrade --no-example <names>`: moves only the named packages.
    pub(in crate::update::regen) fn pub_upgrade(
        cwd: &Path,
        tool: PubTool,
        names: &NonEmpty<PubPackageArg>,
    ) -> Self {
        let mut args = Self::strs(&["pub", "upgrade"]);
        args.extend(Self::strs(&PUB_FLAGS));
        args.extend(names.iter().map(|name| OsString::from(&name.0)));
        Self::new(tool.program(), cwd, args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lossy(invocation: &Invocation) -> Vec<String> {
        invocation
            .args()
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn pub_get_runs_through_the_chosen_front_end() {
        let dart = Invocation::pub_get(Path::new("."), PubTool::Dart);
        let flutter = Invocation::pub_get(Path::new("."), PubTool::Flutter);
        assert_eq!(dart.program(), Program::Dart);
        assert_eq!(flutter.program(), Program::Flutter);
        assert_eq!(lossy(&dart), ["pub", "get", "--no-example"]);
        assert_eq!(lossy(&dart), lossy(&flutter));
    }

    #[test]
    fn pub_upgrade_names_the_packages_last() {
        let names = NonEmpty::new(vec![
            PubPackageArg::parse("http").expect("name"),
            PubPackageArg::parse("path_provider").expect("name"),
        ])
        .expect("non-empty");
        let invocation = Invocation::pub_upgrade(Path::new("."), PubTool::Dart, &names);
        assert_eq!(
            lossy(&invocation),
            ["pub", "upgrade", "--no-example", "http", "path_provider"]
        );
    }

    #[test]
    fn package_arg_follows_the_dart_name_grammar() {
        for name in ["http", "path_provider", "a1", "_private"] {
            assert!(PubPackageArg::parse(name).is_ok(), "{name}");
        }
        for name in [
            "", "1abc", "-x", "A", "a-b", "a.b", "a b", "a/b", "a:1", "*",
        ] {
            assert!(PubPackageArg::parse(name).is_err(), "{name}");
        }
    }
}
