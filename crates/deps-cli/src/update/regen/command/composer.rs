//! Invocation shapes of Composer.

use std::ffi::OsString;
use std::path::Path;

use super::{Invocation, NonEmpty, Program, UnsafeArgument};

/// Pins Composer to the `composer.json` in the working directory, so an inherited `COMPOSER`
/// cannot redirect the lock file the run writes.
const COMPOSER_ENV: &[(&str, &str)] = &[("COMPOSER", "composer.json")];

/// A Composer package name proven safe for argv: `vendor/name`, each part over letters, digits
/// and `_.-` starting with a letter or digit, so no flag, `*` pattern, version suffix or path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::update::regen) struct ComposerPackageArg(String);

impl ComposerPackageArg {
    const MAX_LEN: usize = 214;

    /// Validates `value` as a `vendor/name` Composer package name.
    ///
    /// # Errors
    ///
    /// [`UnsafeArgument`] unless `value` is two non-empty parts joined by one `/`, each starting
    /// with an ASCII letter or digit and containing only ASCII letters, digits and `_.-`.
    pub(in crate::update::regen) fn parse(value: &str) -> Result<Self, UnsafeArgument> {
        let well_formed_part = |part: &str| {
            part.starts_with(|c: char| c.is_ascii_alphanumeric())
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        };
        let shape_ok = value
            .split_once('/')
            .is_some_and(|(vendor, name)| well_formed_part(vendor) && well_formed_part(name));
        if value.len() > Self::MAX_LEN || !shape_ok {
            return Err(UnsafeArgument);
        }
        Ok(Self(value.to_owned()))
    }
}

impl Invocation {
    /// `composer update --no-install --no-scripts --no-plugins --no-interaction <names>`:
    /// re-resolves only the named packages and writes `composer.lock`, never `vendor/`; scripts
    /// and plugins are disabled because they execute code.
    pub(in crate::update::regen) fn composer_update(
        cwd: &Path,
        names: &NonEmpty<ComposerPackageArg>,
    ) -> Self {
        let mut args = Self::strs(&["update"]);
        args.extend(names.iter().map(|name| OsString::from(&name.0)));
        args.extend(Self::strs(&[
            "--no-install",
            "--no-scripts",
            "--no-plugins",
            "--no-interaction",
        ]));
        let mut invocation = Self::new(Program::Composer, cwd, args);
        invocation.env = COMPOSER_ENV;
        invocation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_arg_accepts_vendor_name_pairs() {
        for name in [
            "monolog/monolog",
            "symfony/http-kernel",
            "a1/b_c.d-e",
            "A/B",
        ] {
            assert_eq!(ComposerPackageArg::parse(name).expect(name).0, name);
        }
    }

    #[test]
    fn package_arg_rejects_flags_patterns_and_paths() {
        for name in [
            "",
            "monolog",
            "/monolog",
            "monolog/",
            "a/b/c",
            "-x/y",
            "x/-y",
            ".x/y",
            "x/.y",
            "vendor/*",
            "*/name",
            "vendor/name:1.0",
            "vendor/name=1.0",
            "vendor/na me",
            "../x/y",
            "php",
        ] {
            assert!(ComposerPackageArg::parse(name).is_err(), "{name}");
        }
    }

    #[test]
    fn update_names_the_packages_first_and_disables_code_execution() {
        let names = NonEmpty::new(vec![
            ComposerPackageArg::parse("a/b").expect("name"),
            ComposerPackageArg::parse("c/d").expect("name"),
        ])
        .expect("non-empty");
        let invocation = Invocation::composer_update(Path::new("."), &names);
        let args: Vec<_> = invocation
            .args()
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            [
                "update",
                "a/b",
                "c/d",
                "--no-install",
                "--no-scripts",
                "--no-plugins",
                "--no-interaction"
            ]
        );
        assert_eq!(invocation.env(), [("COMPOSER", "composer.json")]);
        assert_eq!(invocation.program(), Program::Composer);
    }
}
