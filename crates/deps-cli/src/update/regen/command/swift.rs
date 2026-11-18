//! Invocation shapes of SwiftPM (#2086).

use std::ffi::OsString;
use std::path::Path;

use super::{Invocation, NonEmpty, Program, UnsafeArgument};

/// A SwiftPM package identity proven safe for argv, derived from the dependency name the
/// manifest parser reports: `owner/repo` yields the lowercase `repo` (SwiftPM's identity for
/// the location), a bare name is the identity itself. Never a flag, URL or path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::update::regen) struct SwiftIdentityArg(String);

impl SwiftIdentityArg {
    const MAX_LEN: usize = 128;

    /// Derives the identity from `name` (`owner/repo` or a bare identity); ASCII upper case is
    /// folded to lower case.
    ///
    /// # Errors
    ///
    /// [`UnsafeArgument`] for more than one `/`, an empty or over-long part, a leading `-` or
    /// `.`, or any character outside letters, digits and `-_.`.
    pub(in crate::update::regen) fn parse(name: &str) -> Result<Self, UnsafeArgument> {
        let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.');
        let part_ok = |part: &str| {
            !part.is_empty()
                && part.len() <= Self::MAX_LEN
                && !part.starts_with(['-', '.'])
                && part.chars().all(allowed)
        };
        let identity = match name.split_once('/') {
            Some((owner, repo)) if part_ok(owner) => repo,
            Some(_) => return Err(UnsafeArgument),
            None => name,
        };
        if !part_ok(identity) {
            return Err(UnsafeArgument);
        }
        Ok(Self(identity.to_ascii_lowercase()))
    }
}

impl Invocation {
    /// `swift package resolve`: re-resolves against the edited `Package.swift`, keeping pins
    /// that still satisfy it.
    pub(in crate::update::regen) fn swift_package_resolve(cwd: &Path) -> Self {
        Self::new(Program::Swift, cwd, Self::strs(&["package", "resolve"]))
    }

    /// `swift package update <identities>`: moves only the named packages.
    pub(in crate::update::regen) fn swift_package_update(
        cwd: &Path,
        identities: &NonEmpty<SwiftIdentityArg>,
    ) -> Self {
        let mut args = Self::strs(&["package", "update"]);
        args.extend(
            identities
                .iter()
                .map(|identity| OsString::from(&identity.0)),
        );
        Self::new(Program::Swift, cwd, args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_of_owner_repo_is_the_lowercase_repo() {
        assert_eq!(
            SwiftIdentityArg::parse("apple/Swift-Log")
                .expect("identity")
                .0,
            "swift-log"
        );
    }

    #[test]
    fn identity_is_lowercased() {
        assert_eq!(
            SwiftIdentityArg::parse("Swift-Argument.Parser_2")
                .expect("identity")
                .0,
            "swift-argument.parser_2"
        );
    }

    #[test]
    fn identity_rejects_flags_urls_paths_and_globs() {
        for value in [
            "",
            "-x",
            "--help",
            ".hidden",
            "a/b/c",
            "/repo",
            "owner/",
            "-o/repo",
            "owner/-repo",
            "a b",
            "a*",
            "https://x/y",
            "a;b",
            "ä",
            "a@b",
        ] {
            assert!(SwiftIdentityArg::parse(value).is_err(), "{value}");
        }
        assert!(SwiftIdentityArg::parse(&"a".repeat(129)).is_err());
    }

    #[test]
    fn update_names_every_identity_after_the_subcommand() {
        let names = NonEmpty::new(vec![
            SwiftIdentityArg::parse("a").expect("a"),
            SwiftIdentityArg::parse("b").expect("b"),
        ])
        .expect("non-empty");
        let invocation = Invocation::swift_package_update(Path::new("."), &names);
        assert_eq!(invocation.program(), Program::Swift);
        assert_eq!(invocation.args(), ["package", "update", "a", "b"]);
    }

    #[test]
    fn resolve_takes_no_names() {
        assert_eq!(
            Invocation::swift_package_resolve(Path::new(".")).args(),
            ["package", "resolve"]
        );
    }
}
