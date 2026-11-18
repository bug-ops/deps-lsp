//! Invocation shapes of the uv, Bundler and Deno lockers (#2046).

use std::ffi::OsString;
use std::path::Path;

use super::{ArgComponent, Invocation, Program, UnsafeArgument};

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

/// A `deno update` filter proven safe for argv: the bare package name (`chalk`, `@std/fs`),
/// never a flag, glob or path traversal. The `npm:`/`jsr:` scheme is stripped because
/// `deno update` matches names without it (`npm:chalk` matches nothing, `jsr:@std/fs` is
/// rejected).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::update::regen) struct DenoFilter(String);

impl DenoFilter {
    const MAX_LEN: usize = 256;

    /// Validates the scheme-qualified (or bare) package name `value` as a `deno update` filter.
    ///
    /// # Errors
    ///
    /// [`UnsafeArgument`] for an empty or over-long name, a leading `-`, `.` or `/`, `..`, `//`,
    /// or any character outside letters, digits and `-_.~@/`.
    pub(in crate::update::regen) fn parse(value: &str) -> Result<Self, UnsafeArgument> {
        let value = value
            .strip_prefix("npm:")
            .or_else(|| value.strip_prefix("jsr:"))
            .unwrap_or(value);
        let allowed =
            |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~' | '@' | '/');
        let malformed = value.is_empty()
            || value.len() > Self::MAX_LEN
            || value.starts_with(['-', '.', '/'])
            || value.contains("..")
            || value.contains("//")
            || !value.chars().all(allowed);
        if malformed {
            return Err(UnsafeArgument);
        }
        Ok(Self(value.to_owned()))
    }
}

const DENO_LOCK_FLAG: &str = "--lock=./deno.lock";

impl Invocation {
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

    /// `bundle lock`: re-resolves against the edited Gemfile.
    pub(in crate::update::regen) fn bundle_lock(cwd: &Path) -> Self {
        Self::new(Program::Bundle, cwd, Self::strs(&["lock"]))
    }

    /// `bundle lock --conservative --update <names>`: moves only the named gems, leaving their
    /// shared dependencies alone. `--conservative` must precede `--update`, whose optional list
    /// argument would otherwise swallow it.
    pub(in crate::update::regen) fn bundle_lock_update(
        cwd: &Path,
        names: &NonEmpty<ArgComponent>,
    ) -> Self {
        let mut args = Self::strs(&["lock", "--conservative", "--update"]);
        args.extend(names.iter().map(|name| OsString::from(name.as_str())));
        Self::new(Program::Bundle, cwd, args)
    }

    /// `deno install --lockfile-only --lock=./deno.lock`; the explicit path overrides a `lock`
    /// key in `deno.json` that would redirect the write outside the snapshot.
    pub(in crate::update::regen) fn deno_install_lockfile_only(cwd: &Path) -> Self {
        Self::new(
            Program::Deno,
            cwd,
            Self::strs(&["install", "--lockfile-only", DENO_LOCK_FLAG]),
        )
    }

    /// `deno update --compatible --lockfile-only --lock=./deno.lock <filters>`: semver-compatible
    /// moves only.
    pub(in crate::update::regen) fn deno_update_lockfile_only(
        cwd: &Path,
        filters: &NonEmpty<DenoFilter>,
    ) -> Self {
        let mut args = Self::strs(&["update", "--compatible", "--lockfile-only", DENO_LOCK_FLAG]);
        args.extend(filters.iter().map(|filter| OsString::from(&filter.0)));
        Self::new(Program::Deno, cwd, args)
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

    #[test]
    fn deno_filter_strips_the_scheme() {
        for (name, bare) in [
            ("chalk", "chalk"),
            ("npm:chalk", "chalk"),
            ("jsr:@std/fs", "@std/fs"),
            ("npm:@scope/pkg", "@scope/pkg"),
        ] {
            assert_eq!(DenoFilter::parse(name).expect(name).0, bare);
        }
    }

    #[test]
    fn deno_filter_rejects_flags_globs_and_traversal() {
        for name in [
            "", "--lock", "-x", "./a", "/etc", "a/../b", "a//b", "a*", "a b", "a;b", "x:y", "npm:",
        ] {
            assert!(DenoFilter::parse(name).is_err(), "{name}");
        }
    }

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
}
