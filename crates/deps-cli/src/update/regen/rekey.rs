//! Lock-file re-keying for cooldown-fallback pins (#2097).
//!
//! Yarn Berry and Deno key their lock file by the declared requirement. A fallback target is
//! locked under an exact requirement written into the manifest for one install; before the
//! manifest goes back, the lock key is renamed from the pinned descriptor to the declared one so
//! the second install keeps the pinned resolution.

use deps_core::{ConcreteVersion, PackageName, VersionReq};

/// Why a cooldown-fallback pin could not be kept in the lock file after the manifest write-back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekeyRefusal {
    /// No lock entry holds the pinned descriptor.
    PinnedEntryMissing,
    /// More than one lock entry holds the pinned descriptor.
    PinnedEntryAmbiguous,
    /// The lock file already holds the declared descriptor.
    DeclaredRangeAlreadyLocked,
    /// The lock file does not parse.
    UnparsableLock,
}

impl std::fmt::Display for RekeyRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::PinnedEntryMissing => "no lock entry holds the pinned version",
            Self::PinnedEntryAmbiguous => "several lock entries hold the pinned version",
            Self::DeclaredRangeAlreadyLocked => "the lock file already holds the declared range",
            Self::UnparsableLock => "the lock file could not be parsed",
        })
    }
}

/// One pinned descriptor to rename back to the declared requirement.
#[derive(Debug, Clone)]
pub(super) struct LockRekey {
    pub(super) package: PackageName,
    pub(super) pinned: ConcreteVersion,
    pub(super) declared: VersionReq,
}

/// Whether `declared` is a plain version range that can sit inside a lock key unquoted:
/// no protocol, alias, separator, quote, escape or whitespace.
pub(super) fn is_plain_range(declared: &str) -> bool {
    !declared.is_empty()
        && declared.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '.' | '-' | '+' | '_' | '^' | '~' | '*' | '<' | '>' | '=')
        })
}

/// Renames `<name>@npm:<pinned>` to `<name>@npm:<declared>` inside exactly one Yarn Berry entry
/// header per rekey; every other byte is unchanged.
///
/// # Errors
///
/// [`RekeyRefusal::PinnedEntryMissing`] when no header holds the pinned descriptor,
/// [`RekeyRefusal::PinnedEntryAmbiguous`] when several do, and
/// [`RekeyRefusal::DeclaredRangeAlreadyLocked`] when a header already holds the declared one.
pub(super) fn yarn(text: &str, rekeys: &[LockRekey]) -> Result<String, RekeyRefusal> {
    let mut lines: Vec<String> = text.split_inclusive('\n').map(str::to_owned).collect();
    for rekey in rekeys {
        let pinned = format!("{}@npm:{}", rekey.package.as_str(), rekey.pinned.as_str());
        let declared = format!("{}@npm:{}", rekey.package.as_str(), rekey.declared.as_str());
        let holding = |lines: &[String], descriptor: &str| -> Vec<usize> {
            lines
                .iter()
                .enumerate()
                .filter(|(_, line)| {
                    Header::parse(line).is_some_and(|header| header.holds(descriptor))
                })
                .map(|(index, _)| index)
                .collect()
        };
        let pinned_at = match holding(&lines, &pinned).as_slice() {
            [] => return Err(RekeyRefusal::PinnedEntryMissing),
            [only] => *only,
            _ => return Err(RekeyRefusal::PinnedEntryAmbiguous),
        };
        if !holding(&lines, &declared).is_empty() {
            return Err(RekeyRefusal::DeclaredRangeAlreadyLocked);
        }
        let line = lines
            .get_mut(pinned_at)
            .ok_or(RekeyRefusal::PinnedEntryMissing)?;
        let renamed = Header::parse(line)
            .ok_or(RekeyRefusal::PinnedEntryMissing)?
            .renamed(&pinned, &declared);
        *line = renamed;
    }
    Ok(lines.concat())
}

/// A Yarn Berry lock entry header: `"a@npm:1, b@npm:2":`.
struct Header<'a> {
    descriptors: Vec<&'a str>,
    quoted: bool,
    ending: &'a str,
}

impl<'a> Header<'a> {
    fn parse(line: &'a str) -> Option<Self> {
        if line.starts_with([' ', '\t', '#']) || line.starts_with("__metadata") {
            return None;
        }
        let body = line.trim_end_matches(['\r', '\n']);
        let ending = line.strip_prefix(body).unwrap_or_default();
        let key = body.strip_suffix(':')?;
        let (key, quoted) = match key.strip_prefix('"').and_then(|k| k.strip_suffix('"')) {
            Some(inner) => (inner, true),
            None => (key, false),
        };
        Some(Self {
            descriptors: key.split(", ").collect(),
            quoted,
            ending,
        })
    }

    fn holds(&self, descriptor: &str) -> bool {
        self.descriptors.contains(&descriptor)
    }

    fn renamed(&self, from: &str, to: &str) -> String {
        let joined = self
            .descriptors
            .iter()
            .map(|descriptor| if *descriptor == from { to } else { descriptor })
            .collect::<Vec<_>>()
            .join(", ");
        let quote = if self.quoted { "\"" } else { "" };
        format!("{quote}{joined}{quote}:{}", self.ending)
    }
}

/// The specifier schemes Deno locks packages under.
const DENO_SCHEMES: [&str; 2] = ["npm", "jsr"];

/// Renames every occurrence of the JSON string `"<scheme>:<name>@<pinned>"` to the declared
/// specifier: the `specifiers` key and its `workspace.dependencies` value.
///
/// # Errors
///
/// [`RekeyRefusal::UnparsableLock`] when the input or the result is not JSON,
/// [`RekeyRefusal::PinnedEntryMissing`] when `specifiers` has no pinned key (or the package name
/// has no scheme), and [`RekeyRefusal::DeclaredRangeAlreadyLocked`] when the declared key already exists.
pub(super) fn deno(text: &str, rekeys: &[LockRekey]) -> Result<String, RekeyRefusal> {
    let mut out = text.to_owned();
    for rekey in rekeys {
        let lock: serde_json::Value =
            serde_json::from_str(&out).map_err(|_| RekeyRefusal::UnparsableLock)?;
        let specifiers = lock
            .get("specifiers")
            .and_then(serde_json::Value::as_object)
            .ok_or(RekeyRefusal::PinnedEntryMissing)?;
        // Deno package names always carry their scheme (`npm:chalk`).
        let name = rekey.package.as_str();
        let (scheme, bare) = DENO_SCHEMES
            .into_iter()
            .find_map(|scheme| {
                name.strip_prefix(scheme)
                    .and_then(|rest| rest.strip_prefix(':'))
                    .map(|bare| (scheme, bare))
            })
            .ok_or(RekeyRefusal::PinnedEntryMissing)?;
        let key = |version: &str| format!("{scheme}:{bare}@{version}");
        if !specifiers.contains_key(&key(rekey.pinned.as_str())) {
            return Err(RekeyRefusal::PinnedEntryMissing);
        }
        let declared_key = key(rekey.declared.as_str());
        if specifiers.contains_key(&declared_key) {
            return Err(RekeyRefusal::DeclaredRangeAlreadyLocked);
        }
        out = out.replace(
            &json_literal(&key(rekey.pinned.as_str())),
            &json_literal(&declared_key),
        );
    }
    serde_json::from_str::<serde_json::Value>(&out).map_err(|_| RekeyRefusal::UnparsableLock)?;
    Ok(out)
}

fn json_literal(value: &str) -> String {
    serde_json::Value::String(value.to_owned()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rekey(package: &str, pinned: &str, declared: &str) -> LockRekey {
        LockRekey {
            package: PackageName::new(package),
            pinned: ConcreteVersion::from(pinned),
            declared: VersionReq::new(declared),
        }
    }

    const YARN: &str = "__metadata:\n  version: 8\n\n\"a@npm:^2.0.0\":\n  version: 2.0.1\n\n\"x@npm:1.2.8\":\n  version: 1.2.8\n";

    #[test]
    fn plain_ranges_exclude_protocols_separators_and_quotes() {
        for good in ["^1.2.0", "~1.2", "1.x", "*", ">=1.0.0", "1.2.3-beta.1"] {
            assert!(is_plain_range(good), "{good}");
        }
        for bad in ["", "npm:y@^1", "a, b", "\"1\"", "1\\2", ">=1 <2", "1\n"] {
            assert!(!is_plain_range(bad), "{bad:?}");
        }
    }

    #[test]
    fn yarn_renames_only_the_pinned_descriptor() {
        let out = yarn(YARN, &[rekey("x", "1.2.8", "^1.2.5")]).expect("rekeyed");

        assert_eq!(out, YARN.replace("\"x@npm:1.2.8\":", "\"x@npm:^1.2.5\":"));
    }

    #[test]
    fn yarn_renames_one_descriptor_of_a_merged_header() {
        let text = "\"x@npm:1.2.8, x@npm:^1.0.0\":\n  version: 1.2.8\n";

        let out = yarn(text, &[rekey("x", "1.2.8", "~1.2.0")]).expect("rekeyed");

        assert_eq!(out, "\"x@npm:~1.2.0, x@npm:^1.0.0\":\n  version: 1.2.8\n");
    }

    #[test]
    fn yarn_refuses_a_missing_ambiguous_or_already_locked_entry() {
        let both = "\"x@npm:1.2.8\":\n  v: 1\n\n\"x@npm:1.2.8, y@npm:1\":\n  v: 1\n";
        let declared = "\"x@npm:^1.2.5\":\n  v: 1\n\n\"x@npm:1.2.8\":\n  v: 1\n";
        let r = [rekey("x", "1.2.8", "^1.2.5")];

        assert_eq!(
            yarn(YARN, &[rekey("x", "9.9.9", "^1")]),
            Err(RekeyRefusal::PinnedEntryMissing)
        );
        assert_eq!(yarn(both, &r), Err(RekeyRefusal::PinnedEntryAmbiguous));
        assert_eq!(
            yarn(declared, &r),
            Err(RekeyRefusal::DeclaredRangeAlreadyLocked)
        );
    }

    #[test]
    fn yarn_shared_header_with_the_declared_descriptor_is_refused() {
        let text = "\"x@npm:1.2.8, x@npm:^1.2.5\":\n  v: 1\n";

        assert_eq!(
            yarn(text, &[rekey("x", "1.2.8", "^1.2.5")]),
            Err(RekeyRefusal::DeclaredRangeAlreadyLocked)
        );
    }

    #[test]
    fn yarn_rekey_is_not_repeatable() {
        let r = [rekey("x", "1.2.8", "^1.2.5")];
        let once = yarn(YARN, &r).expect("rekeyed");

        assert_eq!(yarn(&once, &r), Err(RekeyRefusal::PinnedEntryMissing));
    }

    const DENO: &str = "{\n  \"specifiers\": {\n    \"jsr:@std/path@1.0.0\": \"1.0.0\",\n    \"npm:b@^1\": \"1.1.0\"\n  },\n  \"workspace\": {\n    \"dependencies\": [\n      \"jsr:@std/path@1.0.0\"\n    ]\n  }\n}\n";

    #[test]
    fn deno_renames_the_key_and_the_workspace_dependency_under_either_scheme() {
        let out = deno(DENO, &[rekey("jsr:@std/path", "1.0.0", "^1.0.0")]).expect("rekeyed");

        assert_eq!(
            out,
            DENO.replace("jsr:@std/path@1.0.0", "jsr:@std/path@^1.0.0")
        );
        assert!(!out.contains("@std/path@1.0.0"));
    }

    #[test]
    fn deno_refuses_unparsable_missing_and_already_locked() {
        let r = [rekey("jsr:@std/path", "1.0.0", "^1.0.0")];
        let locked = DENO.replace("\"npm:b@^1\"", "\"jsr:@std/path@^1.0.0\"");

        assert_eq!(deno("{ nope", &r), Err(RekeyRefusal::UnparsableLock));
        assert_eq!(deno("{}", &r), Err(RekeyRefusal::PinnedEntryMissing));
        assert_eq!(
            deno(&locked, &r),
            Err(RekeyRefusal::DeclaredRangeAlreadyLocked)
        );
    }

    #[test]
    fn deno_needs_a_package_name_that_carries_its_scheme() {
        let text = "{\"specifiers\":{\"npm:x@1.0.0\":\"1.0.0\"}}";

        let out = deno(text, &[rekey("npm:x", "1.0.0", "^1")]).expect("rekeyed");

        assert_eq!(out, "{\"specifiers\":{\"npm:x@^1\":\"1.0.0\"}}");
        assert_eq!(
            deno(text, &[rekey("jsr:x", "1.0.0", "^1")]),
            Err(RekeyRefusal::PinnedEntryMissing)
        );
        assert_eq!(
            deno(text, &[rekey("x", "1.0.0", "^1")]),
            Err(RekeyRefusal::PinnedEntryMissing)
        );
    }
}
