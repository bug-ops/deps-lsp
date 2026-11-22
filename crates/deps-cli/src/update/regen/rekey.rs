//! Lock-file re-keying for cooldown-fallback pins (#2097).
//!
//! Yarn Berry and Deno key their lock file by the declared requirement. A fallback target is
//! locked under an exact requirement written into the manifest for one install; before the
//! manifest goes back, the lock key is renamed from the pinned descriptor to the declared one so
//! the second install keeps the pinned resolution.

use std::collections::HashSet;

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
    /// The original lock file holds no request to restore for the pinned entry.
    OriginalRequestMissing,
}

impl std::fmt::Display for RekeyRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::PinnedEntryMissing => "no lock entry holds the pinned version",
            Self::PinnedEntryAmbiguous => "several lock entries hold the pinned version",
            Self::DeclaredRangeAlreadyLocked => "the lock file already holds the declared range",
            Self::UnparsableLock => "the lock file could not be parsed",
            Self::OriginalRequestMissing => "the original lock file holds no request to restore",
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

/// A refusal bound to the [`LockRekey`] that caused it.
#[derive(Debug)]
pub(super) struct RekeyRefused<'a> {
    pub(super) rekey: &'a LockRekey,
    pub(super) reason: RekeyRefusal,
}

impl<'a> RekeyRefused<'a> {
    const fn new(rekey: &'a LockRekey, reason: RekeyRefusal) -> Self {
        Self { rekey, reason }
    }
}

/// Renames `<name>@npm:<pinned>` to `<name>@npm:<declared>` inside exactly one Yarn Berry entry
/// header per rekey; every other byte is unchanged. The lock text is split once for all rekeys.
///
/// # Errors
///
/// [`RekeyRefusal::PinnedEntryMissing`] when no header holds the pinned descriptor,
/// [`RekeyRefusal::PinnedEntryAmbiguous`] when several do, and
/// [`RekeyRefusal::DeclaredRangeAlreadyLocked`] when a header already holds the declared one,
/// each bound to the first rekey that is refused.
pub(super) fn yarn<'a>(text: &str, rekeys: &'a [LockRekey]) -> Result<String, RekeyRefused<'a>> {
    let mut lines: Vec<Line> = text.split_inclusive('\n').map(Line::parse).collect();
    for rekey in rekeys {
        let pinned = format!("{}@npm:{}", rekey.package.as_str(), rekey.pinned.as_str());
        let declared = format!("{}@npm:{}", rekey.package.as_str(), rekey.declared.as_str());
        let holding = |descriptor: &str| {
            lines
                .iter()
                .filter_map(|line| line.header.as_ref())
                .filter(|header| header.holds(descriptor))
                .count()
        };
        match holding(&pinned) {
            0 => return Err(RekeyRefused::new(rekey, RekeyRefusal::PinnedEntryMissing)),
            1 => {}
            _ => return Err(RekeyRefused::new(rekey, RekeyRefusal::PinnedEntryAmbiguous)),
        }
        if holding(&declared) > 0 {
            return Err(RekeyRefused::new(
                rekey,
                RekeyRefusal::DeclaredRangeAlreadyLocked,
            ));
        }
        for line in &mut lines {
            if let Some(header) = line.header.as_mut().filter(|header| header.holds(&pinned)) {
                header.rename(&pinned, &declared);
                line.text = header.render();
            }
        }
    }
    Ok(lines.into_iter().map(|line| line.text).collect())
}

/// One line of a Yarn Berry lock file, with its parsed header when it is an entry header.
struct Line {
    text: String,
    header: Option<Header>,
}

impl Line {
    fn parse(text: &str) -> Self {
        Self {
            header: Header::parse(text),
            text: text.to_owned(),
        }
    }
}

/// A Yarn Berry lock entry header: `"a@npm:1, b@npm:2":`.
struct Header {
    descriptors: Vec<String>,
    quoted: bool,
    ending: String,
}

impl Header {
    fn parse(line: &str) -> Option<Self> {
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
            descriptors: key.split(", ").map(str::to_owned).collect(),
            quoted,
            ending: ending.to_owned(),
        })
    }

    fn holds(&self, descriptor: &str) -> bool {
        self.descriptors.iter().any(|held| held == descriptor)
    }

    fn rename(&mut self, from: &str, to: &str) {
        for descriptor in &mut self.descriptors {
            if descriptor == from {
                to.clone_into(descriptor);
            }
        }
    }

    fn render(&self) -> String {
        let joined = self.descriptors.join(", ");
        let quote = if self.quoted { "\"" } else { "" };
        format!("{quote}{joined}{quote}:{}", self.ending)
    }
}

/// The specifier schemes Deno locks packages under.
const DENO_SCHEMES: [&str; 2] = ["npm", "jsr"];

/// Renames every occurrence of the JSON string `"<scheme>:<name>@<pinned>"` to the declared
/// specifier: the `specifiers` key and its `workspace.dependencies` value. The lock is parsed
/// once for all rekeys.
///
/// # Errors
///
/// [`RekeyRefusal::UnparsableLock`] when the input (bound to the first rekey) or the result
/// (bound to the last) is not JSON, [`RekeyRefusal::PinnedEntryMissing`] when `specifiers` has
/// no pinned key (or the package name has no scheme), and
/// [`RekeyRefusal::DeclaredRangeAlreadyLocked`] when the declared key already exists.
pub(super) fn deno<'a>(text: &str, rekeys: &'a [LockRekey]) -> Result<String, RekeyRefused<'a>> {
    let (Some(first), Some(last)) = (rekeys.first(), rekeys.last()) else {
        return Ok(text.to_owned());
    };
    let lock: serde_json::Value = serde_json::from_str(text)
        .map_err(|_| RekeyRefused::new(first, RekeyRefusal::UnparsableLock))?;
    let mut specifiers: HashSet<String> = lock
        .get("specifiers")
        .and_then(serde_json::Value::as_object)
        .map(|object| object.keys().cloned().collect())
        .ok_or_else(|| RekeyRefused::new(first, RekeyRefusal::PinnedEntryMissing))?;
    let mut out = text.to_owned();
    for rekey in rekeys {
        let refuse = |reason| RekeyRefused::new(rekey, reason);
        // Deno package names always carry their scheme (`npm:chalk`).
        let name = rekey.package.as_str();
        let (scheme, bare) = DENO_SCHEMES
            .into_iter()
            .find_map(|scheme| {
                name.strip_prefix(scheme)
                    .and_then(|rest| rest.strip_prefix(':'))
                    .map(|bare| (scheme, bare))
            })
            .ok_or_else(|| refuse(RekeyRefusal::PinnedEntryMissing))?;
        let key = |version: &str| format!("{scheme}:{bare}@{version}");
        let pinned_key = key(rekey.pinned.as_str());
        if !specifiers.contains(&pinned_key) {
            return Err(refuse(RekeyRefusal::PinnedEntryMissing));
        }
        let declared_key = key(rekey.declared.as_str());
        if specifiers.contains(&declared_key) {
            return Err(refuse(RekeyRefusal::DeclaredRangeAlreadyLocked));
        }
        out = out.replace(&json_literal(&pinned_key), &json_literal(&declared_key));
        specifiers.remove(&pinned_key);
        specifiers.insert(declared_key);
    }
    serde_json::from_str::<serde_json::Value>(&out)
        .map_err(|_| RekeyRefused::new(last, RekeyRefusal::UnparsableLock))?;
    Ok(out)
}

/// Puts the `requested` literal the `original` NuGet lock held back on every `Direct` entry of
/// each rekeyed package in `current`; every other byte is unchanged.
///
/// A restore against a manifest with an exact pin locks the package under that pin's request
/// (`[2.12.0, 2.12.0]`). The declared requirement went back into the manifest, so the lock must
/// say what a restore of the manifest says, or `--locked-mode` would reject it.
///
/// # Errors
///
/// [`RekeyRefusal::UnparsableLock`] when `current` (bound to the first rekey) or the result
/// (bound to the last) is not JSON, [`RekeyRefusal::PinnedEntryMissing`] when no `Direct` entry
/// of a package (matched by ASCII case-insensitive id) holds the pinned version in some
/// framework section, and [`RekeyRefusal::OriginalRequestMissing`] when `original` has no
/// `requested` literal for that section's entry.
pub(super) fn nuget<'a>(
    current: &str,
    original: &str,
    rekeys: &'a [LockRekey],
) -> Result<String, RekeyRefused<'a>> {
    let (Some(first), Some(last)) = (rekeys.first(), rekeys.last()) else {
        return Ok(current.to_owned());
    };
    let lock: serde_json::Value = serde_json::from_str(current)
        .map_err(|_| RekeyRefused::new(first, RekeyRefusal::UnparsableLock))?;
    let frameworks = lock
        .get("dependencies")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| RekeyRefused::new(first, RekeyRefusal::PinnedEntryMissing))?;

    let mut replacements: Vec<(std::ops::Range<usize>, &str)> = Vec::new();
    for rekey in rekeys {
        let refuse = |reason| RekeyRefused::new(rekey, reason);
        let mut found = false;
        for (framework, entries) in frameworks {
            let Some(entries) = entries.as_object() else {
                continue;
            };
            for (name, entry) in entries {
                let direct =
                    entry.get("type").and_then(serde_json::Value::as_str) == Some("Direct");
                if !direct || !name.eq_ignore_ascii_case(rekey.package.as_str()) {
                    continue;
                }
                found = true;
                let resolved = entry.get("resolved").and_then(serde_json::Value::as_str);
                if resolved != Some(rekey.pinned.as_str()) {
                    return Err(refuse(RekeyRefusal::PinnedEntryMissing));
                }
                let path = ["dependencies", framework, name, "requested"];
                let span = deps_core::json_ast::string_literal_span(current, &path)
                    .ok_or_else(|| refuse(RekeyRefusal::PinnedEntryMissing))?;
                let declared = deps_core::json_ast::string_literal_span(original, &path)
                    .and_then(|range| original.get(range))
                    .ok_or_else(|| refuse(RekeyRefusal::OriginalRequestMissing))?;
                replacements.push((span, declared));
            }
        }
        if !found {
            return Err(refuse(RekeyRefusal::PinnedEntryMissing));
        }
    }

    replacements.sort_by_key(|(span, _)| std::cmp::Reverse(span.start));
    replacements.dedup_by_key(|(span, _)| span.start);
    let mut out = current.to_owned();
    for (span, declared) in replacements {
        out.replace_range(span, declared);
    }
    serde_json::from_str::<serde_json::Value>(&out)
        .map_err(|_| RekeyRefused::new(last, RekeyRefusal::UnparsableLock))?;
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

    fn reason(result: Result<String, RekeyRefused<'_>>) -> Result<String, RekeyRefusal> {
        result.map_err(|refused| refused.reason)
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
            reason(yarn(YARN, &[rekey("x", "9.9.9", "^1")])),
            Err(RekeyRefusal::PinnedEntryMissing)
        );
        assert_eq!(
            reason(yarn(both, &r)),
            Err(RekeyRefusal::PinnedEntryAmbiguous)
        );
        assert_eq!(
            reason(yarn(declared, &r)),
            Err(RekeyRefusal::DeclaredRangeAlreadyLocked)
        );
    }

    #[test]
    fn yarn_shared_header_with_the_declared_descriptor_is_refused() {
        let text = "\"x@npm:1.2.8, x@npm:^1.2.5\":\n  v: 1\n";

        assert_eq!(
            reason(yarn(text, &[rekey("x", "1.2.8", "^1.2.5")])),
            Err(RekeyRefusal::DeclaredRangeAlreadyLocked)
        );
    }

    #[test]
    fn yarn_rekey_is_not_repeatable() {
        let r = [rekey("x", "1.2.8", "^1.2.5")];
        let once = yarn(YARN, &r).expect("rekeyed");

        assert_eq!(
            reason(yarn(&once, &r)),
            Err(RekeyRefusal::PinnedEntryMissing)
        );
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

        assert_eq!(
            reason(deno("{ nope", &r)),
            Err(RekeyRefusal::UnparsableLock)
        );
        assert_eq!(
            reason(deno("{}", &r)),
            Err(RekeyRefusal::PinnedEntryMissing)
        );
        assert_eq!(
            reason(deno(&locked, &r)),
            Err(RekeyRefusal::DeclaredRangeAlreadyLocked)
        );
    }

    #[test]
    fn deno_needs_a_package_name_that_carries_its_scheme() {
        let text = "{\"specifiers\":{\"npm:x@1.0.0\":\"1.0.0\"}}";

        let out = deno(text, &[rekey("npm:x", "1.0.0", "^1")]).expect("rekeyed");

        assert_eq!(out, "{\"specifiers\":{\"npm:x@^1\":\"1.0.0\"}}");
        assert_eq!(
            reason(deno(text, &[rekey("jsr:x", "1.0.0", "^1")])),
            Err(RekeyRefusal::PinnedEntryMissing)
        );
        assert_eq!(
            reason(deno(text, &[rekey("x", "1.0.0", "^1")])),
            Err(RekeyRefusal::PinnedEntryMissing)
        );
    }

    #[test]
    fn yarn_attributes_a_refusal_to_the_pin_that_caused_it() {
        let rekeys = [rekey("x", "1.2.8", "^1.2.5"), rekey("a", "9.9.9", "^2.0.0")];

        let refused = yarn(YARN, &rekeys).expect_err("second pin is not locked");

        assert_eq!(refused.rekey.package.as_str(), "a");
        assert_eq!(refused.reason, RekeyRefusal::PinnedEntryMissing);
    }

    #[test]
    fn yarn_renames_every_pin_of_one_call() {
        let text = "\"x@npm:1.2.8\":\n  v: 1\n\n\"y@npm:2.0.1\":\n  v: 2\n";
        let rekeys = [rekey("x", "1.2.8", "^1.2.5"), rekey("y", "2.0.1", "^2.0.0")];

        let out = yarn(text, &rekeys).expect("rekeyed");

        assert_eq!(
            out,
            "\"x@npm:^1.2.5\":\n  v: 1\n\n\"y@npm:^2.0.0\":\n  v: 2\n"
        );
    }

    #[test]
    fn deno_attributes_a_refusal_to_the_pin_that_caused_it() {
        let rekeys = [
            rekey("jsr:@std/path", "1.0.0", "^1.0.0"),
            rekey("npm:b", "9.9.9", "^1"),
        ];

        let refused = deno(DENO, &rekeys).expect_err("second pin is not locked");

        assert_eq!(refused.rekey.package.as_str(), "npm:b");
        assert_eq!(refused.reason, RekeyRefusal::PinnedEntryMissing);
    }

    #[test]
    fn deno_renames_every_pin_of_one_call() {
        let text = "{\"specifiers\":{\"npm:x@1.0.0\":\"1.0.0\",\"npm:y@2.0.0\":\"2.0.0\"}}";
        let rekeys = [rekey("npm:x", "1.0.0", "^1"), rekey("npm:y", "2.0.0", "^2")];

        let out = deno(text, &rekeys).expect("rekeyed");

        assert_eq!(
            out,
            "{\"specifiers\":{\"npm:x@^1\":\"1.0.0\",\"npm:y@^2\":\"2.0.0\"}}"
        );
    }

    fn nuget_lock(sections: &[(&str, &str, &str)]) -> String {
        let body: Vec<String> = sections
            .iter()
            .map(|(framework, requested, resolved)| {
                format!(
                    "\"{framework}\": {{\"Serilog\": {{\"type\": \"Direct\", \"requested\": {requested}, \"resolved\": \"{resolved}\"}}}}"
                )
            })
            .collect();
        format!(
            "{{\"version\": 1, \"dependencies\": {{{}}}}}",
            body.join(", ")
        )
    }

    #[test]
    fn nuget_restores_the_original_requested_literal_in_every_framework_section() {
        let original = nuget_lock(&[
            ("net6.0", "\"[2.*, )\"", "2.10.0"),
            ("net8.0", "\"[2.*, )\"", "2.10.0"),
        ]);
        let current = nuget_lock(&[
            ("net6.0", "\"[2.12.0, 2.12.0]\"", "2.12.0"),
            ("net8.0", "\"[2.12.0, 2.12.0]\"", "2.12.0"),
        ]);

        let out =
            nuget(&current, &original, &[rekey("serilog", "2.12.0", "2.*")]).expect("rekeyed");

        assert_eq!(out, current.replace("[2.12.0, 2.12.0]", "[2.*, )"));
    }

    #[test]
    fn nuget_keeps_an_escaped_original_literal_byte_for_byte() {
        let original = nuget_lock(&[("net8.0", r#""[2.*, )\u0020""#, "2.10.0")]);
        let current = nuget_lock(&[("net8.0", "\"[2.12.0, 2.12.0]\"", "2.12.0")]);

        let out =
            nuget(&current, &original, &[rekey("Serilog", "2.12.0", "2.*")]).expect("rekeyed");

        assert!(out.contains(r#""[2.*, )\u0020""#), "{out}");
    }

    #[test]
    fn nuget_refuses_a_missing_pinned_entry_a_missing_original_and_a_broken_lock() {
        let original = nuget_lock(&[("net8.0", "\"[2.*, )\"", "2.10.0")]);
        let current = nuget_lock(&[("net8.0", "\"[2.12.0, 2.12.0]\"", "2.12.0")]);
        let widened = nuget_lock(&[
            ("net6.0", "\"[2.12.0, 2.12.0]\"", "2.12.0"),
            ("net8.0", "\"[2.12.0, 2.12.0]\"", "2.12.0"),
        ]);
        let r = [rekey("Serilog", "2.12.0", "2.*")];

        assert_eq!(
            reason(nuget(
                &current,
                &original,
                &[rekey("Serilog", "2.11.0", "2.*")]
            )),
            Err(RekeyRefusal::PinnedEntryMissing)
        );
        assert_eq!(
            reason(nuget(
                &current,
                &original,
                &[rekey("Other", "2.12.0", "2.*")]
            )),
            Err(RekeyRefusal::PinnedEntryMissing)
        );
        assert_eq!(
            reason(nuget(&widened, &original, &r)),
            Err(RekeyRefusal::OriginalRequestMissing)
        );
        assert_eq!(
            reason(nuget("not json", &original, &r)),
            Err(RekeyRefusal::UnparsableLock)
        );
    }
}
