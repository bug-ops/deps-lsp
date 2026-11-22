//! #1982 / spec 099 FR-014: the one warning a malformed publish-age config produces — one per
//! cached file, naming the file, the malformed-key count and at most the first five keys, with
//! attacker-controlled key text sanitized, and malformed `resolver.incompatible-publish-age`
//! reported while the window keeps applying (the `deny` default).

#![expect(clippy::unwrap_used, reason = "test code")]

use std::path::Path;
use std::sync::Arc;

use deps_cargo::config::ConfigFileCache;
use deps_cargo::parser::{CargoParseContext, parse_cargo_toml_with_context};
use deps_core::Dependency;
use deps_core::net_policy::{RegistryAccessPolicy, WorkspaceRegistryAccess};
use deps_core::policy_config::NativeCooldownMode;
use url::Url;

fn ctx() -> CargoParseContext {
    CargoParseContext::new(
        Arc::new(RegistryAccessPolicy::new(WorkspaceRegistryAccess::All)),
        Arc::new(ConfigFileCache::new()),
    )
    .with_native_cooldown(NativeCooldownMode::Honor)
}

/// Parses `serde = "1"` under `config`, returning the window label and the captured log.
fn run(config: &str) -> (Option<String>, String, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join(".cargo")).unwrap();
    let config_path = root.join(".cargo/config.toml");
    std::fs::write(&config_path, config).unwrap();
    let manifest = "[dependencies]\nserde = \"1\"\n";
    let path = root.join("Cargo.toml");
    std::fs::write(&path, manifest).unwrap();
    let uri = Url::from_file_path(&path).unwrap();
    let context = ctx();
    let mut label = None;
    let output = deps_core::test_util::capture_tracing_output(|| {
        for _ in 0..3 {
            let result = parse_cargo_toml_with_context(manifest, &uri, &context).unwrap();
            label = Dependency::native_cooldown(result.dependencies.first().unwrap())
                .map(ToString::to_string);
        }
        drop(dir);
    });
    (label, output, config_path)
}

fn raw_warn_lines(output: &str) -> Vec<&str> {
    output
        .lines()
        .filter(|l| l.contains("malformed Cargo publish-age"))
        .collect()
}

/// The warning lines with the log formatter's colour sequences removed.
fn warn_lines(output: &str) -> Vec<String> {
    raw_warn_lines(output).into_iter().map(plain).collect()
}

/// Removes the log formatter's own colour sequences (`ESC [ ... m`).
fn plain(line: &str) -> String {
    let mut out = String::new();
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for next in chars.by_ref() {
                if next == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn many_malformed(count: usize) -> String {
    let mut config = String::from("[registry]\nglobal-min-publish-age = \"7 days\"\n");
    for i in 0..count {
        config.push_str(&format!("[registries.r{i}]\nmin-publish-age = \"soon\"\n"));
    }
    config
}

#[test]
fn malformed_keys_produce_one_warning_per_file_naming_path_count_and_first_five_keys() {
    let (label, output, config_path) = run(&many_malformed(8));
    assert_eq!(
        label.as_deref(),
        Some("cargo registry.global-min-publish-age = 7 days"),
        "malformed per-registry values count as absent, so the global window applies"
    );
    let lines = warn_lines(&output);
    assert_eq!(lines.len(), 1, "one warning across three parses: {output}");
    let line = lines[0].as_str();
    // Compare path components, not the full canonical string: Windows canonicalize() yields a
    // verbatim `\\?\` form while the logged path is the plain one.
    let temp_dir_name = config_path
        .parent()
        .and_then(Path::parent)
        .and_then(Path::file_name)
        .and_then(std::ffi::OsStr::to_str)
        .unwrap();
    assert!(line.contains(temp_dir_name), "{line}");
    assert!(line.contains(".cargo"), "{line}");
    assert!(line.contains("config.toml"), "{line}");
    assert!(line.contains("count=8"), "{line}");
    let named = (0..8)
        .filter(|i| line.contains(&format!("registries.r{i}.min-publish-age")))
        .count();
    assert_eq!(named, 5, "exactly the first five keys are named: {line}");
}

#[test]
fn a_single_malformed_key_is_named_with_count_one() {
    let (_, output, _) = run("[registry]\nglobal-min-publish-age = \"7 fortnights\"\n");
    let lines = warn_lines(&output);
    assert_eq!(lines.len(), 1, "{output}");
    assert!(lines[0].contains("count=1"), "{}", lines[0]);
    assert!(
        lines[0].contains("registry.global-min-publish-age"),
        "{}",
        lines[0]
    );
}

#[test]
fn well_formed_config_produces_no_warning() {
    let (label, output, _) = run("[registry]\nglobal-min-publish-age = \"7 days\"\n");
    assert!(label.is_some());
    assert!(warn_lines(&output).is_empty(), "{output}");
}

#[test]
fn malformed_incompatible_publish_age_warns_and_the_window_still_applies() {
    let (label, output, _) = run(
        "[registry]\nglobal-min-publish-age = \"7 days\"\n[resolver]\nincompatible-publish-age = \"maybe\"\n",
    );
    assert_eq!(
        label.as_deref(),
        Some("cargo registry.global-min-publish-age = 7 days"),
        "a malformed mode reads as the deny default"
    );
    let lines = warn_lines(&output);
    assert_eq!(lines.len(), 1, "{output}");
    assert!(
        lines[0].contains("resolver.incompatible-publish-age"),
        "{}",
        lines[0]
    );
}

#[test]
fn non_string_incompatible_publish_age_warns_and_the_window_still_applies() {
    let (label, output, _) = run(
        "[registry]\nglobal-min-publish-age = \"7 days\"\n[resolver]\nincompatible-publish-age = true\n",
    );
    assert!(label.is_some());
    assert_eq!(warn_lines(&output).len(), 1, "{output}");
}

#[test]
fn registry_alias_with_invisible_or_control_characters_is_sanitized_in_the_warning() {
    let (_, benign, _) = run("[registries.evil]\nmin-publish-age = \"soon\"\n");
    let (_, hostile, _) =
        run("[registries.\"ev\\u202Eil\\u001B[31m\"]\nmin-publish-age = \"soon\"\n");
    let (benign, hostile) = (
        raw_warn_lines(&benign)[0].to_owned(),
        raw_warn_lines(&hostile),
    );
    assert_eq!(hostile.len(), 1);
    let escapes = |l: &str| l.matches('\u{1b}').count();
    assert_eq!(
        escapes(hostile[0]),
        escapes(&benign),
        "an ESC from the key would add a terminal escape: {:?}",
        hostile[0]
    );
    assert!(
        !hostile[0].contains('\u{202E}'),
        "bidi override leaked: {:?}",
        hostile[0]
    );
    assert!(plain(hostile[0]).contains("registries."));
}
