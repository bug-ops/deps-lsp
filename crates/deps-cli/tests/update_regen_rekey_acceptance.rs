//! #2097 acceptance: cooldown-fallback pins for Yarn Berry and Deno. The tool locks the exact pin
//! with the manifest pinned, the lock key is re-keyed from the pinned descriptor/specifier back to
//! the declared range, and the install form runs again with the original manifest (plan rev 2,
//! Track A and the `rekey` contracts).
//!
//! Driven through fake tools in a re-executed test binary (see `common/regen_harness.rs`). The
//! fake tool writes the lock the real tool writes for the exact pin on its first writing call and
//! does nothing on the second. Not covered here: real re-resolution behaviour (live probes) and
//! `PinnedEntryAmbiguous` (a lock with two headers holding the same descriptor cannot come from
//! a real Yarn, so the harness cannot produce it).

#![cfg(all(unix, feature = "npm", feature = "deno"))]
#![expect(clippy::expect_used, reason = "test code")]

#[path = "common/regen_harness.rs"]
mod harness;

use harness::{Case, Ran, run};

#[tokio::test]
#[ignore = "re-exec target of the parent tests, driven through REGEN_* variables"]
async fn regen_child() {
    harness::regen_child_main().await;
}

fn fallback_case<'a>(
    ecosystem: &'a str,
    manifest: &'a str,
    files: Vec<(&'a str, &'a str)>,
    tool: (&'a str, &'a str),
    bumps: &'a str,
) -> Case<'a> {
    Case {
        ecosystem,
        manifest,
        files: files
            .into_iter()
            .map(|(path, body)| (path, body.as_bytes().to_vec()))
            .collect(),
        tools: vec![tool],
        mode: "lockonly",
        bumps,
        cooldown_fallback: true,
        unlistened: false,
    }
}

fn writing_calls<'a>(ran: &'a Ran, tool: &str) -> Vec<&'a String> {
    ran.calls_of(tool)
        .into_iter()
        .filter(|call| !call.starts_with(&format!("{tool} --version|")))
        .collect()
}

fn text(ran: &Ran, rel: &str) -> String {
    String::from_utf8(ran.read(rel)).expect("utf-8")
}

// --- Yarn Berry ---

const PACKAGE: &str = "{\n  \"name\": \"fx\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {\n    \"minimist\": \"^1.2.0\"\n  }\n}\n";
const YARN_BUMP: &str = "minimist|minimist|^1.2.0|^1.2.0|1.2.0|1.2.8";
const YARN_LOCK_OLD: &str = "__metadata:\n  version: 8\n\n\"minimist@npm:^1.2.0\":\n  version: 1.2.0\n  resolution: \"minimist@npm:1.2.0\"\n  checksum: aaa\n  languageName: node\n  linkType: hard\n";
const YARN_ENTRY_PINNED: &str = "\"minimist@npm:1.2.8\":\n  version: 1.2.8\n  resolution: \"minimist@npm:1.2.8\"\n  checksum: bbb\n  languageName: node\n  linkType: hard\n";

/// A Yarn Berry that writes `lock` on its first writing call and nothing afterwards.
fn yarn_writing(lock: &str) -> String {
    format!(
        "case \"$1\" in\n  --version) echo 4.5.0; exit 0;;\nesac\nif [ ! -f ROOT/.ran ]; then\n  touch ROOT/.ran\n  cat > ROOT/yarn.lock <<'EOF'\n{lock}EOF\nfi\nexit 0\n"
    )
}

fn yarn_run(lock_after_pin: &str) -> Ran {
    let body = yarn_writing(lock_after_pin);
    run(&fallback_case(
        "npm",
        "package.json",
        vec![("package.json", PACKAGE), ("yarn.lock", YARN_LOCK_OLD)],
        ("yarn", &body),
        YARN_BUMP,
    ))
}

fn assert_yarn_refused(ran: &Ran, reason: &str) {
    assert!(
        ran.outcome.contains("FallbackPinNotKept"),
        "{}",
        ran.outcome
    );
    assert!(ran.outcome.contains(reason), "{}", ran.outcome);
    assert_eq!(
        writing_calls(ran, "yarn").len(),
        1,
        "no second install is spent: {:?}",
        ran.calls
    );
    assert_eq!(text(ran, "package.json"), PACKAGE);
    assert_eq!(text(ran, "yarn.lock"), YARN_LOCK_OLD);
}

#[test]
fn yarn_fallback_pin_rekeys_the_descriptor_to_the_declared_range_between_two_installs() {
    let lock = format!("__metadata:\n  version: 8\n\n{YARN_ENTRY_PINNED}");

    let ran = yarn_run(&lock);

    let calls = writing_calls(&ran, "yarn");
    assert_eq!(calls.len(), 2, "{:?}", ran.calls);
    assert!(
        calls
            .iter()
            .all(|call| call.starts_with("yarn install --mode=update-lockfile|")),
        "{calls:?}"
    );
    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
    let final_lock = text(&ran, "yarn.lock");
    assert_eq!(
        final_lock,
        lock.replace("\"minimist@npm:1.2.8\":", "\"minimist@npm:^1.2.0\":"),
        "only the entry header is renamed"
    );
    assert_eq!(text(&ran, "package.json"), PACKAGE);
}

#[test]
fn yarn_fallback_pin_rekey_leaves_unrelated_entries_byte_identical() {
    let other = "\"other@npm:^2.0.0\":\n  version: 2.0.1\n  resolution: \"other@npm:2.0.1\"\n  checksum: ccc\n  languageName: node\n  linkType: hard\n";
    let lock = format!("__metadata:\n  version: 8\n\n{other}\n{YARN_ENTRY_PINNED}");

    let ran = yarn_run(&lock);

    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
    let final_lock = text(&ran, "yarn.lock");
    assert!(final_lock.contains(other), "{final_lock}");
    assert!(
        final_lock.contains("\"minimist@npm:^1.2.0\":"),
        "{final_lock}"
    );
    assert!(
        !final_lock.contains("\"minimist@npm:1.2.8\":"),
        "{final_lock}"
    );
}

#[test]
fn yarn_fallback_pin_missing_from_the_lock_is_refused_and_restored() {
    let lock = format!(
        "__metadata:\n  version: 8\n\n{}",
        YARN_ENTRY_PINNED.replace("minimist@npm:1.2.8\":", "minimist@npm:~1.2.8\":")
    );

    let ran = yarn_run(&lock);

    assert_yarn_refused(&ran, "PinnedEntryMissing");
}

#[test]
fn yarn_fallback_declared_range_already_locked_is_refused_and_restored() {
    let declared = "\"minimist@npm:^1.2.0\":\n  version: 1.2.0\n  resolution: \"minimist@npm:1.2.0\"\n  checksum: aaa\n  languageName: node\n  linkType: hard\n";
    let lock = format!("__metadata:\n  version: 8\n\n{declared}\n{YARN_ENTRY_PINNED}");

    let ran = yarn_run(&lock);

    assert_yarn_refused(&ran, "DeclaredRangeAlreadyLocked");
}

#[test]
fn yarn_fallback_with_a_non_plain_declared_range_is_refused_before_any_write() {
    let package = PACKAGE.replace("^1.2.0", "npm:other@^1.2.0");
    let body = yarn_writing("");

    let ran = run(&fallback_case(
        "npm",
        "package.json",
        vec![("package.json", &package), ("yarn.lock", YARN_LOCK_OLD)],
        ("yarn", &body),
        YARN_BUMP,
    ));

    assert!(
        ran.outcome.contains("CooldownFallbackTarget"),
        "{}",
        ran.outcome
    );
    assert!(writing_calls(&ran, "yarn").is_empty(), "{:?}", ran.calls);
    assert_eq!(text(&ran, "package.json"), package);
}

// --- Deno ---

const DENO_JSON: &str = "{\n  \"imports\": {\n    \"chalk\": \"npm:chalk@^4.0.0\"\n  }\n}\n";
const DENO_BUMP: &str = "npm:chalk|chalk|^4.0.0|^4.0.0|4.0.0|4.1.2";
const DENO_LOCK_OLD: &str = "{\n  \"version\": \"4\",\n  \"specifiers\": {\n    \"npm:chalk@^4.0.0\": \"4.0.0\"\n  },\n  \"npm\": {\n    \"chalk@4.0.0\": {\n      \"integrity\": \"sha512-old\"\n    }\n  },\n  \"workspace\": {\n    \"dependencies\": [\n      \"npm:chalk@^4.0.0\"\n    ]\n  }\n}\n";
const DENO_LOCK_PINNED: &str = "{\n  \"version\": \"4\",\n  \"specifiers\": {\n    \"npm:chalk@4.1.2\": \"4.1.2\"\n  },\n  \"npm\": {\n    \"chalk@4.1.2\": {\n      \"integrity\": \"sha512-new\"\n    }\n  },\n  \"workspace\": {\n    \"dependencies\": [\n      \"npm:chalk@4.1.2\"\n    ]\n  }\n}\n";

fn deno_writing(lock: &str) -> String {
    format!(
        "if [ ! -f ROOT/.ran ]; then\n  touch ROOT/.ran\n  cat > ROOT/deno.lock <<'EOF'\n{lock}EOF\nfi\nexit 0\n"
    )
}

fn deno_run(lock_after_pin: &str) -> Ran {
    let body = deno_writing(lock_after_pin);
    run(&fallback_case(
        "deno",
        "deno.json",
        vec![("deno.json", DENO_JSON), ("deno.lock", DENO_LOCK_OLD)],
        ("deno", &body),
        DENO_BUMP,
    ))
}

fn assert_deno_refused(ran: &Ran, reason: &str) {
    assert!(
        ran.outcome.contains("FallbackPinNotKept"),
        "{}",
        ran.outcome
    );
    assert!(ran.outcome.contains(reason), "{}", ran.outcome);
    assert_eq!(ran.calls_of("deno").len(), 1, "{:?}", ran.calls);
    assert_eq!(text(ran, "deno.json"), DENO_JSON);
    assert_eq!(text(ran, "deno.lock"), DENO_LOCK_OLD);
}

#[test]
fn deno_fallback_pin_rekeys_specifier_and_workspace_dependency_between_two_installs() {
    let ran = deno_run(DENO_LOCK_PINNED);

    let calls = ran.calls_of("deno");
    assert_eq!(calls.len(), 2, "{:?}", ran.calls);
    assert!(
        calls
            .iter()
            .all(|call| call.starts_with("deno install --lockfile-only --lock=./deno.lock|")),
        "{calls:?}"
    );
    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
    let lock: serde_json::Value =
        serde_json::from_slice(&ran.read("deno.lock")).expect("the result parses");
    assert_eq!(lock["specifiers"]["npm:chalk@^4.0.0"], "4.1.2");
    assert!(
        lock["specifiers"].get("npm:chalk@4.1.2").is_none(),
        "{lock}"
    );
    assert_eq!(
        lock["workspace"]["dependencies"],
        serde_json::json!(["npm:chalk@^4.0.0"])
    );
    assert_eq!(lock["npm"]["chalk@4.1.2"]["integrity"], "sha512-new");
    assert_eq!(text(&ran, "deno.json"), DENO_JSON);
}

#[test]
fn deno_fallback_pin_without_a_specifiers_entry_is_refused_and_restored() {
    let ran = deno_run("{\n  \"version\": \"4\"\n}\n");

    assert_deno_refused(&ran, "PinnedEntryMissing");
}

#[test]
fn deno_fallback_unparsable_lock_is_refused_and_restored() {
    let ran = deno_run("{ not json\n");

    assert_deno_refused(&ran, "UnparsableLock");
}

#[test]
fn deno_fallback_declared_specifier_already_locked_is_refused_and_restored() {
    let lock = DENO_LOCK_PINNED.replace(
        "\"specifiers\": {\n",
        "\"specifiers\": {\n    \"npm:chalk@^4.0.0\": \"4.0.0\",\n",
    );

    let ran = deno_run(&lock);

    assert_deno_refused(&ran, "DeclaredRangeAlreadyLocked");
}
