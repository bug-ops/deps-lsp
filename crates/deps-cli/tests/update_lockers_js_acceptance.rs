//! #2089, #2091, #2080, #2076 and #2077 acceptance: JavaScript lock-file regeneration (npm
//! workspace ownership without `npm prefix`, Yarn Berry members and manifest preservation, Bun,
//! cooldown-fallback exact pins) driven through fake tools in a re-executed test binary (see
//! `common/regen_harness.rs`). Fake tools record `tool argv|cwd|env`; where a scenario needs to
//! know what the manifest looked like at a call, the tool appends it to `seen.log`.
//!
//! Not covered here (verified by hand against real npm 11, Yarn 4.9, Bun 1.4, Bundler and Deno):
//! the tools' real flag acceptance and their real re-resolution behaviour.

#![cfg(all(unix, feature = "npm", feature = "bundler"))]
#![expect(clippy::expect_used, reason = "test code")]

#[path = "common/regen_harness.rs"]
mod harness;

use harness::{Case, Ran, run};

#[tokio::test]
#[ignore = "re-exec target of the parent tests, driven through REGEN_* variables"]
async fn regen_child() {
    harness::regen_child_main().await;
}

fn case<'a>(
    ecosystem: &'a str,
    manifest: &'a str,
    files: Vec<(&'a str, &'a str)>,
    tools: Vec<(&'a str, &'a str)>,
    mode: &'a str,
    bumps: &'a str,
) -> Case<'a> {
    Case {
        ecosystem,
        manifest,
        files: files
            .into_iter()
            .map(|(path, body)| (path, body.as_bytes().to_vec()))
            .collect(),
        tools,
        mode,
        bumps,
        cooldown_fallback: false,
        unlistened: false,
    }
}

fn writing_calls<'a>(ran: &'a Ran, tool: &str, probes: &[&str]) -> Vec<&'a String> {
    ran.calls_of(tool)
        .into_iter()
        .filter(|call| {
            !probes
                .iter()
                .any(|probe| call.starts_with(&format!("{tool} {probe}|")))
        })
        .collect()
}

fn cwd_of(call: &str) -> &str {
    call.split('|').nth(1).expect("cwd field")
}

fn seen(ran: &Ran) -> String {
    String::from_utf8(ran.read("seen.log")).expect("utf-8 log")
}

const MINIMIST_EDIT: &str = "minimist|minimist|^1.2.0|^1.2.8|1.2.0|1.2.8";
const MINIMIST_LOCK_ONLY: &str = "minimist|minimist|^1.2.0|^1.2.0|1.2.0|1.2.8";

// --- #2089: npm workspace ownership from the lock file ---

const UUID: &str = "0f8fad5b-d9cb-469f-a165-9c1d8f3b8b1c";
const ROOT_PACKAGE: &str =
    "{\n  \"name\": \"root\",\n  \"private\": true,\n  \"workspaces\": [\"packages/*\"]\n}\n";
const MEMBER_PACKAGE: &str = "{\n  \"name\": \"a\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {\n    \"minimist\": \"^1.2.0\"\n  }\n}\n";
const NPM_LOCK_OLD: &str = "{\"name\":\"root\",\"lockfileVersion\":3,\"requires\":true,\"packages\":{\"\":{\"name\":\"root\",\"workspaces\":[\"packages/*\"]},\"node_modules/minimist\":{\"version\":\"1.2.0\"},\"packages/a\":{\"name\":\"a\",\"version\":\"1.0.0\",\"dependencies\":{\"minimist\":\"^1.2.0\"}}}}\n";
const NPM_LOCK_NEW: &str = "{\"name\":\"root\",\"lockfileVersion\":3,\"requires\":true,\"packages\":{\"\":{\"name\":\"root\",\"workspaces\":[\"packages/*\"]},\"node_modules/minimist\":{\"version\":\"1.2.8\"},\"packages/a\":{\"name\":\"a\",\"version\":\"1.0.0\",\"dependencies\":{\"minimist\":\"^1.2.8\"}}}}\n";

/// An npm that redacts UUID-like path segments in `npm prefix`, as npm 11 does, and rewrites the
/// lock file in `dir` for every other command.
fn redacting_npm(dir: &str) -> String {
    format!(
        "if [ \"$1\" = prefix ]; then echo '/tmp/***/scratchpad/npmws'; exit 0; fi\ncat > ROOT/{dir}package-lock.json <<'EOF'\n{NPM_LOCK_NEW}EOF\n"
    )
}

fn npm_member_files<'a>(
    dir: &'a str,
    root_package: &'a str,
    lock: &'a str,
) -> Vec<(String, &'a str)> {
    vec![
        (format!("{dir}package.json"), root_package),
        (format!("{dir}packages/a/package.json"), MEMBER_PACKAGE),
        (format!("{dir}package-lock.json"), lock),
    ]
}

fn npm_member_run(
    dir: &str,
    root_package: &str,
    lock: &str,
    body: &str,
    mode: &str,
    bumps: &str,
) -> Ran {
    let files = npm_member_files(dir, root_package, lock);
    let manifest = format!("{dir}packages/a/package.json");
    run(&case(
        "npm",
        &manifest,
        files
            .iter()
            .map(|(path, body)| (path.as_str(), *body))
            .collect(),
        vec![("npm", body)],
        mode,
        bumps,
    ))
}

#[test]
fn npm_member_below_a_uuid_named_directory_is_regenerated_without_npm_prefix() {
    let dir = format!("{UUID}/");
    let body = redacting_npm(&dir);

    let ran = npm_member_run(
        &dir,
        ROOT_PACKAGE,
        NPM_LOCK_OLD,
        &body,
        "edit",
        MINIMIST_EDIT,
    );

    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
    assert!(
        ran.calls_of("npm")
            .iter()
            .all(|call| !call.starts_with("npm prefix"))
    );
    let calls = ran.calls_of("npm");
    assert_eq!(calls.len(), 1, "{:?}", ran.calls);
    assert!(calls[0].starts_with("npm install "), "{}", calls[0]);
    assert_eq!(cwd_of(calls[0]), ran.root.join(UUID).display().to_string());
}

#[test]
fn npm_member_lock_only_pin_below_a_uuid_named_directory_uses_the_workspace_flag() {
    let dir = format!("{UUID}/");
    let body = redacting_npm(&dir);

    let ran = npm_member_run(
        &dir,
        ROOT_PACKAGE,
        NPM_LOCK_OLD,
        &body,
        "lockonly",
        MINIMIST_LOCK_ONLY,
    );

    let calls = ran.calls_of("npm");
    assert_eq!(calls.len(), 1, "{:?}", ran.calls);
    assert!(calls[0].starts_with("npm update "), "{}", calls[0]);
    assert!(
        calls[0].contains("--workspace=./packages/a"),
        "{}",
        calls[0]
    );
    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
}

fn assert_ownership_refused(ran: &Ran) {
    assert!(
        ran.outcome.contains("LockfileOwnershipMismatch"),
        "{}",
        ran.outcome
    );
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}

#[test]
fn npm_member_missing_from_the_lock_packages_is_an_ownership_mismatch() {
    let lock = NPM_LOCK_OLD.replace("\"packages/a\"", "\"packages/other\"");

    let ran = npm_member_run("", ROOT_PACKAGE, &lock, "exit 0", "edit", MINIMIST_EDIT);

    assert_ownership_refused(&ran);
}

#[test]
fn npm_member_outside_the_workspaces_patterns_is_an_ownership_mismatch() {
    let root = ROOT_PACKAGE.replace("packages/*", "apps/*");

    let ran = npm_member_run("", &root, NPM_LOCK_OLD, "exit 0", "edit", MINIMIST_EDIT);

    assert_ownership_refused(&ran);
}

#[test]
fn npm_member_with_a_negated_workspaces_pattern_fails_closed() {
    let root = ROOT_PACKAGE.replace("[\"packages/*\"]", "[\"packages/*\", \"!packages/b\"]");

    let ran = npm_member_run("", &root, NPM_LOCK_OLD, "exit 0", "edit", MINIMIST_EDIT);

    assert_ownership_refused(&ran);
}

#[test]
fn npm_member_with_a_v1_lock_is_an_ownership_mismatch() {
    let lock = NPM_LOCK_OLD.replace("\"lockfileVersion\":3", "\"lockfileVersion\":1");

    let ran = npm_member_run("", ROOT_PACKAGE, &lock, "exit 0", "edit", MINIMIST_EDIT);

    assert_ownership_refused(&ran);
}

#[test]
fn npm_member_under_an_outer_workspace_root_is_an_ownership_mismatch() {
    let body = "exit 0";
    let outer =
        "{\n  \"name\": \"outer\",\n  \"private\": true,\n  \"workspaces\": [\"inner\"]\n}\n";
    let files = npm_member_files("inner/", ROOT_PACKAGE, NPM_LOCK_OLD);
    let mut all: Vec<(&str, &str)> = files.iter().map(|(p, b)| (p.as_str(), *b)).collect();
    all.push(("package.json", outer));

    let ran = run(&case(
        "npm",
        "inner/packages/a/package.json",
        all,
        vec![("npm", body)],
        "edit",
        MINIMIST_EDIT,
    ));

    assert_ownership_refused(&ran);
}

#[test]
fn npm_member_of_an_object_form_workspaces_declaration_is_regenerated() {
    let root = ROOT_PACKAGE.replace("[\"packages/*\"]", "{\"packages\": [\"./packages/*\"]}");
    let body = redacting_npm("");

    let ran = npm_member_run("", &root, NPM_LOCK_OLD, &body, "edit", MINIMIST_EDIT);

    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
}

// --- #2091 and #2080: Yarn Berry ---

const YARN_ROOT_PACKAGE: &str =
    "{\"name\":\"root\",\"private\":true,\"workspaces\":[\"packages/*\"]}";
const YARN_A: &str =
    "{\"name\":\"a\",\"version\":\"1.0.0\",\"dependencies\":{\"minimist\":\"^1.2.0\"}}";
const YARN_B: &str =
    "{\"name\":\"b\",\"version\":\"1.0.0\",\"dependencies\":{\"minimist\":\"^1.2.0\"}}";
const YARN_LOCK_OLD: &str = "__metadata:\n  version: 8\n\n\"minimist@npm:^1.2.0\":\n  version: 1.2.0\n  resolution: \"minimist@npm:1.2.0\"\n  checksum: aaa\n  languageName: node\n  linkType: hard\n";
const YARN_LOCK_NEW: &str = "__metadata:\n  version: 8\n\n\"minimist@npm:^1.2.0\":\n  version: 1.2.8\n  resolution: \"minimist@npm:1.2.8\"\n  checksum: bbb\n  languageName: node\n  linkType: hard\n";
const YARN_WORKSPACES: &str = "{\"location\":\".\",\"name\":\"root\"}\n{\"location\":\"packages/a\",\"name\":\"a\"}\n{\"location\":\"packages/b\",\"name\":\"b\"}\n";

/// A Yarn Berry that lists `workspaces`, re-serializes every manifest the way Yarn does (2-space
/// indentation, trailing newline) and writes the new lock file.
fn yarn_body(workspaces: &str, extra_dependency: bool) -> String {
    yarn_body_for(workspaces, extra_dependency, "^1.2.0", "^1.2.0")
}

/// [`yarn_body`] for a member whose declared range is `range`.
fn yarn_body_for(
    workspaces: &str,
    extra_dependency: bool,
    range: &str,
    sibling_range: &str,
) -> String {
    let added = if extra_dependency {
        ",\\n    \\\"extra\\\": \\\"1.0.0\\\""
    } else {
        ""
    };
    format!(
        "case \"$1\" in\n  --version) echo 4.5.0; exit 0;;\n  workspaces) printf '%s' '{workspaces}'; exit 0;;\nesac\nprintf '{{\\n  \"name\": \"a\",\\n  \"version\": \"1.0.0\",\\n  \"dependencies\": {{\\n    \"minimist\": \"{range}\"{added}\\n  }}\\n}}\\n' > ROOT/packages/a/package.json\nprintf '{{\\n  \"name\": \"b\",\\n  \"version\": \"1.0.0\",\\n  \"dependencies\": {{\\n    \"minimist\": \"{sibling_range}\"\\n  }}\\n}}\\n' > ROOT/packages/b/package.json\ncat > ROOT/yarn.lock <<'EOF'\n{YARN_LOCK_NEW}EOF\n"
    )
}

fn yarn_member_case<'a>(body: &'a str, mode: &'a str, bumps: &'a str) -> Case<'a> {
    case(
        "npm",
        "packages/a/package.json",
        vec![
            ("package.json", YARN_ROOT_PACKAGE),
            ("packages/a/package.json", YARN_A),
            ("packages/b/package.json", YARN_B),
            ("yarn.lock", YARN_LOCK_OLD),
        ],
        vec![("yarn", body)],
        mode,
        bumps,
    )
}

const YARN_PROBES: &[&str] = &["--version", "workspaces list --json"];

#[test]
fn yarn_member_runs_at_the_workspace_root_and_keeps_every_manifest_byte_identical() {
    let body = yarn_body(YARN_WORKSPACES, false);

    let ran = run(&yarn_member_case(&body, "lockonly", MINIMIST_LOCK_ONLY));

    let calls = writing_calls(&ran, "yarn", YARN_PROBES);
    assert_eq!(calls.len(), 1, "{:?}", ran.calls);
    assert!(
        calls[0].starts_with("yarn up --recursive --mode=update-lockfile minimist|"),
        "{}",
        calls[0]
    );
    assert_eq!(cwd_of(calls[0]), ran.root.display().to_string());
    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
    assert_eq!(ran.read("packages/a/package.json"), YARN_A.as_bytes());
    assert_eq!(ran.read("packages/b/package.json"), YARN_B.as_bytes());
    assert_eq!(ran.read("package.json"), YARN_ROOT_PACKAGE.as_bytes());
}

#[test]
fn yarn_member_edit_runs_the_install_form_at_the_root() {
    let body = yarn_body_for(YARN_WORKSPACES, false, "^1.2.8", "^1.2.0");

    let ran = run(&yarn_member_case(&body, "edit", MINIMIST_EDIT));

    let calls = writing_calls(&ran, "yarn", YARN_PROBES);
    assert_eq!(calls.len(), 1, "{:?}", ran.calls);
    assert!(
        calls[0].starts_with("yarn install --mode=update-lockfile|"),
        "{}",
        calls[0]
    );
    assert_eq!(cwd_of(calls[0]), ran.root.display().to_string());
    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
}

#[test]
fn yarn_manifest_changed_beyond_formatting_fails_and_is_restored() {
    let body = yarn_body(YARN_WORKSPACES, true);

    let ran = run(&yarn_member_case(&body, "lockonly", MINIMIST_LOCK_ONLY));

    assert!(ran.outcome.contains("ManifestChanged"), "{}", ran.outcome);
    assert_eq!(ran.read("packages/a/package.json"), YARN_A.as_bytes());
    assert_eq!(ran.read("yarn.lock"), YARN_LOCK_OLD.as_bytes());
}

#[test]
fn yarn_sibling_dependency_range_changed_fails_and_restores_every_file() {
    let body = yarn_body_for(YARN_WORKSPACES, false, "^1.2.0", "^1.2.8");

    let ran = run(&yarn_member_case(&body, "lockonly", MINIMIST_LOCK_ONLY));

    assert!(
        ran.outcome.contains("ManifestChanged") && ran.outcome.contains("packages/b/package.json"),
        "{}",
        ran.outcome
    );
    assert_eq!(ran.read("packages/a/package.json"), YARN_A.as_bytes());
    assert_eq!(ran.read("packages/b/package.json"), YARN_B.as_bytes());
    assert_eq!(ran.read("package.json"), YARN_ROOT_PACKAGE.as_bytes());
    assert_eq!(ran.read("yarn.lock"), YARN_LOCK_OLD.as_bytes());
}

#[test]
fn yarn_standalone_compact_manifest_is_restored_after_the_run() {
    let body = "case \"$1\" in\n  --version) echo 4.5.0; exit 0;;\nesac\nprintf '{\\n  \"name\": \"a\",\\n  \"version\": \"1.0.0\",\\n  \"dependencies\": {\\n    \"minimist\": \"^1.2.0\"\\n  }\\n}\\n' > ROOT/package.json\ncat > ROOT/yarn.lock <<'EOF'\n".to_owned() + YARN_LOCK_NEW + "EOF\n";

    let ran = run(&case(
        "npm",
        "package.json",
        vec![("package.json", YARN_A), ("yarn.lock", YARN_LOCK_OLD)],
        vec![("yarn", &body)],
        "lockonly",
        MINIMIST_LOCK_ONLY,
    ));

    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
    assert_eq!(ran.read("package.json"), YARN_A.as_bytes());
}

#[test]
fn yarn_member_not_listed_by_the_tool_is_refused_without_a_writing_spawn() {
    let listing =
        "{\"location\":\".\",\"name\":\"root\"}\n{\"location\":\"packages/b\",\"name\":\"b\"}\n";
    let body = yarn_body(listing, false);

    let ran = run(&yarn_member_case(&body, "lockonly", MINIMIST_LOCK_ONLY));

    assert!(
        ran.outcome.contains("WorkspaceMemberLockfile"),
        "{}",
        ran.outcome
    );
    assert!(
        writing_calls(&ran, "yarn", YARN_PROBES).is_empty(),
        "{:?}",
        ran.calls
    );
}

#[test]
fn yarn_member_listed_twice_is_refused_without_a_writing_spawn() {
    let listing = format!("{YARN_WORKSPACES}{{\"location\":\"packages/a\",\"name\":\"a2\"}}\n");
    let body = yarn_body(&listing, false);

    let ran = run(&yarn_member_case(&body, "lockonly", MINIMIST_LOCK_ONLY));

    assert!(
        ran.outcome.contains("WorkspaceMemberLockfile"),
        "{}",
        ran.outcome
    );
    assert!(
        writing_calls(&ran, "yarn", YARN_PROBES).is_empty(),
        "{:?}",
        ran.calls
    );
}

#[test]
fn yarn_member_with_a_traversing_location_is_a_failed_probe() {
    let listing = "{\"location\":\"../outside\",\"name\":\"x\"}\n";
    let body = yarn_body(listing, false);

    let ran = run(&yarn_member_case(&body, "lockonly", MINIMIST_LOCK_ONLY));

    assert!(
        ran.outcome.contains("UnexpectedProbeOutput"),
        "{}",
        ran.outcome
    );
    assert!(
        writing_calls(&ran, "yarn", YARN_PROBES).is_empty(),
        "{:?}",
        ran.calls
    );
}

fn assert_listing_too_large(listing: String) {
    let body = "case \"$1\" in\n  --version) echo 4.5.0; exit 0;;\n  workspaces) cat ROOT/listing.txt; exit 0;;\nesac\nexit 0\n";
    let mut case = yarn_member_case(body, "lockonly", MINIMIST_LOCK_ONLY);
    case.files.push(("listing.txt", listing.into_bytes()));

    let ran = run(&case);

    assert!(
        ran.outcome.contains("LockfileSetTooLarge"),
        "{}",
        ran.outcome
    );
    assert!(
        writing_calls(&ran, "yarn", YARN_PROBES).is_empty(),
        "{:?}",
        ran.calls
    );
}

#[test]
fn yarn_listing_over_the_probe_cap_is_refused_as_too_large_without_a_writing_spawn() {
    let pad = "x".repeat(1000);
    let mut listing = String::from("{\"location\":\".\",\"name\":\"root\"}\n");
    for index in 0..600 {
        listing.push_str(&format!(
            "{{\"location\":\"w/{index}\",\"name\":\"w{index}{pad}\"}}\n"
        ));
    }
    assert_listing_too_large(listing);
}

#[test]
fn yarn_listing_of_more_than_512_workspaces_is_refused_as_too_large() {
    let mut listing = String::from("{\"location\":\".\",\"name\":\"root\"}\n");
    for index in 0..513 {
        listing.push_str(&format!(
            "{{\"location\":\"w/{index}\",\"name\":\"w{index}\"}}\n"
        ));
    }
    assert_listing_too_large(listing);
}

#[test]
fn yarn_listed_workspace_without_a_manifest_is_an_ownership_mismatch() {
    let listing =
        format!("{YARN_WORKSPACES}{{\"location\":\"packages/gone\",\"name\":\"gone\"}}\n");
    let body = yarn_body(&listing, false);

    let ran = run(&yarn_member_case(&body, "lockonly", MINIMIST_LOCK_ONLY));

    assert!(
        ran.outcome.contains("LockfileOwnershipMismatch"),
        "{}",
        ran.outcome
    );
    assert!(
        writing_calls(&ran, "yarn", YARN_PROBES).is_empty(),
        "{:?}",
        ran.calls
    );
}

#[test]
fn yarn_non_utf8_listing_fails_closed_as_unexpected_output_not_as_too_large() {
    let body = "case \"$1\" in\n  --version) echo 4.5.0; exit 0;;\n  workspaces) printf '\\377\\376\\n'; exit 0;;\nesac\nexit 0\n";

    let ran = run(&yarn_member_case(body, "lockonly", MINIMIST_LOCK_ONLY));

    assert!(
        ran.outcome.contains("UnexpectedProbeOutput"),
        "{}",
        ran.outcome
    );
    assert!(
        !ran.outcome.contains("LockfileSetTooLarge"),
        "{}",
        ran.outcome
    );
    assert!(
        writing_calls(&ran, "yarn", YARN_PROBES).is_empty(),
        "{:?}",
        ran.calls
    );
}

#[test]
fn yarn_malformed_listing_line_fails_closed_as_unexpected_output() {
    let listing = format!("{YARN_WORKSPACES}this is not json\n");
    let body = yarn_body(&listing, false);

    let ran = run(&yarn_member_case(&body, "lockonly", MINIMIST_LOCK_ONLY));

    assert!(
        ran.outcome.contains("UnexpectedProbeOutput"),
        "{}",
        ran.outcome
    );
    assert!(
        !ran.outcome.contains("LockfileSetTooLarge"),
        "{}",
        ran.outcome
    );
    assert!(
        writing_calls(&ran, "yarn", YARN_PROBES).is_empty(),
        "{:?}",
        ran.calls
    );
}

#[test]
fn yarn_listed_glob_location_fails_closed() {
    let listing = "{\"location\":\"packages/*\",\"name\":\"x\"}\n";
    let body = yarn_body(listing, false);

    let ran = run(&yarn_member_case(&body, "lockonly", MINIMIST_LOCK_ONLY));

    assert!(
        ran.outcome.contains("UnexpectedProbeOutput"),
        "{}",
        ran.outcome
    );
}

#[test]
fn yarn_member_under_an_outer_workspace_root_is_refused_without_a_spawn() {
    let outer = "{\"name\":\"outer\",\"private\":true,\"workspaces\":[\"inner\"]}";
    let body = yarn_body(YARN_WORKSPACES, false);

    let ran = run(&case(
        "npm",
        "inner/packages/a/package.json",
        vec![
            ("package.json", outer),
            ("inner/package.json", YARN_ROOT_PACKAGE),
            ("inner/packages/a/package.json", YARN_A),
            ("inner/yarn.lock", YARN_LOCK_OLD),
        ],
        vec![("yarn", &body)],
        "lockonly",
        MINIMIST_LOCK_ONLY,
    ));

    assert!(
        ran.outcome.contains("WorkspaceMemberLockfile"),
        "{}",
        ran.outcome
    );
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}

#[test]
fn yarn_standalone_workspace_root_with_seventy_workspaces_is_regenerated() {
    let root_pkg = "{\"name\":\"root\",\"private\":true,\"workspaces\":[\"packages/*\"],\"dependencies\":{\"minimist\":\"^1.2.0\"}}";
    let mut listing = String::from("{\"location\":\".\",\"name\":\"root\"}\n");
    let mut files: Vec<(String, Vec<u8>)> = vec![
        ("package.json".to_owned(), root_pkg.as_bytes().to_vec()),
        ("yarn.lock".to_owned(), YARN_LOCK_OLD.as_bytes().to_vec()),
    ];
    for index in 0..70 {
        let name = format!("service-component-{index}");
        listing.push_str(&format!(
            "{{\"location\":\"packages/{name}\",\"name\":\"@acme/{name}\"}}\n"
        ));
        files.push((
            format!("packages/{name}/package.json"),
            format!("{{\"name\":\"@acme/{name}\",\"version\":\"1.0.0\"}}").into_bytes(),
        ));
    }
    assert!(
        listing.len() > 4096,
        "the listing must exceed the default probe cap"
    );
    files.push(("listing.txt".to_owned(), listing.into_bytes()));
    let body = format!(
        "case \"$1\" in\n  --version) echo 4.5.0; exit 0;;\n  workspaces) cat ROOT/listing.txt; exit 0;;\nesac\ncat > ROOT/yarn.lock <<'EOF'\n{YARN_LOCK_NEW}EOF\n"
    );
    let mut case = case(
        "npm",
        "package.json",
        Vec::new(),
        vec![("yarn", &body)],
        "lockonly",
        MINIMIST_LOCK_ONLY,
    );
    case.files = files
        .iter()
        .map(|(path, bytes)| (path.as_str(), bytes.clone()))
        .collect();

    let ran = run(&case);

    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
}

// --- #2076: Bun ---

const BUN_PACKAGE: &str = "{\n  \"name\": \"p\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {\n    \"minimist\": \"^1.2.0\"\n  }\n}\n";
const BUN_LOCK_OLD: &str = "{\n  \"lockfileVersion\": 1,\n  \"workspaces\": {\n    \"\": {\n      \"name\": \"p\",\n      \"dependencies\": {\n        \"minimist\": \"^1.2.0\",\n      },\n    },\n  },\n  \"packages\": {\n    \"minimist\": [\"minimist@1.2.0\", \"\", {}, \"sha512-aaa\"],\n  }\n}\n";
const BUN_LOCK_NEW: &str = "{\n  \"lockfileVersion\": 1,\n  \"workspaces\": {\n    \"\": {\n      \"name\": \"p\",\n      \"dependencies\": {\n        \"minimist\": \"^1.2.8\",\n      },\n    },\n  },\n  \"packages\": {\n    \"minimist\": [\"minimist@1.2.8\", \"\", {}, \"sha512-bbb\"],\n  }\n}\n";

fn bun_body() -> String {
    format!("cat package.json >> ROOT/seen.log\ncat > ROOT/bun.lock <<'EOF'\n{BUN_LOCK_NEW}EOF\n")
}

fn bun_case<'a>(body: &'a str, mode: &'a str, bumps: &'a str) -> Case<'a> {
    case(
        "npm",
        "package.json",
        vec![("package.json", BUN_PACKAGE), ("bun.lock", BUN_LOCK_OLD)],
        vec![("bun", body)],
        mode,
        bumps,
    )
}

#[test]
fn bun_manifest_edit_runs_the_lockfile_only_install_with_scripts_disabled() {
    let body = bun_body();

    let ran = run(&bun_case(&body, "edit", MINIMIST_EDIT));

    let calls = ran.calls_of("bun");
    assert_eq!(calls.len(), 1, "{:?}", ran.calls);
    assert!(
        calls[0].starts_with("bun install --lockfile-only --ignore-scripts|"),
        "{}",
        calls[0]
    );
    assert_eq!(cwd_of(calls[0]), ran.root.display().to_string());
    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
}

#[test]
fn bun_workspace_member_is_refused_without_a_spawn() {
    let body = bun_body();

    let ran = run(&case(
        "npm",
        "packages/a/package.json",
        vec![
            ("package.json", ROOT_PACKAGE),
            ("packages/a/package.json", MEMBER_PACKAGE),
            ("bun.lock", BUN_LOCK_OLD),
        ],
        vec![("bun", &body)],
        "edit",
        MINIMIST_EDIT,
    ));

    assert!(
        ran.outcome.contains("WorkspaceMemberLockfile"),
        "{}",
        ran.outcome
    );
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}

// --- #2077: cooldown-fallback exact pins ---

fn fallback(mut case: Case<'_>) -> Case<'_> {
    case.cooldown_fallback = true;
    case
}

fn npm_standalone_body() -> String {
    format!(
        "cat ROOT/package.json >> ROOT/seen.log\ncat > ROOT/package-lock.json <<'EOF'\n{NPM_FALLBACK_LOCK_NEW}EOF\n"
    )
}

const NPM_STANDALONE_PACKAGE: &str = "{\n  \"name\": \"p\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {\n    \"minimist\": \"^1.2.0\"\n  }\n}\n";
const NPM_STANDALONE_LOCK_OLD: &str = "{\"name\":\"p\",\"version\":\"1.0.0\",\"lockfileVersion\":3,\"requires\":true,\"packages\":{\"\":{\"name\":\"p\",\"version\":\"1.0.0\",\"dependencies\":{\"minimist\":\"^1.2.0\"}},\"node_modules/minimist\":{\"version\":\"1.2.0\"}}}\n";
const NPM_FALLBACK_LOCK_NEW: &str = "{\"name\":\"p\",\"version\":\"1.0.0\",\"lockfileVersion\":3,\"requires\":true,\"packages\":{\"\":{\"name\":\"p\",\"version\":\"1.0.0\",\"dependencies\":{\"minimist\":\"^1.2.0\"}},\"node_modules/minimist\":{\"version\":\"1.2.8\"}}}\n";

fn npm_standalone_case<'a>(package: &'a str, body: &'a str, mode: &'a str) -> Case<'a> {
    fallback(case(
        "npm",
        "package.json",
        vec![
            ("package.json", package),
            ("package-lock.json", NPM_STANDALONE_LOCK_OLD),
        ],
        vec![("npm", body)],
        mode,
        MINIMIST_LOCK_ONLY,
    ))
}

#[test]
fn npm_fallback_pin_runs_the_install_form_with_an_exact_pin_then_again_with_the_original_manifest()
{
    let body = npm_standalone_body();

    let ran = run(&npm_standalone_case(
        NPM_STANDALONE_PACKAGE,
        &body,
        "lockonly",
    ));

    let calls = ran.calls_of("npm");
    assert_eq!(calls.len(), 2, "{:?}", ran.calls);
    assert!(
        calls
            .iter()
            .all(|call| call.starts_with("npm install --package-lock-only ")),
        "{calls:?}"
    );
    let log = seen(&ran);
    let (first, second) = log.split_once("}\n{").expect("two manifest dumps");
    assert!(first.contains("\"minimist\": \"1.2.8\""), "{first}");
    assert!(second.contains("\"minimist\": \"^1.2.0\""), "{second}");
    assert_eq!(ran.read("package.json"), NPM_STANDALONE_PACKAGE.as_bytes());
    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
}

#[test]
fn npm_fallback_pin_that_the_lock_does_not_hold_exactly_fails_and_restores_both_files() {
    let body = format!(
        "cat ROOT/package.json >> ROOT/seen.log\ncat > ROOT/package-lock.json <<'EOF'\n{}EOF\n",
        NPM_FALLBACK_LOCK_NEW.replace("1.2.8", "1.2.9")
    );

    let ran = run(&npm_standalone_case(
        NPM_STANDALONE_PACKAGE,
        &body,
        "lockonly",
    ));

    assert!(ran.outcome.contains("VersionMismatch"), "{}", ran.outcome);
    assert_eq!(ran.read("package.json"), NPM_STANDALONE_PACKAGE.as_bytes());
    assert_eq!(
        ran.read("package-lock.json"),
        NPM_STANDALONE_LOCK_OLD.as_bytes()
    );
}

#[test]
fn npm_fallback_pin_declared_twice_is_refused_before_any_write() {
    let package = "{\n  \"name\": \"p\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {\n    \"minimist\": \"^1.2.0\"\n  },\n  \"devDependencies\": {\n    \"minimist\": \"^1.2.0\"\n  }\n}\n";
    let body = npm_standalone_body();

    let ran = run(&npm_standalone_case(package, &body, "lockonly"));

    assert!(
        ran.outcome.contains("CooldownFallbackTarget"),
        "{}",
        ran.outcome
    );
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
    assert_eq!(ran.read("package.json"), package.as_bytes());
}

#[test]
fn npm_fallback_pin_failure_in_the_tool_puts_the_manifest_back() {
    let body = "cat ROOT/package.json >> ROOT/seen.log\nexit 3\n";

    let ran = run(&npm_standalone_case(
        NPM_STANDALONE_PACKAGE,
        body,
        "lockonly",
    ));

    assert!(ran.outcome.contains("ToolFailed"), "{}", ran.outcome);
    assert_eq!(ran.read("package.json"), NPM_STANDALONE_PACKAGE.as_bytes());
    assert_eq!(
        ran.read("package-lock.json"),
        NPM_STANDALONE_LOCK_OLD.as_bytes()
    );
}

const GEMFILE: &str = "source 'https://rubygems.org'\ngem 'rake', '~> 13.0'\n";
const GEM_LOCK_OLD: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.0.6)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rake (~> 13.0)\n\nBUNDLED WITH\n   2.5.0\n";
const GEM_LOCK_NEW: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.1.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rake (~> 13.0)\n\nBUNDLED WITH\n   2.5.0\n";
const RAKE_LOCK_ONLY: &str = "rake|gem 'rake'|~> 13.0|~> 13.0|13.0.6|13.1.0";

#[test]
fn bundler_fallback_pin_locks_the_exact_gem_then_relocks_with_the_original_gemfile() {
    let body = format!(
        "cat ROOT/Gemfile >> ROOT/seen.log\ncat > ROOT/Gemfile.lock <<'EOF'\n{GEM_LOCK_NEW}EOF\n"
    );
    let ran = run(&fallback(case(
        "bundler",
        "Gemfile",
        vec![("Gemfile", GEMFILE), ("Gemfile.lock", GEM_LOCK_OLD)],
        vec![("bundle", &body)],
        "lockonly",
        RAKE_LOCK_ONLY,
    )));

    let calls = ran.calls_of("bundle");
    assert_eq!(calls.len(), 2, "{:?}", ran.calls);
    assert!(
        calls.iter().all(|call| call.starts_with("bundle lock|")),
        "{calls:?}"
    );
    let log = seen(&ran);
    assert!(
        log.starts_with("source 'https://rubygems.org'\ngem 'rake', '13.1.0'\n"),
        "{log}"
    );
    assert!(log.ends_with(GEMFILE), "{log}");
    assert_eq!(ran.read("Gemfile"), GEMFILE.as_bytes());
    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
}

#[test]
fn bun_fallback_pin_installs_twice_around_the_exact_pin() {
    let body = bun_body();
    let ran = run(&fallback(bun_case(&body, "edit", MINIMIST_EDIT)));

    let calls = ran.calls_of("bun");
    assert_eq!(calls.len(), 2, "{:?}", ran.calls);
    let log = seen(&ran);
    assert!(log.contains("\"minimist\": \"1.2.8\""), "{log}");
    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
}
