//! Build script that captures the current git commit hash and build timestamp
//! as `GIT_HASH`/`BUILD_TIME` environment variables, surfaced by `--version`.

use std::path::Path;
use std::process::Command;

/// Runs `program args` and returns its stdout when it is exactly one non-empty line.
///
/// Cargo build-script directives are line-oriented, so any multi-line value is dropped rather
/// than risk it smuggling an extra `cargo:` directive.
fn single_line_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let line = text.trim();
    (!line.is_empty() && !line.contains(['\n', '\r'])).then(|| line.to_string())
}

fn git(args: &[&str]) -> Option<String> {
    single_line_output("git", args)
}

fn rerun_if_exists(path: &str) {
    if Path::new(path).exists() {
        println!("cargo:rerun-if-changed={path}");
    }
}

/// Where the commit HEAD resolves to is stored, which decides what must be watched.
enum RefLocation {
    /// A loose ref file; it wins over `packed-refs`, so it is the only ref file that matters.
    Loose(String),
    /// The branch exists only in `packed-refs`; a loose ref will appear under `dir`.
    PackedOnly {
        dir: String,
        packed_refs: Option<String>,
    },
    /// HEAD points directly at a commit, so `HEAD` itself is the only input.
    Detached,
}

/// Returns `path` when it exists, otherwise its nearest existing ancestor.
fn nearest_existing(path: &str) -> Option<String> {
    let mut candidate = Path::new(path);
    while !candidate.exists() {
        match candidate.parent() {
            Some(parent) if !parent.is_empty() => candidate = parent,
            _ => return None,
        }
    }
    candidate.to_str().map(str::to_string)
}

fn locate_ref() -> RefLocation {
    let Some(reference) = git(&["rev-parse", "--symbolic-full-name", "HEAD"])
        .filter(|reference| reference.starts_with("refs/"))
    else {
        return RefLocation::Detached;
    };
    let Some(path) = git(&["rev-parse", "--git-path", &reference]) else {
        return RefLocation::Detached;
    };
    if Path::new(&path).is_file() {
        return RefLocation::Loose(path);
    }
    match nearest_existing(&path) {
        Some(dir) => RefLocation::PackedOnly {
            dir,
            packed_refs: git(&["rev-parse", "--git-path", "packed-refs"]),
        },
        None => RefLocation::Detached,
    }
}

/// Watches the files that change when HEAD moves: `HEAD` itself (branch switch) plus either the
/// loose ref it points at or, for a branch held only in `packed-refs`, that file and the
/// directory the loose ref will appear in.
///
/// Watching `packed-refs` while a loose ref exists would rebuild on every `git pack-refs` run
/// from a sibling worktree even though this branch's commit did not move.
///
/// Paths come from `git rev-parse --git-path`, so linked worktrees (where `.git` is a file)
/// resolve correctly.
fn emit_rerun_directives() {
    if let Some(head) = git(&["rev-parse", "--git-path", "HEAD"]) {
        rerun_if_exists(&head);
    }
    match locate_ref() {
        RefLocation::Loose(path) => println!("cargo:rerun-if-changed={path}"),
        RefLocation::PackedOnly { dir, packed_refs } => {
            println!("cargo:rerun-if-changed={dir}");
            if let Some(packed) = packed_refs {
                rerun_if_exists(&packed);
            }
        }
        RefLocation::Detached => {}
    }
}

fn main() {
    let hash = git(&["rev-parse", "--short", "HEAD"])
        .filter(|h| h.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or_default();
    println!("cargo:rustc-env=GIT_HASH={hash}");

    let now = single_line_output("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"]).unwrap_or_default();
    println!("cargo:rustc-env=BUILD_TIME={now}");

    emit_rerun_directives();
}
