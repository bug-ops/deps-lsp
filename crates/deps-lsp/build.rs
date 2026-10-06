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

/// Watches `path`, or, when it does not exist yet (a branch held only in `packed-refs`), its
/// nearest existing ancestor directory, whose mtime changes when git writes the loose ref.
fn rerun_if_exists_or_ancestor(path: &str) {
    let mut candidate = Path::new(path);
    while !candidate.exists() {
        match candidate.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => candidate = parent,
            _ => return,
        }
    }
    if let Some(watched) = candidate.to_str() {
        println!("cargo:rerun-if-changed={watched}");
    }
}

/// Watches the files that change when HEAD moves: `HEAD` itself (branch switch), the loose ref
/// it points at (new commit on the branch, or the directory it will appear in when the branch
/// is packed) and `packed-refs` (after `git gc`/pack-refs).
///
/// Paths come from `git rev-parse --git-path`, so linked worktrees (where `.git` is a file)
/// resolve correctly.
fn emit_rerun_directives() {
    if let Some(head) = git(&["rev-parse", "--git-path", "HEAD"]) {
        rerun_if_exists(&head);
    }
    if let Some(reference) = git(&["rev-parse", "--symbolic-full-name", "HEAD"])
        && reference.starts_with("refs/")
        && let Some(path) = git(&["rev-parse", "--git-path", &reference])
    {
        rerun_if_exists_or_ancestor(&path);
    }
    if let Some(packed) = git(&["rev-parse", "--git-path", "packed-refs"]) {
        rerun_if_exists(&packed);
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
