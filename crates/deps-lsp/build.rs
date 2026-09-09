//! Build script that captures the current git commit hash and build timestamp
//! as `GIT_HASH`/`BUILD_TIME` environment variables, surfaced by `--version`.

fn main() {
    let hash = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    println!("cargo:rustc-env=GIT_HASH={}", hash.trim());

    let now = std::process::Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    println!("cargo:rustc-env=BUILD_TIME={}", now.trim());

    println!("cargo:rerun-if-changed=../../.git/HEAD");
}
