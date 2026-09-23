use deps_core::redact_debug::RedactingDebug;

#[derive(RedactingDebug)]
struct ConflictingArgs {
    #[redact(url, key)]
    token: String,
}

fn main() {}
