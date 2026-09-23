use deps_core::redact_debug::RedactingDebug;

#[derive(RedactingDebug)]
struct Conflicting {
    #[redact(url)]
    #[raw]
    token: String,
}

fn main() {}
