use deps_core::redact_debug::RedactingDebug;

#[derive(RedactingDebug)]
struct Unannotated {
    token: String,
}

fn main() {}
