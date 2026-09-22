use deps_core::redact_debug::RedactingDebug;

#[derive(RedactingDebug)]
enum HostKind {
    Literal(String),
    Unresolved,
}

fn main() {}
