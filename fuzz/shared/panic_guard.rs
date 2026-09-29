//! Panic-hook override for fuzz targets whose code under test intentionally `catch_unwind`s a
//! third-party panic (e.g. `node_semver`, `pep508_rs`).
//!
//! `libfuzzer-sys` installs a hook that aborts on *any* panic, including ones a production
//! `catch_unwind` already handles. [`run_aborting_on_escape`] silences that hook only for
//! panics raised inside a [`ToleratedSource`] crate; every other panic still reaches the
//! original hook and aborts at the panic site with full output.

use std::cell::RefCell;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Once;

/// Third-party crates whose panics production code already catches with `catch_unwind`.
#[derive(Clone, Copy)]
enum ToleratedSource {
    NodeSemver,
    Pep508,
}

impl ToleratedSource {
    const ALL: [Self; 2] = [Self::NodeSemver, Self::Pep508];

    const fn crate_dir_prefix(self) -> &'static str {
        match self {
            Self::NodeSemver => "node-semver-",
            Self::Pep508 => "pep508_rs-",
        }
    }

    fn is_panic_site(info: &panic::PanicHookInfo<'_>) -> bool {
        info.location().is_some_and(|location| {
            Self::ALL
                .iter()
                .any(|source| location.file().contains(source.crate_dir_prefix()))
        })
    }
}

thread_local! {
    static LAST_TOLERATED_PANIC: RefCell<String> = const { RefCell::new(String::new()) };
}

static INSTALL: Once = Once::new();

/// Runs `f`, tolerating panics from [`ToleratedSource`] crates that are caught inside it, and
/// aborts the process (so libFuzzer reports a crash) if such a panic escapes `f`.
pub fn run_aborting_on_escape<T>(f: impl FnOnce() -> T) -> T {
    INSTALL.call_once(|| {
        let original_hook = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if ToleratedSource::is_panic_site(info) {
                LAST_TOLERATED_PANIC.with_borrow_mut(|message| *message = info.to_string());
            } else {
                original_hook(info);
            }
        }));
    });
    LAST_TOLERATED_PANIC.with_borrow_mut(String::clear);
    panic::catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| {
        eprintln!(
            "panic escaped: {}",
            LAST_TOLERATED_PANIC.with_borrow(Clone::clone)
        );
        std::process::abort()
    })
}
