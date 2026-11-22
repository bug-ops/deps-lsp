//! #2041 / spec 099 FR-014: a malformed release-age value warns once per file change, not on
//! every `package.json` parse (impl-critic M9).

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{honor, label_of, parse_manifest, root, write};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};

/// Counts `WARN` events.
struct Warnings(Arc<AtomicUsize>);

impl Subscriber for Warnings {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        *metadata.level() <= Level::WARN
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        if *event.metadata().level() == Level::WARN {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}

fn warnings_over<R>(run: impl FnOnce() -> R) -> (R, usize) {
    let count = Arc::new(AtomicUsize::new(0));
    let result = tracing::subscriber::with_default(Warnings(Arc::clone(&count)), run);
    (result, count.load(Ordering::SeqCst))
}

#[test]
fn a_malformed_npmrc_value_warns_once_across_repeated_parses() {
    let (_g, root) = root();
    write(&root.join("package-lock.json"), "{}");
    write(&root.join(".npmrc"), "min-release-age=soon\n");
    let ctx = honor();
    let (labels, warnings) = warnings_over(|| {
        (0..5)
            .map(|_| {
                label_of(
                    &parse_manifest(&root, &[("lodash", "^4.0.0")], &ctx),
                    "lodash",
                )
            })
            .collect::<Vec<_>>()
    });
    assert!(labels.iter().all(Option::is_none));
    assert_eq!(warnings, 1, "one warning per file change, not per parse");
}

#[test]
fn a_changed_malformed_npmrc_warns_again() {
    let (_g, root) = root();
    write(&root.join("package-lock.json"), "{}");
    write(&root.join(".npmrc"), "min-release-age=soon\n");
    let ctx = honor();
    let parse = || parse_manifest(&root, &[("lodash", "^4.0.0")], &ctx);
    let (_, first) = warnings_over(parse);
    // A different length also changes the cache key on filesystems with coarse mtimes.
    write(&root.join(".npmrc"), "min-release-age=later-than-soon\n");
    let (_, second) = warnings_over(parse);
    assert_eq!((first, second), (1, 1));
}
