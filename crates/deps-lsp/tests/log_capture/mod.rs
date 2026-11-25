//! Scoped `tracing` capture shared by the acceptance tests that assert on log levels.
//!
//! The subscriber is installed with `set_default`, so it is thread-local: use it only from a
//! `current_thread` tokio test, where every task of the test runs on the installing thread.

#![expect(clippy::unwrap_used, reason = "test helper")]

use std::io;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl io::Write for SharedBuf {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl tracing_subscriber::fmt::MakeWriter<'_> for SharedBuf {
    type Writer = Self;

    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}

/// The `fmt` layer right-aligns levels to five characters, so `WARN` is preceded by a space while
/// `DEBUG` and `ERROR` start at column 0.
fn has_level(line: &str, level: &str) -> bool {
    line.trim_start()
        .strip_prefix(level)
        .is_some_and(|rest| rest.starts_with(' '))
}

/// Handle to the lines captured since [`LogCapture::install`].
pub(crate) struct LogCapture(Arc<Mutex<Vec<u8>>>);

impl LogCapture {
    /// Installs a DEBUG-level capturing subscriber for the current thread until the guard drops.
    pub(crate) fn install() -> (Self, tracing::subscriber::DefaultGuard) {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(SharedBuf(Arc::clone(&buf)))
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .without_time()
            .finish();
        (Self(buf), tracing::subscriber::set_default(subscriber))
    }

    fn lines(&self) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// Every captured WARN or ERROR line containing `needle`.
    pub(crate) fn warnings_containing(&self, needle: &str) -> Vec<String> {
        self.lines()
            .into_iter()
            .filter(|line| {
                (has_level(line, "WARN") || has_level(line, "ERROR")) && line.contains(needle)
            })
            .collect()
    }

    /// Every captured DEBUG line containing `needle`.
    #[allow(dead_code)] // used by a subset of the test binaries
    pub(crate) fn debug_containing(&self, needle: &str) -> Vec<String> {
        self.lines()
            .into_iter()
            .filter(|line| has_level(line, "DEBUG") && line.contains(needle))
            .collect()
    }
}
