//! Xcode's SCM-to-registry default, read without ever blocking a request (#1879).
//!
//! `registries.swift_scm_to_registry = "from_xcode"` follows the
//! `IDEPackageDependencySCMToRegistryTransformation` user default. Reading it spawns
//! `/usr/bin/defaults`, so the read runs once per process on a plain thread (never a tokio
//! worker) and callers only ever see the cached result through [`XcodeDefaultsCell::cached`].

use std::sync::{Arc, LazyLock, Once};
use std::time::Duration;

use tokio::sync::watch;

use crate::scm::ScmSwizzleMode;

/// What the Xcode user default says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum XcodeScmTransformation {
    /// The default is unset or `none`.
    NotSet,
    /// `useRegistryIdentity`: the registry identity is used but source control stays the version
    /// source, so nothing observable changes.
    UseRegistryIdentity,
    /// `useRegistryIdentityAndSources`: the registry replaces source control.
    UseRegistryIdentityAndSources,
    /// A value this version does not know.
    Unrecognized,
    /// The default cannot be read: not macOS, or the read failed or timed out.
    Unavailable,
}

impl XcodeScmTransformation {
    /// Only `useRegistryIdentityAndSources` swaps dependencies.
    pub(crate) const fn swizzle_mode(self) -> ScmSwizzleMode {
        match self {
            Self::UseRegistryIdentityAndSources => ScmSwizzleMode::Replace,
            Self::NotSet | Self::UseRegistryIdentity | Self::Unrecognized | Self::Unavailable => {
                ScmSwizzleMode::Disabled
            }
        }
    }

    /// Classifies the outcome of `defaults read`: a non-zero exit means the key is unset.
    pub(crate) fn from_defaults_output(success: bool, stdout: &str) -> Self {
        if !success {
            return Self::NotSet;
        }
        match stdout.trim() {
            "none" => Self::NotSet,
            "useRegistryIdentity" => Self::UseRegistryIdentity,
            "useRegistryIdentityAndSources" => Self::UseRegistryIdentityAndSources,
            _ => Self::Unrecognized,
        }
    }
}

/// Reads the Xcode default, blocking; only ever called on the dedicated thread.
pub(crate) type XcodeReader = fn() -> XcodeScmTransformation;

/// A once-per-cell, background-filled cache of the Xcode default.
#[derive(Debug)]
pub(crate) struct XcodeDefaultsCell {
    reader: Option<XcodeReader>,
    primed: Once,
    value: watch::Sender<Option<XcodeScmTransformation>>,
}

static PROCESS: LazyLock<Arc<XcodeDefaultsCell>> =
    LazyLock::new(|| Arc::new(XcodeDefaultsCell::new(system_reader())));

impl XcodeDefaultsCell {
    /// A cell reading through `reader`; `None` means the default cannot exist here, so the cell
    /// is resolved to [`XcodeScmTransformation::Unavailable`] without spawning anything.
    pub(crate) fn new(reader: Option<XcodeReader>) -> Self {
        let (value, _) = watch::channel(
            reader
                .is_none()
                .then_some(XcodeScmTransformation::Unavailable),
        );
        Self {
            reader,
            primed: Once::new(),
            value,
        }
    }

    /// Records the first result; later ones are ignored.
    fn settle(value: &watch::Sender<Option<XcodeScmTransformation>>, read: XcodeScmTransformation) {
        value.send_if_modified(|slot| slot.is_none().then(|| *slot = Some(read)).is_some());
    }

    /// The process-wide cell, so the default is read at most once per process.
    pub(crate) fn process() -> Arc<Self> {
        Arc::clone(&PROCESS)
    }

    /// Starts the read on a plain thread, at most once; returns immediately.
    pub(crate) fn prime(&self) {
        let Some(reader) = self.reader else {
            return;
        };
        self.primed.call_once(|| {
            let value = self.value.clone();
            let spawned = std::thread::Builder::new()
                .name("deps-xcode-defaults".into())
                .spawn({
                    let value = value.clone();
                    move || {
                        let read = reader();
                        if read == XcodeScmTransformation::Unrecognized {
                            tracing::warn!(
                                "unrecognized IDEPackageDependencySCMToRegistryTransformation \
                                 value; treating it as disabled"
                            );
                        }
                        Self::settle(&value, read);
                    }
                });
            if let Err(error) = spawned {
                tracing::warn!(%error, "could not start the Xcode defaults reader");
                Self::settle(&value, XcodeScmTransformation::Unavailable);
            }
        });
    }

    /// The result of the read, or `None` while it is still running or was never started.
    pub(crate) fn cached(&self) -> Option<XcodeScmTransformation> {
        *self.value.borrow()
    }

    /// Resolves when the read has finished (immediately if it already has). A cell that was
    /// never primed never resolves, so callers must prime first.
    pub(crate) async fn wait(&self) {
        let mut ready = self.value.subscribe();
        let _ = ready.wait_for(Option::is_some).await;
    }

    /// Blocks the calling thread until the read finishes or `timeout` passes; for the CLI only,
    /// never a request path.
    pub(crate) fn wait_blocking(&self, timeout: Duration) {
        const POLL: Duration = Duration::from_millis(5);
        let deadline = std::time::Instant::now() + timeout;
        while self.cached().is_none() && std::time::Instant::now() < deadline {
            std::thread::sleep(POLL);
        }
    }
}

#[cfg(target_os = "macos")]
fn system_reader() -> Option<XcodeReader> {
    Some(read_system_defaults)
}

#[cfg(not(target_os = "macos"))]
fn system_reader() -> Option<XcodeReader> {
    None
}

#[cfg(target_os = "macos")]
fn read_system_defaults() -> XcodeScmTransformation {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const TIMEOUT: Duration = Duration::from_secs(2);
    const POLL: Duration = Duration::from_millis(10);
    const MAX_OUTPUT: u64 = 256;

    let spawned = Command::new("/usr/bin/defaults")
        .args([
            "read",
            "com.apple.dt.Xcode",
            "IDEPackageDependencySCMToRegistryTransformation",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = spawned else {
        return XcodeScmTransformation::Unavailable;
    };
    let deadline = Instant::now() + TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL),
            Ok(None) | Err(_) => {
                drop(child.kill());
                drop(child.wait());
                return XcodeScmTransformation::Unavailable;
            }
        }
    };
    let mut stdout = String::new();
    if let Some(pipe) = child.stdout.take()
        && pipe.take(MAX_OUTPUT).read_to_string(&mut stdout).is_err()
    {
        return XcodeScmTransformation::Unavailable;
    }
    XcodeScmTransformation::from_defaults_output(status.success(), &stdout)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use deps_core::policy_config::ScmToRegistry;

    use super::*;
    use crate::scm::ScmToRegistryHandle;

    static READS: AtomicUsize = AtomicUsize::new(0);

    fn counting_reader() -> XcodeScmTransformation {
        READS.fetch_add(1, Ordering::SeqCst);
        XcodeScmTransformation::UseRegistryIdentityAndSources
    }

    fn sources_reader() -> XcodeScmTransformation {
        XcodeScmTransformation::UseRegistryIdentityAndSources
    }

    fn wait_for(cell: &XcodeDefaultsCell) -> XcodeScmTransformation {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(value) = cell.cached() {
                return value;
            }
            assert!(Instant::now() < deadline, "reader did not finish");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn test_defaults_output_classification() {
        use XcodeScmTransformation as X;
        assert_eq!(X::from_defaults_output(false, ""), X::NotSet);
        assert_eq!(X::from_defaults_output(true, "none\n"), X::NotSet);
        assert_eq!(
            X::from_defaults_output(true, "useRegistryIdentity\n"),
            X::UseRegistryIdentity
        );
        assert_eq!(
            X::from_defaults_output(true, "useRegistryIdentityAndSources\n"),
            X::UseRegistryIdentityAndSources
        );
        assert_eq!(X::from_defaults_output(true, "bogus"), X::Unrecognized);
    }

    #[test]
    fn test_only_sources_transformation_replaces() {
        use XcodeScmTransformation as X;
        for value in [
            X::NotSet,
            X::UseRegistryIdentity,
            X::Unrecognized,
            X::Unavailable,
        ] {
            assert_eq!(value.swizzle_mode(), ScmSwizzleMode::Disabled, "{value:?}");
        }
        assert_eq!(
            X::UseRegistryIdentityAndSources.swizzle_mode(),
            ScmSwizzleMode::Replace
        );
    }

    #[test]
    fn test_from_xcode_is_disabled_until_the_read_finishes() {
        let cell = Arc::new(XcodeDefaultsCell::new(Some(sources_reader)));
        let handle = ScmToRegistryHandle::with_xcode(Arc::clone(&cell));
        assert_eq!(handle.get(), ScmSwizzleMode::Disabled);
        handle.set(ScmToRegistry::FromXcode);
        wait_for(&cell);
        assert_eq!(handle.get(), ScmSwizzleMode::Replace);
        handle.set(ScmToRegistry::Disabled);
        assert_eq!(handle.get(), ScmSwizzleMode::Disabled);
    }

    #[test]
    fn test_unprimed_cell_stays_disabled() {
        let cell = Arc::new(XcodeDefaultsCell::new(Some(sources_reader)));
        assert_eq!(cell.cached(), None);
    }

    fn slow_sources_reader() -> XcodeScmTransformation {
        std::thread::sleep(Duration::from_millis(100));
        XcodeScmTransformation::UseRegistryIdentityAndSources
    }

    #[tokio::test]
    async fn test_settled_resolves_to_replace_after_a_slow_read() {
        let cell = Arc::new(XcodeDefaultsCell::new(Some(slow_sources_reader)));
        let handle = ScmToRegistryHandle::with_xcode(Arc::clone(&cell));
        handle.set(ScmToRegistry::FromXcode);
        assert!(handle.xcode_pending());
        assert_eq!(handle.get(), ScmSwizzleMode::Disabled);
        assert!(handle.xcode_settled().await);
        assert!(!handle.xcode_pending());
        assert_eq!(handle.get(), ScmSwizzleMode::Replace);
    }

    #[tokio::test]
    async fn test_settled_is_false_when_xcode_does_not_replace() {
        let cell = Arc::new(XcodeDefaultsCell::new(None));
        let handle = ScmToRegistryHandle::with_xcode(cell);
        handle.set(ScmToRegistry::FromXcode);
        assert!(!handle.xcode_pending());
        assert!(!handle.xcode_settled().await);
    }

    #[test]
    fn test_wait_for_xcode_blocks_until_the_read_ends_and_ignores_other_settings() {
        let cell = Arc::new(XcodeDefaultsCell::new(Some(slow_sources_reader)));
        let handle = ScmToRegistryHandle::with_xcode(cell);
        handle.set(ScmToRegistry::FromXcode);
        handle.wait_for_xcode(Duration::from_secs(5));
        assert_eq!(handle.get(), ScmSwizzleMode::Replace);

        let idle = ScmToRegistryHandle::with_xcode(Arc::new(XcodeDefaultsCell::new(Some(
            slow_sources_reader,
        ))));
        let start = Instant::now();
        idle.wait_for_xcode(Duration::from_secs(5));
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn test_prime_reads_once() {
        let cell = XcodeDefaultsCell::new(Some(counting_reader));
        cell.prime();
        cell.prime();
        wait_for(&cell);
        cell.prime();
        assert_eq!(READS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_cell_without_reader_is_unavailable_and_never_spawns() {
        let cell = XcodeDefaultsCell::new(None);
        assert_eq!(cell.cached(), Some(XcodeScmTransformation::Unavailable));
        cell.prime();
        let handle = ScmToRegistryHandle::with_xcode(Arc::new(cell));
        handle.set(ScmToRegistry::FromXcode);
        assert_eq!(handle.get(), ScmSwizzleMode::Disabled);
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "spawns the real /usr/bin/defaults"]
    fn test_real_defaults_read_completes() {
        let _ = read_system_defaults();
    }
}
