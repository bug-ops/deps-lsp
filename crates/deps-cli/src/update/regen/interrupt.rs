//! SIGINT/SIGTERM (Ctrl-C on Windows) listener for one regeneration.
//!
//! Without a handler a signal kills deps-cli before any `Drop` runs, so a tool running in its
//! own process group would be orphaned. Installing the listener turns the signal into a value
//! the regeneration can `select!` on, which drops the session and fires the child guards.

use std::io;

/// Listens for the process-level interrupt signals; handlers stay installed until exit.
#[derive(Debug)]
pub(in crate::update) struct Interrupts {
    #[cfg(unix)]
    sigint: tokio::signal::unix::Signal,
    #[cfg(unix)]
    sigterm: tokio::signal::unix::Signal,
}

impl Interrupts {
    /// Registers the handlers; must run inside a tokio runtime, before the first spawn.
    ///
    /// # Errors
    ///
    /// The OS refused to register a handler.
    #[cfg(unix)]
    pub(in crate::update) fn install() -> io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            sigint: signal(SignalKind::interrupt())?,
            sigterm: signal(SignalKind::terminate())?,
        })
    }

    /// Registers the handlers; the Windows Ctrl-C handler is installed lazily by [`Self::recv`].
    ///
    /// # Errors
    ///
    /// Never fails on Windows.
    #[cfg(not(unix))]
    #[allow(clippy::unnecessary_wraps)]
    pub(in crate::update) fn install() -> io::Result<Self> {
        Ok(Self {})
    }

    /// Resolves on the first interrupt signal.
    #[cfg(unix)]
    pub(in crate::update) async fn recv(&mut self) {
        tokio::select! {
            _ = self.sigint.recv() => {}
            _ = self.sigterm.recv() => {}
        }
    }

    /// Resolves on the first Ctrl-C; never resolves if the handler cannot be registered.
    #[cfg(not(unix))]
    // Keeps the `&mut self` signature of the unix version, which polls its signal streams.
    #[allow(clippy::needless_pass_by_ref_mut)]
    pub(in crate::update) async fn recv(&mut self) {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}
