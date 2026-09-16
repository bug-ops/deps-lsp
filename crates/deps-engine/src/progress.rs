//! Progress-reporting port for registry fetch tasks.
//!
//! [`ProgressSender`] lets a fetch task report `fetched`/`total` progress without knowing
//! whether, or how, anything renders it — a driving adapter drains the paired
//! `mpsc::Receiver<ProgressUpdate>` returned by [`channel`] however it sees fit (`deps-lsp`'s
//! `RegistryProgress` drives the LSP work-done-progress protocol from it; `deps-cli` may render
//! a terminal progress bar the same way, or drop the receiver and pass `None` as the sender).

use tokio::sync::mpsc;

/// Channel capacity for progress updates.
/// Small buffer is sufficient since updates are coalesced by the consumer.
const PROGRESS_CHANNEL_CAPACITY: usize = 8;

/// Non-blocking sender for progress updates from fetch tasks.
///
/// Cheap to clone and safe to use from multiple concurrent futures.
/// Dropped messages are acceptable — progress is best-effort UI feedback.
#[derive(Clone)]
pub struct ProgressSender {
    tx: mpsc::Sender<ProgressUpdate>,
    total: usize,
}

/// A single fetch-progress observation: `fetched` out of `total` packages processed so far.
#[derive(Debug, Clone, Copy)]
pub struct ProgressUpdate {
    /// Number of packages fetched so far.
    pub fetched: usize,
    /// Total number of packages being fetched in this run.
    pub total: usize,
}

impl ProgressSender {
    /// Send a progress update without blocking.
    ///
    /// Uses `try_send` — if the channel is full, the update is silently dropped.
    /// This is intentional: progress is best-effort UI feedback, and dropping
    /// updates is always preferable to blocking fetch tasks.
    ///
    /// # Examples
    ///
    /// ```
    /// let (sender, mut receiver) = deps_engine::progress::channel(10);
    /// sender.send(3);
    /// let update = receiver.try_recv().unwrap();
    /// assert_eq!((update.fetched, update.total), (3, 10));
    /// ```
    pub fn send(&self, fetched: usize) {
        let _ = self.tx.try_send(ProgressUpdate {
            fetched,
            total: self.total,
        });
    }
}

/// Creates a progress port: a [`ProgressSender`] fetch tasks report through, paired with the
/// `Receiver` a driving adapter drains to render progress however it sees fit.
///
/// `total` is the total unit count (e.g. dependency count) every [`ProgressUpdate`] sent
/// through the returned sender will carry.
///
/// # Examples
///
/// ```
/// let (sender, mut receiver) = deps_engine::progress::channel(5);
/// sender.send(1);
/// sender.send(2);
/// assert_eq!(receiver.try_recv().unwrap().fetched, 1);
/// assert_eq!(receiver.try_recv().unwrap().fetched, 2);
/// ```
#[must_use]
pub fn channel(total: usize) -> (ProgressSender, mpsc::Receiver<ProgressUpdate>) {
    let (tx, rx) = mpsc::channel(PROGRESS_CHANNEL_CAPACITY);
    (ProgressSender { tx, total }, rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_percentage_calculation() {
        let calculate = |fetched: usize, total: usize| -> u32 {
            if total == 0 {
                return 0;
            }
            ((fetched as f64 / total as f64) * 100.0) as u32
        };

        assert_eq!(calculate(0, 10), 0);
        assert_eq!(calculate(5, 10), 50);
        assert_eq!(calculate(10, 10), 100);
        assert_eq!(calculate(7, 10), 70);
        assert_eq!(calculate(0, 0), 0);
    }

    #[tokio::test]
    async fn test_progress_sender_try_send_on_closed_channel() {
        let (sender, rx) = channel(10);

        drop(rx);

        sender.send(5);
    }

    #[tokio::test]
    async fn test_progress_sender_try_send_on_full_channel() {
        let (tx, _rx) = mpsc::channel(1);
        let sender = ProgressSender { tx, total: 10 };

        sender.send(1);
        sender.send(2);
        sender.send(3);
    }
}
