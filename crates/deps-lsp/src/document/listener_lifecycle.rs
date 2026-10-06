//! Shared lifecycle of a background listener owned by the backend: subscribed at construction
//! (so no event is lost before it starts), running, then stopped for good.

/// A running listener's handle(s), aborted when the lifecycle stops.
pub(crate) trait AbortOnStop {
    /// Aborts the running task(s).
    fn abort(self);
}

impl AbortOnStop for tokio::task::AbortHandle {
    fn abort(self) {
        Self::abort(&self);
    }
}

/// Lifecycle of one listener: `S` is what was subscribed at construction, `T` the running
/// handle(s).
#[derive(Debug)]
pub(crate) enum ListenerLifecycle<S, T> {
    Subscribed(S),
    Running(T),
    Stopped,
}

impl<S, T: AbortOnStop> ListenerLifecycle<S, T> {
    /// Spawns the listener from `Subscribed`; in any other state this is a no-op, so a repeated
    /// start neither orphans a running listener nor starts a second one.
    pub(crate) fn start(&mut self, spawn: impl FnOnce(S) -> T) {
        match std::mem::replace(self, Self::Stopped) {
            Self::Subscribed(subscription) => *self = Self::Running(spawn(subscription)),
            other => *self = other,
        }
    }

    /// Aborts a running listener and moves to `Stopped`, which no later `start` can leave.
    pub(crate) fn stop(&mut self) {
        if let Self::Running(tasks) = std::mem::replace(self, Self::Stopped) {
            tasks.abort();
        }
    }
}
