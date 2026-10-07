//! Opt-in macOS Keychain lookup of SE-0292 registry credentials.
//!
//! A [`KeychainStore`] is the one process-wide place that reads Keychain items through
//! `/usr/bin/security`. Reading a secret can raise a macOS access prompt that a human answers
//! at their own pace, so the store never blocks a caller on it: each server's lookup runs in a
//! detached single-flight task that outlives any caller cancelled by its own fetch timeout, so
//! a timed-out caller cannot re-trigger the prompt.
//!
//! Outcomes are memoized per [`KeychainServer`]:
//!
//! | outcome | kept |
//! |---|---|
//! | `Ok` (found) | for the process lifetime |
//! | [`NotFound`](KeychainError::NotFound) | 5 minutes |
//! | [`Refused`](KeychainError::Refused) | until the generation advances or the process restarts |
//! | [`Transient`](KeychainError::Transient) | never |
//!
//! The generation is the opt-in setting's toggle counter: advancing it purges every entry
//! (zeroizing `Found` secrets) and aborts in-flight lookups, so a dialog for a revoked setting
//! is dismissed and its late answer is never memoized or broadcast.
//!
//! On anything but `Found` the caller sends no credential, as SwiftPM does when its provider
//! returns nothing; a 401 never triggers a new lookup.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;

use deps_core::secret::Redacted;
use futures::future::BoxFuture;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::{Semaphore, broadcast, watch};
use tokio::task::AbortHandle;
use tokio::time::{Instant, timeout};
use zeroize::Zeroizing;

use deps_core::keychain_credentials::{
    KeychainCredentialsHandle, KeychainGeneration, KeychainGenerationObserver,
};

use crate::auth::SwiftCredential;

const SECURITY_PROGRAM: &str = "/usr/bin/security";
const NOT_FOUND_EXIT_CODE: i32 = 44;
const INTERACTION_NOT_ALLOWED_EXIT_CODE: i32 = 36;
const MAX_OUTPUT_BYTES: u64 = 64 * 1024;
const LOOKUP_BUDGET: Duration = Duration::from_mins(10);
const NOT_FOUND_TTL: Duration = Duration::from_mins(5);

/// Why a [`KeychainServer`] could not be built.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum KeychainServerError {
    /// The host was empty.
    #[error("keychain server host is empty")]
    EmptyHost,
    /// The host would be parsed as an option by `security`.
    #[error("keychain server host must not start with '-'")]
    OptionLikeHost,
}

/// The Keychain item key: a registry host and optional explicit port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct KeychainServer {
    host: String,
    port: Option<u16>,
}

impl KeychainServer {
    /// Builds the key, rejecting a host that `security` would read as an option.
    ///
    /// # Errors
    ///
    /// [`KeychainServerError`] when `host` is empty or starts with `-`.
    pub(crate) fn new(host: &str, port: Option<u16>) -> Result<Self, KeychainServerError> {
        if host.is_empty() {
            return Err(KeychainServerError::EmptyHost);
        }
        if host.starts_with('-') {
            return Err(KeychainServerError::OptionLikeHost);
        }
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }

    /// Builds the key for `url`'s host and explicit port. An IPv6 literal is stored without
    /// brackets, as the Keychain's server attribute holds it.
    pub(crate) fn from_url(url: &url::Url) -> Option<Self> {
        let host = match url.host()? {
            url::Host::Domain(domain) => domain.to_owned(),
            url::Host::Ipv4(address) => address.to_string(),
            url::Host::Ipv6(address) => address.to_string(),
        };
        Self::new(&host, url.port())
            .inspect_err(|error| {
                tracing::debug!(?error, "registry host unusable as a Keychain server");
            })
            .ok()
    }
}

/// A Keychain lookup failure.
///
/// Also the log-safe view of an outcome: it carries no credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeychainError {
    /// No matching item (`security` exit code 44).
    NotFound,
    /// Denied, cancelled, unparsable, or the tool is unusable; retrying will not fix it.
    Refused,
    /// The lookup timed out, its task died, or no prompt was shown (for example a locked
    /// keychain with interaction disallowed); the next call retries.
    Transient,
}

/// The result of a Keychain lookup, as seen by a caller.
pub(crate) type KeychainOutcome = Result<SwiftCredential, KeychainError>;

/// The two Keychain reads a lookup performs.
///
/// Implementations apply no timeout of their own (the store bounds the whole lookup) and must
/// stop the underlying work when the returned future is dropped, which dismisses a pending
/// prompt.
pub(crate) trait KeychainBackend: Send + Sync + 'static {
    /// Reads the account name of the item for `server`. Not expected to prompt, but a locked
    /// keychain can still show an unlock dialog.
    fn find_account<'a>(
        &'a self,
        server: &'a KeychainServer,
    ) -> BoxFuture<'a, Result<Redacted, KeychainError>>;

    /// Reads the secret of `account`'s item for `server`. May show an access prompt.
    fn read_secret<'a>(
        &'a self,
        server: &'a KeychainServer,
        account: &'a Redacted,
    ) -> BoxFuture<'a, Result<Redacted, KeychainError>>;
}

/// The real backend: `/usr/bin/security find-internet-password`, run through `tokio::process`
/// with a null stdin and stderr, a capped stdout, and `kill_on_drop`. Neither stream is ever
/// logged.
#[derive(Debug, Clone)]
pub(crate) struct SecurityCli {
    program: PathBuf,
}

/// Which stream of `security` carries the wanted output: `-g` prints the password on stderr.
#[derive(Debug, Clone, Copy)]
enum Capture {
    Stdout,
    Stderr,
}

impl SecurityCli {
    pub(crate) fn new() -> Self {
        Self {
            program: PathBuf::from(SECURITY_PROGRAM),
        }
    }

    fn base_args(server: &KeychainServer) -> Vec<OsString> {
        let mut args: Vec<OsString> = vec![
            "find-internet-password".into(),
            "-s".into(),
            (&server.host).into(),
            "-r".into(),
            "htps".into(),
        ];
        if let Some(port) = server.port {
            args.push("-P".into());
            args.push(port.to_string().into());
        }
        args
    }

    async fn run(
        &self,
        args: &[OsString],
        capture: Capture,
    ) -> Result<Zeroizing<Vec<u8>>, KeychainError> {
        let (stdout, stderr) = match capture {
            Capture::Stdout => (Stdio::piped(), Stdio::null()),
            Capture::Stderr => (Stdio::null(), Stdio::piped()),
        };
        let mut child = Command::new(&self.program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| {
                tracing::warn!(kind = ?error.kind(), "cannot spawn the macOS `security` tool");
                KeychainError::Refused
            })?;
        let mut stream: Box<dyn tokio::io::AsyncRead + Send + Unpin> = match capture {
            Capture::Stdout => Box::new(child.stdout.take().ok_or(KeychainError::Refused)?),
            Capture::Stderr => Box::new(child.stderr.take().ok_or(KeychainError::Refused)?),
        };
        let mut output = Zeroizing::new(Vec::new());
        let read = (&mut stream)
            .take(MAX_OUTPUT_BYTES)
            .read_to_end(&mut output)
            .await;
        drop(stream);
        let status = child.wait().await;
        if read.is_err() {
            return Err(KeychainError::Refused);
        }
        match status {
            Ok(status) => classify_exit(status.code()).map(|()| output),
            Err(_) => Err(KeychainError::Refused),
        }
    }
}

impl KeychainBackend for SecurityCli {
    fn find_account<'a>(
        &'a self,
        server: &'a KeychainServer,
    ) -> BoxFuture<'a, Result<Redacted, KeychainError>> {
        Box::pin(async move {
            let output = self.run(&Self::base_args(server), Capture::Stdout).await?;
            let text = std::str::from_utf8(&output).map_err(|_| KeychainError::Refused)?;
            parse_account(text)
                .map(Redacted::new)
                .ok_or(KeychainError::Refused)
        })
    }

    fn read_secret<'a>(
        &'a self,
        server: &'a KeychainServer,
        account: &'a Redacted,
    ) -> BoxFuture<'a, Result<Redacted, KeychainError>> {
        Box::pin(async move {
            let mut args = Self::base_args(server);
            args.push("-a".into());
            args.push(account.expose_secret().into());
            // `-w` prints a non-ASCII secret as bare hex, indistinguishable from an ASCII secret
            // that looks like hex; `-g` marks the hex form with `0x`.
            args.push("-g".into());
            let output = self.run(&args, Capture::Stderr).await?;
            let text = std::str::from_utf8(&output).map_err(|_| KeychainError::Refused)?;
            parse_password(text)
                .map(Redacted::new)
                .ok_or(KeychainError::Refused)
        })
    }
}

fn classify_exit(code: Option<i32>) -> Result<(), KeychainError> {
    match code {
        Some(0) => Ok(()),
        Some(NOT_FOUND_EXIT_CODE) => Err(KeychainError::NotFound),
        Some(INTERACTION_NOT_ALLOWED_EXIT_CODE) => Err(KeychainError::Transient),
        _ => Err(KeychainError::Refused),
    }
}

/// Extracts the `"acct"` attribute from `security find-internet-password` output.
///
/// The value is `"name"` for printable ASCII and `0xHEX  "escaped"` otherwise; the hex form is
/// authoritative. `<NULL>` or a missing line yields `None`.
fn parse_account(output: &str) -> Option<String> {
    parse_blob(output, "\"acct\"<blob>=")
}

/// Extracts the password from `security find-internet-password -g` output (`password: ...`
/// on stderr), in the same two forms as [`parse_account`].
fn parse_password(output: &str) -> Option<String> {
    parse_blob(output, "password: ")
}

fn parse_blob(output: &str, prefix: &str) -> Option<String> {
    let value = output
        .lines()
        .find_map(|line| line.trim_start().strip_prefix(prefix))?;
    if let Some(hex) = value.strip_prefix("0x") {
        let hex = hex.split_whitespace().next()?;
        return decode_hex_utf8(hex).filter(|decoded| !decoded.is_empty());
    }
    value
        .strip_circumfix('"', '"')
        .filter(|decoded| !decoded.is_empty())
        .map(str::to_owned)
}

fn decode_hex_utf8(hex: &str) -> Option<String> {
    let bytes = hex.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
        return None;
    }
    let decoded = Zeroizing::new(
        bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let pair = std::str::from_utf8(pair).ok()?;
                u8::from_str_radix(pair, 16).ok()
            })
            .collect::<Option<Vec<u8>>>()?,
    );
    std::str::from_utf8(&decoded).ok().map(str::to_owned)
}

enum Entry {
    Found(SwiftCredential),
    NotFound { since: Instant },
    Refused,
    InFlight(Flight),
}

struct Flight {
    id: u64,
    outcome: watch::Receiver<Option<KeychainOutcome>>,
    abort: AbortHandle,
    signal: Arc<FlightSignal>,
}

/// Whether some waiter gave up before a flight's result, and whether that has been announced.
///
/// The publisher stores the result and then reads `abandoned`; a dropping waiter sets
/// `abandoned` and then reads the result. Both orders are `SeqCst`, so at least one side sees
/// the other, and `announced` makes exactly one of them send.
#[derive(Default)]
struct FlightSignal {
    abandoned: AtomicBool,
    announced: AtomicBool,
}

impl FlightSignal {
    fn announce_if_due(&self, found: bool, resolved: &broadcast::Sender<()>) {
        if found
            && self.abandoned.load(Ordering::SeqCst)
            && !self.announced.swap(true, Ordering::SeqCst)
            && resolved.send(()).is_err()
        {
            tracing::debug!("keychain credential resolved with no listeners");
        }
    }
}

#[derive(Default)]
struct State {
    generation: KeychainGeneration,
    next_flight: u64,
    entries: HashMap<KeychainServer, Entry>,
}

/// A caller waiting on an in-flight lookup; dropping it before the result marks the flight
/// abandoned, which later licenses the `resolved` broadcast.
struct Waiter {
    outcome: watch::Receiver<Option<KeychainOutcome>>,
    signal: Arc<FlightSignal>,
    resolved: broadcast::Sender<()>,
    delivered: bool,
}

impl Waiter {
    fn new(
        outcome: watch::Receiver<Option<KeychainOutcome>>,
        signal: Arc<FlightSignal>,
        resolved: broadcast::Sender<()>,
    ) -> Self {
        Self {
            outcome,
            signal,
            resolved,
            delivered: false,
        }
    }

    async fn wait(mut self) -> KeychainOutcome {
        let outcome = match self.outcome.wait_for(Option::is_some).await {
            Ok(value) => value.clone().unwrap_or(Err(KeychainError::Transient)),
            Err(_) => Err(KeychainError::Transient),
        };
        self.delivered = true;
        outcome
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        if !self.delivered {
            self.signal.abandoned.store(true, Ordering::SeqCst);
            let found = matches!(&*self.outcome.borrow(), Some(Ok(_)));
            self.signal.announce_if_due(found, &self.resolved);
        }
    }
}

enum Joined {
    Ready(KeychainOutcome),
    Waiting(Waiter),
}

/// Removes a flight's map entry when its task ends without finishing (a panic), so the next
/// call starts a fresh lookup instead of joining a dead one.
struct FlightCleanup<'a> {
    store: &'a KeychainStore,
    server: &'a KeychainServer,
    id: u64,
}

impl Drop for FlightCleanup<'_> {
    fn drop(&mut self) {
        let mut state = self.store.lock();
        if matches!(state.entries.get(self.server), Some(Entry::InFlight(flight)) if flight.id == self.id)
        {
            state.entries.remove(self.server);
        }
    }
}

impl KeychainGenerationObserver for KeychainStore {
    fn generation_advanced(&self, generation: KeychainGeneration) {
        self.advance_generation(generation);
    }
}

/// Serializes interactive lookups: one dialog at a time.
static SYSTEM_PROMPT: Semaphore = Semaphore::const_new(1);

/// Live system stores, one per [`KeychainCredentialsHandle`].
static SYSTEM_STORES: Mutex<Vec<(Weak<KeychainCredentialsHandle>, Weak<KeychainStore>)>> =
    Mutex::new(Vec::new());

/// Where a store queues for the one-dialog-at-a-time permit.
enum PromptGate {
    /// The process-wide permit, shared by every system store.
    ProcessWide,
    /// A permit private to one store, so tests on a paused runtime never share one.
    Local(Semaphore),
}

impl PromptGate {
    fn semaphore(&self) -> &Semaphore {
        match self {
            Self::ProcessWide => &SYSTEM_PROMPT,
            Self::Local(semaphore) => semaphore,
        }
    }
}

/// The Keychain credential store of one [`KeychainCredentialsHandle`], shared through [`Arc`].
///
/// One lookup per server runs at a time; one permit serializes the whole interactive lookup
/// (either read can raise a dialog) across servers, and for system stores that permit is
/// process-wide, so at most one macOS prompt is open whatever the number of stores; one
/// 10-minute budget, started once a lookup holds the permit, bounds a whole lookup, and
/// exceeding it is [`KeychainError::Transient`].
pub(crate) struct KeychainStore {
    backend: Box<dyn KeychainBackend>,
    prompt: PromptGate,
    state: Mutex<State>,
    resolved: broadcast::Sender<()>,
}

impl std::fmt::Debug for KeychainStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeychainStore").finish_non_exhaustive()
    }
}

impl KeychainStore {
    /// A store over `backend` that announces on `resolved` when a lookup yields `Found` after
    /// some caller already gave up waiting for it.
    pub(crate) fn new(backend: impl KeychainBackend, resolved: broadcast::Sender<()>) -> Self {
        Self {
            backend: Box::new(backend),
            prompt: PromptGate::Local(Semaphore::new(1)),
            state: Mutex::new(State::default()),
            resolved,
        }
    }

    /// The store over the real `/usr/bin/security` backend, queueing on the process-wide prompt
    /// permit.
    fn system(resolved: broadcast::Sender<()>) -> Self {
        Self {
            prompt: PromptGate::ProcessWide,
            ..Self::new(SecurityCli::new(), resolved)
        }
    }

    /// The system store of `handle`: the first call creates it and registers it as the handle's
    /// generation observer; later calls with the same handle return the same store, so there is
    /// one memo per handle.
    pub(crate) fn system_for(handle: &Arc<KeychainCredentialsHandle>) -> Arc<Self> {
        let mut stores = SYSTEM_STORES.lock().unwrap_or_else(PoisonError::into_inner);
        stores.retain(|(handle, store)| handle.strong_count() > 0 && store.strong_count() > 0);
        let target = Arc::downgrade(handle);
        if let Some(store) = stores
            .iter()
            .find(|(candidate, _)| Weak::ptr_eq(candidate, &target))
            .and_then(|(_, store)| store.upgrade())
        {
            return store;
        }
        let store = Arc::new(Self::system(handle.resolved_sender()));
        handle.register_observer(Arc::downgrade(&store) as _);
        stores.push((target, Arc::downgrade(&store)));
        store
    }

    #[cfg(test)]
    pub(crate) fn memoized_entries(&self) -> usize {
        self.lock().entries.len()
    }

    #[cfg(test)]
    fn subscribe_resolved(&self) -> broadcast::Receiver<()> {
        self.resolved.subscribe()
    }

    /// Moves the store to `generation` when it is newer: aborts in-flight lookups and purges
    /// every entry. An equal or older value is ignored.
    pub(crate) fn advance_generation(&self, generation: KeychainGeneration) {
        let purged = {
            let mut state = self.lock();
            if generation <= state.generation {
                return;
            }
            state.generation = generation;
            std::mem::take(&mut state.entries)
        };
        // Aborting outside the lock: a dropped task's cleanup guard locks the state itself.
        for entry in purged.into_values() {
            if let Entry::InFlight(flight) = entry {
                flight.abort.abort();
            }
        }
    }

    /// Resolves the credential for `server` at the setting's `generation`.
    ///
    /// Returns memoized outcomes immediately and otherwise joins (or starts) the server's
    /// single-flight lookup. Dropping the returned future abandons only the wait, never the
    /// lookup. A `generation` older than the store's yields [`Err(KeychainError::Transient)`].
    pub(crate) async fn resolve(
        self: &Arc<Self>,
        server: &KeychainServer,
        generation: KeychainGeneration,
    ) -> KeychainOutcome {
        self.advance_generation(generation);
        match self.join(server, generation) {
            Joined::Ready(outcome) => outcome,
            Joined::Waiting(waiter) => waiter.wait().await,
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn join(self: &Arc<Self>, server: &KeychainServer, generation: KeychainGeneration) -> Joined {
        let mut state = self.lock();
        if generation < state.generation {
            return Joined::Ready(Err(KeychainError::Transient));
        }
        match state.entries.get(server) {
            Some(Entry::Found(credential)) => {
                return Joined::Ready(Ok(credential.clone()));
            }
            Some(Entry::Refused) => return Joined::Ready(Err(KeychainError::Refused)),
            Some(Entry::NotFound { since }) => {
                if since.elapsed() < NOT_FOUND_TTL {
                    return Joined::Ready(Err(KeychainError::NotFound));
                }
                state.entries.remove(server);
            }
            Some(Entry::InFlight(flight)) => {
                return Joined::Waiting(Waiter::new(
                    flight.outcome.clone(),
                    Arc::clone(&flight.signal),
                    self.resolved.clone(),
                ));
            }
            None => {}
        }
        let id = state.next_flight;
        state.next_flight += 1;
        let (sender, outcome) = watch::channel(None);
        let signal = Arc::new(FlightSignal::default());
        let task =
            tokio::spawn(Arc::clone(self).run_flight(server.clone(), generation, id, sender));
        state.entries.insert(
            server.clone(),
            Entry::InFlight(Flight {
                id,
                outcome: outcome.clone(),
                abort: task.abort_handle(),
                signal: Arc::clone(&signal),
            }),
        );
        Joined::Waiting(Waiter::new(outcome, signal, self.resolved.clone()))
    }

    async fn run_flight(
        self: Arc<Self>,
        server: KeychainServer,
        generation: KeychainGeneration,
        id: u64,
        sender: watch::Sender<Option<KeychainOutcome>>,
    ) {
        let _cleanup = FlightCleanup {
            store: &self,
            server: &server,
            id,
        };
        // Queueing for the one-dialog-at-a-time permit is not part of the budget, so a server
        // that waited behind others still gets its full lookup time.
        let outcome = match self.prompt.semaphore().acquire().await {
            Ok(_permit) => timeout(LOOKUP_BUDGET, self.lookup(&server))
                .await
                .unwrap_or(Err(KeychainError::Transient)),
            Err(_) => Err(KeychainError::Transient),
        };
        self.finish(&server, generation, id, outcome, &sender);
    }

    async fn lookup(&self, server: &KeychainServer) -> KeychainOutcome {
        let account = self.backend.find_account(server).await?;
        let password = self.backend.read_secret(server, &account).await?;
        Ok(SwiftCredential::Login {
            username: account,
            password,
        })
    }

    fn finish(
        &self,
        server: &KeychainServer,
        generation: KeychainGeneration,
        id: u64,
        outcome: KeychainOutcome,
        sender: &watch::Sender<Option<KeychainOutcome>>,
    ) {
        let signal = {
            let mut state = self.lock();
            if state.generation != generation {
                return;
            }
            let signal = match state.entries.get(server) {
                Some(Entry::InFlight(flight)) if flight.id == id => Arc::clone(&flight.signal),
                Some(
                    Entry::InFlight(_) | Entry::Found(_) | Entry::NotFound { .. } | Entry::Refused,
                )
                | None => return,
            };
            match &outcome {
                Ok(credential) => {
                    state
                        .entries
                        .insert(server.clone(), Entry::Found(credential.clone()));
                }
                Err(KeychainError::NotFound) => {
                    state.entries.insert(
                        server.clone(),
                        Entry::NotFound {
                            since: Instant::now(),
                        },
                    );
                }
                Err(KeychainError::Refused) => {
                    state.entries.insert(server.clone(), Entry::Refused);
                }
                Err(KeychainError::Transient) => {
                    state.entries.remove(server);
                }
            }
            signal
        };
        let found = outcome.is_ok();
        tracing::debug!(outcome = ?outcome.as_ref().map(|_| ()), "keychain lookup finished");
        sender.send_replace(Some(outcome));
        signal.announce_if_due(found, &self.resolved);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod fake {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    pub(crate) type Reply = Result<&'static str, KeychainError>;

    #[derive(Clone)]
    pub(crate) struct Fake {
        pub(crate) account: Arc<Mutex<Reply>>,
        pub(crate) secret: Arc<Mutex<Reply>>,
        pub(crate) secret_delay: Duration,
        pub(crate) find_delay: Duration,
        pub(crate) panic_on_secret: bool,
        pub(crate) active_calls: Arc<AtomicUsize>,
        pub(crate) max_active_calls: Arc<AtomicUsize>,
        pub(crate) find_calls: Arc<AtomicUsize>,
        pub(crate) secret_calls: Arc<AtomicUsize>,
        pub(crate) active_secrets: Arc<AtomicUsize>,
        pub(crate) max_active_secrets: Arc<AtomicUsize>,
    }

    impl Fake {
        pub(crate) fn new(account: Reply, secret: Reply) -> Self {
            Self {
                account: Arc::new(Mutex::new(account)),
                secret: Arc::new(Mutex::new(secret)),
                secret_delay: Duration::ZERO,
                find_delay: Duration::ZERO,
                panic_on_secret: false,
                active_calls: Arc::default(),
                max_active_calls: Arc::default(),
                find_calls: Arc::default(),
                secret_calls: Arc::default(),
                active_secrets: Arc::default(),
                max_active_secrets: Arc::default(),
            }
        }

        pub(crate) fn found() -> Self {
            Self::new(Ok("user"), Ok("hunter2"))
        }

        pub(crate) fn delayed(mut self, delay: Duration) -> Self {
            self.secret_delay = delay;
            self
        }

        pub(crate) fn set_secret(&self, reply: Reply) {
            *self.secret.lock().unwrap() = reply;
        }

        fn enter_call(&self) {
            let active = self.active_calls.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active_calls.fetch_max(active, Ordering::SeqCst);
        }

        pub(crate) fn with_find_delay(mut self, delay: Duration) -> Self {
            self.find_delay = delay;
            self
        }

        pub(crate) fn secret_calls(&self) -> usize {
            self.secret_calls.load(Ordering::SeqCst)
        }
    }

    impl KeychainBackend for Fake {
        fn find_account<'a>(
            &'a self,
            _server: &'a KeychainServer,
        ) -> BoxFuture<'a, Result<Redacted, KeychainError>> {
            Box::pin(async move {
                self.find_calls.fetch_add(1, Ordering::SeqCst);
                self.enter_call();
                tokio::time::sleep(self.find_delay).await;
                self.active_calls.fetch_sub(1, Ordering::SeqCst);
                let reply = *self.account.lock().unwrap();
                reply.map(|account| Redacted::new(account.to_owned()))
            })
        }

        fn read_secret<'a>(
            &'a self,
            _server: &'a KeychainServer,
            _account: &'a Redacted,
        ) -> BoxFuture<'a, Result<Redacted, KeychainError>> {
            Box::pin(async move {
                self.secret_calls.fetch_add(1, Ordering::SeqCst);
                self.enter_call();
                let active = self.active_secrets.fetch_add(1, Ordering::SeqCst) + 1;
                self.max_active_secrets.fetch_max(active, Ordering::SeqCst);
                assert!(!self.panic_on_secret, "simulated crashed lookup");
                tokio::time::sleep(self.secret_delay).await;
                self.active_secrets.fetch_sub(1, Ordering::SeqCst);
                self.active_calls.fetch_sub(1, Ordering::SeqCst);
                let reply = *self.secret.lock().unwrap();
                reply.map(|secret| Redacted::new(secret.to_owned()))
            })
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::fake::Fake;
    use super::*;
    use std::assert_matches;

    fn generation(steps: u32) -> KeychainGeneration {
        (0..steps).fold(KeychainGeneration::INITIAL, |generation, _| {
            generation.next()
        })
    }

    fn test_sender() -> broadcast::Sender<()> {
        broadcast::channel(8).0
    }

    fn server(host: &str) -> KeychainServer {
        KeychainServer::new(host, None).unwrap()
    }

    fn store(fake: &Fake) -> Arc<KeychainStore> {
        Arc::new(KeychainStore::new(fake.clone(), test_sender()))
    }

    fn password(outcome: &KeychainOutcome) -> String {
        match outcome {
            Ok(SwiftCredential::Login { password, .. }) => password.expose_secret().to_owned(),
            other => panic!("expected a found login, got {other:?}"),
        }
    }

    #[test]
    fn server_rejects_empty_and_option_like_hosts() {
        assert_eq!(
            KeychainServer::new("", None),
            Err(KeychainServerError::EmptyHost)
        );
        assert_eq!(
            KeychainServer::new("-evil", None),
            Err(KeychainServerError::OptionLikeHost)
        );
        assert!(KeychainServer::new("registry.example.com", Some(8443)).is_ok());
    }

    #[test]
    fn parses_plain_hex_and_null_accounts() {
        let plain = "    \"acct\"<blob>=\"plainuser\"\n    \"atyp\"<blob>=\"dflt\"\n";
        assert_eq!(parse_account(plain).as_deref(), Some("plainuser"));
        let hex = "    \"acct\"<blob>=0x757365722DC3A9  \"user-\\303\\251\"\n";
        assert_eq!(parse_account(hex).as_deref(), Some("user-\u{e9}"));
        assert_eq!(parse_account("    \"acct\"<blob>=<NULL>\n"), None);
        assert_eq!(parse_account("    \"srvr\"<blob>=\"h\"\n"), None);
        assert_eq!(parse_account("    \"acct\"<blob>=0x7  \"x\"\n"), None);
        assert_eq!(parse_account("    \"acct\"<blob>=0xFFFE  \"x\"\n"), None);
    }

    #[test]
    fn parses_plain_and_hex_passwords_from_g_output() {
        assert_eq!(
            parse_password("password: \"s3cret\"\n").as_deref(),
            Some("s3cret")
        );
        let hex =
            "password: 0x70C3A4737377C3B672642DC3A9  \"p\\303\\244ssw\\303\\266rd-\\303\\251\"\n";
        assert_eq!(
            parse_password(hex).as_deref(),
            Some("p\u{e4}ssw\u{f6}rd-\u{e9}")
        );
        let quoted = "password: 0x6122625C632064  \"a\"b\\134c d\"\n";
        assert_eq!(parse_password(quoted).as_deref(), Some("a\"b\\c d"));
        assert_eq!(parse_password("password: \"\"\n"), None);
        assert_eq!(parse_password("keychain: x\n"), None);
        assert_eq!(parse_password("password: 0xZZ  \"x\"\n"), None);
        assert_eq!(parse_password("password: 0xC328  \"x\"\n"), None);
    }

    #[test]
    fn maps_exit_codes() {
        assert_eq!(classify_exit(Some(0)), Ok(()));
        assert_eq!(classify_exit(Some(44)), Err(KeychainError::NotFound));
        assert_eq!(classify_exit(Some(36)), Err(KeychainError::Transient));
        assert_eq!(classify_exit(Some(128)), Err(KeychainError::Refused));
        assert_eq!(classify_exit(None), Err(KeychainError::Refused));
    }

    #[test]
    fn system_store_is_one_per_handle() {
        let handle = Arc::new(KeychainCredentialsHandle::default());
        let other = Arc::new(KeychainCredentialsHandle::default());
        let first = KeychainStore::system_for(&handle);
        assert!(Arc::ptr_eq(&first, &KeychainStore::system_for(&handle)));
        assert!(!Arc::ptr_eq(&first, &KeychainStore::system_for(&other)));
    }

    #[test]
    fn debug_never_prints_secrets() {
        let fake = Fake::found();
        let rendered = format!("{:?}", KeychainStore::new(fake, test_sender()));
        assert_eq!(rendered, "KeychainStore { .. }");
        let credential: KeychainOutcome = Ok(SwiftCredential::Login {
            username: Redacted::new("user".to_owned()),
            password: Redacted::new("hunter2".to_owned()),
        });
        assert!(!format!("{credential:?}").contains("hunter2"));
    }

    #[tokio::test(start_paused = true)]
    async fn found_is_memoized_for_the_process_lifetime() {
        let fake = Fake::found();
        let store = store(&fake);
        let host = server("a.example");
        assert_eq!(
            password(&store.resolve(&host, generation(0)).await),
            "hunter2"
        );
        tokio::time::advance(Duration::from_hours(48)).await;
        assert_eq!(
            password(&store.resolve(&host, generation(0)).await),
            "hunter2"
        );
        assert_eq!(fake.secret_calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn not_found_expires_after_five_minutes() {
        let fake = Fake::new(Err(KeychainError::NotFound), Ok("x"));
        let store = store(&fake);
        let host = server("a.example");
        assert_matches!(
            store.resolve(&host, generation(0)).await,
            Err(KeychainError::NotFound)
        );
        tokio::time::advance(Duration::from_mins(4)).await;
        drop(store.resolve(&host, generation(0)).await);
        assert_eq!(fake.find_calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_mins(2)).await;
        drop(store.resolve(&host, generation(0)).await);
        assert_eq!(fake.find_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn refused_sticks_until_the_generation_advances() {
        let fake = Fake::new(Ok("user"), Err(KeychainError::Refused));
        let store = store(&fake);
        let host = server("a.example");
        assert_matches!(
            store.resolve(&host, generation(0)).await,
            Err(KeychainError::Refused)
        );
        tokio::time::advance(Duration::from_hours(48)).await;
        assert_matches!(
            store.resolve(&host, generation(0)).await,
            Err(KeychainError::Refused)
        );
        assert_eq!(fake.secret_calls(), 1);

        fake.set_secret(Ok("hunter2"));
        assert_eq!(
            password(&store.resolve(&host, generation(1)).await),
            "hunter2"
        );
        assert_eq!(fake.secret_calls(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_timed_out_lookup_is_transient_and_retried_on_the_next_call() {
        let fake = Fake::found().delayed(Duration::from_hours(1));
        let store = store(&fake);
        let host = server("a.example");
        assert_matches!(
            store.resolve(&host, generation(0)).await,
            Err(KeychainError::Transient)
        );
        assert_matches!(
            store.resolve(&host, generation(0)).await,
            Err(KeychainError::Transient)
        );
        assert_eq!(fake.secret_calls(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_crashed_lookup_task_is_transient_and_resets() {
        let mut fake = Fake::found();
        fake.panic_on_secret = true;
        let store = store(&fake);
        let host = server("a.example");
        assert_matches!(
            store.resolve(&host, generation(0)).await,
            Err(KeychainError::Transient)
        );
        assert_matches!(
            store.resolve(&host, generation(0)).await,
            Err(KeychainError::Transient)
        );
        assert_eq!(fake.secret_calls(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_callers_share_one_lookup() {
        let fake = Fake::found().delayed(Duration::from_secs(30));
        let store = store(&fake);
        let host = server("a.example");
        let (first, second) = tokio::join!(
            store.resolve(&host, generation(0)),
            store.resolve(&host, generation(0))
        );
        assert_eq!(password(&first), "hunter2");
        assert_eq!(password(&second), "hunter2");
        assert_eq!(fake.secret_calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn secret_reads_are_serialized_across_servers() {
        let fake = Fake::found().delayed(Duration::from_secs(30));
        let store = store(&fake);
        let (a, b) = (server("a.example"), server("b.example"));
        let (first, second) = tokio::join!(
            store.resolve(&a, generation(0)),
            store.resolve(&b, generation(0))
        );
        assert_eq!(password(&first), "hunter2");
        assert_eq!(password(&second), "hunter2");
        assert_eq!(fake.max_active_secrets.load(Ordering::SeqCst), 1);
        assert_eq!(fake.secret_calls(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_cancelled_caller_does_not_stop_the_lookup_and_triggers_resolved() {
        let fake = Fake::found().delayed(Duration::from_secs(30));
        let store = store(&fake);
        let mut resolved = store.subscribe_resolved();
        let host = server("a.example");

        let gave_up = timeout(Duration::from_secs(5), store.resolve(&host, generation(0))).await;
        assert!(gave_up.is_err());

        timeout(Duration::from_secs(60), resolved.recv())
            .await
            .expect("resolved after an abandoned wait")
            .expect("resolved channel open");
        drop(store.resolve(&host, generation(0)).await);
        assert_matches!(
            resolved.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        );
        assert_eq!(
            password(&store.resolve(&host, generation(0)).await),
            "hunter2"
        );
        assert_eq!(fake.secret_calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn no_resolved_broadcast_when_every_waiter_got_the_result() {
        let fake = Fake::found().delayed(Duration::from_secs(1));
        let store = store(&fake);
        let mut resolved = store.subscribe_resolved();
        drop(store.resolve(&server("a.example"), generation(0)).await);
        assert_matches!(
            resolved.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn no_resolved_broadcast_for_a_non_found_result() {
        let fake =
            Fake::new(Ok("user"), Err(KeychainError::Refused)).delayed(Duration::from_secs(30));
        let store = store(&fake);
        let mut resolved = store.subscribe_resolved();
        let host = server("a.example");
        assert!(
            timeout(Duration::from_secs(5), store.resolve(&host, generation(0)))
                .await
                .is_err()
        );
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_matches!(
            resolved.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn advancing_the_generation_aborts_the_lookup_and_drops_its_late_result() {
        let fake = Fake::found().delayed(Duration::from_secs(30));
        let store = store(&fake);
        let mut resolved = store.subscribe_resolved();
        let host = server("a.example");

        let pending = tokio::spawn({
            let store = Arc::clone(&store);
            let host = host.clone();
            async move { store.resolve(&host, generation(0)).await }
        });
        tokio::time::advance(Duration::from_secs(1)).await;
        pending.abort();
        store.advance_generation(generation(1));
        tokio::time::sleep(Duration::from_secs(60)).await;

        assert_matches!(
            resolved.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        );
        let waiting = store.lock().entries.is_empty();
        assert!(waiting, "stale lookup left an entry");
    }

    #[tokio::test(start_paused = true)]
    async fn waiters_of_an_aborted_lookup_see_transient() {
        let fake = Fake::found().delayed(Duration::from_secs(30));
        let store = store(&fake);
        let host = server("a.example");
        let waiter = tokio::spawn({
            let store = Arc::clone(&store);
            let host = host.clone();
            async move { store.resolve(&host, generation(0)).await }
        });
        tokio::time::advance(Duration::from_secs(1)).await;
        store.advance_generation(generation(1));
        let outcome = timeout(Duration::from_secs(1), waiter)
            .await
            .expect("an aborted lookup releases its waiters at once")
            .unwrap();
        assert_matches!(outcome, Err(KeychainError::Transient));
    }

    #[tokio::test]
    async fn advancing_the_generation_purges_found_secrets() {
        let fake = Fake::found();
        let store = store(&fake);
        let host = server("a.example");
        drop(store.resolve(&host, generation(0)).await);
        store.advance_generation(generation(1));
        assert!(store.lock().entries.is_empty());
        drop(store.resolve(&host, generation(1)).await);
        assert_eq!(fake.secret_calls(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn the_whole_lookup_is_serialized_across_servers() {
        let fake = Fake::found().with_find_delay(Duration::from_secs(10));
        let store = store(&fake);
        let (a, b) = (server("a.example"), server("b.example"));
        let (first, second) = tokio::join!(
            store.resolve(&a, generation(0)),
            store.resolve(&b, generation(0))
        );
        assert_eq!(password(&first), "hunter2");
        assert_eq!(password(&second), "hunter2");
        assert_eq!(fake.max_active_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fake.find_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn queueing_for_the_dialog_does_not_consume_the_lookup_budget() {
        let fake = Fake::found().delayed(Duration::from_mins(8));
        let store = store(&fake);
        let (a, b) = (server("a.example"), server("b.example"));
        let started = Instant::now();
        let (first, second) = tokio::join!(
            store.resolve(&a, generation(0)),
            store.resolve(&b, generation(0))
        );
        assert_eq!(password(&first), "hunter2");
        assert_eq!(password(&second), "hunter2");
        assert!(started.elapsed() >= Duration::from_mins(16));
    }

    #[tokio::test]
    async fn a_found_memo_is_per_server() {
        let fake = Fake::found();
        let store = store(&fake);
        drop(store.resolve(&server("a.example"), generation(0)).await);
        drop(store.resolve(&server("b.example"), generation(0)).await);
        assert_eq!(fake.find_calls.load(Ordering::SeqCst), 2);
        assert_eq!(fake.secret_calls(), 2);
        assert_eq!(store.memoized_entries(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_waiter_dropped_after_the_result_landed_still_announces_once() {
        let fake = Fake::found().delayed(Duration::from_secs(1));
        let store = store(&fake);
        let mut resolved = store.subscribe_resolved();
        let host = server("a.example");
        let Joined::Waiting(mut waiter) = store.join(&host, generation(0)) else {
            panic!("expected an in-flight lookup");
        };
        waiter
            .outcome
            .wait_for(Option::is_some)
            .await
            .expect("lookup publishes a result");
        drop(waiter);
        resolved.try_recv().expect("announced on drop");
        assert_matches!(
            resolved.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        );
    }

    #[tokio::test]
    async fn an_interaction_not_allowed_failure_is_transient_and_not_memoized() {
        let fake = Fake::new(Ok("user"), Err(KeychainError::Transient));
        let store = store(&fake);
        let host = server("a.example");
        assert_matches!(
            store.resolve(&host, generation(0)).await,
            Err(KeychainError::Transient)
        );
        assert_matches!(
            store.resolve(&host, generation(0)).await,
            Err(KeychainError::Transient)
        );
        assert_eq!(fake.secret_calls(), 2);
        assert_eq!(store.memoized_entries(), 0);
    }

    #[test]
    fn from_url_strips_ipv6_brackets_and_keeps_the_explicit_port() {
        let key = |raw: &str| KeychainServer::from_url(&url::Url::parse(raw).unwrap()).unwrap();
        assert_eq!(
            key("https://[2001:4860:4860::8888]:8443/api"),
            KeychainServer::new("2001:4860:4860::8888", Some(8443)).unwrap()
        );
        assert_eq!(
            key("https://93.184.216.34/api"),
            KeychainServer::new("93.184.216.34", None).unwrap()
        );
        assert_eq!(
            key("https://swift.acme.dev/api"),
            KeychainServer::new("swift.acme.dev", None).unwrap()
        );
    }

    #[tokio::test]
    async fn an_older_generation_is_stale() {
        let fake = Fake::found();
        let store = store(&fake);
        store.advance_generation(generation(3));
        assert_matches!(
            store.resolve(&server("a.example"), generation(2)).await,
            Err(KeychainError::Transient)
        );
        assert_eq!(fake.find_calls.load(Ordering::SeqCst), 0);
    }

    #[cfg(unix)]
    mod security_cli {
        use std::assert_matches;
        use std::os::unix::fs::PermissionsExt;

        use super::*;

        fn script_backend(dir: &tempfile::TempDir, body: &str) -> SecurityCli {
            let path = dir.path().join("security");
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            SecurityCli { program: path }
        }

        #[tokio::test]
        async fn reads_the_account_then_the_secret() {
            let dir = tempfile::tempdir().unwrap();
            let backend = script_backend(
                &dir,
                r#"case "$*" in
  *" -g") echo 'password: "s3cret"' >&2 ;;
  *) echo '    "acct"<blob>="alice"' ;;
esac"#,
            );
            let store = Arc::new(KeychainStore::new(backend, test_sender()));
            let outcome = store.resolve(&server("a.example"), generation(0)).await;
            let Ok(SwiftCredential::Login { username, password }) = outcome else {
                panic!("expected a login, got {outcome:?}");
            };
            assert_eq!(username.expose_secret(), "alice");
            assert_eq!(password.expose_secret(), "s3cret");
        }

        #[tokio::test]
        async fn exit_44_is_not_found_and_other_failures_are_refused() {
            let dir = tempfile::tempdir().unwrap();
            let store = KeychainStore::new(script_backend(&dir, "exit 44"), test_sender());
            assert_matches!(
                Arc::new(store)
                    .resolve(&server("a.example"), generation(0))
                    .await,
                Err(KeychainError::NotFound)
            );
            let dir = tempfile::tempdir().unwrap();
            let store = KeychainStore::new(script_backend(&dir, "exit 128"), test_sender());
            assert_matches!(
                Arc::new(store)
                    .resolve(&server("a.example"), generation(0))
                    .await,
                Err(KeychainError::Refused)
            );
        }

        #[tokio::test]
        async fn oversized_output_on_either_stream_is_capped_and_refused() {
            let dir = tempfile::tempdir().unwrap();
            let store = KeychainStore::new(
                script_backend(
                    &dir,
                    "head -c 300000 /dev/zero | tr '\\0' x >&2; head -c 300000 /dev/zero | tr '\\0' x",
                ),
                test_sender(),
            );
            assert_matches!(
                Arc::new(store)
                    .resolve(&server("a.example"), generation(0))
                    .await,
                Err(KeychainError::Refused)
            );
        }

        #[tokio::test]
        async fn a_missing_tool_is_refused() {
            let backend = SecurityCli {
                program: PathBuf::from("/nonexistent/security"),
            };
            let store = Arc::new(KeychainStore::new(backend, test_sender()));
            assert_matches!(
                store.resolve(&server("a.example"), generation(0)).await,
                Err(KeychainError::Refused)
            );
        }

        #[tokio::test]
        async fn unparsable_attributes_are_refused() {
            let dir = tempfile::tempdir().unwrap();
            let store = KeychainStore::new(script_backend(&dir, "echo garbage"), test_sender());
            assert_matches!(
                Arc::new(store)
                    .resolve(&server("a.example"), generation(0))
                    .await,
                Err(KeychainError::Refused)
            );
        }
    }

    /// Every system store queues on the one process-wide prompt permit, whatever the number of
    /// handles; a store built over a fake backend keeps a permit of its own. Creating a system
    /// store never runs the `security` CLI (only a lookup does).
    #[test]
    fn test_system_stores_share_the_process_wide_prompt_permit() {
        let handle = |setting| Arc::new(KeychainCredentialsHandle::new(setting));
        let (first, second) = (
            handle(deps_core::policy_config::KeychainCredentials::Enabled),
            handle(deps_core::policy_config::KeychainCredentials::Enabled),
        );
        let store_a = KeychainStore::system_for(&first);
        let store_b = KeychainStore::system_for(&second);

        assert!(!Arc::ptr_eq(&store_a, &store_b), "one memo per handle");
        assert!(Arc::ptr_eq(&store_a, &KeychainStore::system_for(&first)));
        assert!(std::ptr::eq(
            store_a.prompt.semaphore(),
            store_b.prompt.semaphore()
        ));
        assert!(std::ptr::eq(
            store_a.prompt.semaphore(),
            &raw const SYSTEM_PROMPT
        ));

        let (sender, _) = broadcast::channel(1);
        let local = KeychainStore::new(Fake::found(), sender);
        assert!(!std::ptr::eq(
            local.prompt.semaphore(),
            &raw const SYSTEM_PROMPT
        ));
    }
}
