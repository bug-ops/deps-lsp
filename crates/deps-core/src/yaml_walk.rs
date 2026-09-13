//! Generic frame-stack mechanics shared by every `yaml-rust2`
//! `MarkedEventReceiver`-based parser in this workspace (`deps-dart`,
//! `deps-github-actions`, `deps-gitlab-ci`).
//!
//! # What is generic vs. what stays per-crate
//!
//! Before this module existed, all three receivers independently reimplemented the
//! same state-machine mechanics: opening/closing `Mapping`/`Sequence` frames, tracking
//! whether the current frame is awaiting a key or a value, resetting that flag once a
//! value is consumed, and (only in `deps-dart`) recognizing an explicit complex YAML
//! key (`? <mapping>` / `? <sequence>`) so its subtree doesn't desync the enclosing
//! mapping's key/value alternation. [`FrameStack`] owns exactly that, and nothing
//! else — the role vocabulary, which child role a given parent/key combination
//! produces, per-role field capture, alias-resolution *policy* (a scalar-anchor value
//! table's own mechanics are shared instead, via [`crate::yaml_anchor::ScalarAnchorTable`]),
//! dependency budgets, and multi-document handling all stay in each crate's own receiver,
//! threaded through the stack's generic `payload: P`.
//!
//! A trait-based visitor was considered and rejected: the three crates' role
//! vocabularies, capture logic, and finalization steps share nothing beyond the
//! mechanics above, so a trait would either force a lowest-common-denominator shape
//! (losing each crate's own capture idiom) or grow enough associated types/methods to
//! be no simpler than driving a shared, monomorphised generic directly. `FrameStack`
//! is monomorphised per crate (no `dyn`, no boxing) — driving it costs nothing over the
//! hand-rolled version it replaces.
//!
//! # Complex-key handling
//!
//! [`FrameStack::push`] checks, before pushing, whether the *current* top frame is a
//! `Mapping` still awaiting a key ([`FrameStack::is_complex_key_position`]) — this is
//! exactly the position an explicit `?`-prefixed complex key's subtree occupies. When
//! it is, the parent's `awaiting_key`/pending-key state is left untouched (it stays
//! "awaiting a key", since the complex key hasn't finished yet) and the new frame is
//! marked internally so [`FrameStack::pop`] knows to flip the parent from "awaiting a
//! key" to "awaiting this entry's value" once the subtree closes — exactly what a
//! plain scalar key does, and the only way to avoid desyncing the rest of the
//! mapping's key/value alternation. Outside a complex-key position, `push`/`pop`
//! behave as every crate's own `consume_pending_value` did: reset `awaiting_key` to
//! `true` and `pending_key` to its default.
//!
//! Because a parent's `pending_key` is still at its default while it awaits a key, a
//! caller's own child-role computation (keyed off `pending_key`) naturally falls
//! through to whatever "irrelevant" role it already uses for an unrecognized key —
//! no crate-side special-casing is needed to get complex-key support: it falls out of
//! driving [`FrameStack`] directly.
//!
//! # Examples
//!
//! ```
//! use deps_core::yaml_walk::{FrameKind, FrameStack, ScalarPosition};
//!
//! #[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
//! enum Key {
//!     #[default]
//!     None,
//!     Name,
//! }
//!
//! let mut stack: FrameStack<(), Key, ()> = FrameStack::new();
//! stack.push(FrameKind::Mapping, (), ());
//! assert_eq!(stack.scalar_position(), ScalarPosition::Key);
//!
//! stack.observe_key(Key::Name);
//! assert_eq!(stack.scalar_position(), ScalarPosition::Value);
//! assert_eq!(*stack.top().unwrap().pending_key(), Key::Name);
//!
//! stack.consume_value();
//! assert_eq!(stack.scalar_position(), ScalarPosition::Key);
//! ```

/// Which container kind a [`Frame`] represents.
///
/// Mirrors `yaml-rust2`'s `Event::MappingStart`/`Event::SequenceStart` split, which
/// every driving crate already matches on before calling [`FrameStack::push`].
///
/// Deliberately **not** `#[non_exhaustive]`: YAML has exactly two container kinds, a
/// closed grammar concept this crate has no reason to ever extend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// A YAML mapping (`{}` or block-style `key: value` pairs).
    Mapping,
    /// A YAML sequence (`[]` or block-style `- item` entries).
    Sequence,
}

/// Where the next scalar event sits relative to the open frame stack.
///
/// Deliberately **not** `#[non_exhaustive]`: this exhaustively covers every position a
/// scalar can occupy relative to a frame stack (key, value, or neither) — a closed
/// concept with no fourth case to ever add.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarPosition {
    /// The top frame is a `Mapping` currently awaiting a key.
    Key,
    /// The top frame is a `Mapping` currently awaiting a value.
    Value,
    /// The stack is empty, or the top frame is a `Sequence` — a scalar here has no
    /// key/value meaning of its own (a bare sequence item, or a document-level bare
    /// scalar).
    Outside,
}

/// One open container frame.
///
/// Holds its structural kind, the driving crate's own `role` (`R`) and
/// `pending_key` (`K`) vocabulary, and an arbitrary per-frame `payload` (`P`) the
/// driving crate accumulates fields into.
///
/// `kind`/`awaiting_key`/`pending_key`/the complex-key flag are private and reachable
/// only through [`FrameStack`]'s invariant-preserving methods; `role` is read-only via
/// [`Frame::role`]. `payload` is `pub` — it is exactly the state a driving crate's own
/// per-role capture logic needs to read and mutate directly (e.g. `top_mut().payload`)
/// between calls to [`FrameStack::observe_key`]/[`FrameStack::consume_value`].
pub struct Frame<R, K, P> {
    kind: FrameKind,
    role: R,
    awaiting_key: bool,
    pending_key: K,
    /// Set by [`FrameStack::push`] when this frame occupies a complex-key position
    /// (see the module docs) — read back by [`FrameStack::pop`] to decide how the
    /// parent's key/value state transitions once this frame closes.
    is_complex_key: bool,
    /// The driving crate's own per-frame accumulated state.
    pub payload: P,
}

impl<R, K, P> Frame<R, K, P> {
    /// Whether this frame is a `Mapping` or a `Sequence`.
    #[must_use]
    pub const fn kind(&self) -> FrameKind {
        self.kind
    }

    /// The driving crate's role for this frame (e.g. "this is the `include:` value").
    #[must_use]
    pub const fn role(&self) -> &R {
        &self.role
    }

    /// The key this frame is currently holding a value for, if it is a `Mapping` past
    /// its key scalar — meaningless while the frame is still awaiting that key (see
    /// [`FrameStack::scalar_position`]).
    #[must_use]
    pub const fn pending_key(&self) -> &K {
        &self.pending_key
    }
}

/// The generic frame-stack mechanics described in the [module docs](self).
///
/// `K` must be `Clone + Default` (not `Copy`) — [`FrameStack::consume_value`] resets
/// the top frame's pending key to `K::default()`, and [`Frame::pending_key`] hands
/// back a reference rather than forcing every driving crate's key enum to be `Copy`.
pub struct FrameStack<R, K, P> {
    frames: Vec<Frame<R, K, P>>,
}

impl<R, K, P> Default for FrameStack<R, K, P>
where
    K: Clone + Default,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<R, K, P> FrameStack<R, K, P>
where
    K: Clone + Default,
{
    /// Creates an empty stack.
    #[must_use]
    pub const fn new() -> Self {
        Self { frames: Vec::new() }
    }

    /// Number of currently open frames — `0` at the document root before any
    /// `MappingStart`/`SequenceStart` has been pushed.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.frames.len()
    }

    /// The innermost open frame, if any.
    #[must_use]
    pub fn top(&self) -> Option<&Frame<R, K, P>> {
        self.frames.last()
    }

    /// Mutable access to the innermost open frame, if any.
    #[must_use]
    pub fn top_mut(&mut self) -> Option<&mut Frame<R, K, P>> {
        self.frames.last_mut()
    }

    /// The top frame's role, or `default` if the stack is empty.
    ///
    /// Convenience for `self.top().map_or(default, |f| *f.role())` — a pattern every
    /// driving crate's own child-role computation and key-scalar handling repeats at
    /// each call site, since a fresh role must always be read before deciding how to
    /// route a new key or child container.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::yaml_walk::{FrameKind, FrameStack};
    ///
    /// #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    /// enum Role {
    ///     Irrelevant,
    ///     Root,
    /// }
    ///
    /// let mut stack: FrameStack<Role, (), ()> = FrameStack::new();
    /// assert_eq!(stack.top_role_or(Role::Irrelevant), Role::Irrelevant);
    ///
    /// stack.push(FrameKind::Mapping, Role::Root, ());
    /// assert_eq!(stack.top_role_or(Role::Irrelevant), Role::Root);
    /// ```
    #[must_use]
    pub fn top_role_or(&self, default: R) -> R
    where
        R: Copy,
    {
        self.top().map_or(default, |frame| *frame.role())
    }

    /// Closes every open frame without running any [`FrameStack::pop`] transition —
    /// for a multi-document YAML stream, called on `Event::DocumentStart`/
    /// `Event::DocumentEnd` so one document's nesting never mis-scopes another's.
    pub fn clear(&mut self) {
        self.frames.clear();
    }

    /// Where the next scalar event sits: awaiting a key, awaiting a value, or outside
    /// any key/value-bearing context (an empty stack, or a `Sequence` top).
    #[must_use]
    pub fn scalar_position(&self) -> ScalarPosition {
        match self.frames.last() {
            None => ScalarPosition::Outside,
            Some(frame) if frame.kind == FrameKind::Sequence => ScalarPosition::Outside,
            Some(frame) if frame.awaiting_key => ScalarPosition::Key,
            Some(_) => ScalarPosition::Value,
        }
    }

    /// Whether a container about to be pushed would occupy a complex YAML key's
    /// position (`? <mapping>` / `? <sequence>`): the top frame is a `Mapping` still
    /// awaiting a key. Exposed so a driving crate's own `on_alias`-replay path (which
    /// calls [`FrameStack::push`]/[`FrameStack::pop`] out of band, not from a live key
    /// position) can assert it is never mistaken for a complex key.
    #[must_use]
    pub fn is_complex_key_position(&self) -> bool {
        self.frames
            .last()
            .is_some_and(|frame| frame.kind == FrameKind::Mapping && frame.awaiting_key)
    }

    /// Records that a key scalar (or an alias resolving to one) was just read: the top
    /// frame transitions from awaiting a key to awaiting `key`'s value. A no-op if the
    /// stack is empty.
    pub fn observe_key(&mut self, key: K)
    where
        K: PartialEq,
    {
        if let Some(top) = self.frames.last_mut() {
            debug_assert!(
                !top.awaiting_key || top.pending_key == K::default(),
                "observe_key: pending_key was not at its default while awaiting_key was \
                 true — the pending_key/awaiting_key invariant this module relies on \
                 throughout has been violated"
            );
            top.pending_key = key;
            top.awaiting_key = false;
        }
    }

    /// Records that a value was just consumed (a scalar, alias, or a just-closed
    /// container): the top frame transitions back to awaiting a key, and its pending
    /// key resets to `K::default()`. A no-op if the stack is empty.
    ///
    /// Like [`FrameStack::push`]/[`FrameStack::pop`], this mutates `awaiting_key`/
    /// `pending_key` unconditionally, even when the top frame is a `Sequence` (which
    /// has no key/value structure of its own). This is harmless as long as every
    /// caller reads a frame's key/value state only through
    /// [`FrameStack::scalar_position`]/[`FrameStack::is_complex_key_position`] — both
    /// already treat a `Sequence` top as [`ScalarPosition::Outside`]/never a complex
    /// key — rather than reading [`Frame::pending_key`] directly without first
    /// checking the frame's [`FrameKind`].
    pub fn consume_value(&mut self) {
        if let Some(top) = self.frames.last_mut() {
            top.awaiting_key = true;
            top.pending_key = K::default();
        }
    }

    /// Opens a new frame of kind `kind`, role `role`, and initial `payload`.
    ///
    /// If the current top frame occupies a complex-key position (see the [module
    /// docs](self)), the parent is left untouched (still awaiting its key) and the
    /// new frame is marked so [`FrameStack::pop`] applies the matching transition
    /// instead of the ordinary one; otherwise this is exactly
    /// [`FrameStack::consume_value`] on the parent followed by pushing the new frame.
    ///
    /// # Examples
    ///
    /// Pushing a container onto a `Mapping` still awaiting its key (`? <mapping>:
    /// value`, a complex key's own subtree) is recognized via
    /// [`FrameStack::is_complex_key_position`] *before* the push — that recognition is
    /// exactly what makes the matching [`FrameStack::pop`] transition possible once the
    /// subtree closes (see that method's own example for the visible effect):
    ///
    /// ```
    /// use deps_core::yaml_walk::{FrameKind, FrameStack, ScalarPosition};
    ///
    /// let mut stack: FrameStack<(), (), ()> = FrameStack::new();
    /// stack.push(FrameKind::Mapping, (), ()); // the enclosing mapping
    /// assert_eq!(stack.scalar_position(), ScalarPosition::Key);
    ///
    /// assert!(stack.is_complex_key_position());
    /// stack.push(FrameKind::Mapping, (), ()); // `? <mapping>`'s own subtree
    /// assert_eq!(stack.depth(), 2);
    /// ```
    pub fn push(&mut self, kind: FrameKind, role: R, payload: P) {
        let is_complex_key = self.is_complex_key_position();
        if !is_complex_key {
            self.consume_value();
        }
        self.frames.push(Frame {
            kind,
            role,
            awaiting_key: true,
            pending_key: K::default(),
            is_complex_key,
            payload,
        });
    }

    /// Closes the innermost open frame and returns it, or `None` if the stack was
    /// already empty.
    ///
    /// If the closed frame was pushed at a complex-key position, the new top (the
    /// former parent) transitions directly to "awaiting this entry's value" — the
    /// same transition a plain scalar key produces — rather than the ordinary
    /// [`FrameStack::consume_value`] reset, which would leave it stuck awaiting
    /// another key and desync the rest of the mapping's key/value alternation.
    ///
    /// # Examples
    ///
    /// Closing a complex key's subtree (`? <mapping>: value`) flips the parent
    /// straight to "awaiting a value", exactly as a plain scalar key would — not back
    /// to "awaiting a key", which is what would happen for an ordinary (non-complex-key)
    /// child:
    ///
    /// ```
    /// use deps_core::yaml_walk::{FrameKind, FrameStack, ScalarPosition};
    ///
    /// let mut stack: FrameStack<(), (), ()> = FrameStack::new();
    /// stack.push(FrameKind::Mapping, (), ()); // the enclosing mapping
    /// stack.push(FrameKind::Mapping, (), ()); // `? <mapping>`'s own subtree
    /// stack.pop(); // closes the complex key
    ///
    /// // The parent now awaits this entry's *value* — not another key.
    /// assert_eq!(stack.scalar_position(), ScalarPosition::Value);
    /// ```
    pub fn pop(&mut self) -> Option<Frame<R, K, P>> {
        let frame = self.frames.pop()?;
        if frame.is_complex_key {
            if let Some(parent) = self.frames.last_mut() {
                parent.awaiting_key = false;
                parent.pending_key = K::default();
            }
        } else {
            self.consume_value();
        }
        Some(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::{FrameKind, FrameStack, ScalarPosition};

    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    enum Key {
        #[default]
        None,
        Name,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Role {
        Root,
        Irrelevant,
    }

    #[test]
    fn test_key_value_toggling() {
        let mut stack: FrameStack<Role, Key, ()> = FrameStack::new();
        stack.push(FrameKind::Mapping, Role::Root, ());
        assert_eq!(stack.scalar_position(), ScalarPosition::Key);

        stack.observe_key(Key::Name);
        assert_eq!(stack.scalar_position(), ScalarPosition::Value);
        assert_eq!(*stack.top().unwrap().pending_key(), Key::Name);

        stack.consume_value();
        assert_eq!(stack.scalar_position(), ScalarPosition::Key);
        assert_eq!(*stack.top().unwrap().pending_key(), Key::None);
    }

    #[test]
    fn test_sequence_parent_scalar_position_is_outside() {
        let mut stack: FrameStack<Role, Key, ()> = FrameStack::new();
        stack.push(FrameKind::Sequence, Role::Irrelevant, ());
        assert_eq!(stack.scalar_position(), ScalarPosition::Outside);
        // A sequence frame never tracks a key at all.
        stack.observe_key(Key::Name);
        assert_eq!(*stack.top().unwrap().pending_key(), Key::Name);
        assert_eq!(stack.scalar_position(), ScalarPosition::Outside);
    }

    #[test]
    fn test_empty_stack_scalar_position_is_outside() {
        let stack: FrameStack<Role, Key, ()> = FrameStack::new();
        assert_eq!(stack.scalar_position(), ScalarPosition::Outside);
        assert!(stack.top().is_none());
    }

    #[test]
    fn test_alias_in_key_position_toggles_same_as_a_scalar_key() {
        // A resolved YAML alias in key position (`*anchor: value`) is driven through
        // exactly the same `observe_key`/`consume_value` calls a plain scalar key
        // would use — the walker has no separate "alias" concept at all.
        let mut stack: FrameStack<Role, Key, ()> = FrameStack::new();
        stack.push(FrameKind::Mapping, Role::Root, ());
        assert_eq!(stack.scalar_position(), ScalarPosition::Key);
        stack.observe_key(Key::Name);
        assert_eq!(stack.scalar_position(), ScalarPosition::Value);
        stack.consume_value();
        assert_eq!(stack.scalar_position(), ScalarPosition::Key);
    }

    #[test]
    fn test_complex_key_subtree_does_not_disturb_parent_then_flips_to_awaiting_value() {
        // `? <mapping>: value` — the complex key's own subtree is a Mapping pushed
        // while the parent is still awaiting a key.
        let mut stack: FrameStack<Role, Key, ()> = FrameStack::new();
        stack.push(FrameKind::Mapping, Role::Root, ());
        assert!(stack.is_complex_key_position());

        stack.push(FrameKind::Mapping, Role::Irrelevant, ());
        // Pushing into a complex-key position must not touch the parent at all —
        // there is no parent-visible effect until the subtree closes.
        assert_eq!(stack.depth(), 2);

        let closed = stack.pop().unwrap();
        assert_eq!(closed.kind(), FrameKind::Mapping);
        assert_eq!(stack.depth(), 1);
        // The parent now behaves exactly as if a plain scalar key had just been read:
        // awaiting this entry's value, not another key.
        assert_eq!(stack.scalar_position(), ScalarPosition::Value);
        assert_eq!(*stack.top().unwrap().pending_key(), Key::None);
    }

    #[test]
    fn test_nested_complex_key_sequence_form() {
        // `? <sequence>: value` — the sequence variant of a complex key.
        let mut stack: FrameStack<Role, Key, ()> = FrameStack::new();
        stack.push(FrameKind::Mapping, Role::Root, ());
        stack.push(FrameKind::Sequence, Role::Irrelevant, ());
        assert_eq!(stack.top().unwrap().kind(), FrameKind::Sequence);
        stack.pop();
        assert_eq!(stack.scalar_position(), ScalarPosition::Value);
    }

    #[test]
    fn test_ordinary_mapping_value_push_pop_resets_parent_to_awaiting_key() {
        let mut stack: FrameStack<Role, Key, ()> = FrameStack::new();
        stack.push(FrameKind::Mapping, Role::Root, ());
        stack.observe_key(Key::Name);
        // The value is itself a nested mapping — an ordinary (non-complex-key) push,
        // since the parent is awaiting a *value*, not a key, at this point.
        assert!(!stack.is_complex_key_position());
        stack.push(FrameKind::Mapping, Role::Irrelevant, ());
        stack.pop();
        assert_eq!(stack.scalar_position(), ScalarPosition::Key);
        assert_eq!(*stack.top().unwrap().pending_key(), Key::None);
    }

    #[test]
    fn test_depth_tracks_open_frames() {
        let mut stack: FrameStack<Role, Key, ()> = FrameStack::new();
        assert_eq!(stack.depth(), 0);
        stack.push(FrameKind::Mapping, Role::Root, ());
        assert_eq!(stack.depth(), 1);
        stack.push(FrameKind::Sequence, Role::Irrelevant, ());
        assert_eq!(stack.depth(), 2);
        stack.pop();
        assert_eq!(stack.depth(), 1);
    }

    #[test]
    fn test_clear_drops_every_open_frame() {
        let mut stack: FrameStack<Role, Key, ()> = FrameStack::new();
        stack.push(FrameKind::Mapping, Role::Root, ());
        stack.push(FrameKind::Sequence, Role::Irrelevant, ());
        stack.clear();
        assert_eq!(stack.depth(), 0);
        assert_eq!(stack.scalar_position(), ScalarPosition::Outside);
    }

    #[test]
    fn test_payload_is_directly_mutable_between_key_and_value() {
        let mut stack: FrameStack<Role, Key, Vec<u32>> = FrameStack::new();
        stack.push(FrameKind::Mapping, Role::Root, Vec::new());
        stack.top_mut().unwrap().payload.push(1);
        stack.observe_key(Key::Name);
        stack.top_mut().unwrap().payload.push(2);
        assert_eq!(stack.top().unwrap().payload, vec![1, 2]);
    }
}
