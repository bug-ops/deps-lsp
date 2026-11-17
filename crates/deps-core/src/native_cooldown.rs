//! Native package-manager publish-age windows (spec 099 Phase 1, #1982).
//!
//! STUB: signatures only, behaviour pending implementation.

use std::fmt;

use crate::lsp_helpers::VersionData;
use crate::{ConcreteVersion, CooldownWindow, Dependency, PackageKey, PublishTime};

/// Unit of a configured native time span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeUnit {
    /// Seconds.
    Second,
    /// Minutes.
    Minute,
    /// Hours.
    Hour,
    /// Days.
    Day,
    /// Weeks.
    Week,
    /// Months.
    Month,
}

/// A parsed, non-zero `<count> <unit>` span as configured by the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeTimeSpan {
    count: u64,
    unit: TimeUnit,
}

impl fmt::Display for NativeTimeSpan {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (self.count, self.unit);
        todo!()
    }
}

/// Result of parsing a configured time span: disabled (zero) or an actual span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeSpanValue {
    /// Zero in any spelling: the window is turned off.
    Disabled,
    /// A non-zero span.
    Span(NativeTimeSpan),
}

/// Why a configured time span could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeSpanError {
    /// The text is outside the supported grammar.
    Malformed,
    /// The span does not fit in `u64` seconds.
    Overflow,
}

/// Parses Cargo's time-span grammar (`<integer> <unit>`).
///
/// # Errors
///
/// [`TimeSpanError::Malformed`] outside the grammar, [`TimeSpanError::Overflow`] when the
/// span exceeds `u64` seconds.
pub fn parse_time_span(_raw: &str) -> Result<TimeSpanValue, TimeSpanError> {
    todo!()
}

/// A non-zero publish-age window, clamped to a maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeWindow(CooldownWindow);

impl NativeWindow {
    /// Whether a publish age in seconds falls inside the window.
    #[must_use]
    pub const fn contains(self, _age_secs: u64) -> bool {
        let _ = self.0;
        todo!()
    }
}

/// A registry alias as written in `[registries.<name>]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryAlias(pub String);

/// Which configuration key a native window came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeCooldownSource {
    /// `registry.global-min-publish-age`.
    CargoGlobal,
    /// `registries.<alias>.min-publish-age`.
    CargoRegistry {
        /// The registry the key belongs to.
        alias: RegistryAlias,
    },
}

/// A native window together with the setting it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeCooldown {
    span: NativeTimeSpan,
    source: NativeCooldownSource,
}

impl NativeCooldown {
    /// Builds a cooldown from a span and its source.
    #[must_use]
    pub const fn new(span: NativeTimeSpan, source: NativeCooldownSource) -> Self {
        Self { span, source }
    }

    /// The window this cooldown enforces.
    #[must_use]
    pub fn window(&self) -> NativeWindow {
        let _ = (&self.span, &self.source);
        todo!()
    }
}

impl fmt::Display for NativeCooldown {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

/// Read-time predicate deciding whether a version is held back by a native window.
#[derive(Debug, Clone, Copy)]
pub struct NativeGate<'a> {
    cooldown: &'a NativeCooldown,
}

impl<'a> NativeGate<'a> {
    /// Builds the gate for `dep`, or `None` when it has no native window.
    #[must_use]
    pub fn for_dependency(
        _dep: &'a dyn Dependency,
        _key: &PackageKey,
        _versions: &VersionData<'a>,
    ) -> Option<Self> {
        todo!()
    }

    /// Whether `version`, published at `published_at`, is excluded at `now`.
    #[must_use]
    pub fn excludes(
        &self,
        _published_at: Option<PublishTime>,
        _version: &ConcreteVersion,
        _now: PublishTime,
    ) -> bool {
        let _ = self.cooldown;
        todo!()
    }

    /// Seconds until `version` becomes eligible, when it is currently excluded.
    #[must_use]
    pub fn remaining(
        &self,
        _published_at: Option<PublishTime>,
        _version: &ConcreteVersion,
        _now: PublishTime,
    ) -> Option<u64> {
        todo!()
    }
}
