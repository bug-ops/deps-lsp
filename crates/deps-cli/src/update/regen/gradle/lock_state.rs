//! The lock state Gradle records per configuration, parsed from both lock layouts.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

/// Longest configuration name accepted; real names are far shorter.
const MAX_CONFIGURATION_BYTES: usize = 256;
/// Longest coordinate accepted; bounds the per-configuration copies of one lock line.
const MAX_COORDINATE_BYTES: usize = 1024;
/// Longest lock line accepted.
const MAX_LINE_BYTES: usize = 64 * 1024;

/// The name of a Gradle configuration a lock file records (`compileClasspath`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LockConfiguration(Arc<str>);

impl LockConfiguration {
    /// Parses a configuration name; `None` for an empty name or one with a separator or whitespace.
    pub(in crate::update::regen) fn new(raw: &str) -> Option<Self> {
        let valid = !raw.is_empty()
            && raw.len() <= MAX_CONFIGURATION_BYTES
            && !raw.contains(|c: char| c == ',' || c == '=' || c.is_whitespace());
        valid.then(|| Self(Arc::from(raw)))
    }

    /// The configuration name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LockConfiguration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A locked `group:artifact:version` coordinate of a lock file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LockedCoordinate(Arc<str>);

impl LockedCoordinate {
    /// Parses a coordinate; `None` unless it has three non-empty `:`-separated parts.
    pub(in crate::update::regen) fn new(raw: &str) -> Option<Self> {
        let mut parts = raw.split(':');
        let well_formed = (0..3).all(|_| parts.next().is_some_and(|part| !part.is_empty()))
            && parts.next().is_none();
        (well_formed && raw.len() <= MAX_COORDINATE_BYTES).then(|| Self(Arc::from(raw)))
    }

    /// The coordinate text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The `group:artifact` part, which is what an update pin names.
    pub(super) fn module(&self) -> &str {
        self.0
            .rsplit_once(':')
            .map_or(&self.0, |(module, _)| module)
    }
}

impl fmt::Display for LockedCoordinate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// How a configuration's locked coordinates changed during a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockStateChange {
    /// The run added a coordinate the lock did not hold.
    Gained(LockedCoordinate),
    /// The run dropped a coordinate the lock held.
    Lost(LockedCoordinate),
}

impl fmt::Display for LockStateChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gained(coordinate) => write!(f, "gained {coordinate}"),
            Self::Lost(coordinate) => write!(f, "lost {coordinate}"),
        }
    }
}

/// Which of a project's two lock files a configuration belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum LockScope {
    /// `gradle.lockfile`.
    Project,
    /// `buildscript-gradle.lockfile`.
    Buildscript,
}

impl LockScope {
    pub(super) const ALL: [Self; 2] = [Self::Project, Self::Buildscript];

    /// The unified lock file name of this scope.
    pub(super) const fn unified_file_name(self) -> &'static str {
        match self {
            Self::Project => "gradle.lockfile",
            Self::Buildscript => "buildscript-gradle.lockfile",
        }
    }

    /// The scope of a unified lock file name.
    pub(super) fn of_unified_file_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|scope| scope.unified_file_name() == name)
    }

    /// The scope and configuration a legacy `<configuration>.lockfile` file name stands for.
    pub(super) fn of_legacy_file_name(name: &str) -> Option<(Self, LockConfiguration)> {
        let stem = name.strip_suffix(".lockfile")?;
        match stem.strip_prefix("buildscript-") {
            Some(rest) => Some((Self::Buildscript, LockConfiguration::new(rest)?)),
            None => Some((Self::Project, LockConfiguration::new(stem)?)),
        }
    }
}

/// The coordinates locked per configuration, keyed by scope.
pub(super) type LockState = BTreeMap<(LockScope, LockConfiguration), BTreeSet<LockedCoordinate>>;

fn content_lines(text: &str) -> Option<impl Iterator<Item = &str>> {
    if text.lines().any(|line| line.len() > MAX_LINE_BYTES) {
        return None;
    }
    Some(
        text.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#')),
    )
}

/// The coordinates of one legacy `<configuration>.lockfile`; `None` for an unparsable line.
pub(super) fn parse_legacy(text: &str) -> Option<BTreeSet<LockedCoordinate>> {
    content_lines(text)?.map(LockedCoordinate::new).collect()
}

/// The state of a unified lock file of `scope`; `None` for an unparsable line.
///
/// `empty=a,b` marks configurations without coordinates; a bare `empty=` marks none.
pub(super) fn parse_unified(scope: LockScope, text: &str) -> Option<LockState> {
    let mut state = LockState::new();
    for line in content_lines(text)? {
        let (head, configurations) = line.split_once('=')?;
        let configurations = configurations
            .split(',')
            .filter(|name| !name.is_empty())
            .map(LockConfiguration::new)
            .collect::<Option<Vec<_>>>()?;
        if head == "empty" {
            for configuration in configurations {
                state.entry((scope, configuration)).or_default();
            }
        } else {
            let coordinate = LockedCoordinate::new(head)?;
            if configurations.is_empty() {
                return None;
            }
            for configuration in configurations {
                state
                    .entry((scope, configuration))
                    .or_default()
                    .insert(coordinate.clone());
            }
        }
    }
    Some(state)
}

/// `state` without the coordinates of the given `group:artifact` modules.
pub(super) fn without_modules(state: &LockState, modules: &[&str]) -> LockState {
    state
        .iter()
        .map(|(key, coordinates)| {
            let kept = coordinates
                .iter()
                .filter(|coordinate| !modules.contains(&coordinate.module()))
                .cloned()
                .collect();
            (key.clone(), kept)
        })
        .collect()
}

/// How [`first_drift`] handles configurations present in `before` and absent from `after`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DroppedConfigurations {
    /// Legacy-layout migration: legacy-only configurations are classified separately as
    /// `Removal::StaleEmpty` or `Removal::StaleDropped`, not as drift.
    AllowStale,
    /// Unified regeneration: missing-in-after configurations compare against an empty set, so
    /// dropping any non-empty configuration is [`LockStateChange::Lost`] drift.
    Refuse,
}

fn configuration_drift(
    before: &BTreeSet<LockedCoordinate>,
    after: &BTreeSet<LockedCoordinate>,
) -> Option<LockStateChange> {
    after
        .difference(before)
        .next()
        .map(|c| LockStateChange::Gained(c.clone()))
        .or_else(|| {
            before
                .difference(after)
                .next()
                .map(|c| LockStateChange::Lost(c.clone()))
        })
}

/// The first configuration whose coordinates differ between `before` and `after`, and how.
///
/// A configuration `before` does not know compares as empty, so gaining an empty one is no drift.
/// Configurations present in `before` and absent from `after` are handled according to `dropped`.
pub(super) fn first_drift(
    before: &LockState,
    after: &LockState,
    dropped: DroppedConfigurations,
) -> Option<(LockScope, LockConfiguration, LockStateChange)> {
    let none = BTreeSet::new();
    match dropped {
        DroppedConfigurations::AllowStale => after.iter().find_map(|(key, now)| {
            let prior = before.get(key).unwrap_or(&none);
            configuration_drift(prior, now).map(|change| (key.0, key.1.clone(), change))
        }),
        DroppedConfigurations::Refuse => {
            let keys: BTreeSet<&(LockScope, LockConfiguration)> =
                before.keys().chain(after.keys()).collect();
            keys.into_iter().find_map(|key| {
                let prior = before.get(key).unwrap_or(&none);
                let now = after.get(key).unwrap_or(&none);
                configuration_drift(prior, now).map(|change| (key.0, key.1.clone(), change))
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coordinate(raw: &str) -> LockedCoordinate {
        LockedCoordinate::new(raw).expect(raw)
    }

    fn configuration(raw: &str) -> LockConfiguration {
        LockConfiguration::new(raw).expect(raw)
    }

    #[test]
    fn unified_lines_assign_a_coordinate_to_every_listed_configuration() {
        let state = parse_unified(
            LockScope::Project,
            "# header\n\ng:a:1=compile,runtime\nempty=kapt\n",
        )
        .expect("parses");

        let key = |name: &str| (LockScope::Project, configuration(name));
        assert_eq!(
            state[&key("compile")],
            BTreeSet::from([coordinate("g:a:1")])
        );
        assert_eq!(state[&key("runtime")], state[&key("compile")]);
        assert!(state[&key("kapt")].is_empty());
    }

    #[test]
    fn a_bare_empty_marker_lists_no_configurations() {
        let state = parse_unified(LockScope::Buildscript, "empty=\n").expect("parses");

        assert!(state.is_empty());
    }

    #[test]
    fn unparsable_unified_and_legacy_lines_fail_closed() {
        for text in ["junk\n", "g:a=compile\n", "g:a:1=\n", "g:a:1=a b\n"] {
            assert!(
                parse_unified(LockScope::Project, text).is_none(),
                "{text:?}"
            );
        }
        assert!(parse_legacy("g:a\n").is_none());
        assert_eq!(
            parse_legacy("# c\n\ng:a:1\n").expect("parses"),
            BTreeSet::from([coordinate("g:a:1")])
        );
        assert!(
            parse_legacy("# only a header\n")
                .expect("parses")
                .is_empty()
        );
    }

    #[test]
    fn legacy_file_names_give_scope_and_configuration() {
        assert_eq!(
            LockScope::of_legacy_file_name("compileClasspath.lockfile"),
            Some((LockScope::Project, configuration("compileClasspath")))
        );
        assert_eq!(
            LockScope::of_legacy_file_name("buildscript-classpath.lockfile"),
            Some((LockScope::Buildscript, configuration("classpath")))
        );
        assert!(LockScope::of_legacy_file_name("notes.txt").is_none());
        assert!(LockScope::of_legacy_file_name(".lockfile").is_none());
    }

    #[test]
    fn drift_is_a_gained_or_lost_coordinate_in_a_migrated_configuration() {
        let key = (LockScope::Project, configuration("compile"));
        let legacy = LockState::from([(key.clone(), BTreeSet::from([coordinate("g:a:1")]))]);
        let gained = LockState::from([(
            key.clone(),
            BTreeSet::from([coordinate("g:a:1"), coordinate("g:b:1")]),
        )]);
        let lost = LockState::from([(key, BTreeSet::new())]);

        for dropped in [
            DroppedConfigurations::AllowStale,
            DroppedConfigurations::Refuse,
        ] {
            assert!(first_drift(&legacy, &legacy, dropped).is_none());
            assert_eq!(
                first_drift(&legacy, &gained, dropped).map(|(_, _, change)| change),
                Some(LockStateChange::Gained(coordinate("g:b:1")))
            );
            assert_eq!(
                first_drift(&legacy, &lost, dropped).map(|(_, _, change)| change),
                Some(LockStateChange::Lost(coordinate("g:a:1")))
            );
        }
    }

    #[test]
    fn module_and_without_modules_drop_only_the_named_modules() {
        let key = (LockScope::Project, configuration("compile"));
        let state = LockState::from([(
            key.clone(),
            BTreeSet::from([coordinate("g:a:1"), coordinate("g:b:1")]),
        )]);

        assert_eq!(coordinate("g:a:1").module(), "g:a");
        assert_eq!(
            without_modules(&state, &["g:a"])[&key],
            BTreeSet::from([coordinate("g:b:1")])
        );
        assert_eq!(
            LockScope::of_unified_file_name("buildscript-gradle.lockfile"),
            Some(LockScope::Buildscript)
        );
        assert!(LockScope::of_unified_file_name("compile.lockfile").is_none());
    }

    #[test]
    fn gaining_an_empty_configuration_is_no_drift() {
        let migrated =
            LockState::from([((LockScope::Project, configuration("kapt")), BTreeSet::new())]);

        for dropped in [
            DroppedConfigurations::AllowStale,
            DroppedConfigurations::Refuse,
        ] {
            assert!(first_drift(&LockState::new(), &migrated, dropped).is_none());
        }
    }

    #[test]
    fn dropped_non_empty_configuration_is_lost_when_refused_and_ignored_when_stale_allowed() {
        let before = LockState::from([
            (
                (LockScope::Project, configuration("compileClasspath")),
                BTreeSet::from([coordinate("commons-io:commons-io:2.11.0")]),
            ),
            (
                (LockScope::Project, configuration("runtimeClasspath")),
                BTreeSet::from([coordinate("g:kept:1.0.0")]),
            ),
        ]);
        let after = LockState::from([(
            (LockScope::Project, configuration("runtimeClasspath")),
            BTreeSet::from([coordinate("g:kept:1.0.0")]),
        )]);

        assert!(first_drift(&before, &after, DroppedConfigurations::AllowStale).is_none());
        assert_eq!(
            first_drift(&before, &after, DroppedConfigurations::Refuse),
            Some((
                LockScope::Project,
                configuration("compileClasspath"),
                LockStateChange::Lost(coordinate("commons-io:commons-io:2.11.0")),
            ))
        );
    }

    #[test]
    fn dropped_empty_configuration_is_no_drift_under_either_policy() {
        let before = LockState::from([(
            (LockScope::Project, configuration("annotationProcessor")),
            BTreeSet::new(),
        )]);

        for dropped in [
            DroppedConfigurations::AllowStale,
            DroppedConfigurations::Refuse,
        ] {
            assert!(first_drift(&before, &LockState::new(), dropped).is_none());
        }
    }

    #[test]
    fn first_drift_visits_union_of_configurations_in_sorted_scope_and_name_order() {
        let before_earlier = LockState::from([(
            (LockScope::Project, configuration("a_dropped")),
            BTreeSet::from([coordinate("g:dropped:1.0.0")]),
        )]);
        let after_later = LockState::from([(
            (LockScope::Project, configuration("b_gained")),
            BTreeSet::from([coordinate("g:gained:1.0.0")]),
        )]);
        assert_eq!(
            first_drift(&before_earlier, &after_later, DroppedConfigurations::Refuse),
            Some((
                LockScope::Project,
                configuration("a_dropped"),
                LockStateChange::Lost(coordinate("g:dropped:1.0.0")),
            ))
        );

        let before_later = LockState::from([(
            (LockScope::Project, configuration("b_dropped")),
            BTreeSet::from([coordinate("g:dropped:1.0.0")]),
        )]);
        let after_earlier = LockState::from([(
            (LockScope::Project, configuration("a_gained")),
            BTreeSet::from([coordinate("g:gained:1.0.0")]),
        )]);
        assert_eq!(
            first_drift(&before_later, &after_earlier, DroppedConfigurations::Refuse),
            Some((
                LockScope::Project,
                configuration("a_gained"),
                LockStateChange::Gained(coordinate("g:gained:1.0.0")),
            ))
        );

        let before_scope = LockState::from([(
            (LockScope::Project, configuration("z_project")),
            BTreeSet::from([coordinate("g:proj:1.0.0")]),
        )]);
        let after_scope = LockState::from([(
            (LockScope::Buildscript, configuration("a_buildscript")),
            BTreeSet::from([coordinate("g:bs:1.0.0")]),
        )]);
        assert_eq!(
            first_drift(&before_scope, &after_scope, DroppedConfigurations::Refuse),
            Some((
                LockScope::Project,
                configuration("z_project"),
                LockStateChange::Lost(coordinate("g:proj:1.0.0")),
            ))
        );
    }

    #[test]
    fn oversized_names_and_lines_are_unparsable() {
        let coordinate = format!("g:{}:1", "a".repeat(MAX_COORDINATE_BYTES));
        assert!(LockedCoordinate::new(&coordinate).is_none());
        assert!(LockConfiguration::new(&"c".repeat(MAX_CONFIGURATION_BYTES + 1)).is_none());
        let long_line = format!("empty={}\n", "c,".repeat(MAX_LINE_BYTES));
        assert!(parse_unified(LockScope::Project, &long_line).is_none());
        assert!(parse_legacy(&"x".repeat(MAX_LINE_BYTES + 1)).is_none());
    }
}
