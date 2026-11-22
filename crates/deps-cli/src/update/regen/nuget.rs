//! Regeneration for NuGet `packages.lock.json` (#2084).

use std::path::Path;

use deps_core::lsp_helpers::BoundedVersionReq;
use deps_core::{NormalizeName, PackageName};

use super::command::dotnet::{ProjectFileArg, RestoreMode};
use super::fallback::{ExactPinRun, Relax};
use super::lockers::Located;
use super::{
    Invocation, LockPin, LockfileOutcome, NotApplicableReason, PinCheck, Program,
    RegenerationError, Session, UnsupportedReason, unsupported,
};

/// What the manifest file is, decided from its name the way the NuGet ecosystem parser does.
enum ManifestKind {
    /// `Directory.Packages.props`: versions live outside the project files.
    CentralPackageVersions,
    /// `packages.config`: the manifest is itself the pin file.
    PackagesConfig,
    /// Anything else: a project file.
    ProjectFile,
}

impl ManifestKind {
    fn of(file_name: &str) -> Self {
        match file_name.to_lowercase().as_str() {
            "directory.packages.props" => Self::CentralPackageVersions,
            "packages.config" => Self::PackagesConfig,
            _ => Self::ProjectFile,
        }
    }
}

/// Whether a declared requirement carries a floating pattern (`2.*`), the only shape a lock-only
/// pin can follow forward without an edit.
pub(super) fn declares_float_pattern(requirement: &str) -> bool {
    requirement.contains('*')
}

/// Whether restore may move a package of this requirement on its own: a floating `*` or a range
/// with an upper bound. A plain version, an open-ended floor and an inclusive pair of equal
/// bounds (`[a, a]`, the exact pin a restore writes into the lock) resolve to the same version
/// again, so they stay put.
fn requirement_floats(requirement: &str) -> bool {
    let requirement = requirement.trim();
    if declares_float_pattern(requirement) {
        return true;
    }
    if !requirement.starts_with(['[', '(']) {
        return false;
    }
    let Some((lower, upper)) = requirement.split_once(',') else {
        return false;
    };
    let upper_bound = upper.trim_end_matches([')', ']']).trim();
    if upper_bound.is_empty() {
        return false;
    }
    let inclusive = requirement.starts_with('[') && requirement.ends_with(']');
    let lower_bound = lower.trim_start_matches(['[', '(']).trim();
    !(inclusive && lower_bound == upper_bound)
}

/// How a lock-only pin of a project file is moved.
enum LockOnlyClass {
    /// The declaration floats: the run pins the target exactly, restores, and puts the declared
    /// requirement back.
    Floating,
    /// The declared floor or exact pin already equals the target: one restore moves the lock.
    Fixed,
    /// No restore form moves the pin without re-resolving other packages.
    Unmovable,
}

/// Whether some entry of the lock file other than a pinned package carries a requirement that
/// restore would re-resolve: a `Direct` or `CentralTransitive` `requested` value, or a range of
/// a `Project` entry's dependencies, in any framework section.
fn lock_floats_other(lock: &serde_json::Value, is_pinned: impl Fn(&str) -> bool) -> bool {
    let Some(frameworks) = lock
        .get("dependencies")
        .and_then(serde_json::Value::as_object)
    else {
        return false;
    };
    let floats = |value: Option<&serde_json::Value>| {
        value
            .and_then(serde_json::Value::as_str)
            .is_some_and(requirement_floats)
    };
    frameworks
        .values()
        .filter_map(serde_json::Value::as_object)
        .flatten()
        .filter(|(name, _)| !is_pinned(name))
        .any(
            |(_, entry)| match entry.get("type").and_then(serde_json::Value::as_str) {
                Some("Direct" | "CentralTransitive") => floats(entry.get("requested")),
                Some("Project") => entry
                    .get("dependencies")
                    .and_then(serde_json::Value::as_object)
                    .is_some_and(|dependencies| {
                        dependencies
                            .iter()
                            .any(|(name, range)| !is_pinned(name) && floats(Some(range)))
                    }),
                _ => false,
            },
        )
}

impl Session<'_> {
    /// Whether a dependency other than the pins carries a requirement restore would re-resolve.
    ///
    /// Restore re-resolves every floating dependency of a project once any package changed
    /// (verified: `Serilog 2.*` locked at 2.10.0 moved to 2.12.0 in an unrelated edit), which
    /// bypasses the cooldown for that package. A lock-only pin that stays out of the session
    /// counts here too.
    fn other_requirements_float(&self) -> Result<bool, RegenerationError> {
        let parsed = self.reparse_manifest()?;
        let formatter = self.target.ecosystem.formatter();
        Ok(parsed.dependencies().into_iter().any(|dep| {
            let edited = self
                .pins
                .iter()
                .any(|pin| formatter.normalize_package_name(dep.name()) == pin.normalized);
            !edited
                && dep
                    .version_requirement()
                    .is_some_and(|requirement| requirement_floats(requirement.as_str()))
        }))
    }

    /// Which of the three ways a lock-only `pin` moves, from its single declaration in `parsed`.
    fn lock_only_class(
        &self,
        pin: &LockPin,
        parsed: &dyn deps_core::ParsedManifest,
    ) -> LockOnlyClass {
        let formatter = self.target.ecosystem.formatter();
        let declarations: Vec<_> = parsed
            .dependencies()
            .into_iter()
            .filter(|dep| formatter.normalize_package_name(dep.name()) == pin.normalized)
            .collect();
        let [declaration] = declarations.as_slice() else {
            return LockOnlyClass::Unmovable;
        };
        let Some(requirement) = declaration.version_requirement() else {
            return LockOnlyClass::Unmovable;
        };
        if declares_float_pattern(requirement.as_str()) {
            return LockOnlyClass::Floating;
        }
        let resolves_to_target = BoundedVersionReq::new(requirement).is_some_and(|bounded| {
            formatter.bounded_requirement_already_resolves_to(bounded, &pin.target)
        });
        if resolves_to_target {
            LockOnlyClass::Fixed
        } else {
            LockOnlyClass::Unmovable
        }
    }

    /// `dotnet restore <project> --use-lock-file --no-dependencies --force` after a manifest
    /// edit, and for lock-only pins whose declaration lets restore reach the target.
    ///
    /// A lock-only pin is one of three kinds (see [`LockOnlyClass`]). A floating one is pinned
    /// exactly in the manifest for one restore, then the declared requirement goes back into the
    /// manifest and the lock file and a locked-mode restore proves they agree. A fixed one only
    /// needs the restore. Any other lock-only pin stays out of the run; when nothing else is
    /// left, the run is refused. `--force-evaluate` is never used: it re-resolves every floating
    /// dependency (cooldown bypass, unrelated churn), so a floating requirement of any other
    /// package, in the manifest or in the lock file, refuses the run.
    pub(super) async fn nuget(&self) -> Result<LockfileOutcome, RegenerationError> {
        let file_name = self
            .target
            .manifest_path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or_default();
        match ManifestKind::of(file_name) {
            ManifestKind::CentralPackageVersions => {
                return Ok(unsupported(None, UnsupportedReason::CentralPackageVersions));
            }
            ManifestKind::PackagesConfig => {
                return Ok(LockfileOutcome::NotApplicable(
                    NotApplicableReason::NoLockfilePresent,
                ));
            }
            ManifestKind::ProjectFile => {}
        }
        let located = match self.lockfile_beside_manifest().await? {
            Located::Beside(path) => path,
            Located::Stop(outcome) => return Ok(outcome),
        };
        let Ok(project) = ProjectFileArg::parse(file_name) else {
            return Ok(unsupported(
                Some(self.display_lock_path(&located)),
                UnsupportedReason::LockfileOwnershipMismatch,
            ));
        };

        let parsed = self.reparse_manifest()?;
        let mut restorable: Vec<LockPin> = Vec::new();
        let mut floating: Vec<LockPin> = Vec::new();
        for pin in self.pins {
            if !pin.is_lockfile_only() {
                restorable.push(pin.clone());
                continue;
            }
            match self.lock_only_class(pin, parsed.as_ref()) {
                LockOnlyClass::Floating => floating.push(pin.clone()),
                LockOnlyClass::Fixed => restorable.push(pin.clone()),
                LockOnlyClass::Unmovable => {}
            }
        }
        if restorable.is_empty()
            && floating.is_empty()
            && self.pins.iter().any(LockPin::is_lockfile_only)
        {
            return Ok(unsupported(
                Some(self.display_lock_path(&located)),
                UnsupportedReason::LockfileOnlyUpdateUnsupported(Program::Dotnet),
            ));
        }
        // A floating pin is pinned exactly by the run itself, so a withheld target is not a
        // problem for it; an edit or fixed pin cannot be pinned that way.
        if restorable.iter().any(|pin| pin.cooldown_fallback) {
            return Ok(unsupported(
                Some(self.display_lock_path(&located)),
                UnsupportedReason::CooldownFallbackTarget,
            ));
        }
        let has_floating = !floating.is_empty();
        let pins: Vec<LockPin> = restorable.into_iter().chain(floating).collect();
        let session = Session {
            pins: &pins,
            ..*self
        };
        session.restore_pins(&located, &project, has_floating).await
    }

    /// Restores the pinned packages after the float guards, with the exact-pin round trip when
    /// `has_floating`.
    async fn restore_pins(
        &self,
        located: &Path,
        project: &ProjectFileArg,
        has_floating: bool,
    ) -> Result<LockfileOutcome, RegenerationError> {
        let display = self.display_lock_path(located);
        if let Some(outcome) = self.placement_refusal(located) {
            return Ok(outcome);
        }
        let original = deps_core::fs_probe::read_capped_no_follow(
            located,
            deps_core::lockfile::MAX_LOCKFILE_BYTES,
        )
        .ok()
        .flatten()
        .ok_or_else(|| RegenerationError::LockfileUnreadable {
            path: display.shown.clone(),
        })?;
        let lock: serde_json::Value = serde_json::from_slice(&original).map_err(|_| {
            RegenerationError::UnrecognizedLockfile {
                path: display.shown.clone(),
            }
        })?;
        let formatter = self.target.ecosystem.formatter();
        let is_pinned = |name: &str| {
            let normalized = formatter.normalize_package_name(&PackageName::new(name));
            self.pins.iter().any(|pin| pin.normalized == normalized)
        };
        if self.other_requirements_float()? || lock_floats_other(&lock, is_pinned) {
            return Ok(unsupported(
                Some(display),
                UnsupportedReason::OtherFloatingRequirements,
            ));
        }

        let resolve = Invocation::dotnet_restore(self.manifest_dir, project, RestoreMode::Resolve);
        if has_floating {
            let settle =
                Invocation::dotnet_restore(self.manifest_dir, project, RestoreMode::Locked);
            return self
                .run_with_exact_pins(ExactPinRun {
                    tool: Program::Dotnet,
                    lockfile: located,
                    manifest: self.target.manifest_path,
                    install: &resolve,
                    update: None,
                    relax: Relax::RestoreRequested {
                        settle: &settle,
                        original: &original,
                    },
                    siblings: &[],
                })
                .await;
        }

        self.capture(&[located])?;
        self.runner.run(&resolve, self.deadline).await?;
        self.verified(Program::Dotnet, located, PinCheck::SatisfiesInLock)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::{lock_floats_other, requirement_floats};

    fn lock(entries: &str) -> serde_json::Value {
        serde_json::from_str(&format!(
            "{{\"version\": 1, \"dependencies\": {{\"net8.0\": {{{entries}}}}}}}"
        ))
        .expect("lock json")
    }

    fn floats_besides(lock: &serde_json::Value, pinned: &str) -> bool {
        lock_floats_other(lock, |name| name.eq_ignore_ascii_case(pinned))
    }

    #[test]
    fn exact_bracket_pairs_do_not_float() {
        for requirement in ["[1.4.0]", "[1.4.0, 1.4.0]", "[ 1.4.0 ,1.4.0 ]"] {
            assert!(!requirement_floats(requirement), "{requirement}");
        }
        for requirement in ["(1.4.0, 1.4.0]", "[1.4.0, 1.4.0)", "[1.4.0, 1.5.0]"] {
            assert!(requirement_floats(requirement), "{requirement}");
        }
    }

    #[test]
    fn lock_floats_cover_direct_central_transitive_and_project_entries() {
        let direct =
            lock(r#""A": {"type": "Direct", "requested": "[1.*, )", "resolved": "1.0.0"}"#);
        let central = lock(
            r#""A": {"type": "CentralTransitive", "requested": "[1.0.0, 2.0.0)", "resolved": "1.0.0"}"#,
        );
        let project = lock(r#""P": {"type": "Project", "dependencies": {"A": "[1.0.0, 2.0.0)"}}"#);

        assert!(floats_besides(&direct, "other"));
        assert!(floats_besides(&central, "other"));
        assert!(floats_besides(&project, "other"));
    }

    #[test]
    fn lock_floats_ignore_pinned_packages_and_non_floating_requests() {
        let pinned =
            lock(r#""A": {"type": "Direct", "requested": "[1.*, )", "resolved": "1.0.0"}"#);
        let stable = lock(
            r#""B": {"type": "Direct", "requested": "[1.4.0, 1.4.0]", "resolved": "1.4.0"},
               "C": {"type": "Transitive", "resolved": "3.0.0"},
               "D": {"type": "Direct", "requested": "[2.0.0, )", "resolved": "2.0.0"}"#,
        );
        let project_on_pinned =
            lock(r#""P": {"type": "Project", "dependencies": {"a": "[1.0.0, 2.0.0)"}}"#);

        assert!(!floats_besides(&pinned, "a"));
        assert!(!floats_besides(&stable, "a"));
        assert!(!floats_besides(&project_on_pinned, "a"));
    }

    #[test]
    fn floating_and_bounded_requirements_float() {
        for requirement in [
            "2.*",
            "*",
            "1.0.*-*",
            "[1.0,2.0)",
            "(1.0, 2.0]",
            "[1.0, 1.5]",
        ] {
            assert!(requirement_floats(requirement), "{requirement}");
        }
    }

    #[test]
    fn plain_exact_and_open_floor_requirements_stay_put() {
        for requirement in ["13.0.1", "1.0.0-beta.2", "[1.0.0]", "[1.0, )", "(1.0,)", ""] {
            assert!(!requirement_floats(requirement), "{requirement:?}");
        }
    }
}
