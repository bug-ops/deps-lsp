//! Regeneration for NuGet `packages.lock.json` (#2084).

use deps_core::NormalizeName;

use super::command::dotnet::ProjectFileArg;
use super::lockers::Located;
use super::{
    Invocation, LockfileOutcome, NotApplicableReason, PinCheck, Program, RegenerationError,
    Session, UnsupportedReason, unsupported,
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

/// Whether restore may move a package of this requirement on its own: a floating `*` or a range
/// with an upper bound. A plain version or an open-ended floor resolves to the same lowest
/// version again, so it stays put.
fn requirement_floats(requirement: &str) -> bool {
    let requirement = requirement.trim();
    if requirement.contains('*') {
        return true;
    }
    requirement.starts_with(['[', '('])
        && requirement
            .split_once(',')
            .is_some_and(|(_, upper)| !upper.trim_end_matches([')', ']']).trim().is_empty())
}

impl Session<'_> {
    /// Whether a dependency other than the pins carries a requirement restore would re-resolve.
    ///
    /// Restore re-resolves every floating dependency of a project once any package changed
    /// (verified: `Serilog 2.*` locked at 2.10.0 moved to 2.12.0 in an unrelated edit), which
    /// bypasses the cooldown for that package.
    fn other_requirements_float(&self) -> Result<bool, RegenerationError> {
        let reparse_failed = || RegenerationError::ManifestReparseFailed {
            path: self.target.display_path.to_path_buf(),
        };
        let content = deps_core::fs_probe::read_to_string_capped_no_follow(
            self.target.manifest_path,
            crate::MAX_MANIFEST_FILE_SIZE,
        )
        .ok()
        .flatten()
        .ok_or_else(reparse_failed)?;
        let parsed = deps_core::ecosystem::parse_manifest_now(
            self.target.ecosystem,
            &content,
            self.target.uri,
        )
        .ok_or_else(reparse_failed)?;
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

    /// `dotnet restore <project> --use-lock-file --no-dependencies` after a manifest edit.
    ///
    /// Lock-only pins are refused as a whole: NuGet resolves the lowest applicable version, so
    /// no restore form moves a locked package forward except `--force-evaluate`, which
    /// re-resolves every floating dependency (cooldown bypass, unrelated churn).
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
        if self.pins.iter().any(super::LockPin::is_lockfile_only) {
            return Ok(unsupported(
                Some(self.display_lock_path(&located)),
                UnsupportedReason::LockfileOnlyUpdateUnsupported(Program::Dotnet),
            ));
        }
        if let Some(outcome) = self.cooldown_refusal(&located) {
            return Ok(outcome);
        }
        if self.other_requirements_float()? {
            return Ok(unsupported(
                Some(self.display_lock_path(&located)),
                UnsupportedReason::OtherFloatingRequirements,
            ));
        }
        if let Some(outcome) = self.placement_refusal(&located) {
            return Ok(outcome);
        }

        self.capture(&[&located])?;
        self.runner
            .run(
                &Invocation::dotnet_restore(self.manifest_dir, &project),
                self.deadline,
            )
            .await?;
        self.verified(Program::Dotnet, &located, PinCheck::SatisfiesInLock)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::requirement_floats;

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
