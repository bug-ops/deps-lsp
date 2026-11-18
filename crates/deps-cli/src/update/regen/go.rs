//! Regeneration for Go modules, including vendored dependencies.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use deps_core::ConcreteVersion;

use super::command::{ArgComponent, GoModuleMode, GoWork};
use super::{
    Companion, Invocation, LockfileOutcome, NotApplicableReason, PinCheck, Program,
    RegenerationError, Session, UnsupportedReason, arg_pair, unsupported,
};

/// Distinguishes the scratch directories of one process.
static SCRATCH_SEQUENCE: AtomicU64 = AtomicU64::new(0);

const SCRATCH_ATTEMPTS: u32 = 8;

/// A scratch directory that is removed on drop unless the run moved it into place.
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    /// Exclusively creates an empty directory inside `parent`.
    fn create(parent: &Path) -> std::io::Result<Self> {
        let mut last = std::io::Error::from(std::io::ErrorKind::AlreadyExists);
        for _ in 0..SCRATCH_ATTEMPTS {
            let id = SCRATCH_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(".deps-cli-vendor-{}-{id}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => last = error,
                Err(error) => return Err(error),
            }
        }
        Err(last)
    }

    fn sibling(&self, suffix: &str) -> PathBuf {
        let mut name = self.path.file_name().unwrap_or_default().to_owned();
        name.push(suffix);
        self.path.with_file_name(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// The version `modules.txt` records for `module`: its first `# <module> <version>` line, with
/// or without a `=>` replacement.
fn vendored_version<'a>(modules_txt: &'a str, module: &str) -> Option<&'a str> {
    modules_txt.lines().find_map(|line| {
        let mut fields = line.strip_prefix("# ")?.split_whitespace();
        (fields.next()? == module).then(|| fields.next()).flatten()
    })
}

impl Session<'_> {
    pub(super) async fn go(&self) -> Result<LockfileOutcome, RegenerationError> {
        let vendor = self.manifest_dir.join("vendor");
        let vendored = vendor.join("modules.txt").is_file();
        if vendored
            && let Some(outcome) = self
                .vendor_refusal(&vendor)
                .or_else(|| self.placement_refusal(&vendor.join("modules.txt")))
        {
            return Ok(outcome);
        }
        let workspace = self
            .runner
            .probe(&Invocation::go_env_gowork(self.manifest_dir), self.deadline)
            .await?;
        let work = if workspace.is_empty() || workspace == "off" {
            GoWork::Inherit
        } else {
            GoWork::Off
        };
        let owned = self.manifest_dir.join("go.sum");
        if !owned.is_file() {
            return Ok(LockfileOutcome::NotApplicable(
                NotApplicableReason::NoLockfilePresent,
            ));
        }
        if let Some(outcome) = self.ownership_refusal(&owned).await? {
            return Ok(outcome);
        }

        let go_mod = self.manifest_dir.join("go.mod");
        if let Some(outcome) = self.placement_refusal(&go_mod) {
            return Ok(outcome);
        }

        let modules = self
            .pins
            .iter()
            .map(arg_pair)
            .collect::<Result<Vec<_>, _>>()?;
        self.capture(&[&go_mod, &owned])?;
        let mode = if vendored {
            GoModuleMode::ModuleCache
        } else {
            GoModuleMode::Inherit
        };
        self.runner
            .run(
                &Invocation::go_get(self.manifest_dir, &modules, work, mode),
                self.deadline,
            )
            .await?;
        if !vendored {
            return self
                .verified(Program::Go, &owned, PinCheck::ExactInLock)
                .await;
        }
        let lockfile = self.display_lock_path(&owned);
        let pins = self
            .refresh_vendor(&vendor, &lockfile, &modules, work)
            .await?;
        Ok(LockfileOutcome::Regenerated {
            lockfile,
            tool: Program::Go,
            pins,
            companions: vec![Companion::Tree(vendor)],
        })
    }

    /// Refuses a vendor tree that is a symlink, not a directory, or outside the scope.
    fn vendor_refusal(&self, vendor: &Path) -> Option<LockfileOutcome> {
        let plain =
            std::fs::symlink_metadata(vendor).is_ok_and(|metadata| metadata.file_type().is_dir());
        let reason = if !plain {
            UnsupportedReason::LockfileSymlink
        } else if !self.within_scope(vendor) {
            UnsupportedReason::LockfileOutsideRepository
        } else {
            return None;
        };
        Some(unsupported(None, reason))
    }

    /// Rebuilds `vendor` from the updated `go.mod`: vendors into a scratch directory, verifies
    /// it, then swaps it in with synchronous renames. The pin reports come from the verification
    /// before the swap, so nothing awaits (and nothing can fail or be cancelled) once the new
    /// tree is in place.
    async fn refresh_vendor(
        &self,
        vendor: &Path,
        lockfile: &super::DisplayLockPath,
        modules: &[(ArgComponent, ArgComponent)],
        work: GoWork,
    ) -> Result<Vec<super::PinReport>, RegenerationError> {
        let io_failed = |source| RegenerationError::Spawn {
            program: Program::Go,
            source,
        };
        let scratch = Scratch::create(self.manifest_dir).map_err(io_failed)?;
        self.runner
            .run(
                &Invocation::go_mod_vendor(
                    self.manifest_dir,
                    &scratch.path,
                    work,
                    GoModuleMode::ModuleCache,
                ),
                self.deadline,
            )
            .await?;

        // Both checks precede the swap, so a mismatch leaves the old vendor tree in place.
        let pins = self.verify_pins(PinCheck::ExactInLock, lockfile).await?;
        self.verify_vendored(&scratch.path.join("modules.txt"), modules)?;

        let old = scratch.sibling(".old");
        std::fs::rename(vendor, &old).map_err(io_failed)?;
        if let Err(source) = std::fs::rename(&scratch.path, vendor) {
            if let Err(error) = std::fs::rename(&old, vendor) {
                tracing::warn!(%error, path = %old.display(), "could not put the previous vendor tree back");
            }
            return Err(io_failed(source));
        }
        if let Err(error) = std::fs::remove_dir_all(&old) {
            tracing::warn!(%error, path = %old.display(), "could not remove the previous vendor tree");
        }
        Ok(pins)
    }

    fn verify_vendored(
        &self,
        modules_txt: &Path,
        modules: &[(ArgComponent, ArgComponent)],
    ) -> Result<(), RegenerationError> {
        let content = deps_core::fs_probe::read_to_string_capped_no_follow(
            modules_txt,
            deps_core::lockfile::MAX_LOCKFILE_BYTES,
        )
        .ok()
        .flatten()
        .ok_or_else(|| RegenerationError::LockfileUnreadable {
            path: self.display_lock_path(modules_txt).shown,
        })?;
        for (pin, (module, version)) in self.pins.iter().zip(modules) {
            let found = vendored_version(&content, module.as_str());
            if found != Some(version.as_str()) {
                return Err(RegenerationError::VersionMismatch {
                    package: pin.package.clone(),
                    expected: pin.target.clone(),
                    found: found.map(ConcreteVersion::from),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::vendored_version;

    const MODULES: &str = "# golang.org/x/text v0.31.0\n## explicit; go 1.24\ngolang.org/x/text/unicode\n# example.com/dep v1.0.0 => ../dep\n## explicit; go 1.21\nexample.com/dep\n";

    #[test]
    fn vendored_version_reads_plain_and_replaced_modules() {
        assert_eq!(
            vendored_version(MODULES, "golang.org/x/text"),
            Some("v0.31.0")
        );
        assert_eq!(vendored_version(MODULES, "example.com/dep"), Some("v1.0.0"));
    }

    #[test]
    fn vendored_version_ignores_package_lines_and_prefix_matches() {
        assert_eq!(vendored_version(MODULES, "golang.org/x"), None);
        assert_eq!(vendored_version(MODULES, "golang.org/x/text/unicode"), None);
    }
}
