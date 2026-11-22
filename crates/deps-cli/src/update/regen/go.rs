//! Regeneration for Go modules, including vendored dependencies.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use deps_core::ConcreteVersion;

use super::command::{ArgComponent, GoModuleMode, GoWork};
use super::{
    Companion, Invocation, IoOperation, LockfileOutcome, NotApplicableReason, PinCheck, Program,
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

/// `path`, or `.` when the manifest sits at the repository root and its display directory is
/// empty, so an error message never names an empty path.
fn non_empty_or_dot(path: PathBuf) -> PathBuf {
    if path.is_empty() {
        PathBuf::from(".")
    } else {
        path
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
        let vendor_shown = self.display_lock_path(vendor).shown;
        let io_failed = |operation, path: &Path| {
            let path = path.to_path_buf();
            move |source| RegenerationError::Io {
                operation,
                path,
                source,
            }
        };
        let manifest_dir_shown = non_empty_or_dot(self.display_lock_path(self.manifest_dir).shown);
        let scratch = Scratch::create(self.manifest_dir).map_err(io_failed(
            IoOperation::CreateScratchDirectory,
            &manifest_dir_shown,
        ))?;
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
        swap_vendor(vendor, &scratch.path, &old, |from, to| {
            std::fs::rename(from, to)
        })
        .map_err(|failure| io_failed(failure.operation, &vendor_shown)(failure.source))?;
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

/// The rename that failed while swapping a refreshed vendor tree in.
struct VendorSwapFailure {
    operation: IoOperation,
    source: std::io::Error,
}

/// Moves `vendor` to `old`, then `scratch` to `vendor`; when the second move fails the first is
/// undone so the previous tree stays in place. `rename` is the file-system seam.
fn swap_vendor(
    vendor: &Path,
    scratch: &Path,
    old: &Path,
    mut rename: impl FnMut(&Path, &Path) -> std::io::Result<()>,
) -> Result<(), VendorSwapFailure> {
    rename(vendor, old).map_err(|source| VendorSwapFailure {
        operation: IoOperation::MoveVendorAside,
        source,
    })?;
    if let Err(source) = rename(scratch, vendor) {
        if let Err(error) = rename(old, vendor) {
            tracing::warn!(%error, path = %old.display(), "could not put the previous vendor tree back");
        }
        return Err(VendorSwapFailure {
            operation: IoOperation::MoveVendorIntoPlace,
            source,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{IoOperation, non_empty_or_dot, swap_vendor, vendored_version};

    const MODULES: &str = "# golang.org/x/text v0.31.0\n## explicit; go 1.24\ngolang.org/x/text/unicode\n# example.com/dep v1.0.0 => ../dep\n## explicit; go 1.21\nexample.com/dep\n";

    #[test]
    fn an_empty_display_directory_is_shown_as_dot() {
        assert_eq!(non_empty_or_dot(PathBuf::new()), PathBuf::from("."));
        assert_eq!(non_empty_or_dot(PathBuf::from("sub")), PathBuf::from("sub"));
    }

    #[test]
    fn a_failed_second_rename_reports_the_move_into_place_and_restores_the_old_tree() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (vendor, scratch, old) = (
            dir.path().join("vendor"),
            dir.path().join("scratch"),
            dir.path().join("old"),
        );
        std::fs::create_dir(&vendor).expect("vendor");
        std::fs::write(vendor.join("marker"), "previous").expect("marker");
        std::fs::create_dir(&scratch).expect("scratch");
        let mut calls = 0;

        let failure = swap_vendor(&vendor, &scratch, &old, |from, to| {
            calls += 1;
            if calls == 2 {
                Err(std::io::Error::other("denied"))
            } else {
                std::fs::rename(from, to)
            }
        })
        .expect_err("the second rename fails");

        assert_eq!(failure.operation, IoOperation::MoveVendorIntoPlace);
        assert_eq!(calls, 3, "the aside move is undone");
        assert_eq!(
            std::fs::read_to_string(vendor.join("marker")).expect("marker"),
            "previous"
        );
        assert!(
            scratch.exists(),
            "the refreshed tree stays in its scratch directory"
        );
    }

    #[test]
    fn a_failed_first_rename_reports_the_move_aside() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (vendor, scratch, old) = (
            dir.path().join("vendor"),
            dir.path().join("scratch"),
            dir.path().join("old"),
        );

        let failure = swap_vendor(&vendor, &scratch, &old, |_, _| {
            Err(std::io::Error::other("denied"))
        })
        .expect_err("the first rename fails");

        assert_eq!(failure.operation, IoOperation::MoveVendorAside);
    }

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
