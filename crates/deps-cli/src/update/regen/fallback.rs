//! Manifest preservation (#2091) and cooldown-fallback pinning (#2077).
//!
//! A cooldown-fallback target sits below the newest release, so range resolution would pick the
//! withheld version. These tools pin it by writing an exact requirement into the manifest, running
//! the tool's install form so the lock file moves to it, then putting the manifest back and
//! running the install form again so the lock file agrees with the original requirement.

use std::path::{Path, PathBuf};

use deps_core::NormalizeName;
use deps_core::edit::{ManifestEdit, apply_edits};

use super::{
    Invocation, LockfileOutcome, PinCheck, Program, RegenerationError, Session, UnsupportedReason,
    unsafe_argument, unsupported,
};

/// A manifest as it was before the first writing spawn.
pub(super) struct CapturedManifest {
    path: PathBuf,
    display: PathBuf,
    bytes: Vec<u8>,
}

/// Writes the captured manifest back when dropped while armed, so a run abandoned between the
/// exact-pin write and the write-back (SIGINT under `--open-pr` drops the whole future) cannot
/// leave the exact pins behind.
struct ManifestGuard<'a> {
    manifest: &'a CapturedManifest,
    armed: bool,
}

impl Drop for ManifestGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Err(error) =
            deps_core::fs_probe::write_atomic_bytes(&self.manifest.path, &self.manifest.bytes)
        {
            tracing::warn!(%error, "could not put the manifest back after an abandoned run");
        }
    }
}

/// The tool forms of one cooldown-fallback run.
pub(super) struct ExactPinRun<'a> {
    pub(super) tool: Program,
    pub(super) lockfile: &'a Path,
    /// The manifest the plan edited.
    pub(super) manifest: &'a Path,
    /// Re-resolves the lock file against the manifest.
    pub(super) install: &'a Invocation,
    /// Moves lockfile-only pins that are not cooldown fallbacks, when there are any.
    pub(super) update: Option<&'a Invocation>,
}

impl Session<'_> {
    pub(super) fn has_fallback_pins(&self) -> bool {
        self.pins.iter().any(|pin| pin.cooldown_fallback)
    }

    /// Each lockfile-only pin's package name that is not a cooldown fallback, validated by
    /// `parse`.
    pub(super) fn update_only_args<T>(
        &self,
        parse: impl Fn(&str) -> Result<T, super::command::UnsafeArgument>,
    ) -> Result<Vec<T>, RegenerationError> {
        self.pins
            .iter()
            .filter(|pin| pin.is_lockfile_only() && !pin.cooldown_fallback)
            .map(|pin| parse(pin.package.as_str()).map_err(|_| unsafe_argument(pin)))
            .collect()
    }

    /// Reads `path` as it is now, for [`Self::restore_formatting`].
    ///
    /// # Errors
    ///
    /// [`RegenerationError::SnapshotFailed`] when it is unreadable, a symlink or oversized.
    pub(super) fn read_manifest(&self, path: &Path) -> Result<CapturedManifest, RegenerationError> {
        let display = self.display_lock_path(path).shown;
        deps_core::fs_probe::read_capped_no_follow(path, crate::MAX_MANIFEST_FILE_SIZE)
            .ok()
            .flatten()
            .map(|bytes| CapturedManifest {
                path: path.to_path_buf(),
                display: display.clone(),
                bytes,
            })
            .ok_or(RegenerationError::SnapshotFailed { path: display })
    }

    /// Puts every captured manifest back byte for byte when the tool only re-serialized it.
    ///
    /// # Errors
    ///
    /// [`RegenerationError::ManifestChanged`] for a manifest that is gone or whose JSON content
    /// differs (the caller's snapshot restore then puts it back), and
    /// [`RegenerationError::RestoreFailed`] when the original bytes cannot be written.
    pub(super) fn restore_formatting<'a>(
        &self,
        captured: impl IntoIterator<Item = &'a CapturedManifest>,
    ) -> Result<(), RegenerationError> {
        for manifest in captured {
            let changed = |display: &Path| RegenerationError::ManifestChanged {
                path: display.to_path_buf(),
            };
            let current = deps_core::fs_probe::read_capped_no_follow(
                &manifest.path,
                crate::MAX_MANIFEST_FILE_SIZE,
            )
            .ok()
            .flatten()
            .ok_or_else(|| changed(&manifest.display))?;
            if current == manifest.bytes {
                continue;
            }
            if !same_json(&current, &manifest.bytes) {
                return Err(changed(&manifest.display));
            }
            deps_core::fs_probe::write_atomic_bytes(&manifest.path, &manifest.bytes).map_err(
                |source| RegenerationError::RestoreFailed {
                    cause: Box::new(changed(&manifest.display)),
                    path: manifest.display.clone(),
                    source,
                },
            )?;
        }
        Ok(())
    }

    /// Pins every cooldown-fallback target exactly for one run of the tool's install form.
    ///
    /// Ends as `Unsupported(CooldownFallbackTarget)` before any write when a fallback package
    /// has no single declaration to pin or its ecosystem has no exact-pin rendering.
    ///
    /// # Errors
    ///
    /// Any [`RegenerationError`] of the spawned tool, the verification, or a manifest the tool
    /// changed beyond its formatting.
    pub(super) async fn run_with_exact_pins(
        &self,
        run: ExactPinRun<'_>,
    ) -> Result<LockfileOutcome, RegenerationError> {
        self.capture(&[run.lockfile, run.manifest])?;
        let original = self.read_manifest(run.manifest)?;

        let Some(pinned) = self.exact_pinned_text(&original.bytes)? else {
            return Ok(unsupported(
                Some(self.display_lock_path(run.lockfile)),
                UnsupportedReason::CooldownFallbackTarget,
            ));
        };

        let mut guard = ManifestGuard {
            manifest: &original,
            armed: true,
        };
        deps_core::fs_probe::write_atomic_bytes(&original.path, pinned.as_bytes()).map_err(
            |_| RegenerationError::ManifestChanged {
                path: original.display.clone(),
            },
        )?;
        self.runner.run(run.install, self.deadline).await?;
        if let Some(update) = run.update {
            self.runner.run(update, self.deadline).await?;
        }
        deps_core::fs_probe::write_atomic_bytes(&original.path, &original.bytes).map_err(
            |source| RegenerationError::RestoreFailed {
                cause: Box::new(RegenerationError::ManifestChanged {
                    path: original.display.clone(),
                }),
                path: original.display.clone(),
                source,
            },
        )?;
        self.runner.run(run.install, self.deadline).await?;
        self.restore_formatting(std::iter::once(&original))?;
        guard.armed = false;
        self.verified(run.tool, run.lockfile, PinCheck::SatisfiesInLock)
            .await
    }

    /// The manifest text with every cooldown-fallback package's single declaration rewritten to
    /// an exact pin; `None` when one has no declaration, several, or no exact rendering.
    fn exact_pinned_text(&self, bytes: &[u8]) -> Result<Option<String>, RegenerationError> {
        let reparse_failed = || RegenerationError::ManifestReparseFailed {
            path: self.target.display_path.to_path_buf(),
        };
        let content = std::str::from_utf8(bytes).map_err(|_| reparse_failed())?;
        let parsed = deps_core::ecosystem::parse_manifest_now(
            self.target.ecosystem,
            content,
            self.target.uri,
        )
        .ok_or_else(reparse_failed)?;
        let formatter = self.target.ecosystem.formatter();

        let mut edits = Vec::new();
        for pin in self.pins.iter().filter(|pin| pin.cooldown_fallback) {
            if !pin.target.as_str().chars().all(is_version_char) {
                return Err(unsafe_argument(pin));
            }
            let declarations: Vec<_> = parsed
                .dependencies()
                .into_iter()
                .filter(|dep| formatter.normalize_package_name(dep.name()) == pin.normalized)
                .collect();
            let [declaration] = declarations.as_slice() else {
                return Ok(None);
            };
            let (Some(current), Some(range)) = (
                declaration.version_requirement(),
                declaration.version_range(),
            ) else {
                return Ok(None);
            };
            let Some(new_text) =
                formatter.format_version_exact_pin_replacing(&pin.target, current.as_str())
            else {
                return Ok(None);
            };
            edits.push(ManifestEdit { range, new_text });
        }
        Ok(Some(apply_edits(content, &edits)))
    }
}

/// A character a version may carry into a manifest string without any quoting concern.
const fn is_version_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '_')
}

/// Whether both texts are JSON documents with equal content.
fn same_json(a: &[u8], b: &[u8]) -> bool {
    match (
        serde_json::from_slice::<serde_json::Value>(a),
        serde_json::from_slice::<serde_json::Value>(b),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn captured(path: &Path) -> CapturedManifest {
        CapturedManifest {
            path: path.to_path_buf(),
            display: PathBuf::from("package.json"),
            bytes: b"original".to_vec(),
        }
    }

    #[test]
    fn an_armed_guard_writes_the_captured_bytes_back_on_drop() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("package.json");
        std::fs::write(&path, b"exact pins").expect("write");
        let manifest = captured(&path);

        drop(ManifestGuard {
            manifest: &manifest,
            armed: true,
        });

        assert_eq!(std::fs::read(&path).expect("read"), b"original");
    }

    #[test]
    fn a_disarmed_guard_leaves_the_manifest_alone() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("package.json");
        std::fs::write(&path, b"final").expect("write");
        let manifest = captured(&path);

        drop(ManifestGuard {
            manifest: &manifest,
            armed: false,
        });

        assert_eq!(std::fs::read(&path).expect("read"), b"final");
    }

    #[test]
    fn json_with_equal_content_is_the_same_whatever_its_formatting() {
        assert!(same_json(b"{\"a\":1}", b"{\n  \"a\": 1\n}\n"));
        assert!(!same_json(b"{\"a\":1}", b"{\"a\":2}"));
        assert!(!same_json(b"not json", b"not json"));
    }

    #[test]
    fn version_characters_exclude_quotes_and_whitespace() {
        assert!("1.2.3-beta.1+build_5".chars().all(is_version_char));
        for bad in ["1\"2", "1 2", "1\n2", "1@2", "1/2"] {
            assert!(!bad.chars().all(is_version_char), "{bad}");
        }
    }
}
