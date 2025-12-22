#![warn(clippy::all, clippy::pedantic)]

use std::fs;
use zed_extension_api::{self as zed, LanguageServerId, Result};

const BINARY_NAME: &str = "deps-lsp";
const GITHUB_REPO: &str = "bug-ops/deps-lsp";

struct DepsExtension {
    cached_binary_path: Option<String>,
}

impl DepsExtension {
    /// Returns the path to the `deps-lsp` binary.
    ///
    /// Lookup order:
    /// 1. Cached path from previous invocation
    /// 2. System PATH via `worktree.which()`
    /// 3. Download from GitHub releases
    fn language_server_binary_path(
        &mut self,
        language_server_id: &LanguageServerId,
        worktree: &zed::Worktree,
    ) -> Result<String> {
        // Check cached path
        if let Some(path) = &self.cached_binary_path
            && fs::metadata(path).is_ok_and(|stat| stat.is_file())
        {
            return Ok(path.clone());
        }

        // Check system PATH
        if let Some(path) = worktree.which(BINARY_NAME) {
            return Ok(path);
        }

        // Download from GitHub releases
        self.download_binary(language_server_id)
    }

    fn download_binary(&mut self, language_server_id: &LanguageServerId) -> Result<String> {
        zed::set_language_server_installation_status(
            language_server_id,
            &zed::LanguageServerInstallationStatus::CheckingForUpdate,
        );

        let release = zed::latest_github_release(
            GITHUB_REPO,
            zed::GithubReleaseOptions {
                require_assets: true,
                pre_release: false,
            },
        )?;

        let (platform, arch) = zed::current_platform();

        let asset_name = format!(
            "{BINARY_NAME}-{arch}-{os}",
            arch = match arch {
                zed::Architecture::Aarch64 => "aarch64",
                zed::Architecture::X86 => "x86",
                zed::Architecture::X8664 => "x86_64",
            },
            os = match platform {
                zed::Os::Mac => "apple-darwin.tar.gz",
                zed::Os::Linux => "unknown-linux-gnu.tar.gz",
                zed::Os::Windows => "pc-windows-msvc.zip",
            },
        );

        let asset = release
            .assets
            .iter()
            .find(|asset| asset.name == asset_name)
            .ok_or_else(|| format!("no asset found matching {asset_name:?}"))?;

        let version_dir = format!("{BINARY_NAME}-{}", release.version);

        fs::create_dir_all(&version_dir)
            .map_err(|err| format!("failed to create directory '{version_dir}': {err}"))?;

        let binary_path = format!(
            "{version_dir}/{bin_name}",
            bin_name = match platform {
                zed::Os::Windows => format!("{BINARY_NAME}.exe"),
                zed::Os::Mac | zed::Os::Linux => BINARY_NAME.to_string(),
            }
        );

        let file_type = match platform {
            zed::Os::Windows => zed::DownloadedFileType::Zip,
            zed::Os::Mac | zed::Os::Linux => zed::DownloadedFileType::GzipTar,
        };

        // Download if binary doesn't exist
        if !fs::metadata(&binary_path).is_ok_and(|stat| stat.is_file()) {
            zed::set_language_server_installation_status(
                language_server_id,
                &zed::LanguageServerInstallationStatus::Downloading,
            );

            zed::download_file(&asset.download_url, &version_dir, file_type)
                .map_err(|err| format!("failed to download file: {err}"))?;

            zed::make_file_executable(&binary_path)?;

            // Clean up old versions
            Self::cleanup_old_versions(&version_dir);
        }

        self.cached_binary_path = Some(binary_path.clone());
        Ok(binary_path)
    }

    fn cleanup_old_versions(current_version_dir: &str) {
        let Ok(entries) = fs::read_dir(".") else {
            return;
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };

            // Remove old deps-lsp-* directories
            if name_str.starts_with(BINARY_NAME) && name_str != current_version_dir {
                fs::remove_dir_all(entry.path()).ok();
            }
        }
    }
}

impl zed::Extension for DepsExtension {
    fn new() -> Self {
        Self {
            cached_binary_path: None,
        }
    }

    fn language_server_command(
        &mut self,
        language_server_id: &LanguageServerId,
        worktree: &zed::Worktree,
    ) -> Result<zed::Command> {
        Ok(zed::Command {
            command: self.language_server_binary_path(language_server_id, worktree)?,
            args: vec!["--stdio".into()],
            env: Vec::default(),
        })
    }
}

zed::register_extension!(DepsExtension);
