use zed_extension_api::{self as zed, Result};

struct DepsExtension {
    #[allow(dead_code)] // Used for binary caching
    cached_binary_path: Option<String>,
}

impl zed::Extension for DepsExtension {
    fn new() -> Self {
        Self {
            cached_binary_path: None,
        }
    }

    fn language_server_command(
        &mut self,
        _language_server_id: &zed::LanguageServerId,
        _worktree: &zed::Worktree,
    ) -> Result<zed::Command> {
        let binary_path = self.ensure_binary_installed()?;

        Ok(zed::Command {
            command: binary_path,
            args: vec!["--stdio".into()],
            env: Default::default(),
        })
    }
}

impl DepsExtension {
    fn ensure_binary_installed(&mut self) -> Result<String> {
        // TODO: implement binary download from GitHub releases
        Err(
            "deps-lsp binary not found. Please install manually with: cargo install deps-lsp"
                .into(),
        )
    }
}

zed::register_extension!(DepsExtension);
