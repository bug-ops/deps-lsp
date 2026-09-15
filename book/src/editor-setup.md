# Editor Setup

`deps-lsp` speaks standard LSP over stdio, so any LSP-capable editor can use it. The
[README](https://github.com/bug-ops/deps-lsp#readme) covers the quickest way to get it running in
Zed; this page has the full per-editor reference, including editors with no first-party
extension.

> **Note:** Inlay hints, code lens, and (in some editors) inline diagnostics are off by default at
> the *editor* level, independent of `deps-lsp`'s own
> [`initialization_options`](configuration.md). The server always advertises support for all
> three — each section below covers the editor-side toggle needed to actually see them.

## Zed

Install the **Deps** extension from the Zed Extensions marketplace. Ruby support is enabled for
`Gemfile` files.

Enable inlay hints, code lens, and (optionally) inline diagnostics in Zed settings:

```json
{
  "inlay_hints": {
    "enabled": true
  },
  "code_lens": "on",
  "diagnostics": {
    "inline": {
      "enabled": true
    }
  }
}
```

`code_lens` accepts `"on"`, `"off"` (default), or `"menu"`, and is required for the "Update N
outdated dependencies" lens to appear. `diagnostics.inline` is optional — diagnostics already show
in the gutter and Problems panel without it; this additionally renders `deps-lsp`'s short one-line
messages inline next to each dependency.

## Neovim

```lua
require('lspconfig').deps_lsp.setup({
  cmd = { "deps-lsp", "--stdio" },
  filetypes = { "toml", "json", "gomod", "ruby", "yaml", "xml", "swift", "php", "requirements" },
})

-- Enable inlay hints (Neovim 0.10+)
vim.lsp.inlay_hint.enable(true)
```

For older Neovim versions, use [nvim-lsp-inlayhints](https://github.com/lvimuser/lsp-inlayhints.nvim).

**Code lens** is not refreshed or rendered automatically by Neovim's built-in client — wire it up
via an `LspAttach` autocommand:

```lua
vim.api.nvim_create_autocmd("LspAttach", {
  callback = function(args)
    local client = vim.lsp.get_client_by_id(args.data.client_id)
    if client and client:supports_method("textDocument/codeLens") then
      vim.lsp.codelens.refresh({ bufnr = args.buf })
      vim.api.nvim_create_autocmd({ "BufEnter", "CursorHold", "InsertLeave" }, {
        buffer = args.buf,
        callback = function() vim.lsp.codelens.refresh({ bufnr = args.buf }) end,
      })
    end
  end,
})

vim.keymap.set("n", "<leader>cl", vim.lsp.codelens.run, { desc = "Run code lens" })
```

> **Warning:** Neovim 0.11 changed diagnostic virtual text (inline diagnostics) from opt-out to
> opt-in. On 0.11+, run `vim.diagnostic.config({ virtual_text = true })` if `deps-lsp`'s warnings
> aren't appearing inline — on 0.10 and earlier this was already the default.

## Helix

```toml
# ~/.config/helix/languages.toml
[[language]]
name = "toml"
language-servers = ["deps-lsp"]

[[language]]
name = "json"
language-servers = ["deps-lsp"]

[language-server.deps-lsp]
command = "deps-lsp"
args = ["--stdio"]
```

Enable inlay hints in Helix config:

```toml
# ~/.config/helix/config.toml
[editor.lsp]
display-inlay-hints = true
```

Diagnostics render inline by default with no configuration needed.

> **Note:** Helix does not implement `textDocument/codeLens` — the "Update N outdated
> dependencies" batch action is unavailable there; use the per-dependency code action
> (`Cmd+.`/`Ctrl+.` equivalent) instead.

## VS Code

Install an LSP client extension and configure `deps-lsp`. Enable inlay hints:

```json
{
  "editor.inlayHints.enabled": "on"
}
```

`editor.codeLens` is `true` by default in VS Code itself, so `deps-lsp`'s code lens should appear
automatically — provided your chosen generic LSP client extension forwards the `codeLens`
capability (most do; check its documentation if the lens doesn't show up). Diagnostics render as
squiggles plus entries in the Problems panel by default; for an always-visible inline message next
to each dependency, install the third-party
[Error Lens](https://marketplace.visualstudio.com/items?itemName=usernamehw.errorlens) extension.

## Emacs (`eglot`)

```elisp
(with-eval-after-load 'eglot
  (add-to-list 'eglot-server-programs
               '((conf-toml-mode yaml-mode json-mode) . ("deps-lsp" "--stdio"))))
```

> **Note:** `eglot` manages one server per buffer by default, so running `deps-lsp` alongside a
> primary language server for the same buffer (e.g. `rust-analyzer` on `Cargo.toml`) needs
> `eglot`'s multi-server support rather than this snippet alone.

## Emacs (`lsp-mode`)

A first-party `lsp-mode` client is tracked in
[#712](https://github.com/bug-ops/deps-lsp/issues/712); until it ships, register `deps-lsp`
manually as an add-on server:

```elisp
(with-eval-after-load 'lsp-mode
  (lsp-register-client
   (make-lsp-client
    :new-connection (lsp-stdio-connection '("deps-lsp" "--stdio"))
    :activation-fn (lsp-activate-on 'toml-mode 'json-mode 'yaml-mode)
    :add-on? t
    :server-id 'deps-lsp)))
```

`:add-on? t` is required so `deps-lsp` runs in addition to, not instead of, the buffer's primary
server.

## Sublime Text (LSP package)

```json
{
  "clients": {
    "deps-lsp": {
      "enabled": true,
      "command": ["deps-lsp", "--stdio"],
      "selector": "source.toml | source.json | source.yaml"
    }
  }
}
```

Add to `LSP.sublime-settings`. The `sublimelsp/LSP` package runs multiple clients per view, so
this coexists with any primary language server already configured for the same selector.

## Kate

```json
{
  "servers": {
    "deps-lsp": {
      "command": ["deps-lsp", "--stdio"],
      "highlightingModeRegex": "^(TOML|JSON|YAML)$"
    }
  }
}
```

Add to Kate's built-in LSP Client plugin settings (Settings → Configure Kate → LSP Client → User
Server Settings). Kate supports multiple LSP servers per document, so this runs alongside any
primary language server already registered for the same syntax.

## coc.nvim

```json
{
  "languageserver": {
    "deps-lsp": {
      "command": "deps-lsp",
      "args": ["--stdio"],
      "filetypes": ["toml", "json", "yaml", "gomod", "ruby", "xml", "swift", "php", "requirements"]
    }
  }
}
```

Add to `coc-settings.json` (`:CocConfig`). `coc.nvim` attaches every configured `languageserver`
entry whose `filetypes` match, so this coexists with a primary language server for the same
filetype.
