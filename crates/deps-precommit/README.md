# deps-precommit

pre-commit support for [deps-lsp](https://github.com/bug-ops/deps-lsp): hover, diagnostics, code
actions and completion for the `rev:` of each GitHub `repos:` entry in `.pre-commit-config.yaml`
and `.pre-commit-config.yml`.

This crate is constructor-only. The pre-commit ecosystem is the pre-commit flavor of
`deps_github_actions::GithubActionsEcosystem`: both resolve `owner/repo` pins against the same
GitHub tags registry, so the parser, registry and diagnostics live in `deps-github-actions`.

```rust,ignore
let ecosystem = deps_precommit::standalone(cache);
```

> [!IMPORTANT]
> Requires Rust 1.98 or later.
