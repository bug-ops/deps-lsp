# pre-commit

## Basics

`.pre-commit-config.yaml` and `.pre-commit-config.yml` declare [pre-commit](https://pre-commit.com)
hooks under `repos:`. Each entry pins a hook repository with `repo:` and `rev:`:

```yaml
repos:
  - repo: https://github.com/psf/black
    rev: 24.1.0
    hooks:
      - id: black
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: 8ba0ac6f3b4e3d3d4e5d6c7b8a9f0e1d2c3b4a5f # frozen: v4.5.0
    hooks:
      - id: trailing-whitespace
```

pre-commit itself reads only `.pre-commit-config.yaml`; `.pre-commit-config.yml` is routed as well
(Renovate matches both, and `pre-commit -c` accepts any name).

pre-commit is the `PreCommit` flavor of the same ecosystem type as
[GitHub Actions](github-actions.md). Both resolve an `owner/repo` pin against GitHub's tags API, so
hover, completion, outdated and unknown-ref diagnostics, the SHA-pin comment check and the
tag-to-SHA code actions behave the same way. When both are enabled they share one registry: the
HTTP cache, rate budget, request coalescing and tag index serve a repository that appears in a
workflow and in a hook config from a single fetch. Set `GITHUB_TOKEN` to raise the unauthenticated
60 requests per hour limit.

## What is parsed

One dependency per `repos[]` entry whose `repo:` is `https://github.com/<owner>/<repo>` (an
optional `.git` suffix or trailing `/` is accepted) and that has a `rev:`. The dependency name is
`owner/repo`.

| Entry | Result |
|---|---|
| `repo: local`, `repo: meta` | skipped silently |
| another host (`gitlab.com`, `bitbucket.org`, ...) or an SSH form (`git@github.com:o/r`) | skipped, debug log only |
| a URL with userinfo, a port, a query or a fragment | skipped |
| missing or non-string `repo:` / `rev:` | skipped with a warn log; the rest of the file still parses |
| invalid YAML | `parse-error` diagnostic at the document start |

`hooks[].additional_dependencies` pins are not read; they belong to the PyPI/npm ecosystems.

## Pins and comments

| `rev:` | Treatment |
|---|---|
| a tag (`24.1.0`, `v4.5.0`) | resolved against the tags API, compared with the latest release |
| 40 hex characters | a SHA pin; the trailing comment names its tag |
| 7 to 39 hex characters | not resolvable: no version diagnostics |

A SHA pin's tag comment is read in both spellings, `# v4.5.0` and `# frozen: v4.5.0` (what
`pre-commit autoupdate --freeze` writes). A code action that rewrites the pin keeps the spelling it
found; a pin that had no comment gets `# frozen: <tag>`.

## Mutable-ref pinning

pre-commit's own rule decides what is mutable: a `rev:` is mutable when it contains no `.` and is
not entirely hexadecimal. `v1` and `main` are flagged; `v1.2`, `v1.2.3` and `abc1234` are not. The
diagnostic code is `pre-commit-mutable-ref-pin` and its text calls the entry a hook (`... hook is
pinned to the mutable rev ...`); severity follows `diagnostics.mutable_ref_pin_severity`. See
[CI/CD Pinning](../cross-ecosystem/ci-pinning.md) for the quick fix and the bulk "Pin All to SHA"
code lens, which says "hooks" here.

## Vulnerability scanning

OSV.dev has no ecosystem for hook repositories, so pre-commit pins are not scanned for
vulnerabilities and deps.dev signals are not requested.

## Known limitations

- Only GitHub-hosted hook repositories are resolved.
- A short hex `rev:` is never resolved.
- `additional_dependencies` and `default_language_version` are not checked.
