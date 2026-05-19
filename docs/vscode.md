# VS Code extension

The Pipeline-Check VS Code extension drives the same rule registry as
the CLI and surfaces findings inline as you edit workflow files.
Editor diagnostics match `pipeline_check --output json` byte-for-byte
(modulo position translation), so what you see in the gutter is what
the gate will report in CI.

- VS Code Marketplace: <https://marketplace.visualstudio.com/items?itemName=greylag-ci.pipeline-check>
- Open VSX (VSCodium, Cursor, Windsurf, Gitpod, code-server): <https://open-vsx.org/extension/greylag-ci/pipeline-check>
- Source: <https://github.com/greylag-ci/pipeline-check-vscode>

## Install

Search for **Pipeline-Check** in the extensions panel, or install from
the command line:

```bash
# Microsoft VS Code Marketplace
code --install-extension greylag-ci.pipeline-check

# Open VSX (VSCodium, Cursor, Gitpod, code-server)
codium --install-extension greylag-ci.pipeline-check
```

The extension is a thin LSP client. The rule engine runs in Python and
must be installed separately under whichever interpreter is on `PATH`:

```bash
pip install 'pipeline-check[lsp]'
```

## Requirements

- VS Code 1.85 or newer (Cursor, Windsurf, VSCodium, code-server, and
  Gitpod all track a recent VS Code base and work the same way).
- Python 3.11 or newer on `PATH`, with `pipeline-check[lsp]` installed.

## What it scans

Pilot provider coverage matches the single-file workflow providers
plus Dockerfile. Files are matched by path glob and language ID, so
no manual provider selection is needed.

| Provider | Trigger file(s) |
|---|---|
| GitHub Actions | `.github/workflows/*.yml` |
| GitLab CI | `.gitlab-ci.yml` |
| Azure DevOps | `azure-pipelines.yml` |
| Bitbucket Pipelines | `bitbucket-pipelines.yml` |
| CircleCI | `.circleci/config.yml` |
| Google Cloud Build | `cloudbuild.yaml` |
| Buildkite | `.buildkite/pipeline.yml` |
| Drone CI | `.drone.yml` / `.drone.yaml` |
| Jenkins | `Jenkinsfile` (Declarative and Scripted) |
| Dockerfile | `Dockerfile` / `Containerfile` |

Multi-file and context-heavy providers (Kubernetes, Helm, Terraform
plans, live AWS, CloudFormation, SCM posture, package registries) ship
in a later release. The CLI already covers them today.

## Features

### Inline diagnostics

Every finding shows up as a gutter squiggle and a row in the Problems
panel. Severity drives the color (CRITICAL and HIGH read red, MEDIUM
yellow, LOW info-blue). Hover reveals the rule title, the `--explain`
prose, and a link to the per-rule documentation page.

### Findings panel

A dedicated slot in the activity bar with a Pipeline-Check pipeline
glyph. Findings re-group by **severity** (default), **file**, or
**rule** via the title-bar **Change Grouping** button. The activity-bar
icon carries a live count badge so the panel doesn't need to be open
to know the workspace state.

### Status bar item

Bottom-left of the window, showing the top two severity counts at a
glance (for example `🛡 3C 1H` for three CRITICAL and one HIGH). Click
to reveal the Findings panel.

### CodeLens summary

Every scanned file carries a `Pipeline-Check: 2 critical · 1 high`
lens at line 1. Click navigates to the Findings panel filtered to the
file.

### Keyboard navigation

| Action | Keybinding |
|---|---|
| Next finding | <kbd>Alt</kbd>+<kbd>F8</kbd> |
| Previous finding | <kbd>Shift</kbd>+<kbd>Alt</kbd>+<kbd>F8</kbd> |

Both wrap at the ends of the list. The chord mirrors VS Code's built-in
<kbd>F8</kbd> for "next problem" so muscle memory carries over.

### Tunable signal

Two settings quiet the editor surface without restarting the server:

- `pipelineCheck.severityThreshold` raises the floor below which
  diagnostics are dropped (`low` / `medium` / `high` / `critical`,
  mirrors the CLI's `--severity-threshold`).
- `pipelineCheck.disabledProviders` silences entire providers, useful
  in a monorepo where Pipeline-Check would otherwise lint files
  belonging to a sub-project.

## Configuration

All settings live under the `pipelineCheck` namespace in
`settings.json`.

| Setting | Default | Description |
|---|---|---|
| `pipelineCheck.serverCommand` | `python` | Command used to launch the language server. Override if `pipeline_check` is installed under a different interpreter (a virtualenv, `pyenv` shim, or a system `python3`). Marked `machine-overridable`: workspace overrides require an explicit prompt. |
| `pipelineCheck.serverArgs` | `["-m", "pipeline_check.lsp"]` | Arguments passed to the server command. Marked `machine-overridable` for the same reason. |
| `pipelineCheck.severityThreshold` | `low` | Lowest severity that produces a diagnostic. One of `low`, `medium`, `high`, `critical`. Mirrors the CLI's `--severity-threshold`. |
| `pipelineCheck.disabledProviders` | `[]` | Provider IDs to silence entirely. Diagnostics for files matching a disabled provider's path glob are dropped before they reach the editor. Valid IDs: `github-actions`, `gitlab`, `azure`, `bitbucket`, `circleci`, `cloud-build`, `buildkite`, `drone`, `jenkins`, `dockerfile` (covers Containerfile too). |
| `pipelineCheck.trace.server` | `off` | Traces LSP traffic to the output channel. Set to `verbose` when debugging a missing or wrong diagnostic. |

## Commands

All commands appear in the Command Palette under the **Pipeline-Check**
category.

| Command | Default keybinding |
|---|---|
| Restart language server | (no default) |
| Show language server output | (no default) |
| Go to next finding | <kbd>Alt</kbd>+<kbd>F8</kbd> |
| Go to previous finding | <kbd>Shift</kbd>+<kbd>Alt</kbd>+<kbd>F8</kbd> |
| Change Grouping (Findings view) | (no default) |
| Refresh (Findings view) | (no default) |

**Restart language server** kills and respawns the LSP child process,
the right thing to reach for after a `pip install -U pipeline-check`
or a `pipelineCheck.serverCommand` change.

**Show language server output** focuses the output channel that
collects LSP server logs plus `[client]` client-side breadcrumbs (file
opens, settings changes, request errors). When `trace.server` is set
to `verbose`, this is where the JSON-RPC traffic shows up too.

## Workspace trust

The extension spawns the configured Python interpreter to analyze
workflow files. To keep that subprocess from running on first-open of
a freshly cloned repository, the extension declares
`capabilities.untrustedWorkspaces: "limited"` and stays inactive until
the workspace is trusted.

The `serverCommand` and `serverArgs` settings are `machine-overridable`,
so a malicious `.vscode/settings.json` cannot silently swap the
interpreter or inject arbitrary args even after trust is granted.
Workspace-level overrides surface as an explicit "Untrusted setting"
prompt.

## Architecture

```text
┌──────────────────────┐    stdio JSON-RPC     ┌──────────────────────────┐
│ VS Code extension    │ ◀───────────────────▶ │ pipeline_check.lsp        │
│ (TypeScript, in      │                        │ (Python, pygls; in this   │
│  greylag-ci/         │                        │  repo under               │
│  pipeline-check-     │                        │  pipeline_check/lsp/)     │
│  vscode)             │                        │                           │
└──────────────────────┘                        └──────────────────────────┘
```

The extension spawns `python -m pipeline_check.lsp` as a child process
and exchanges Language Server Protocol messages over stdin and stdout.
The server reads the same rule registry that powers the CLI, so editor
findings match `pipeline_check --output json` byte-for-byte (modulo
position translation).

Glob patterns the LSP listens on: `.github/workflows/`, `.gitlab-ci.yml`,
`azure-pipelines.yml`, `bitbucket-pipelines.yml`, `.circleci/`,
`cloudbuild.yaml`, `.buildkite/`, `.drone.yml`, `Jenkinsfile`, and
`Dockerfile` (or `Containerfile`). Each diagnostic carries the rule
ID, severity, the dynamic recommendation, and a `codeDescription` link
back to the per-rule docs page on this site.

## Non-VS Code editors

Any editor that speaks LSP can drive the same server. The most common
hosts (Cursor, Windsurf, VSCodium, code-server, Gitpod) install the
same `.vsix` from Open VSX and work without further config. For Neovim,
Helix, Emacs, Sublime Text, and others, point the editor's LSP client
at the standalone server:

```bash
pip install 'pipeline-check[lsp]'
python -m pipeline_check.lsp
```

The server speaks standard LSP over stdio. No proprietary extensions.

## Differences vs the CLI

The extension and the CLI share a rule engine, so findings are
identical for the same file. A few features only make sense in one
mode:

| Feature | CLI | Extension |
|---|---|---|
| Per-rule diagnostic with hover prose | JSON only | yes |
| Attack chains | yes | not in the pilot release |
| Scoring + grade + CI gate | yes | not surfaced (the editor is read-only) |
| STRIDE threat model export | yes (`--output threatmodel`) | no |
| Multi-file providers (Kubernetes, Helm, Terraform plan, SCM, registries) | yes | later release |
| MCP server (`--serve`) | yes (see [mcp.md](mcp.md)) | no |
| Baselines and ignore files | yes | inherited via the LSP server's config-file reader |

In a typical setup the extension catches issues at edit time and the
CLI runs in CI as the gate. The two are designed to agree on every
finding they both produce.

## Troubleshooting

**"Pipeline-Check: server failed to start"**
The interpreter on `PATH` does not have `pipeline-check[lsp]`
installed, or `serverCommand` points at the wrong one. Run
`python -m pipeline_check.lsp --version` from the same shell that
launched VS Code. If that fails, install the extra:
`pip install 'pipeline-check[lsp]'`.

**No diagnostics on a file you expect to be scanned**
Check that the file matches one of the trigger globs in the table
above. If `pipelineCheck.disabledProviders` includes the file's
provider, remove it. If `pipelineCheck.severityThreshold` is set
above the finding's severity, lower it. The output channel
(**Pipeline-Check: Show language server output**) logs the
provider-detection decision per file.

**The Findings panel disagrees with Problems**
The Findings panel groups by severity / file / rule and respects the
extension's `severityThreshold`. Problems shows VS Code's full
diagnostic stream from every extension. If a row is in Problems but
not in Findings, the severity threshold is filtering it.

**Diagnostics lag behind edits**
Each save (or `onDidChangeTextDocument` debounce) triggers a full
re-scan of the file. Very large workflow files may take a few hundred
milliseconds. Set `pipelineCheck.trace.server` to `verbose` and watch
the output channel for the request/response timing.

## See also

- [usage.md](usage.md): CLI reference
- [mcp.md](mcp.md): MCP server (`--serve`) for AI-client integration
- [config.md](config.md): the `pipelinecheck.yml` config file (the
  LSP server reads it too, so workspace-level ignores carry over)
- [providers/](providers/README.md): per-provider check reference
