# Developer-environment provider

Scans the config files that run code the moment a developer opens or
checks out the repository, a surface distinct from the CI pipeline
definitions the rest of the scanner covers:

- `.vscode/tasks.json` tasks set to `runOptions.runOn: folderOpen`
- `.devcontainer/devcontainer.json` lifecycle commands
  (`postCreateCommand` and friends) and the host-side
  `initializeCommand`
- `.claude/settings.json` Claude Code hooks of `type: command`

Text-only JSON(C) parsing (comments and trailing commas are
tolerated), no tokens, no network. The threat is the second stage of
campaigns like the 2026 Red Hat npm compromise: a poisoned repo that
runs a loader on folder-open / devcontainer-create / agent-session-
start, before any build or test. `DEV-004` reserves CRITICAL for the
remote-fetch-and-execute shape.

## Producer workflow

```bash
# Auto-detected when .vscode/ , .devcontainer/ , or .claude/ config
# files are present at cwd; defaults to scanning the current directory.
pipeline_check --pipeline devenv

# …or point it at a repo root or a single config file.
pipeline_check --pipeline devenv --devenv-path ./checkout
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

## What it covers

10 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [DEV-001](#dev-001) | VS Code task runs automatically on folder open | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [DEV-002](#dev-002) | Devcontainer lifecycle command runs automatically | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [DEV-003](#dev-003) | Committed Claude Code hook runs a shell command | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [DEV-004](#dev-004) | Auto-run command fetches and executes remote code | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [DEV-005](#dev-005) | Devcontainer initializeCommand runs unsandboxed on the host | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [DEV-006](#dev-006) | VS Code settings point a tool at a repo-local binary | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [DEV-007](#dev-007) | Committed MCP config auto-launches a local command server | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [DEV-008](#dev-008) | Credential-shaped literal in a developer-environment config | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [DEV-009](#dev-009) | Committed MCP config uses a remote server over plaintext HTTP | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [DEV-010](#dev-010) | Committed MCP config blanket-auto-approves a server's tools | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |

---

<div class="pg-rule pg-rule--low" markdown>

## DEV-001: VS Code task runs automatically on folder open { #dev-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires on any task in ``.vscode/tasks.json`` whose ``runOptions.runOn`` is ``folderOpen``. VS Code Workspace Trust gates the first run, but reviewers routinely trust repos they open, so this is a real reachable-on-open surface rather than a purely theoretical one.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove ``runOptions.runOn: folderOpen`` so the task runs only when invoked explicitly, or move the logic into a documented setup script a developer chooses to run. If an auto-task is genuinely required, keep its command vendored in the repo and free of any network fetch (see DEV-004).

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## DEV-002: Devcontainer lifecycle command runs automatically { #dev-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires when ``devcontainer.json`` declares any of ``onCreateCommand`` / ``updateContentCommand`` / ``postCreateCommand`` / ``postStartCommand`` / ``postAttachCommand``. The host-side ``initializeCommand`` is handled separately by DEV-005 (it runs unsandboxed on the host).

<div class="pg-rule__rec" markdown>

**Recommended action**

Treat the lifecycle commands as code that runs on every Codespace / devcontainer create. Keep them vendored in the repo, free of network fetches (DEV-004), and review changes to them the way you would any executable in the build path. There is no way to disable lifecycle execution short of removing the keys; this finding is informational so a reviewer notices what runs on open.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## DEV-003: Committed Claude Code hook runs a shell command { #dev-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires on any ``hooks.<Event>`` entry of ``type: command`` in ``.claude/settings.json`` or ``.claude/settings.local.json``. ``SessionStart`` is the open-the-repo trigger; other events run during interaction. ``prompt``-type hooks (no shell) are not flagged.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't commit ``type: command`` hooks that other contributors will execute unknowingly. Keep agent hooks in the user-level ``~/.claude/settings.json`` or the git-ignored ``.claude/settings.local.json`` instead of the shared ``.claude/settings.json``. If a project hook is genuinely needed, keep its command vendored and free of network fetches (DEV-004) and document it so reviewers expect it.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## DEV-004: Auto-run command fetches and executes remote code { #dev-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Fires when a command on an auto-execution surface (VS Code ``folderOpen`` task, devcontainer lifecycle / ``initializeCommand``, or a Claude Code ``command`` hook) matches the remote-fetch-to-interpreter idiom catalog (``curl|bash``, ``wget|sh``, ``bash -c "$(curl …)"``, PowerShell ``irm|iex``, …). Scoped to the auto-run command strings, so an unrelated URL elsewhere in the config does not trigger it. Vendor-trusted installer hosts are still flagged (the auto-run-on-open context makes them risky) but carry a ``vendor_trusted`` marker in the detector output.

**Seen in the wild**

- Red Hat npm compromise second-stage loaders (BoostSecurity, "Trusted Publishing, Untrusted Branch", 2026): editor / devcontainer / agent configs that fetch-and-run on repo open.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove the network fetch from any command that runs on repo open. Vendor the script into the repository and invoke the checked-in copy, or download to a file and verify a pinned sha256 before executing. A ``curl | sh`` that runs the instant the repo is opened is arbitrary remote code execution on the developer's machine.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DEV-005: Devcontainer initializeCommand runs unsandboxed on the host { #dev-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires whenever ``devcontainer.json`` declares an ``initializeCommand``. That hook runs on the host before the container is created, so unlike the in-container lifecycle hooks (DEV-002) it has no container isolation. Common on legitimate setups too, hence HIGH rather than CRITICAL unless it also fetches remote code.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move host-side setup into ``onCreateCommand`` / ``postCreateCommand`` so it runs inside the container, where the blast radius is the disposable devcontainer rather than the developer's workstation. Reserve ``initializeCommand`` for genuinely host-only, trusted, vendored steps, and never let it fetch and run remote code (DEV-004).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DEV-006: VS Code settings point a tool at a repo-local binary { #dev-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-426</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires on a ``.vscode/settings.json`` that (a) sets a known executable-path key (or a ``go.alternateTools`` / terminal automation-profile path) to a repo-relative value (a path with a separator that is not absolute, or one using ``${workspaceFolder}``), (b) sets ``terminal.integrated.env.*`` to a process-hijack variable, or (c) enables ``task.allowAutomaticTasks``. A bare command (``git``, resolved from ``PATH``) or an absolute system path passes. VS Code Workspace Trust gates the first open, but reviewers routinely trust repos they clone. Complements DEV-001 (folder-open task), DEV-003 (committed Claude hook), and DEV-005 (devcontainer host command); this is the settings-file launch surface none of them read.

**Seen in the wild**

- Microsoft VS Code Workspace Trust exists precisely because a committed workspace ``settings.json`` can point tool / interpreter paths at attacker-controlled binaries that run on folder open; the 2026 npm second-stage 'open the checkout' loaders (Red Hat compromise) used the same checkout-time auto-execution class.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't commit a workspace ``.vscode/settings.json`` that points an executable-path setting (``git.path``, ``python.defaultInterpreterPath``, ``eslint.runtime``, ``go.alternateTools``, a terminal automation profile, ...) at a repo-relative path, injects a process-hijack variable through ``terminal.integrated.env.*`` (``PATH`` / ``LD_PRELOAD`` / ``NODE_OPTIONS``), or sets ``task.allowAutomaticTasks: on``. Keep tool paths pointing at system binaries (an absolute path or a bare command resolved from the user's ``PATH``), and let each developer configure machine-specific paths in their user settings, not a committed workspace file.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## DEV-007: Committed MCP config auto-launches a local command server { #dev-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-94</span>
</div>

Fires when a committed MCP config (``.mcp.json``, ``.cursor/mcp.json``, ``.vscode/mcp.json``, Zed's ``.zed/settings.json``, or Continue's ``.continue/config.yaml`` / ``.continue/mcpServers/*.yaml``) defines a server with a ``command`` (a stdio server the editor / agent launches as a local process on project open). The ``mcpServers`` (Claude / Cursor object, Continue list), ``servers`` (VS Code), and ``context_servers`` (Zed) block names are all read. ``url``-only servers (``type: http`` / ``sse``) don't spawn a local process and don't fire here (DEV-009 checks their transport). Commands that fetch an unpinned remote package (``npx -y`` / ``uvx`` / ``pnpm dlx`` / ``bunx`` / ``pipx run``) are called out as the sharpest case.

**Known false-positive modes**

- A first-party MCP server invoked from a checked-in, reviewed script (``node ./tools/mcp-server.js``) is intentional. The finding still flags that the config auto-launches a process on open; suppress on the file with a rationale naming the server.

<div class="pg-rule__rec" markdown>

**Recommended action**

Treat a committed MCP server config as code that runs on project open. Prefer a first-party server invoked from a checked-in, reviewed script over a ``npx -y`` / ``uvx`` runner that pulls an unpinned remote package; if a remote package is required, pin it to an exact version (and ideally an integrity hash). Keep developer-specific or untrusted MCP servers in user-level config (``~/.cursor`` / user settings) rather than committing them to the repository where they auto-launch for every contributor.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## DEV-008: Credential-shaped literal in a developer-environment config { #dev-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Scans every string in a developer-environment config (``.vscode/`` tasks / settings, ``.devcontainer``, ``.claude/settings.json``, and MCP configs ``.mcp.json`` / ``.cursor/mcp.json`` / ``.vscode/mcp.json`` / Zed's ``.zed/settings.json`` / Continue's ``.continue/`` YAML) against the cross-provider credential-shape catalog. The common hit is a token in an MCP server's ``env`` block or a devcontainer ``remoteEnv`` / ``containerEnv``.

**Known false-positive modes**

- Documentation / example configs sometimes embed credential-shaped strings (a sample ``ghp_`` token, a JWT). Well-known vendor example tokens are suppressed by the shared catalog; suppress a genuine fixture per-resource with a rationale.

<div class="pg-rule__rec" markdown>

**Recommended action**

Rotate the exposed credential immediately, it is in the repo's history. Don't commit secrets to editor / agent / container config: pass them through the environment at run time (an MCP server reads ``${env:GITHUB_TOKEN}`` from the developer's shell, a devcontainer reads a host env var) or a local, git-ignored config rather than a committed literal.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## DEV-009: Committed MCP config uses a remote server over plaintext HTTP { #dev-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-319</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires when a committed MCP config (``.mcp.json``, ``.cursor/mcp.json``, ``.vscode/mcp.json``, Zed's ``.zed/settings.json``, or Continue's ``.continue/config.yaml`` / ``.continue/mcpServers/*.yaml``) defines a remote server whose ``url`` is plaintext ``http://`` to a non-loopback host (any ``sse`` / ``streamable-http`` transport included). Loopback URLs (``localhost`` / ``127.0.0.0/8`` / ``::1``) and ``https://`` endpoints pass. Stdio (``command``) servers are DEV-007's concern, not this rule's.

**Known false-positive modes**

- A remote server reached over plaintext inside a trusted, isolated network segment may be intentional. Prefer TLS regardless; if the plaintext hop is truly contained, suppress on the file with a rationale naming the server and the network boundary.

<div class="pg-rule__rec" markdown>

**Recommended action**

Point the MCP server at an ``https://`` endpoint so the tool stream is authenticated and encrypted. A plaintext ``http://`` transport to a remote host lets an on-path attacker read or rewrite the tools the agent is offered and the data it exchanges. If the server genuinely runs locally, bind it to loopback (``http://localhost`` / ``127.0.0.1``), which is not flagged.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## DEV-010: Committed MCP config blanket-auto-approves a server's tools { #dev-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-284</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Fires when a committed MCP config (``.mcp.json``, ``.cursor/mcp.json``, ``.vscode/mcp.json``, Zed's ``.zed/settings.json``, or Continue's ``.continue/config.yaml`` / ``.continue/mcpServers/*.yaml``) sets a *blanket* tool auto-approval on a server: ``autoApprove: true`` / ``["*"]`` or ``alwaysAllow`` containing ``"*"``. A grant scoped to specific named tools is a bounded choice and passes.

**Known false-positive modes**

- A blanket grant on a first-party, fully trusted local server may be intentional. Prefer a named-tool allow-list; if the blanket grant is deliberate, suppress on the file with a rationale naming the server.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't commit a blanket tool auto-approval. Remove ``autoApprove: true`` / ``["*"]`` (and Cline's ``alwaysAllow: ["*"]``) so tool calls keep their human confirmation, or scope the grant to the specific low-risk tools you trust (``alwaysAllow: ["read_file"]``). Combined with an auto-launched server (DEV-007), a blanket grant means a poisoned tool runs with no prompt for every contributor who opens the repo.

</div>

</div>

---

## Adding a new Developer environment check

1. Create a new module at
   `pipeline_check/core/checks/devenv/rules/NNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the parsed YAML document.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/devenv/-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py devenv
   ```
