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

6 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [DEV-001](#dev-001) | VS Code task runs automatically on folder open | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [DEV-002](#dev-002) | Devcontainer lifecycle command runs automatically | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [DEV-003](#dev-003) | Committed Claude Code hook runs a shell command | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [DEV-004](#dev-004) | Auto-run command fetches and executes remote code | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [DEV-005](#dev-005) | Devcontainer initializeCommand runs unsandboxed on the host | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [DEV-006](#dev-006) | VS Code settings point a tool at a repo-local binary | <span class="pg-sev pg-sev--high">HIGH</span> |  |

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
