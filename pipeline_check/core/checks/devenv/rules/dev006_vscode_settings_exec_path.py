"""DEV-006, VS Code workspace settings point a tool at a repo-local binary.

A committed ``.vscode/settings.json`` can set executable-path keys
(``git.path``, ``python.defaultInterpreterPath``, ``eslint.runtime``,
``go.alternateTools``, a terminal automation profile, ...) to a path
inside the repository. The moment a developer opens the checkout in VS
Code (and trusts the workspace), VS Code launches that repo-shipped
binary as the tool: checkout-time code execution, the same second-stage
shape DEV-001..005 cover, on a file the loader did not previously read.
Injecting ``terminal.integrated.env.*`` process-hijack variables, or
turning on ``task.allowAutomaticTasks``, weakens the same surface.
"""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import KIND_VSCODE_SETTINGS, WorkspaceFile, location_for

RULE = Rule(
    id="DEV-006",
    title="VS Code settings point a tool at a repo-local binary",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-426", "CWE-829"),
    recommendation=(
        "Don't commit a workspace ``.vscode/settings.json`` that points "
        "an executable-path setting (``git.path``, "
        "``python.defaultInterpreterPath``, ``eslint.runtime``, "
        "``go.alternateTools``, a terminal automation profile, ...) at a "
        "repo-relative path, injects a process-hijack variable through "
        "``terminal.integrated.env.*`` (``PATH`` / ``LD_PRELOAD`` / "
        "``NODE_OPTIONS``), or sets ``task.allowAutomaticTasks: on``. Keep "
        "tool paths pointing at system binaries (an absolute path or a "
        "bare command resolved from the user's ``PATH``), and let each "
        "developer configure machine-specific paths in their user "
        "settings, not a committed workspace file."
    ),
    docs_note=(
        "Fires on a ``.vscode/settings.json`` that (a) sets a known "
        "executable-path key (or a ``go.alternateTools`` / terminal "
        "automation-profile path) to a repo-relative value (a path with a "
        "separator that is not absolute, or one using "
        "``${workspaceFolder}``), (b) sets ``terminal.integrated.env.*`` "
        "to a process-hijack variable, or (c) enables "
        "``task.allowAutomaticTasks``. A bare command (``git``, resolved "
        "from ``PATH``) or an absolute system path passes. VS Code "
        "Workspace Trust gates the first open, but reviewers routinely "
        "trust repos they clone. Complements DEV-001 (folder-open task), "
        "DEV-003 (committed Claude hook), and DEV-005 (devcontainer "
        "host command); this is the settings-file launch surface none of "
        "them read."
    ),
    incident_refs=(
        "Microsoft VS Code Workspace Trust exists precisely because a "
        "committed workspace ``settings.json`` can point tool / "
        "interpreter paths at attacker-controlled binaries that run on "
        "folder open; the 2026 npm second-stage 'open the checkout' "
        "loaders (Red Hat compromise) used the same checkout-time "
        "auto-execution class.",
    ),
    exploit_example=(
        "// Vulnerable: .vscode/settings.json points git and the Python\n"
        "// interpreter at binaries committed in the repo, and prepends a\n"
        "// repo dir to the integrated terminal's PATH.\n"
        "{\n"
        '  "git.path": "./.tools/git",\n'
        '  "python.defaultInterpreterPath": "${workspaceFolder}/.venv/bin/python",\n'
        '  "terminal.integrated.env.linux": { "PATH": "${workspaceFolder}/.bin:${env:PATH}" },\n'
        '  "task.allowAutomaticTasks": "on"\n'
        "}\n"
        "\n"
        "// Attack: ./.tools/git (and .venv/bin/python, and anything in\n"
        "// .bin) is an attacker-shipped script. Opening the cloned repo in\n"
        "// VS Code runs it the first time the editor invokes git / Python\n"
        "// or spawns a terminal, with the developer's environment.\n"
        "\n"
        "// Safe: leave tool paths to the user's PATH / absolute system\n"
        "// binaries; configure machine-specific paths in user settings.\n"
        "{\n"
        '  "git.path": "git"\n'
        "}"
    ),
)

# Flat, string-valued settings keys whose value VS Code launches as an
# executable. (Dict-valued surfaces, go.alternateTools and the terminal
# automation profile, are handled separately below.)
_EXEC_PATH_KEYS: frozenset[str] = frozenset({
    "git.path",
    "python.defaultInterpreterPath",
    "python.pythonPath",
    "eslint.runtime",
    "eslint.nodePath",
    "deno.path",
    "php.validate.executablePath",
    "php.executablePath",
    "rust-analyzer.server.path",
    "cmake.cmakePath",
    "rubyLsp.rubyExecutablePath",
    "ruby.interpreter.commandPath",
    "julia.executablePath",
    "terraform.languageServer.path",
    "gopls.path",
})

_TERMINAL_ENV_KEYS: tuple[str, ...] = (
    "terminal.integrated.env.linux",
    "terminal.integrated.env.osx",
    "terminal.integrated.env.windows",
)
_AUTOMATION_PROFILE_KEYS: tuple[str, ...] = (
    "terminal.integrated.automationProfile.linux",
    "terminal.integrated.automationProfile.osx",
    "terminal.integrated.automationProfile.windows",
)
# Env vars that hijack a later process (a preloaded object, a Node
# require, a shell startup file, the binary search path).
_HIJACK_VARS: frozenset[str] = frozenset({
    "PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "NODE_OPTIONS", "BASH_ENV",
    "PYTHONPATH", "PYTHONSTARTUP", "PERL5LIB", "RUBYOPT", "GEM_PATH",
})

_WINDOWS_ABS_RE = re.compile(r"^[A-Za-z]:[\\/]")


def _is_repo_local_path(value: str) -> bool:
    """True when *value* is a repo-relative executable path, not a system one."""
    s = value.strip()
    if not s:
        return False
    if s.startswith("${"):
        # A VS Code variable; only the workspace-relative ones are repo-local.
        return "${workspaceFolder}" in s or "${workspaceRoot}" in s
    if "${workspaceFolder}" in s or "${workspaceRoot}" in s:
        return True
    if "/" not in s and "\\" not in s:
        return False  # bare command, resolved from PATH
    if s.startswith(("/", "~", "\\\\")) or _WINDOWS_ABS_RE.match(s):
        return False  # absolute / home / UNC path
    return True


def check(path: str, wf: WorkspaceFile) -> Finding:
    if wf.kind != KIND_VSCODE_SETTINGS:
        return _pass(path)
    data = wf.data
    offenders: list[str] = []

    for key in _EXEC_PATH_KEYS:
        val = data.get(key)
        if isinstance(val, str) and _is_repo_local_path(val):
            offenders.append(f"{key}={val}")

    alt = data.get("go.alternateTools")
    if isinstance(alt, dict):
        for tool, p in alt.items():
            if isinstance(p, str) and _is_repo_local_path(p):
                offenders.append(f"go.alternateTools.{tool}={p}")

    for prof_key in _AUTOMATION_PROFILE_KEYS:
        prof = data.get(prof_key)
        if isinstance(prof, dict):
            p = prof.get("path")
            if isinstance(p, str) and _is_repo_local_path(p):
                offenders.append(f"{prof_key}.path={p}")

    for env_key in _TERMINAL_ENV_KEYS:
        env = data.get(env_key)
        if isinstance(env, dict):
            for var in env:
                if isinstance(var, str) and var.upper() in _HIJACK_VARS:
                    offenders.append(f"{env_key}.{var}")

    if str(data.get("task.allowAutomaticTasks", "")).lower() == "on":
        offenders.append("task.allowAutomaticTasks=on")

    if not offenders:
        return _pass(path)
    shown = ", ".join(offenders[:4]) + ("…" if len(offenders) > 4 else "")
    return RULE.fail_finding(
        resource=path,
        description=(
            f"{len(offenders)} VS Code workspace setting(s) launch a "
            f"repo-local binary or inject a process-hijack variable on "
            f"folder open: {shown}. Opening this repo in VS Code (once "
            f"trusted) runs the committed binary as the tool."
        ),
        locations=location_for(path, wf.raw, offenders[0].split("=", 1)[0]),
    )


def _pass(path: str) -> Finding:
    return RULE.pass_finding(
        path, "No repo-local tool paths or env injection in VS Code settings.",
    )
