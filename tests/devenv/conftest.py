"""Shared helpers for developer-environment (devenv) per-rule tests.

Parse a JSON(C) snippet into a one-file ``DevEnvContext`` of the given
kind, run the orchestrator, return the Finding for the requested
check_id. Keeps each rule's tests small inline literals.
"""
from __future__ import annotations

import textwrap

from pipeline_check.core.checks.devenv.base import (
    KIND_CLAUDE_SETTINGS,
    KIND_DEVCONTAINER,
    KIND_MCP_CONFIG,
    KIND_VSCODE_SETTINGS,
    KIND_VSCODE_TASKS,
    DevEnvContext,
    WorkspaceFile,
    loads_jsonc,
)
from pipeline_check.core.checks.devenv.checks import DevEnvChecks

_DEFAULT_PATH = {
    KIND_VSCODE_TASKS: ".vscode/tasks.json",
    KIND_VSCODE_SETTINGS: ".vscode/settings.json",
    KIND_DEVCONTAINER: ".devcontainer/devcontainer.json",
    KIND_CLAUDE_SETTINGS: ".claude/settings.json",
    KIND_MCP_CONFIG: ".mcp.json",
}


def devenv_ctx(raw: str, kind: str, path: str | None = None) -> DevEnvContext:
    """Build a DevEnvContext with one WorkspaceFile of *kind*."""
    raw = textwrap.dedent(raw)
    data = loads_jsonc(raw)
    if not isinstance(data, dict):
        data = {}
    return DevEnvContext(
        [WorkspaceFile(path=path or _DEFAULT_PATH[kind], kind=kind, data=data, raw=raw)]
    )


def run_check(raw: str, kind: str, check_id: str):
    """Run every devenv check; return the Finding with the given id."""
    ctx = devenv_ctx(raw, kind)
    for f in DevEnvChecks(ctx).run():
        if f.check_id == check_id:
            return f
    raise AssertionError(
        f"check_id {check_id!r} not found in devenv orchestrator output"
    )
