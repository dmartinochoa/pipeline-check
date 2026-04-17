"""GitHub Actions provider — scans workflow YAML under ``.github/workflows/``.

Producer workflow:

    pipeline_check --pipeline github --gha-path .github/workflows

Only YAML parsing is required — no network calls, no GitHub API token.
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.github.base import GitHubContext
from ..checks.github.workflows import WorkflowChecks
from ..inventory import Component
from .base import BaseProvider


class GitHubProvider(BaseProvider):
    """GitHub Actions provider — parses workflow YAML from disk."""

    NAME = "github"

    def build_context(self, gha_path: str | None = None, **_: Any) -> GitHubContext:
        if not gha_path:
            raise ValueError(
                "The github provider requires --gha-path <dir> pointing at the "
                "directory of workflow YAML files (typically .github/workflows)."
            )
        return GitHubContext.from_path(gha_path)

    @property
    def check_classes(self) -> list[type[BaseCheck]]:
        return [WorkflowChecks]

    def inventory(self, context: GitHubContext) -> list[Component]:
        out: list[Component] = []
        for wf in context.workflows:
            data = wf.data if isinstance(wf.data, dict) else {}
            out.append(Component(
                provider=self.NAME,
                type="workflow",
                identifier=str(data.get("name") or wf.path),
                source=wf.path,
                metadata=_gha_metadata(data),
            ))
        return out


def _gha_metadata(data: dict) -> dict:
    meta: dict = {}
    jobs = data.get("jobs")
    if isinstance(jobs, dict):
        meta["jobs"] = sorted(jobs.keys())
        # Runner labels tell you where the workflow physically runs;
        # environment names tell you whether protection rules apply.
        runners: set[str] = set()
        environments: set[str] = set()
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            ro = job.get("runs-on")
            if isinstance(ro, str):
                runners.add(ro)
            elif isinstance(ro, list):
                runners.update(x for x in ro if isinstance(x, str))
            env = job.get("environment")
            if isinstance(env, str):
                environments.add(env)
            elif isinstance(env, dict) and isinstance(env.get("name"), str):
                environments.add(env["name"])
        if runners:
            meta["runners"] = sorted(runners)
        if environments:
            meta["environments"] = sorted(environments)
    # Trigger events — ``pull_request_target`` is the one that grants
    # write tokens on fork PRs, so surfacing triggers is load-bearing
    # for any "which workflows are reachable from untrusted input"
    # audit.
    # PyYAML parses bare ``on:`` as the Python ``True`` key (YAML 1.1
    # boolean coercion), so probe both.
    on = data.get("on")
    if on is None:
        on = data.get(True)
    if isinstance(on, dict):
        meta["triggers"] = sorted(on.keys())
    elif isinstance(on, list):
        meta["triggers"] = sorted(x for x in on if isinstance(x, str))
    elif isinstance(on, str):
        meta["triggers"] = [on]
    # Top-level ``permissions:``  — tightened token scopes worth recording.
    perms = data.get("permissions")
    if isinstance(perms, str):
        meta["permissions"] = perms
    elif isinstance(perms, dict):
        meta["permissions"] = "scoped"
    return meta
