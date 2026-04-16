"""GitHub Actions context and base check.

The context loads every ``*.yml`` / ``*.yaml`` document under a
``.github/workflows/`` directory and exposes them as parsed dicts. Checks
subclass :class:`GitHubBaseCheck` and iterate ``self.ctx.workflows``.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..base import BaseCheck


@dataclass(frozen=True)
class Workflow:
    """A parsed GitHub Actions workflow document."""

    path: str   # relative path, used as the finding's resource handle
    data: dict[str, Any]


class GitHubContext:
    """Loaded set of workflows from a ``.github/workflows`` directory."""

    def __init__(self, workflows: list[Workflow]) -> None:
        self.workflows = workflows

    @classmethod
    def from_path(cls, path: str | Path) -> "GitHubContext":
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--gha-path {root} does not exist. Pass the workflows "
                f"directory (typically .github/workflows)."
            )
        if root.is_file():
            files = [root]
        else:
            files = sorted(
                p for p in root.rglob("*")
                if p.is_file() and p.suffix.lower() in {".yml", ".yaml"}
            )
        workflows: list[Workflow] = []
        for f in files:
            try:
                text = f.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            try:
                data = yaml.safe_load(text)
            except yaml.YAMLError:
                continue
            if not isinstance(data, dict):
                continue
            workflows.append(Workflow(path=str(f), data=data))
        return cls(workflows)


class GitHubBaseCheck(BaseCheck):
    """Base class for GitHub Actions workflow checks."""

    PROVIDER = "github"

    def __init__(self, ctx: GitHubContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: GitHubContext = ctx


def iter_jobs(workflow: dict[str, Any]):
    """Yield ``(job_id, job_dict)`` for every job in a workflow."""
    jobs = workflow.get("jobs") or {}
    if isinstance(jobs, dict):
        for job_id, job in jobs.items():
            if isinstance(job, dict):
                yield job_id, job


def iter_steps(job: dict[str, Any]):
    """Yield every step dict from a job."""
    steps = job.get("steps") or []
    if isinstance(steps, list):
        for step in steps:
            if isinstance(step, dict):
                yield step


def workflow_triggers(workflow: dict[str, Any]) -> list[str]:
    """Return the list of event names this workflow is triggered by.

    GitHub's ``on:`` field can be a string, a list, or a mapping. Any boolean
    ``True`` yielded by ``safe_load`` for a bareword ``on`` key (which YAML
    1.1 parses as a boolean) is also normalised here — ``workflow["on"]``
    becomes ``workflow[True]`` under YAML 1.1 semantics.
    """
    on = workflow.get("on")
    if on is None:
        on = workflow.get(True)  # YAML 1.1 "on" → boolean True
    if on is None:
        return []
    if isinstance(on, str):
        return [on]
    if isinstance(on, list):
        return [str(v) for v in on]
    if isinstance(on, dict):
        return [str(k) for k in on.keys()]
    return []
