"""GitLab CI context and base check.

The context loads one or more ``.gitlab-ci.yml`` documents from disk and
exposes them as parsed dicts. Checks subclass :class:`GitLabBaseCheck`
and iterate ``self.ctx.pipelines``.
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..base import BaseCheck

# Top-level keys that are *not* jobs. Anything else at the root is a job.
# https://docs.gitlab.com/ee/ci/yaml/
_TOPLEVEL_KEYWORDS: set[str] = {
    "default", "include", "stages", "variables", "workflow",
    "image", "services", "cache", "before_script", "after_script",
    "pages",
}


@dataclass(frozen=True)
class Pipeline:
    """A parsed GitLab CI document."""

    path: str
    data: dict[str, Any]


class GitLabContext:
    """Loaded set of GitLab CI YAML documents."""

    def __init__(self, pipelines: list[Pipeline]) -> None:
        self.pipelines = pipelines

    @classmethod
    def from_path(cls, path: str | Path) -> GitLabContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--gitlab-path {root} does not exist. Pass a .gitlab-ci.yml "
                f"file or a directory containing one."
            )
        if root.is_file():
            files = [root]
        else:
            files = sorted(
                p for p in root.rglob("*")
                if p.is_file() and p.name in {".gitlab-ci.yml", ".gitlab-ci.yaml"}
            )
            if not files:
                # fall back to any yaml under the directory (e.g. included files)
                files = sorted(
                    p for p in root.rglob("*")
                    if p.is_file() and p.suffix.lower() in {".yml", ".yaml"}
                )
        pipelines: list[Pipeline] = []
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
            pipelines.append(Pipeline(path=str(f), data=data))
        return cls(pipelines)


class GitLabBaseCheck(BaseCheck):
    """Base class for GitLab CI checks."""

    PROVIDER = "gitlab"

    def __init__(self, ctx: GitLabContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: GitLabContext = ctx


def iter_jobs(pipeline: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield ``(job_name, job_dict)`` for every job in a GitLab CI doc."""
    for name, value in pipeline.items():
        if not isinstance(name, str):
            continue
        if name in _TOPLEVEL_KEYWORDS:
            continue
        if name.startswith("."):  # hidden / template job
            continue
        if isinstance(value, dict):
            yield name, value


def job_scripts(job: dict[str, Any]) -> list[str]:
    """Return a flat list of every script line across before_script / script / after_script."""
    lines: list[str] = []
    for key in ("before_script", "script", "after_script"):
        v = job.get(key)
        if isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    lines.append(item)
        elif isinstance(v, str):
            lines.append(v)
    return lines
