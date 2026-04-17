"""CircleCI context and base check.

The context loads a ``.circleci/config.yml`` document from disk and
exposes the parsed YAML dict alongside helpers for iterating jobs,
steps, and orbs.

CircleCI config structure (v2.1)::

    version: 2.1
    orbs:
      node: circleci/node@5.1.0
    executors:
      default:
        docker:
          - image: cimg/node:18.17
    jobs:
      build:
        executor: default
        steps:
          - checkout
          - run: npm ci
    workflows:
      main:
        jobs:
          - build
          - deploy:
              requires: [build]
              type: approval
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..base import BaseCheck, safe_load_yaml


@dataclass(frozen=True)
class CircleConfig:
    """A parsed CircleCI config document."""

    path: str
    data: dict[str, Any]


class CircleCIContext:
    """Loaded set of CircleCI config documents."""

    def __init__(self, pipelines: list[CircleConfig]) -> None:
        self.pipelines = pipelines
        self.files_scanned: int = len(pipelines)
        self.files_skipped: int = 0
        self.warnings: list[str] = []

    @classmethod
    def from_path(cls, path: str | Path) -> CircleCIContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--circleci-path {root} does not exist. Pass a "
                f".circleci/config.yml file or a directory containing one."
            )
        if root.is_file():
            files = [root]
        else:
            files = sorted(
                p for p in root.rglob("*")
                if p.is_file() and p.name in {
                    "config.yml", "config.yaml",
                }
            )
        pipelines: list[CircleConfig] = []
        warnings: list[str] = []
        skipped = 0
        for f in files:
            try:
                text = f.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                warnings.append(f"{f}: read error: {exc}")
                skipped += 1
                continue
            try:
                data = safe_load_yaml(text)
            except yaml.YAMLError as exc:
                first_line = str(exc).split("\n", 1)[0]
                warnings.append(f"{f}: YAML parse error: {first_line}")
                skipped += 1
                continue
            if not isinstance(data, dict):
                continue
            pipelines.append(CircleConfig(path=str(f), data=data))
        ctx = cls(pipelines)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


class CircleCIBaseCheck(BaseCheck):
    """Base class for CircleCI config checks."""

    PROVIDER = "circleci"

    def __init__(self, ctx: CircleCIContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: CircleCIContext = ctx


def iter_jobs(doc: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield ``(job_id, job_dict)`` for every job defined in the config."""
    jobs = doc.get("jobs") or {}
    if isinstance(jobs, dict):
        for job_id, job in jobs.items():
            if isinstance(job, dict):
                yield job_id, job


def iter_steps(job: dict[str, Any]) -> Iterator[dict[str, Any] | str]:
    """Yield every step from a job (may be a dict or bare string)."""
    steps = job.get("steps") or []
    if isinstance(steps, list):
        yield from steps


def iter_run_commands(job: dict[str, Any]) -> Iterator[str]:
    """Yield the command string from every ``run:`` step in a job."""
    for step in iter_steps(job):
        if isinstance(step, dict):
            run = step.get("run")
            if isinstance(run, str):
                yield run
            elif isinstance(run, dict):
                cmd = run.get("command")
                if isinstance(cmd, str):
                    yield cmd
        elif isinstance(step, str) and step.startswith("run:"):
            yield step[4:].strip()


def iter_workflow_jobs(doc: dict[str, Any]) -> Iterator[tuple[str, str, dict[str, Any]]]:
    """Yield ``(workflow_name, job_name, job_config)`` for every job
    reference in every workflow."""
    workflows = doc.get("workflows") or {}
    if not isinstance(workflows, dict):
        return
    for wf_name, wf in workflows.items():
        if not isinstance(wf, dict):
            continue
        jobs = wf.get("jobs") or []
        if not isinstance(jobs, list):
            continue
        for entry in jobs:
            if isinstance(entry, str):
                yield wf_name, entry, {}
            elif isinstance(entry, dict):
                for job_name, job_cfg in entry.items():
                    if not isinstance(job_cfg, dict):
                        job_cfg = {}
                    yield wf_name, job_name, job_cfg


def get_docker_images(doc: dict[str, Any]) -> list[str]:
    """Return every docker image referenced in jobs and executors."""
    images: list[str] = []
    for _, job in iter_jobs(doc):
        docker = job.get("docker")
        if isinstance(docker, list):
            for entry in docker:
                if isinstance(entry, dict) and isinstance(entry.get("image"), str):
                    images.append(entry["image"])
    executors = doc.get("executors") or {}
    if isinstance(executors, dict):
        for _, exc in executors.items():
            if not isinstance(exc, dict):
                continue
            docker = exc.get("docker")
            if isinstance(docker, list):
                for entry in docker:
                    if isinstance(entry, dict) and isinstance(entry.get("image"), str):
                        images.append(entry["image"])
    return images
