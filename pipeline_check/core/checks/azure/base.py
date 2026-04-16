"""Azure DevOps Pipelines context and base check.

ADO YAML can take four shapes depending on how much structure is
declared:

1. Flat single-job pipeline — top-level ``steps:``
2. Single-stage multi-job — top-level ``jobs:`` (each with ``steps:``)
3. Multi-stage — top-level ``stages:`` → ``jobs:`` → ``steps:``
4. Deployment jobs — ``jobs:`` may contain ``deployment:`` entries whose
   steps live under ``strategy.runOnce|rolling|canary.{preDeploy,deploy,
   routeTraffic,postRouteTraffic,on.{success,failure}}.steps``.

``iter_jobs`` yields every job (both regular and deployment jobs) with
a human-readable location handle; ``iter_steps`` flattens every step in
a job, handling the deployment-strategy nesting.
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..base import BaseCheck


@dataclass(frozen=True)
class Pipeline:
    """A parsed azure-pipelines.yml document."""

    path: str
    data: dict[str, Any]


class AzureContext:
    """Loaded set of ADO pipeline documents."""

    def __init__(self, pipelines: list[Pipeline]) -> None:
        self.pipelines = pipelines

    @classmethod
    def from_path(cls, path: str | Path) -> AzureContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--azure-path {root} does not exist. Pass an "
                f"azure-pipelines.yml file or a directory containing one."
            )
        if root.is_file():
            files = [root]
        else:
            files = sorted(
                p for p in root.rglob("*")
                if p.is_file() and p.name in {
                    "azure-pipelines.yml", "azure-pipelines.yaml",
                }
            )
            if not files:
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


class AzureBaseCheck(BaseCheck):
    """Base class for Azure DevOps Pipelines checks."""

    PROVIDER = "azure"

    def __init__(self, ctx: AzureContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: AzureContext = ctx


def iter_jobs(doc: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield ``(location, job_dict)`` for every job in the pipeline.

    Handles all three shapes — flat steps, flat jobs, and staged jobs —
    as well as ``deployment:`` jobs.
    """
    # Shape 3: stages → jobs
    stages = doc.get("stages")
    if isinstance(stages, list):
        for i, stage in enumerate(stages):
            if not isinstance(stage, dict):
                continue
            stage_name = stage.get("stage") or f"stage{i}"
            jobs = stage.get("jobs")
            if isinstance(jobs, list):
                for j, job in enumerate(jobs):
                    if isinstance(job, dict):
                        yield f"{stage_name}.{_job_name(job, j)}", job
        return

    # Shape 2: jobs
    jobs = doc.get("jobs")
    if isinstance(jobs, list):
        for j, job in enumerate(jobs):
            if isinstance(job, dict):
                yield _job_name(job, j), job
        return

    # Shape 1: top-level steps → synthesise a single job
    if isinstance(doc.get("steps"), list):
        yield "<pipeline>", doc


def iter_steps(job: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield ``(path, step_dict)`` for every step in *job*.

    Deployment jobs nest steps under a strategy; this walker flattens
    every strategy phase (``preDeploy``, ``deploy``, ``routeTraffic``,
    ``postRouteTraffic``, ``on.success``, ``on.failure``) across every
    strategy kind.
    """
    direct = job.get("steps")
    if isinstance(direct, list):
        for i, step in enumerate(direct):
            if isinstance(step, dict):
                yield f"steps[{i}]", step
        return

    strategy = job.get("strategy")
    if isinstance(strategy, dict):
        for kind in ("runOnce", "rolling", "canary"):
            body = strategy.get(kind)
            if not isinstance(body, dict):
                continue
            for phase in (
                "preDeploy", "deploy", "routeTraffic", "postRouteTraffic",
            ):
                p = body.get(phase)
                if isinstance(p, dict):
                    steps = p.get("steps")
                    if isinstance(steps, list):
                        for i, step in enumerate(steps):
                            if isinstance(step, dict):
                                yield f"{kind}.{phase}[{i}]", step
            # YAML 1.1 coerces bareword `on:` to boolean True — handle both.
            on = body.get("on")
            if on is None:
                on = body.get(True)
            if isinstance(on, dict):
                for hook in ("success", "failure"):
                    h = on.get(hook)
                    if isinstance(h, dict):
                        steps = h.get("steps")
                        if isinstance(steps, list):
                            for i, step in enumerate(steps):
                                if isinstance(step, dict):
                                    yield f"{kind}.on.{hook}[{i}]", step


def _job_name(job: dict[str, Any], idx: int) -> str:
    if isinstance(job.get("deployment"), str):
        return f"deployment:{job['deployment']}"
    if isinstance(job.get("job"), str):
        return f"job:{job['job']}"
    return f"job{idx}"
