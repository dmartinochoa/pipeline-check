"""Drone CI context and base check.

Loads ``.drone.yml`` / ``.drone.yaml`` from disk. Drone's pipeline
file is a multi-document YAML stream; each document is a top-level
pipeline with a ``kind: pipeline`` discriminator. Documents that
don't carry ``kind: pipeline`` are silently skipped, so a
directory mixing Drone with unrelated YAML is safe to point at.

Each pipeline has a ``type:`` (``docker``, ``kubernetes``,
``ssh``, ``exec``, ``digitalocean``); the rule pack scopes itself
to the container-flavored types (``docker`` / ``kubernetes``) by
default, since the security-relevant patterns
(image pinning, privileged steps, parameter injection) only
make sense there.

Rules subclass :class:`DroneBaseCheck` and iterate
``self.ctx.pipelines``.
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .._yaml_files import load_yaml_files
from .._yaml_lines import line_of as _line_of
from ..base import BaseCheck, Location


@dataclass(frozen=True, slots=True)
class Pipeline:
    """A parsed Drone pipeline document."""

    path: str
    doc_index: int  # 0-based index within the multi-doc YAML stream
    data: dict[str, Any]


class DroneContext:
    """Loaded set of Drone pipeline documents."""

    def __init__(self, pipelines: list[Pipeline]) -> None:
        self.pipelines = pipelines
        self.files_scanned: int = len({p.path for p in pipelines})
        self.files_skipped: int = 0
        self.warnings: list[str] = []

    @classmethod
    def from_path(cls, path: str | Path) -> DroneContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--drone-path {root} does not exist. Pass a "
                ".drone.yml file or a directory containing one."
            )
        if root.is_file():
            files = [root]
        else:
            # Match the canonical filenames at any depth so monorepos
            # with one ``.drone.yml`` per service all get scanned.
            files = sorted(
                p for p in root.rglob("*")
                if p.is_file() and p.name in {".drone.yml", ".drone.yaml"}
            )
        loaded, warnings, skipped = load_yaml_files(files, multi_doc=True)
        pipelines: list[Pipeline] = []
        for entry in loaded:
            for idx, data in enumerate(entry.docs):
                if not isinstance(data, dict):
                    continue
                # Heuristic gate: Drone pipelines declare
                # ``kind: pipeline``. Anything else (a stray YAML
                # doc, a Kubernetes manifest sharing the directory)
                # is skipped silently rather than spamming warnings.
                if data.get("kind") != "pipeline":
                    continue
                pipelines.append(Pipeline(
                    path=str(entry.path), doc_index=idx, data=data,
                ))
        ctx = cls(pipelines)
        # Count every file the loader actually inspected, not just
        # the ones that produced a ``kind: pipeline`` doc. A file
        # that only carried Drone secrets (``kind: secret``) is
        # still a scanned file from a telemetry standpoint.
        ctx.files_scanned = len(files)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


class DroneBaseCheck(BaseCheck[DroneContext]):
    """Base class for Drone rule modules."""

    PROVIDER = "drone"

    def __init__(self, ctx: DroneContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: DroneContext = ctx


# ── Helpers shared by multiple rule modules ───────────────────────────


def is_container_pipeline(pipeline: Pipeline) -> bool:
    """True for ``type: docker`` / ``kubernetes`` pipelines.

    Most security rules only make sense for container-flavored
    pipelines; ``ssh`` / ``exec`` / ``digitalocean`` pipelines run
    on a different runtime and have no ``image:`` field. Default
    to ``True`` when ``type:`` is omitted, Drone's own default is
    ``docker``.
    """
    kind = pipeline.data.get("type")
    if not isinstance(kind, str):
        return True
    return kind in ("docker", "kubernetes")


def iter_steps(
    pipeline: Pipeline,
) -> Iterator[tuple[int, dict[str, Any]]]:
    """Yield ``(index, step_dict)`` for every step on a pipeline.

    Skips bare strings (not valid Drone, but tolerate them) and
    non-dict entries. ``services:`` (sidecar containers) are NOT
    yielded by this helper; rules that care about them iterate
    ``pipeline.data['services']`` directly.
    """
    steps = pipeline.data.get("steps") or []
    if not isinstance(steps, list):
        return
    for idx, raw in enumerate(steps):
        if isinstance(raw, dict):
            yield idx, raw


def iter_services(
    pipeline: Pipeline,
) -> Iterator[tuple[int, dict[str, Any]]]:
    """Yield ``(index, service_dict)`` for every sidecar service.

    Drone services are containers running alongside the pipeline
    (databases, message brokers, etc.). They share the image-
    pinning and privileged-mode surface of step containers, so
    rules that scan steps usually also scan services.
    """
    services = pipeline.data.get("services") or []
    if not isinstance(services, list):
        return
    for idx, raw in enumerate(services):
        if isinstance(raw, dict):
            yield idx, raw


def step_label(
    step: dict[str, Any], fallback_idx: int, *, kind: str = "steps",
) -> str:
    """Return a stable human name for a step or service.

    Drone's ``name:`` is required in practice, but tolerate its
    absence so a malformed pipeline still produces a readable
    finding. *kind* parameterizes the fallback so service
    callers (DR-001 / DR-002 iterating ``iter_services``)
    produce ``services[0]`` rather than the misleading
    ``steps[0]``.
    """
    name = step.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    return f"{kind}[{fallback_idx}]"


def step_commands(step: dict[str, Any]) -> list[str]:
    """Return every command string from a step.

    Drone accepts ``commands:`` (a list of strings).  ``commands``
    can also be a single string in some misconfigured pipelines;
    normalize to a flat list.
    """
    out: list[str] = []
    cmd = step.get("commands")
    if isinstance(cmd, str):
        out.append(cmd)
    elif isinstance(cmd, list):
        for item in cmd:
            if isinstance(item, str):
                out.append(item)
    return out


def step_location(path: str, step: dict[str, Any]) -> Location:
    """Build a :class:`Location` pointing at *step* in *path*.

    Falls back to a path-only location when the loader didn't
    preserve line info, keeps call sites uniform.
    """
    line = _line_of(step)
    return Location(path=path, start_line=line, end_line=line)


def is_plugin_step(step: dict[str, Any]) -> bool:
    """True when *step* is a plugin invocation.

    Drone treats a step as a plugin when it has a ``settings:``
    block. Plugins are invoked with the step's ``image:`` and
    receive ``settings:`` keys as ``PLUGIN_*`` env vars.
    """
    return isinstance(step.get("settings"), dict)


def from_secret_value(value: Any) -> str | None:
    """If *value* is a ``{from_secret: NAME}`` reference, return NAME.

    Drone's secret-injection contract is ``key: { from_secret: NAME }``;
    rules that distinguish "literal credential string" from
    "secret reference" use this helper. Returns ``None`` when
    *value* is anything else (a literal string, a list, a plain
    dict, etc.).
    """
    if not isinstance(value, dict):
        return None
    name = value.get("from_secret")
    if isinstance(name, str) and name.strip():
        return name.strip()
    return None
