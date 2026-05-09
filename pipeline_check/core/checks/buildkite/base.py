"""Buildkite context and base check.

Parses ``.buildkite/pipeline.yml`` (or any user-named pipeline file) on
disk. Each file becomes a :class:`Pipeline` wrapping the parsed YAML
document; checks subclass :class:`BuildkiteBaseCheck` and iterate
``self.ctx.pipelines``.

Buildkite's pipeline file shape (highlights)::

    env:
      GLOBAL_VAR: value
    agents:
      queue: default
    steps:
      - label: ":docker: Build"
        command: docker build .
        plugins:
          - docker-compose#v4.13.0:
              run: app
        agents:
          queue: linux-large
        timeout_in_minutes: 30
        env:
          MY_VAR: value
      - wait
      - block: "Deploy?"
      - trigger: deploy-pipeline

The parser is lenient, a document without a top-level ``steps`` list
is skipped, so unrelated YAML files in the same directory don't get
double-scanned.
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .._yaml_lines import (
    line_of as _line_of,
)
from .._yaml_lines import (
    line_of_item as _line_of_item,
)
from .._yaml_lines import (
    safe_load_yaml_lines,
)
from ..base import BaseCheck, Location


@dataclass(frozen=True, slots=True)
class Pipeline:
    """A parsed Buildkite YAML document."""

    path: str
    data: dict[str, Any]


class BuildkiteContext:
    """Loaded set of Buildkite pipeline documents."""

    def __init__(self, pipelines: list[Pipeline]) -> None:
        self.pipelines = pipelines
        self.files_scanned: int = len(pipelines)
        self.files_skipped: int = 0
        self.warnings: list[str] = []

    @classmethod
    def from_path(cls, path: str | Path) -> BuildkiteContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--buildkite-path {root} does not exist. Pass a "
                "pipeline.yml file or a directory containing one."
            )
        if root.is_file():
            files = [root]
        else:
            # Prefer ``.buildkite/pipeline.yml`` when scanning a repo
            # root; also include any ``pipeline.yml`` / ``pipeline.yaml``
            # elsewhere in the tree so monorepos with one file per
            # service still scan completely. Preferred entries lead the
            # list so the canonical pipeline appears first in reports.
            preferred = sorted(
                p for p in root.rglob("*")
                if p.is_file()
                and p.parent.name == ".buildkite"
                and p.name in {"pipeline.yml", "pipeline.yaml"}
            )
            preferred_set = set(preferred)
            others = sorted(
                p for p in root.rglob("*")
                if p.is_file()
                and p.name in {"pipeline.yml", "pipeline.yaml"}
                and p not in preferred_set
            )
            files = preferred + others
        pipelines: list[Pipeline] = []
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
                data = safe_load_yaml_lines(text)
            except yaml.YAMLError as exc:
                first_line = str(exc).split("\n", 1)[0]
                warnings.append(f"{f}: YAML parse error: {first_line}")
                skipped += 1
                continue
            if not isinstance(data, dict):
                continue
            # Heuristic gate: a Buildkite pipeline file must declare
            # ``steps``. Skipping anything else avoids double-scanning
            # non-Buildkite YAML that happens to sit next to one.
            if not isinstance(data.get("steps"), list):
                continue
            pipelines.append(Pipeline(path=str(f), data=data))
        ctx = cls(pipelines)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


class BuildkiteBaseCheck(BaseCheck):
    """Base class for Buildkite rule modules."""

    PROVIDER = "buildkite"

    def __init__(self, ctx: BuildkiteContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: BuildkiteContext = ctx


# ── Helpers shared by multiple rule modules ────────────────────────────


def iter_command_steps(doc: dict[str, Any]) -> Iterator[tuple[int, dict[str, Any]]]:
    """Yield ``(index, step_dict)`` for every command-style step.

    Skips bare strings (``- wait``), ``wait`` / ``block`` / ``input`` /
    ``trigger`` flow-control steps, and group containers (which we
    recurse into). Group steps' ``steps:`` children are flattened into
    the iteration order.
    """
    steps = doc.get("steps") or []
    if not isinstance(steps, list):
        return
    idx = 0
    for raw in steps:
        if not isinstance(raw, dict):
            idx += 1
            continue
        # Flow-control steps don't carry a command; skip cleanly.
        if any(k in raw for k in ("wait", "block", "input", "trigger")):
            idx += 1
            continue
        # Group step, flatten its children with continued indices.
        if "group" in raw and isinstance(raw.get("steps"), list):
            for child in raw["steps"]:
                if isinstance(child, dict) and not any(
                    k in child for k in ("wait", "block", "input", "trigger")
                ):
                    yield idx, child
                    idx += 1
            continue
        yield idx, raw
        idx += 1


def step_label(step: dict[str, Any], fallback_idx: int) -> str:
    """Return a stable human name for a step, prefers ``key`` then ``label``."""
    for k in ("key", "label"):
        v = step.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return f"steps[{fallback_idx}]"


def step_commands(step: dict[str, Any]) -> list[str]:
    """Return every command string from a step.

    Buildkite accepts both ``command:`` and ``commands:``, each of which
    can be a single string or a list of strings. Normalize to a flat
    list of command strings.
    """
    out: list[str] = []
    for key in ("command", "commands"):
        v = step.get(key)
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    out.append(item)
    return out


def step_location(path: str, step: dict[str, Any]) -> Location:
    """Build a :class:`Location` pointing at *step* in *path*.

    Returns a path-only location when the loader didn't preserve line
    info, keeps the call sites uniform whether or not lines are
    available.
    """
    line = _line_of(step)
    return Location(path=path, start_line=line, end_line=line)


def plugin_location(
    path: str, step: dict[str, Any], plugin_idx: int,
) -> Location:
    """Locate a plugin entry inside ``step['plugins']``.

    Falls back to the step's line when the plugins list isn't
    line-tagged (defensive for non-line-aware loaders, e.g. tests).
    """
    plugins = step.get("plugins")
    line: int | None = None
    if isinstance(plugins, list):
        line = _line_of_item(plugins, plugin_idx)
    if line is None:
        line = _line_of(step)
    return Location(path=path, start_line=line, end_line=line)


def iter_plugins(step: dict[str, Any]) -> Iterator[tuple[str, Any]]:
    """Yield ``(plugin_ref, plugin_config)`` for each plugin entry on a step.

    Buildkite accepts a list of either bare strings (``- foo#v1``) or
    single-key dicts (``- foo#v1: {opt: val}``). Both forms produce a
    string key in the iteration; the value is the plugin's config dict
    or ``None``.
    """
    plugins = step.get("plugins")
    if isinstance(plugins, list):
        for entry in plugins:
            if isinstance(entry, str):
                yield entry, None
            elif isinstance(entry, dict):
                for ref, cfg in entry.items():
                    if isinstance(ref, str):
                        yield ref, cfg
    elif isinstance(plugins, dict):
        # Map form (less common but legal): ``plugins: {foo#v1: {...}}``.
        for ref, cfg in plugins.items():
            if isinstance(ref, str):
                yield ref, cfg
