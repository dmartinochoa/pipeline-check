"""Bitbucket Pipelines context and base check.

The context loads a ``bitbucket-pipelines.yml`` document from disk and
exposes every step across every pipeline category (default, branches,
pull-requests, tags, custom) as a flat iterable.
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..base import BaseCheck, safe_load_yaml


@dataclass(frozen=True)
class Pipeline:
    """A parsed bitbucket-pipelines.yml document."""

    path: str
    data: dict[str, Any]


class BitbucketContext:
    """One or more bitbucket-pipelines.yml documents."""

    def __init__(self, pipelines: list[Pipeline]) -> None:
        self.pipelines = pipelines
        self.files_scanned: int = len(pipelines)
        self.files_skipped: int = 0
        self.warnings: list[str] = []

    @classmethod
    def from_path(cls, path: str | Path) -> BitbucketContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--bitbucket-path {root} does not exist. Pass a "
                f"bitbucket-pipelines.yml file or a directory containing one."
            )
        if root.is_file():
            files = [root]
        else:
            files = sorted(
                p for p in root.rglob("*")
                if p.is_file() and p.name in {
                    "bitbucket-pipelines.yml", "bitbucket-pipelines.yaml",
                }
            )
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
                data = safe_load_yaml(text)
            except yaml.YAMLError as exc:
                first_line = str(exc).split("\n", 1)[0]
                warnings.append(f"{f}: YAML parse error: {first_line}")
                skipped += 1
                continue
            if not isinstance(data, dict):
                continue
            pipelines.append(Pipeline(path=str(f), data=data))
        ctx = cls(pipelines)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


class BitbucketBaseCheck(BaseCheck):
    """Base class for Bitbucket Pipelines checks."""

    PROVIDER = "bitbucket"

    def __init__(self, ctx: BitbucketContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: BitbucketContext = ctx


def iter_steps(doc: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield ``(location, step_dict)`` for every step in the pipelines block.

    ``location`` is a human-readable handle (e.g. ``default[0]``,
    ``branches.main[1]``, ``custom.nightly[0]``) used as the finding's
    resource label.
    """
    pipelines = doc.get("pipelines")
    if not isinstance(pipelines, dict):
        return
    for category, value in pipelines.items():
        if isinstance(value, list):
            yield from _walk_steps(str(category), value)
        elif isinstance(value, dict):
            for sub, items in value.items():
                if isinstance(items, list):
                    yield from _walk_steps(f"{category}.{sub}", items)


def _walk_steps(prefix: str, items: list[Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    for idx, entry in enumerate(items):
        if not isinstance(entry, dict):
            continue
        if "step" in entry and isinstance(entry["step"], dict):
            yield f"{prefix}[{idx}]", entry["step"]
        elif "parallel" in entry:
            parallel = entry["parallel"]
            # parallel: [ {step: {...}}, ... ] or {steps: [...]}
            par_steps = (
                parallel.get("steps") if isinstance(parallel, dict) else parallel
            )
            if isinstance(par_steps, list):
                for jdx, psub in enumerate(par_steps):
                    if isinstance(psub, dict) and isinstance(psub.get("step"), dict):
                        yield f"{prefix}[{idx}].parallel[{jdx}]", psub["step"]
        elif "stage" in entry and isinstance(entry["stage"], dict):
            st = entry["stage"]
            inner = st.get("steps")
            if isinstance(inner, list):
                for jdx, sub in enumerate(inner):
                    if isinstance(sub, dict) and isinstance(sub.get("step"), dict):
                        yield f"{prefix}[{idx}].stage[{jdx}]", sub["step"]


def step_scripts(step: dict[str, Any]) -> list[str]:
    """Return every `script:` line in *step* (Bitbucket `script:` is a list)."""
    out: list[str] = []
    script = step.get("script")
    if isinstance(script, list):
        for item in script:
            if isinstance(item, str):
                out.append(item)
    elif isinstance(script, str):
        out.append(script)
    return out
