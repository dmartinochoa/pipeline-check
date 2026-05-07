"""Tekton context and base check.

Parses multi-doc YAML files and keeps only documents whose
``apiVersion`` is ``tekton.dev/v1`` (or ``tekton.dev/v1beta1``,
``tekton.dev/v1alpha1``). Recognized kinds:

  - ``Task`` / ``ClusterTask``       — define reusable steps
  - ``Pipeline``                     — composes Tasks
  - ``TaskRun`` / ``PipelineRun``    — concrete runtime instances

Rules iterate ``self.ctx.docs`` and dispatch on ``.kind``. The shape
each rule walks is the parsed Kubernetes-style API object — Tekton's
schema is just CRDs, so the parsing layer is identical to the
plain-Kubernetes provider but with a stricter API-group filter.
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..base import BaseCheck

#: Kinds we recognize as Tekton resources.
TEKTON_KINDS: frozenset[str] = frozenset({
    "Task", "ClusterTask", "Pipeline", "TaskRun", "PipelineRun",
})


@dataclass(frozen=True)
class TektonDoc:
    """One parsed Tekton API document."""

    path: str
    doc_index: int
    api_version: str
    kind: str
    name: str
    namespace: str
    data: dict[str, Any]

    @property
    def display(self) -> str:
        ns = self.namespace or "(no-namespace)"
        return f"{self.kind}/{self.name} in {ns} ({self.path}#{self.doc_index})"


class TektonContext:
    """Loaded set of Tekton documents."""

    def __init__(self, docs: list[TektonDoc]) -> None:
        self.docs = docs
        self.files_scanned: int = len({d.path for d in docs})
        self.files_skipped: int = 0
        self.warnings: list[str] = []

    @classmethod
    def from_path(cls, path: str | Path) -> TektonContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--tekton-path {root} does not exist. Pass a Tekton "
                "YAML file or a directory containing one."
            )
        if root.is_file():
            files = [root]
        else:
            files = sorted(
                p for p in root.rglob("*")
                if p.is_file() and p.suffix.lower() in {".yml", ".yaml"}
            )
        docs: list[TektonDoc] = []
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
                from .._yaml_lines import safe_load_all_with_lines
                parsed_with_lines = list(safe_load_all_with_lines(text))
            except yaml.YAMLError as exc:
                first_line = str(exc).split("\n", 1)[0]
                warnings.append(f"{f}: YAML parse error: {first_line}")
                skipped += 1
                continue
            for idx, (_doc_start_line, raw) in enumerate(parsed_with_lines):
                d = _to_doc(str(f), idx, raw)
                if d is not None:
                    docs.append(d)
        ctx = cls(docs)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


def _to_doc(path: str, idx: int, doc: Any) -> TektonDoc | None:
    if not isinstance(doc, dict):
        return None
    api_version = doc.get("apiVersion")
    kind = doc.get("kind")
    if not isinstance(api_version, str) or not isinstance(kind, str):
        return None
    group, sep, _version = api_version.partition("/")
    if sep != "/" or group != "tekton.dev":
        return None
    if kind not in TEKTON_KINDS:
        return None
    metadata = doc.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {}
    name_val = metadata.get("name")
    name = name_val if isinstance(name_val, str) else ""
    ns_val = metadata.get("namespace")
    namespace = ns_val if isinstance(ns_val, str) else ""
    return TektonDoc(
        path=path,
        doc_index=idx,
        api_version=api_version,
        kind=kind,
        name=name,
        namespace=namespace,
        data=doc,
    )


class TektonBaseCheck(BaseCheck):
    """Base class for Tekton rule modules."""

    PROVIDER = "tekton"

    def __init__(self, ctx: TektonContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: TektonContext = ctx


# ── Helpers shared by multiple rule modules ────────────────────────────


def task_steps(doc: TektonDoc) -> list[dict[str, Any]]:
    """Return the ``spec.steps`` list of a Task / ClusterTask, or [].

    Works for ``Task`` and ``ClusterTask``. ``Pipeline`` and ``*Run``
    kinds don't have steps directly — they reference Tasks.
    """
    if doc.kind not in ("Task", "ClusterTask"):
        return []
    spec = doc.data.get("spec") or {}
    if not isinstance(spec, dict):
        return []
    steps = spec.get("steps") or []
    if not isinstance(steps, list):
        return []
    return [s for s in steps if isinstance(s, dict)]


def pipeline_tasks(doc: TektonDoc) -> list[dict[str, Any]]:
    """Return the ``spec.tasks`` list of a Pipeline, or []."""
    if doc.kind != "Pipeline":
        return []
    spec = doc.data.get("spec") or {}
    if not isinstance(spec, dict):
        return []
    tasks = spec.get("tasks") or []
    if not isinstance(tasks, list):
        return []
    return [t for t in tasks if isinstance(t, dict)]


def step_name(step: dict[str, Any], idx: int) -> str:
    n = step.get("name")
    if isinstance(n, str) and n.strip():
        return n.strip()
    return f"steps[{idx}]"


def iter_step_scripts(doc: TektonDoc) -> Iterator[tuple[str, str]]:
    """Yield ``(step_name, script_text)`` for every step that has a script."""
    for idx, step in enumerate(task_steps(doc)):
        script = step.get("script")
        if isinstance(script, str) and script:
            yield step_name(step, idx), script


def iter_step_commands(doc: TektonDoc) -> Iterator[tuple[str, list[str]]]:
    """Yield ``(step_name, command_args)`` for every step using
    ``command:`` / ``args:``. Returns the joined arg list as strings."""
    for idx, step in enumerate(task_steps(doc)):
        parts: list[str] = []
        cmd = step.get("command")
        if isinstance(cmd, list):
            parts.extend(c for c in cmd if isinstance(c, str))
        args = step.get("args")
        if isinstance(args, list):
            parts.extend(a for a in args if isinstance(a, str))
        if parts:
            yield step_name(step, idx), parts
