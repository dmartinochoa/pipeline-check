"""Harness CI/CD context and base check.

Loads Harness pipeline YAML from disk. Harness stores pipelines as
YAML (the "pipeline-as-code" / Git Experience form), usually under a
``.harness/`` directory but with no canonical filename, so the loader
globs ``*.yml`` / ``*.yaml`` and keeps the documents whose top-level
key is ``pipeline:`` (Harness's discriminator). A document that
carries ``template:`` (a step / stage template) or anything else is
skipped, so a directory mixing Harness with unrelated YAML is safe to
point at.

A Harness pipeline nests steps several levels deep: ``pipeline.stages``
is a list of ``{stage: {...}}`` (or ``{parallel: [{stage: ...}]}``)
entries, a CI stage's steps live under
``stage.spec.execution.steps``, and each step entry is a ``{step: ...}``,
a ``{parallel: [...]}`` group, or a ``{stepGroup: {steps: [...]}}``.
:func:`iter_steps` flattens all of that to the leaf ``step`` dicts.

Rules subclass :class:`HarnessBaseCheck` and iterate
``self.ctx.pipelines``.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .._yaml_files import load_yaml_files
from ..base import BaseCheck

#: Harness ``<+...>`` expressions whose value an outside contributor
#: controls through a pull request / webhook: the codebase identity and
#: ref / title / message fields, and the entire ``trigger`` / raw
#: ``eventPayload`` webhook context. ``<+codebase.commitSha>`` and
#: ``<+codebase.repoUrl>`` are intentionally excluded (a 40-hex SHA and
#: the configured repo URL are not attacker-controllable injection text).
#: The Harness analog of GHA-002's ``github.event.*`` taint set, shared by
#: HARNESS-002 (shell injection) and HARNESS-008 (AI prompt injection).
UNTRUSTED_EXPR_RE = re.compile(
    r"<\+\s*(?P<field>"
    r"codebase\.(?:gitUser|gitUserEmail|branch|sourceBranch|targetBranch|"
    r"prTitle|pullRequestTitle|pullRequestBody|commitMessage|commitRef|tag)"
    r"|trigger\."
    r"|eventPayload\."
    r")",
)


@dataclass(frozen=True, slots=True)
class HarnessPipeline:
    """A parsed Harness ``pipeline:`` document.

    ``data`` is the value of the top-level ``pipeline:`` key (the
    pipeline object itself), so rules read ``data['stages']`` directly.
    """

    path: str
    doc_index: int  # 0-based index within the multi-doc YAML stream
    data: dict[str, Any]

    @property
    def identifier(self) -> str:
        ident = self.data.get("identifier")
        if isinstance(ident, str) and ident.strip():
            return ident.strip()
        name = self.data.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
        return "pipeline"


class HarnessContext:
    """Loaded set of Harness pipeline documents."""

    def __init__(self, pipelines: list[HarnessPipeline]) -> None:
        self.pipelines = pipelines
        self.files_scanned: int = len({p.path for p in pipelines})
        self.files_skipped: int = 0
        self.warnings: list[str] = []

    @classmethod
    def from_path(cls, path: str | Path) -> HarnessContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--harness-path {root} does not exist. Pass a Harness "
                "pipeline YAML file or a directory containing one (for "
                "example a .harness/ folder)."
            )
        if root.is_file():
            files = [root]
        else:
            # Harness has no canonical filename, so match any YAML at any
            # depth; the ``pipeline:`` discriminator below filters out the
            # non-Harness documents.
            files = sorted(
                p for p in root.rglob("*")
                if p.is_file() and p.suffix in {".yml", ".yaml"}
            )
        loaded, warnings, skipped = load_yaml_files(files, multi_doc=True)
        pipelines: list[HarnessPipeline] = []
        for entry in loaded:
            for idx, data in enumerate(entry.docs):
                if not isinstance(data, dict):
                    continue
                pipeline = data.get("pipeline")
                if not isinstance(pipeline, dict):
                    continue
                pipelines.append(HarnessPipeline(
                    path=str(entry.path), doc_index=idx, data=pipeline,
                ))
        ctx = cls(pipelines)
        ctx.files_scanned = len(files)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


class HarnessBaseCheck(BaseCheck[HarnessContext]):
    """Base class for Harness rule modules."""

    PROVIDER = "harness"

    def __init__(
        self, ctx: HarnessContext, target: str | None = None,
    ) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: HarnessContext = ctx


# ── Helpers shared by multiple rule modules ───────────────────────────


def _iter_stage_dicts(pipeline: HarnessPipeline) -> Iterator[dict[str, Any]]:
    """Yield every ``stage`` dict, flattening stage-level ``parallel``."""
    stages = pipeline.data.get("stages")
    if not isinstance(stages, list):
        return
    for entry in stages:
        if not isinstance(entry, dict):
            continue
        stage = entry.get("stage")
        if isinstance(stage, dict):
            yield stage
            continue
        parallel = entry.get("parallel")
        if isinstance(parallel, list):
            for sub in parallel:
                if isinstance(sub, dict):
                    inner = sub.get("stage")
                    if isinstance(inner, dict):
                        yield inner


def _iter_step_dicts(steps: Any) -> Iterator[dict[str, Any]]:
    """Yield every leaf ``step`` dict from a ``steps:`` list.

    Recurses into ``parallel`` groups and ``stepGroup`` blocks so a
    step nested any number of levels deep is still visited.
    """
    if not isinstance(steps, list):
        return
    for entry in steps:
        if not isinstance(entry, dict):
            continue
        step = entry.get("step")
        if isinstance(step, dict):
            yield step
            continue
        parallel = entry.get("parallel")
        if isinstance(parallel, list):
            yield from _iter_step_dicts(parallel)
            continue
        group = entry.get("stepGroup")
        if isinstance(group, dict):
            yield from _iter_step_dicts(group.get("steps"))


def iter_steps(
    pipeline: HarnessPipeline,
) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield ``(stage_identifier, step_dict)`` for every step in the pipeline.

    Walks every stage (CI and CD), descending into the stage's
    ``spec.execution.steps`` and flattening ``parallel`` / ``stepGroup``
    nesting. The stage identifier labels each finding's offender.
    """
    for stage in _iter_stage_dicts(pipeline):
        ident = stage.get("identifier")
        stage_id = ident.strip() if isinstance(ident, str) and ident.strip() else "stage"
        spec = stage.get("spec")
        if not isinstance(spec, dict):
            continue
        execution = spec.get("execution")
        steps = execution.get("steps") if isinstance(execution, dict) else None
        for step in _iter_step_dicts(steps):
            yield stage_id, step


def iter_stages(
    pipeline: HarnessPipeline,
) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield ``(stage_identifier, stage_dict)`` for every stage.

    Flattens stage-level ``parallel`` groups. The stage dict is the raw
    ``stage:`` mapping (carrying ``type``, ``spec``, ``variables``, ...).
    """
    for stage in _iter_stage_dicts(pipeline):
        ident = stage.get("identifier")
        stage_id = ident.strip() if isinstance(ident, str) and ident.strip() else "stage"
        yield stage_id, stage


def step_label(stage_id: str, step: dict[str, Any]) -> str:
    """Stable ``stage/step`` name for a finding offender."""
    ident = step.get("identifier") or step.get("name")
    name = ident.strip() if isinstance(ident, str) and ident.strip() else "step"
    return f"{stage_id}/{name}"


def step_spec(step: dict[str, Any]) -> dict[str, Any]:
    """Return a step's ``spec:`` dict (empty when absent / malformed)."""
    spec = step.get("spec")
    return spec if isinstance(spec, dict) else {}


def step_command_text(step: dict[str, Any]) -> str:
    """Return a step's ``spec.command`` as text (joining a list form).

    Harness ``Run`` steps carry the script in ``spec.command``, usually a
    multi-line string but occasionally a list; both normalize to one text
    blob for command scanning.
    """
    cmd = step_spec(step).get("command")
    if isinstance(cmd, str):
        return cmd
    if isinstance(cmd, list):
        return "\n".join(c for c in cmd if isinstance(c, str))
    return ""


def iter_variables(
    pipeline: HarnessPipeline,
) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield ``(scope_label, variable_dict)`` for every declared pipeline /
    stage variable.

    Harness ``variables:`` entries are ``{name, type, value}`` dicts and
    appear at the pipeline level (``pipeline.variables``) and per stage
    (``stage.variables``). The scope label (``pipeline`` or a stage
    identifier) prefixes the finding offender.
    """
    pvars = pipeline.data.get("variables")
    if isinstance(pvars, list):
        for var in pvars:
            if isinstance(var, dict):
                yield "pipeline", var
    for stage in _iter_stage_dicts(pipeline):
        svars = stage.get("variables")
        if not isinstance(svars, list):
            continue
        ident = stage.get("identifier")
        scope = ident.strip() if isinstance(ident, str) and ident.strip() else "stage"
        for var in svars:
            if isinstance(var, dict):
                yield scope, var
