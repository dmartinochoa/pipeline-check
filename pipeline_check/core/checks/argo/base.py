"""Argo Workflows context and base check.

Parses multi-doc YAML files and keeps documents whose ``apiVersion``
is ``argoproj.io/v1alpha1`` (or any future ``argoproj.io/*``).
Recognized kinds:

  - ``Workflow``                  — concrete run instance
  - ``WorkflowTemplate``          — namespaced template
  - ``ClusterWorkflowTemplate``   — cluster-scoped template
  - ``CronWorkflow``              — cron-triggered Workflow

Rules iterate ``self.ctx.docs``; helpers below normalize template
walking so a rule can iterate every container / script regardless of
whether it sits inside ``container:``, ``script:``, ``steps:``, or
``dag:``.
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..base import BaseCheck

ARGO_KINDS: frozenset[str] = frozenset({
    "Workflow", "WorkflowTemplate", "ClusterWorkflowTemplate",
    "CronWorkflow",
})


@dataclass(frozen=True)
class ArgoDoc:
    """One parsed Argo Workflows API document."""

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


class ArgoContext:
    """Loaded set of Argo Workflows documents."""

    def __init__(self, docs: list[ArgoDoc]) -> None:
        self.docs = docs
        self.files_scanned: int = len({d.path for d in docs})
        self.files_skipped: int = 0
        self.warnings: list[str] = []

    @classmethod
    def from_path(cls, path: str | Path) -> ArgoContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--argo-path {root} does not exist. Pass an Argo "
                "Workflow YAML file or a directory containing one."
            )
        if root.is_file():
            files = [root]
        else:
            files = sorted(
                p for p in root.rglob("*")
                if p.is_file() and p.suffix.lower() in {".yml", ".yaml"}
            )
        docs: list[ArgoDoc] = []
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
                parsed = list(yaml.safe_load_all(text))
            except yaml.YAMLError as exc:
                first_line = str(exc).split("\n", 1)[0]
                warnings.append(f"{f}: YAML parse error: {first_line}")
                skipped += 1
                continue
            for idx, raw in enumerate(parsed):
                d = _to_doc(str(f), idx, raw)
                if d is not None:
                    docs.append(d)
        ctx = cls(docs)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


def _to_doc(path: str, idx: int, doc: Any) -> ArgoDoc | None:
    if not isinstance(doc, dict):
        return None
    api_version = doc.get("apiVersion")
    kind = doc.get("kind")
    if not isinstance(api_version, str) or not isinstance(kind, str):
        return None
    group, sep, _version = api_version.partition("/")
    if sep != "/" or group != "argoproj.io":
        return None
    if kind not in ARGO_KINDS:
        return None
    metadata = doc.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {}
    name_val = metadata.get("name")
    name = name_val if isinstance(name_val, str) else ""
    ns_val = metadata.get("namespace")
    namespace = ns_val if isinstance(ns_val, str) else ""
    return ArgoDoc(
        path=path,
        doc_index=idx,
        api_version=api_version,
        kind=kind,
        name=name,
        namespace=namespace,
        data=doc,
    )


class ArgoBaseCheck(BaseCheck):
    """Base class for Argo Workflows rule modules."""

    PROVIDER = "argo"

    def __init__(self, ctx: ArgoContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: ArgoContext = ctx


# ── Helpers shared by multiple rule modules ────────────────────────────


def workflow_spec(doc: ArgoDoc) -> dict[str, Any]:
    """Return the document's effective workflow spec.

    For ``Workflow`` and ``WorkflowTemplate`` / ``ClusterWorkflowTemplate``
    the spec is at ``spec``. For ``CronWorkflow`` the workflow body is
    nested under ``spec.workflowSpec``.
    """
    spec = doc.data.get("spec") or {}
    if not isinstance(spec, dict):
        return {}
    if doc.kind == "CronWorkflow":
        inner = spec.get("workflowSpec") or {}
        return inner if isinstance(inner, dict) else {}
    return spec


def iter_templates(doc: ArgoDoc) -> Iterator[dict[str, Any]]:
    """Yield each template dict in the workflow spec.

    Handles the canonical ``spec.templates`` list. ``workflowTemplateRef``
    indirection has no inline template body and is skipped.
    """
    spec = workflow_spec(doc)
    templates = spec.get("templates")
    if isinstance(templates, list):
        for t in templates:
            if isinstance(t, dict):
                yield t


def template_name(template: dict[str, Any], idx: int) -> str:
    n = template.get("name")
    if isinstance(n, str) and n.strip():
        return n.strip()
    return f"templates[{idx}]"


def iter_containers(template: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield every container-shaped child of a template.

    Argo templates can use ``container``, ``script``, or ``containerSet``.
    All carry an ``image`` and ``securityContext`` in the same place; we
    yield each one as a dict so rules can read uniform fields.
    """
    for key in ("container", "script"):
        v = template.get(key)
        if isinstance(v, dict):
            yield v
    cs = template.get("containerSet")
    if isinstance(cs, dict):
        children = cs.get("containers")
        if isinstance(children, list):
            for c in children:
                if isinstance(c, dict):
                    yield c
