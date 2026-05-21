"""Argo CD context and base check.

Parses multi-doc YAML on disk and keeps two disjoint document
families:

  - ``argoproj.io/v1alpha1`` ``Application`` / ``ApplicationSet`` /
    ``AppProject`` CRDs.
  - core ``v1 ConfigMap`` documents named ``argocd-cm`` or
    ``argocd-rbac-cm`` (Argo CD's anonymous-access toggle, repo
    credential blocks, and RBAC ``policy.csv`` live in plain
    ConfigMaps, not under the ``argoproj.io`` group).

Argo Workflows already owns the ``argoproj.io`` ``Workflow*`` /
``CronWorkflow`` kinds via ``checks/argo``. The two providers are
deliberately disjoint: each one's kind filter rejects the other's
docs so pointing them at the same directory under
``--pipelines argo,argocd`` produces disjoint findings rather than
double-counting.
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .._yaml_files import load_yaml_files
from ..base import BaseCheck

#: Argo CD CRDs we care about, under ``argoproj.io/v1alpha1``.
ARGOCD_CRD_KINDS: frozenset[str] = frozenset({
    "Application", "ApplicationSet", "AppProject",
})

#: The two ConfigMaps Argo CD reads its instance-wide config from.
#: Both live at ``v1 ConfigMap`` (NOT under ``argoproj.io``).
ARGOCD_CONFIGMAPS: frozenset[str] = frozenset({
    "argocd-cm", "argocd-rbac-cm",
})


@dataclass(frozen=True, slots=True)
class ArgoCDDoc:
    """One parsed Argo CD document.

    ``api_version`` is the raw apiVersion string (``argoproj.io/v1alpha1``
    for CRDs, ``v1`` for the config ConfigMaps).
    """

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


class ArgoCDContext:
    """Loaded set of Argo CD documents."""

    def __init__(self, docs: list[ArgoCDDoc]) -> None:
        self.docs = docs
        self.files_scanned: int = len({d.path for d in docs})
        self.files_skipped: int = 0
        self.warnings: list[str] = []

    @classmethod
    def from_path(cls, path: str | Path) -> ArgoCDContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--argocd-path {root} does not exist. Pass an Argo "
                "CD YAML file (Application / ApplicationSet / AppProject "
                "or argocd-cm / argocd-rbac-cm) or a directory "
                "containing one."
            )
        if root.is_file():
            files = [root]
        else:
            files = sorted(
                p for p in root.rglob("*")
                if p.is_file() and p.suffix.lower() in {".yml", ".yaml"}
            )
        loaded, warnings, skipped = load_yaml_files(files, multi_doc=True)
        docs: list[ArgoCDDoc] = []
        for entry in loaded:
            for idx, raw in enumerate(entry.docs):
                d = _to_doc(str(entry.path), idx, raw)
                if d is not None:
                    docs.append(d)
        ctx = cls(docs)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


def _to_doc(path: str, idx: int, doc: Any) -> ArgoCDDoc | None:
    if not isinstance(doc, dict):
        return None
    api_version = doc.get("apiVersion")
    kind = doc.get("kind")
    if not isinstance(api_version, str) or not isinstance(kind, str):
        return None
    metadata = doc.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {}
    name_val = metadata.get("name")
    name = name_val if isinstance(name_val, str) else ""
    ns_val = metadata.get("namespace")
    namespace = ns_val if isinstance(ns_val, str) else ""

    group, sep, _version = api_version.partition("/")
    if sep == "/" and group == "argoproj.io":
        if kind not in ARGOCD_CRD_KINDS:
            return None
    elif api_version == "v1" and kind == "ConfigMap":
        if name not in ARGOCD_CONFIGMAPS:
            return None
    else:
        return None

    return ArgoCDDoc(
        path=path,
        doc_index=idx,
        api_version=api_version,
        kind=kind,
        name=name,
        namespace=namespace,
        data=doc,
    )


class ArgoCDBaseCheck(BaseCheck[ArgoCDContext]):
    """Base class for Argo CD rule modules."""

    PROVIDER = "argocd"

    def __init__(self, ctx: ArgoCDContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: ArgoCDContext = ctx


# ── Helpers shared by multiple rule modules ────────────────────────────


def iter_applications(ctx: ArgoCDContext) -> Iterator[ArgoCDDoc]:
    for d in ctx.docs:
        if d.kind == "Application":
            yield d


def iter_applicationsets(ctx: ArgoCDContext) -> Iterator[ArgoCDDoc]:
    for d in ctx.docs:
        if d.kind == "ApplicationSet":
            yield d


def iter_appprojects(ctx: ArgoCDContext) -> Iterator[ArgoCDDoc]:
    for d in ctx.docs:
        if d.kind == "AppProject":
            yield d


def argocd_cm(ctx: ArgoCDContext) -> ArgoCDDoc | None:
    for d in ctx.docs:
        if d.kind == "ConfigMap" and d.name == "argocd-cm":
            return d
    return None


def argocd_rbac_cm(ctx: ArgoCDContext) -> ArgoCDDoc | None:
    for d in ctx.docs:
        if d.kind == "ConfigMap" and d.name == "argocd-rbac-cm":
            return d
    return None


def application_sources(app: ArgoCDDoc) -> Iterator[dict[str, Any]]:
    """Yield every source dict on an ``Application`` or
    ``ApplicationSet.spec.template`` doc.

    Argo CD allows either the single-source form (``spec.source``) or
    the multi-source form (``spec.sources``). For ``ApplicationSet``
    the same shape lives one level deeper under ``spec.template.spec``.
    """
    if app.kind == "ApplicationSet":
        tmpl = (app.data.get("spec") or {}).get("template") or {}
        spec = tmpl.get("spec") if isinstance(tmpl, dict) else None
    else:
        spec = app.data.get("spec")
    if not isinstance(spec, dict):
        return
    single = spec.get("source")
    if isinstance(single, dict):
        yield single
    multi = spec.get("sources")
    if isinstance(multi, list):
        for s in multi:
            if isinstance(s, dict):
                yield s
