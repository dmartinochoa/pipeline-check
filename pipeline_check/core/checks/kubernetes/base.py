"""Kubernetes manifest context and base check.

Parses Kubernetes API documents from ``*.yaml`` / ``*.yml`` on disk.
Each parsed document — single-doc or one slice of a multi-doc YAML —
becomes a :class:`Manifest`. Checks subclass :class:`KubernetesBaseCheck`
and iterate ``self.ctx.manifests``.

The parser is deliberately lenient: documents that don't carry the
canonical ``apiVersion`` + ``kind`` shape are silently skipped, so a
directory mixing K8s manifests with helm ``values.yaml`` /
``Chart.yaml`` / kustomization files won't trip the loader. Helm
charts and kustomize bases are intentionally out of scope for this
provider — they need rendering, which would require a `helm` or
`kustomize` binary.

Workload kinds (``Deployment``, ``StatefulSet``, ``DaemonSet``,
``Job``, ``CronJob``, ``ReplicaSet``, ``Pod``) all expose a pod
spec, but at different paths. :func:`pod_specs` normalises that and
yields ``(path_prefix, podspec)`` tuples; rules iterate that rather
than walking each kind themselves.
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..base import BaseCheck

#: Workload kinds whose pod spec lives at ``spec.template.spec``.
_TEMPLATE_WORKLOAD_KINDS: frozenset[str] = frozenset({
    "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job",
})

#: ``CronJob`` nests an extra ``jobTemplate`` between spec and template.
_CRONJOB_KIND = "CronJob"

#: ``Pod`` has the pod spec directly at ``spec``.
_POD_KIND = "Pod"

#: All kinds that carry a pod spec.
WORKLOAD_KINDS: frozenset[str] = (
    _TEMPLATE_WORKLOAD_KINDS | {_CRONJOB_KIND, _POD_KIND}
)


@dataclass(frozen=True, slots=True)
class Manifest:
    """One parsed Kubernetes API document."""

    path: str
    doc_index: int
    api_version: str
    kind: str
    name: str
    namespace: str
    data: dict[str, Any]
    #: For manifests sourced from a Helm render, the chart-relative
    #: template path (e.g. ``mychart/templates/deployment.yaml``) that
    #: produced this doc. ``None`` for manifests loaded directly from
    #: disk by the kubernetes provider.
    source_template: str | None = None

    @property
    def display(self) -> str:
        """Stable human-readable identifier for findings."""
        ns = self.namespace or "(no-namespace)"
        loc = self.source_template or self.path
        return f"{self.kind}/{self.name} in {ns} ({loc}#{self.doc_index})"


class KubernetesContext:
    """Loaded set of Kubernetes manifests."""

    def __init__(self, manifests: list[Manifest]) -> None:
        self.manifests = manifests
        self.files_scanned: int = len({m.path for m in manifests})
        self.files_skipped: int = 0
        self.warnings: list[str] = []

    @classmethod
    def from_path(cls, path: str | Path) -> KubernetesContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--k8s-path {root} does not exist. Pass a Kubernetes "
                "YAML manifest or a directory containing one."
            )
        if root.is_file():
            files = [root]
        else:
            files = sorted(
                p for p in root.rglob("*")
                if p.is_file() and p.suffix.lower() in {".yml", ".yaml"}
            )
        manifests: list[Manifest] = []
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
                docs_with_lines = list(safe_load_all_with_lines(text))
            except yaml.YAMLError as exc:
                first_line = str(exc).split("\n", 1)[0]
                warnings.append(f"{f}: YAML parse error: {first_line}")
                skipped += 1
                continue
            for idx, (_doc_start_line, doc) in enumerate(docs_with_lines):
                m = _to_manifest(str(f), idx, doc)
                if m is not None:
                    manifests.append(m)
        ctx = cls(manifests)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx

    @classmethod
    def from_yaml_stream(
        cls,
        text: str,
        path_hint: str = "<rendered>",
        source_templates: list[str | None] | None = None,
    ) -> KubernetesContext:
        """Parse already-rendered YAML text into a KubernetesContext.

        Used by the Helm provider, which shells out to ``helm template``
        and feeds the resulting multi-doc YAML stream through this same
        rule pack.

        Parameters
        ----------
        text:
            Rendered YAML, possibly multi-doc.
        path_hint:
            Synthetic path stored on each ``Manifest.path``. Reporters
            read ``path`` for grouping; the chart-relative source
            template (when known) goes on ``source_template`` instead.
        source_templates:
            Optional per-doc list of chart-relative template paths
            aligned with the order docs appear in *text*. ``None``
            entries (and a missing list entirely) mean "unknown
            source." The Helm renderer parses ``# Source:`` headers
            to populate this.
        """
        ctx = cls([])
        try:
            docs = list(yaml.safe_load_all(text))
        except yaml.YAMLError as exc:
            first_line = str(exc).split("\n", 1)[0]
            ctx.warnings = [f"{path_hint}: YAML parse error: {first_line}"]
            return ctx
        manifests: list[Manifest] = []
        for idx, doc in enumerate(docs):
            src_tpl: str | None = None
            if source_templates is not None and idx < len(source_templates):
                src_tpl = source_templates[idx]
            m = _to_manifest(path_hint, idx, doc, source_template=src_tpl)
            if m is not None:
                manifests.append(m)
        ctx.manifests = manifests
        ctx.files_scanned = 1 if manifests else 0
        return ctx


def _to_manifest(
    path: str,
    idx: int,
    doc: Any,
    source_template: str | None = None,
) -> Manifest | None:
    """Best-effort conversion of one parsed YAML doc to :class:`Manifest`.

    Returns None for documents that don't look like K8s API objects
    (no ``apiVersion`` + ``kind``). This is how helm ``values.yaml`` and
    kustomization files get filtered out without raising.
    """
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
    return Manifest(
        path=path,
        doc_index=idx,
        api_version=api_version,
        kind=kind,
        name=name,
        namespace=namespace,
        data=doc,
        source_template=source_template,
    )


class KubernetesBaseCheck(BaseCheck):
    """Base class for Kubernetes manifest rule modules."""

    PROVIDER = "kubernetes"

    def __init__(
        self, ctx: KubernetesContext, target: str | None = None,
    ) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: KubernetesContext = ctx


# ── Helpers shared by multiple rule modules ────────────────────────────


def is_workload(m: Manifest) -> bool:
    """Return True if *m*'s kind has a pod spec we can scan."""
    return m.kind in WORKLOAD_KINDS


def pod_spec(m: Manifest) -> dict[str, Any] | None:
    """Return the pod spec dict for a workload manifest, or None.

    Path varies by kind:
      - Pod: ``spec``
      - Deployment / StatefulSet / DaemonSet / ReplicaSet / Job:
        ``spec.template.spec``
      - CronJob: ``spec.jobTemplate.spec.template.spec``
    """
    spec = m.data.get("spec")
    if not isinstance(spec, dict):
        return None
    if m.kind == _POD_KIND:
        return spec
    if m.kind in _TEMPLATE_WORKLOAD_KINDS:
        template = spec.get("template")
        if not isinstance(template, dict):
            return None
        inner = template.get("spec")
        return inner if isinstance(inner, dict) else None
    if m.kind == _CRONJOB_KIND:
        job_template = spec.get("jobTemplate")
        if not isinstance(job_template, dict):
            return None
        job_spec = job_template.get("spec")
        if not isinstance(job_spec, dict):
            return None
        template = job_spec.get("template")
        if not isinstance(template, dict):
            return None
        inner = template.get("spec")
        return inner if isinstance(inner, dict) else None
    return None


def iter_containers(
    podspec: dict[str, Any],
) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield ``(kind_label, container_dict)`` across all container lists.

    ``kind_label`` is ``container``, ``initContainer``, or
    ``ephemeralContainer`` so rules can scope by container family.
    """
    for key, label in (
        ("containers", "container"),
        ("initContainers", "initContainer"),
        ("ephemeralContainers", "ephemeralContainer"),
    ):
        items = podspec.get(key)
        if not isinstance(items, list):
            continue
        for c in items:
            if isinstance(c, dict):
                yield label, c


def container_name(c: dict[str, Any], fallback: str = "?") -> str:
    n = c.get("name")
    return n if isinstance(n, str) and n.strip() else fallback


def iter_volumes(podspec: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield each volume dict from ``spec.volumes``."""
    vols = podspec.get("volumes")
    if not isinstance(vols, list):
        return
    for v in vols:
        if isinstance(v, dict):
            yield v


def iter_workload_pod_specs(
    ctx: KubernetesContext,
) -> Iterator[tuple[Manifest, dict[str, Any]]]:
    """Yield ``(manifest, podspec)`` for every workload manifest in *ctx*."""
    for m in ctx.manifests:
        if not is_workload(m):
            continue
        ps = pod_spec(m)
        if ps is not None:
            yield m, ps


__all__ = [
    "KubernetesBaseCheck",
    "KubernetesContext",
    "Manifest",
    "WORKLOAD_KINDS",
    "container_name",
    "is_workload",
    "iter_containers",
    "iter_volumes",
    "iter_workload_pod_specs",
    "pod_spec",
]
