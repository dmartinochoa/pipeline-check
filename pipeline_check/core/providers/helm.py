"""Helm provider — renders charts via ``helm template`` and reuses the K8s rule pack.

    pipeline_check --pipeline helm --helm-path path/to/chart \\
        [--helm-values values-prod.yaml] [--helm-set key=value]

Shells out to the local ``helm`` (Helm 3) binary, parses the rendered
multi-doc YAML stream, and feeds it through every existing K8S-* rule.
No Helm-specific rules ship in this provider yet; the value here is
that today's K8s rules now apply to chart-deployed workloads, which is
how most production K8s actually ships.

The chart is rendered with synthetic ``.Release.Name = "pipeline-check"``
and ``.Release.Namespace = "default"``. Charts that require live cluster
state (``.Capabilities.APIVersions``, ``lookup``) render against Helm's
default capability set, which means cluster-version-conditional logic
won't reflect a real target. That is acceptable for a static scanner —
the alternative is to require cluster credentials, which crosses the
"text-only static analysis" line the rest of the providers respect.
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.helm.base import HelmContext
from ..checks.kubernetes.manifests import KubernetesManifestChecks
from ..inventory import Component
from .base import BaseProvider


class HelmProvider(BaseProvider):
    """Helm provider — renders charts and runs the K8s rule pack on them."""

    NAME = "helm"

    def build_context(
        self,
        helm_path: str | None = None,
        helm_values: list[str] | tuple[str, ...] | None = None,
        helm_set: list[str] | tuple[str, ...] | None = None,
        **_: Any,
    ) -> HelmContext:
        if not helm_path:
            raise ValueError(
                "The helm provider requires --helm-path "
                "<chart-dir|chart.tgz|parent-dir> pointing at a Helm "
                "chart, a packaged chart, or a directory containing "
                "one or more charts."
            )
        values = list(helm_values) if helm_values else None
        sets = list(helm_set) if helm_set else None
        return HelmContext.from_path(
            helm_path, values_files=values, set_overrides=sets,
        )

    @property
    def check_classes(self) -> list[type[BaseCheck]]:
        # Same orchestrator as the kubernetes provider — every K8S-*
        # rule applies unchanged because HelmContext IS-A
        # KubernetesContext. Helm-native rules (HELM-001..) are
        # deferred to a follow-up release per the v0.5.0 scope.
        return [KubernetesManifestChecks]

    def inventory(self, context: HelmContext) -> list[Component]:
        out: list[Component] = []
        for m in context.manifests:
            metadata: dict[str, Any] = {
                "api_version": m.api_version,
                "kind": m.kind,
                "namespace": m.namespace or "(no-namespace)",
                "doc_index": m.doc_index,
                "source_template": m.source_template or "(unknown)",
            }
            out.append(Component(
                provider=self.NAME,
                type=m.kind,
                identifier=m.name or f"{m.path}#{m.doc_index}",
                source=m.source_template or m.path,
                metadata=metadata,
            ))
        return out
