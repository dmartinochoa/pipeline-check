"""Kubernetes manifest provider — scans Kubernetes API documents on disk.

    pipeline_check --pipeline kubernetes --k8s-path path/to/manifests/

Text-only YAML parsing — no `kubectl`, no cluster access, no Helm or
Kustomize rendering. Helm chart values and kustomization base files
are silently skipped (they don't carry the canonical
``apiVersion`` + ``kind`` shape).
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.kubernetes.base import KubernetesContext
from ..checks.kubernetes.manifests import KubernetesManifestChecks
from ..inventory import Component
from .base import BaseProvider


class KubernetesProvider(BaseProvider):
    """Kubernetes provider — parses K8s API YAML manifests."""

    NAME = "kubernetes"

    def build_context(
        self,
        k8s_path: str | None = None,
        **_: Any,
    ) -> KubernetesContext:
        if not k8s_path:
            raise ValueError(
                "The kubernetes provider requires --k8s-path "
                "<file-or-dir> pointing at a Kubernetes manifest "
                "or a directory containing one."
            )
        return KubernetesContext.from_path(k8s_path)

    @property
    def check_classes(self) -> list[type[BaseCheck]]:
        return [KubernetesManifestChecks]

    def inventory(self, context: KubernetesContext) -> list[Component]:
        out: list[Component] = []
        for m in context.manifests:
            metadata: dict[str, Any] = {
                "api_version": m.api_version,
                "kind": m.kind,
                "namespace": m.namespace or "(no-namespace)",
                "doc_index": m.doc_index,
            }
            out.append(Component(
                provider=self.NAME,
                type=m.kind,
                identifier=m.name or f"{m.path}#{m.doc_index}",
                source=m.path,
                metadata=metadata,
            ))
        return out
