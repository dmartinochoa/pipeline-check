"""Shared helpers for Kubernetes manifest per-rule tests.

K8s rules each take a ``KubernetesContext`` (a list of parsed
manifests), unlike the YAML-provider rules which take ``(path, doc)``.
This conftest exposes a ``run_check(manifest, check_id)`` helper that
wraps a single inline manifest dict in a context, runs the
orchestrator, and returns the matching ``Finding``.
"""
from __future__ import annotations

from typing import Any

from pipeline_check.core.checks.kubernetes.base import (
    KubernetesContext,
    Manifest,
)
from pipeline_check.core.checks.kubernetes.manifests import (
    KubernetesManifestChecks,
)


def k8s_ctx(*docs: dict[str, Any]) -> KubernetesContext:
    """Build a KubernetesContext from a sequence of parsed YAML docs."""
    manifests = []
    for idx, doc in enumerate(docs):
        api_version = doc.get("apiVersion", "v1")
        kind = doc.get("kind", "Pod")
        metadata = doc.get("metadata") or {}
        manifests.append(Manifest(
            path=f"manifest-{idx}.yaml",
            doc_index=idx,
            api_version=api_version,
            kind=kind,
            name=metadata.get("name", "x"),
            namespace=metadata.get("namespace", ""),
            data=doc,
        ))
    return KubernetesContext(manifests)


def run_check(manifest: dict[str, Any], check_id: str):
    """Run every K8s check on a single manifest; return the matching Finding."""
    ctx = k8s_ctx(manifest)
    for f in KubernetesManifestChecks(ctx).run():
        if f.check_id == check_id:
            return f
    raise AssertionError(
        f"check_id {check_id!r} not found in K8s orchestrator output"
    )


def pod(
    *,
    name: str = "app",
    namespace: str = "default",
    containers: list[dict[str, Any]] | None = None,
    pod_spec_extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a minimal Deployment manifest with a single container."""
    spec: dict[str, Any] = {
        "containers": containers or [{
            "name": "c",
            "image": "nginx@sha256:0000000000000000000000000000000000000000000000000000000000000001",
        }],
    }
    if pod_spec_extra:
        spec.update(pod_spec_extra)
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"template": {"spec": spec}},
    }
