"""Unit tests for K8S-028 — Container declares hostPort."""
from __future__ import annotations

from typing import Any

from pipeline_check.core.checks.kubernetes.base import (
    KubernetesContext,
    Manifest,
)
from pipeline_check.core.checks.kubernetes.rules import (
    k8s028_container_host_port as r28,
)


def _ctx(*docs: dict[str, Any]) -> KubernetesContext:
    manifests = []
    for idx, doc in enumerate(docs):
        api_version = doc.get("apiVersion", "v1")
        kind = doc.get("kind", "Deployment")
        metadata = doc.get("metadata") or {}
        manifests.append(Manifest(
            path=f"manifest-{idx}.yaml",
            doc_index=idx,
            api_version=api_version,
            kind=kind,
            name=metadata.get("name", "x"),
            namespace=metadata.get("namespace", "default"),
            data=doc,
        ))
    return KubernetesContext(manifests)


def _deployment(*, name: str, ports: list[dict[str, Any]] | None) -> dict[str, Any]:
    container: dict[str, Any] = {
        "name": "c",
        "image": "nginx@sha256:" + "0" * 63 + "1",
    }
    if ports is not None:
        container["ports"] = ports
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": "prod"},
        "spec": {"template": {"spec": {"containers": [container]}}},
    }


class TestK8S028HostPort:
    def test_fails_when_container_declares_host_port(self):
        f = r28.check(_ctx(_deployment(
            name="exposed",
            ports=[{"containerPort": 8080, "hostPort": 8080}],
        )))
        assert not f.passed
        assert "hostPort=8080" in f.description

    def test_passes_with_container_port_only(self):
        f = r28.check(_ctx(_deployment(
            name="ok",
            ports=[{"containerPort": 8080}],
        )))
        assert f.passed

    def test_passes_when_no_ports_declared(self):
        f = r28.check(_ctx(_deployment(name="ok", ports=None)))
        assert f.passed

    def test_passes_when_host_port_is_zero(self):
        # Zero is the unset sentinel — kubelet treats it as no binding.
        f = r28.check(_ctx(_deployment(
            name="ok",
            ports=[{"containerPort": 8080, "hostPort": 0}],
        )))
        assert f.passed
