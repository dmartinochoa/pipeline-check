"""Unit tests for K8S-027 — Ingress without TLS configuration.

Pattern matches ``test_k8s_rules_023_to_026.py``: build a
``KubernetesContext`` from inline manifest dicts and call the rule's
``check()`` directly.
"""
from __future__ import annotations

from typing import Any

from pipeline_check.core.checks.kubernetes.base import (
    KubernetesContext,
    Manifest,
)
from pipeline_check.core.checks.kubernetes.rules import (
    k8s027_ingress_without_tls as r27,
)


def _ctx(*docs: dict[str, Any]) -> KubernetesContext:
    manifests = []
    for idx, doc in enumerate(docs):
        api_version = doc.get("apiVersion", "v1")
        kind = doc.get("kind", "Ingress")
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


def _ingress(name: str, *, tls: list | None = None) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "rules": [{
            "host": f"{name}.example.com",
            "http": {"paths": [{
                "path": "/",
                "pathType": "Prefix",
                "backend": {"service": {
                    "name": "app", "port": {"number": 80},
                }},
            }]},
        }],
    }
    if tls is not None:
        spec["tls"] = tls
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {"name": name, "namespace": "prod"},
        "spec": spec,
    }


class TestK8S027IngressWithoutTLS:
    def test_fails_when_no_tls_block(self):
        f = r27.check(_ctx(_ingress("api")))
        assert not f.passed
        assert "Ingress/api" in f.description

    def test_fails_when_tls_is_empty_list(self):
        f = r27.check(_ctx(_ingress("api", tls=[])))
        assert not f.passed

    def test_passes_with_populated_tls_block(self):
        tls = [{
            "hosts": ["api.example.com"],
            "secretName": "api-tls",
        }]
        f = r27.check(_ctx(_ingress("api", tls=tls)))
        assert f.passed

    def test_passes_when_no_ingress_objects(self):
        # A context with only Deployments shouldn't trigger the rule.
        deployment = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "app", "namespace": "prod"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "c", "image": "nginx@sha256:" + "0" * 63 + "1"},
            ]}}},
        }
        f = r27.check(_ctx(deployment))
        assert f.passed
