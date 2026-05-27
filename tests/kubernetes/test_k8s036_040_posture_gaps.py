"""Per-rule unit tests for K8S-036..040.

K8S-036 (SA imagePullSecrets references missing Secret — cross-doc),
K8S-037 (ConfigMap data carries credential), K8S-038 (NetworkPolicy
allow-all rule), K8S-039 (Pod shareProcessNamespace: true), K8S-040
(Container procMount: Unmasked).
"""
from __future__ import annotations

from typing import Any

from pipeline_check.core.checks.kubernetes.rules.k8s036_image_pull_secret_missing import (
    check as check_k8s036,
)
from pipeline_check.core.checks.kubernetes.rules.k8s037_configmap_credential import (
    check as check_k8s037,
)
from pipeline_check.core.checks.kubernetes.rules.k8s038_networkpolicy_allow_all import (
    check as check_k8s038,
)
from pipeline_check.core.checks.kubernetes.rules.k8s039_share_process_namespace import (
    check as check_k8s039,
)
from pipeline_check.core.checks.kubernetes.rules.k8s040_proc_mount_unmasked import (
    check as check_k8s040,
)

from .conftest import k8s_ctx


def _sa(name: str, namespace: str, pull_secret: str | None) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {"name": name, "namespace": namespace},
    }
    if pull_secret is not None:
        doc["imagePullSecrets"] = [{"name": pull_secret}]
    return doc


def _secret(name: str, namespace: str) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": name, "namespace": namespace},
        "type": "kubernetes.io/dockerconfigjson",
        "stringData": {".dockerconfigjson": "{}"},
    }


def _cm(name: str, data: dict[str, Any]) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": "default"},
        "data": data,
    }


def _np(name: str, ingress: Any = None, egress: Any = None) -> dict[str, Any]:
    spec: dict[str, Any] = {"podSelector": {"matchLabels": {"app": "x"}}}
    if ingress is not None:
        spec["ingress"] = ingress
        spec.setdefault("policyTypes", []).append("Ingress")
    if egress is not None:
        spec["egress"] = egress
        spec.setdefault("policyTypes", []).append("Egress")
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": name, "namespace": "default"},
        "spec": spec,
    }


# ──────────────────────────────────────────────────────────────────
# K8S-036 — SA imagePullSecrets references missing Secret
# ──────────────────────────────────────────────────────────────────


class TestK8S036:
    def test_passes_when_secret_exists_in_namespace(self):
        ctx = k8s_ctx(
            _sa("app-sa", "ci", "registry-creds"),
            _secret("registry-creds", "ci"),
        )
        assert check_k8s036(ctx).passed

    def test_fails_when_secret_missing(self):
        ctx = k8s_ctx(_sa("app-sa", "ci", "registry-creds"))
        f = check_k8s036(ctx)
        assert not f.passed
        assert "ServiceAccount/app-sa" in f.description
        assert "registry-creds" in f.description

    def test_fails_when_secret_in_different_namespace(self):
        # imagePullSecrets is namespace-scoped — a Secret in ``other``
        # doesn't satisfy a SA in ``ci``.
        ctx = k8s_ctx(
            _sa("app-sa", "ci", "registry-creds"),
            _secret("registry-creds", "other"),
        )
        f = check_k8s036(ctx)
        assert not f.passed

    def test_passes_when_no_imagepullsecrets_declared(self):
        ctx = k8s_ctx(_sa("app-sa", "ci", None))
        assert check_k8s036(ctx).passed

    def test_passes_when_no_serviceaccounts(self):
        ctx = k8s_ctx(_secret("registry-creds", "ci"))
        assert check_k8s036(ctx).passed

    def test_handles_implicit_namespace(self):
        # Both SA and Secret with namespace="" — they should match.
        ctx = k8s_ctx(_sa("app-sa", "", "creds"), _secret("creds", ""))
        assert check_k8s036(ctx).passed


# ──────────────────────────────────────────────────────────────────
# K8S-037 — ConfigMap with credential-shaped value
# ──────────────────────────────────────────────────────────────────


class TestK8S037:
    def test_passes_with_non_credential_data(self):
        ctx = k8s_ctx(_cm("config", {
            "endpoint": "https://api.example.com",
            "log_level": "info",
        }))
        assert check_k8s037(ctx).passed

    def test_fails_with_aws_key_value(self):
        ctx = k8s_ctx(_cm("config", {
            "AWS_ACCESS_KEY_ID": "AKIAZ3MHALF2TESTHIJK",
        }))
        f = check_k8s037(ctx)
        assert not f.passed
        assert "AKIA-shaped" in f.description

    def test_fails_with_credential_shaped_key(self):
        ctx = k8s_ctx(_cm("config", {
            "api_key": "supersecret-value-here",
        }))
        f = check_k8s037(ctx)
        assert not f.passed
        assert "credential-shaped name" in f.description

    def test_passes_when_credential_shaped_key_has_empty_value(self):
        # K8S-018 flags empty placeholder values; for ConfigMap we
        # treat empty values as "not yet set" and pass — K8S-018 is
        # the right place for the placeholder check, not K8S-037.
        ctx = k8s_ctx(_cm("config", {"api_key": ""}))
        assert check_k8s037(ctx).passed

    def test_fails_with_binary_data_carrying_aws_key(self):
        # binaryData is base64-encoded; decode and detect.
        import base64
        encoded = base64.b64encode(b"AKIAZ3MHALF2TESTHIJK").decode()
        doc = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "c", "namespace": "default"},
            "binaryData": {"creds.bin": encoded},
        }
        ctx = k8s_ctx(doc)
        f = check_k8s037(ctx)
        assert not f.passed


# ──────────────────────────────────────────────────────────────────
# K8S-038 — NetworkPolicy allow-all rule
# ──────────────────────────────────────────────────────────────────


class TestK8S038:
    def test_passes_with_explicit_peer(self):
        ctx = k8s_ctx(_np("p", ingress=[{
            "from": [{"podSelector": {"matchLabels": {"app": "frontend"}}}],
        }]))
        assert check_k8s038(ctx).passed

    def test_fails_with_empty_from_list(self):
        ctx = k8s_ctx(_np("p", ingress=[{"from": []}]))
        f = check_k8s038(ctx)
        assert not f.passed
        assert "ingress[0]" in f.description
        assert "allow-all" in f.description

    def test_fails_with_empty_to_list(self):
        ctx = k8s_ctx(_np("p", egress=[{"to": []}]))
        f = check_k8s038(ctx)
        assert not f.passed
        assert "egress[0]" in f.description

    def test_fails_with_missing_from_field(self):
        # K8s semantics: rule with no `from:` matches every peer.
        ctx = k8s_ctx(_np("p", ingress=[{"ports": [{"port": 80}]}]))
        f = check_k8s038(ctx)
        assert not f.passed

    def test_passes_when_no_networkpolicies(self):
        # K8S-032 covers absence of default-deny; K8S-038 only checks
        # the rules that exist. No policies at all = nothing to fail.
        ctx = k8s_ctx()
        assert check_k8s038(ctx).passed

    def test_multiple_offenders_aggregate(self):
        ctx = k8s_ctx(
            _np("p1", ingress=[{"from": []}]),
            _np("p2", egress=[{"to": []}]),
        )
        f = check_k8s038(ctx)
        assert not f.passed
        assert "p1" in f.description and "p2" in f.description


# ──────────────────────────────────────────────────────────────────
# K8S-039 — Pod shareProcessNamespace: true
# ──────────────────────────────────────────────────────────────────


class TestK8S039:
    def _pod(self, share: Any = None) -> dict[str, Any]:
        spec: dict[str, Any] = {"containers": [{
            "name": "c", "image": "nginx@sha256:" + "0" * 64,
        }]}
        if share is not None:
            spec["shareProcessNamespace"] = share
        return {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "p", "namespace": "default"},
            "spec": spec,
        }

    def test_passes_when_field_absent(self):
        ctx = k8s_ctx(self._pod())
        assert check_k8s039(ctx).passed

    def test_passes_when_field_explicitly_false(self):
        ctx = k8s_ctx(self._pod(share=False))
        assert check_k8s039(ctx).passed

    def test_fails_when_field_true(self):
        ctx = k8s_ctx(self._pod(share=True))
        f = check_k8s039(ctx)
        assert not f.passed
        assert "Pod/p" in f.description

    def test_fires_on_deployment_template(self):
        # Walks ``spec.template.spec`` for Deployment-shaped manifests.
        deploy = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "d", "namespace": "default"},
            "spec": {"template": {"spec": {
                "shareProcessNamespace": True,
                "containers": [{"name": "c", "image": "nginx@sha256:" + "0" * 64}],
            }}},
        }
        ctx = k8s_ctx(deploy)
        f = check_k8s039(ctx)
        assert not f.passed
        assert "Deployment/d" in f.description


# ──────────────────────────────────────────────────────────────────
# K8S-040 — Container procMount: Unmasked
# ──────────────────────────────────────────────────────────────────


class TestK8S040:
    def _pod(self, proc_mount: str | None) -> dict[str, Any]:
        sc: dict[str, Any] = {}
        if proc_mount is not None:
            sc["procMount"] = proc_mount
        return {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "p", "namespace": "default"},
            "spec": {"containers": [{
                "name": "c",
                "image": "nginx@sha256:" + "0" * 64,
                "securityContext": sc,
            }]},
        }

    def test_passes_when_field_absent(self):
        ctx = k8s_ctx(self._pod(None))
        assert check_k8s040(ctx).passed

    def test_passes_when_field_default(self):
        ctx = k8s_ctx(self._pod("Default"))
        assert check_k8s040(ctx).passed

    def test_fails_when_field_unmasked(self):
        ctx = k8s_ctx(self._pod("Unmasked"))
        f = check_k8s040(ctx)
        assert not f.passed
        assert "Pod/p" in f.description
        assert "Unmasked" in f.description

    def test_fires_on_init_container(self):
        pod = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "p", "namespace": "default"},
            "spec": {
                "initContainers": [{
                    "name": "init",
                    "image": "busybox@sha256:" + "0" * 64,
                    "securityContext": {"procMount": "Unmasked"},
                }],
                "containers": [{
                    "name": "c",
                    "image": "nginx@sha256:" + "0" * 64,
                }],
            },
        }
        ctx = k8s_ctx(pod)
        f = check_k8s040(ctx)
        assert not f.passed
        assert "initContainer" in f.description
