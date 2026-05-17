"""Per-rule unit tests for K8S-041..043.

K8S-041 (Service externalIPs / CVE-2020-8554),
K8S-042 (RoleBinding to system:anonymous / system:unauthenticated),
K8S-043 (Ingress rule with wildcard / missing host).
"""
from __future__ import annotations

from typing import Any

from pipeline_check.core.checks.kubernetes.rules.k8s041_service_external_ips import (
    check as check_k8s041,
)
from pipeline_check.core.checks.kubernetes.rules.k8s042_anonymous_rolebinding import (
    check as check_k8s042,
)
from pipeline_check.core.checks.kubernetes.rules.k8s043_ingress_wildcard_host import (
    check as check_k8s043,
)

from .conftest import k8s_ctx


def _svc(name: str, *, external_ips: list[str] | None = None,
         svc_type: str = "ClusterIP") -> dict[str, Any]:
    spec: dict[str, Any] = {
        "type": svc_type,
        "selector": {"app": "x"},
        "ports": [{"port": 80, "targetPort": 8080}],
    }
    if external_ips is not None:
        spec["externalIPs"] = external_ips
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": name, "namespace": "default"},
        "spec": spec,
    }


def _binding(kind: str, name: str, subjects: list[dict[str, Any]],
             role: str = "viewer") -> dict[str, Any]:
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": kind,
        "metadata": {"name": name, "namespace": "default"},
        "subjects": subjects,
        "roleRef": {
            "kind": "ClusterRole",
            "name": role,
            "apiGroup": "rbac.authorization.k8s.io",
        },
    }


def _ingress(name: str, hosts: list[str | None]) -> dict[str, Any]:
    rules: list[dict[str, Any]] = []
    for h in hosts:
        rule: dict[str, Any] = {"http": {"paths": [{
            "path": "/",
            "pathType": "Prefix",
            "backend": {"service": {"name": "x", "port": {"number": 80}}},
        }]}}
        if h is not None:
            rule["host"] = h
        rules.append(rule)
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {"name": name, "namespace": "default"},
        "spec": {"rules": rules},
    }


# ──────────────────────────────────────────────────────────────────
# K8S-041 — Service.externalIPs
# ──────────────────────────────────────────────────────────────────


class TestK8S041:
    def test_passes_when_field_absent(self):
        ctx = k8s_ctx(_svc("svc"))
        assert check_k8s041(ctx).passed

    def test_passes_when_field_is_empty_list(self):
        ctx = k8s_ctx(_svc("svc", external_ips=[]))
        assert check_k8s041(ctx).passed

    def test_fails_when_externalips_populated(self):
        ctx = k8s_ctx(_svc("svc", external_ips=["198.51.100.10"]))
        f = check_k8s041(ctx)
        assert not f.passed
        assert "Service/svc" in f.description
        assert "198.51.100.10" in f.description

    def test_fires_regardless_of_service_type(self):
        # externalIPs is independent of Service.type — the apiserver
        # honors it for ClusterIP, NodePort, and LoadBalancer alike.
        ctx = k8s_ctx(_svc("svc", external_ips=["10.0.0.1"], svc_type="LoadBalancer"))
        assert not check_k8s041(ctx).passed

    def test_passes_when_no_services(self):
        # A manifest set with no Service objects is trivially safe.
        ctx = k8s_ctx({
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": "c", "namespace": "default"},
            "data": {"k": "v"},
        })
        assert check_k8s041(ctx).passed


# ──────────────────────────────────────────────────────────────────
# K8S-042 — anonymous RoleBinding
# ──────────────────────────────────────────────────────────────────


class TestK8S042:
    def test_fails_on_system_anonymous_user(self):
        ctx = k8s_ctx(_binding("ClusterRoleBinding", "anon-binding", [{
            "kind": "User", "name": "system:anonymous",
            "apiGroup": "rbac.authorization.k8s.io",
        }]))
        f = check_k8s042(ctx)
        assert not f.passed
        assert "anon-binding" in f.description

    def test_fails_on_system_unauthenticated_group(self):
        ctx = k8s_ctx(_binding("ClusterRoleBinding", "unauth-binding", [{
            "kind": "Group", "name": "system:unauthenticated",
            "apiGroup": "rbac.authorization.k8s.io",
        }]))
        assert not check_k8s042(ctx).passed

    def test_fails_on_namespaced_rolebinding(self):
        ctx = k8s_ctx(_binding("RoleBinding", "ns-binding", [{
            "kind": "User", "name": "system:anonymous",
            "apiGroup": "rbac.authorization.k8s.io",
        }]))
        assert not check_k8s042(ctx).passed

    def test_passes_with_named_user(self):
        ctx = k8s_ctx(_binding("ClusterRoleBinding", "named-binding", [{
            "kind": "User", "name": "alice@example.com",
            "apiGroup": "rbac.authorization.k8s.io",
        }]))
        assert check_k8s042(ctx).passed

    def test_passes_when_no_bindings_present(self):
        # No RBAC bindings at all — trivially safe.
        ctx = k8s_ctx({
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": "c", "namespace": "default"},
            "data": {"k": "v"},
        })
        assert check_k8s042(ctx).passed

    def test_passes_when_subject_missing_name(self):
        # Malformed subject (no ``name`` field) must not crash and must
        # not match — the rule guards against this with isinstance.
        ctx = k8s_ctx(_binding("ClusterRoleBinding", "broken", [{
            "kind": "User", "apiGroup": "rbac.authorization.k8s.io",
        }]))
        assert check_k8s042(ctx).passed


# ──────────────────────────────────────────────────────────────────
# K8S-043 — Ingress wildcard / missing host
# ──────────────────────────────────────────────────────────────────


class TestK8S043:
    def test_passes_with_specific_hostname(self):
        ctx = k8s_ctx(_ingress("ing", ["api.example.com"]))
        assert check_k8s043(ctx).passed

    def test_fails_with_missing_host(self):
        ctx = k8s_ctx(_ingress("ing", [None]))
        f = check_k8s043(ctx)
        assert not f.passed
        assert "missing" in f.description

    def test_fails_with_wildcard_star(self):
        ctx = k8s_ctx(_ingress("ing", ["*"]))
        f = check_k8s043(ctx)
        assert not f.passed
        assert "wildcard" in f.description

    def test_fails_with_subdomain_wildcard(self):
        ctx = k8s_ctx(_ingress("ing", ["*.example.com"]))
        assert not check_k8s043(ctx).passed

    def test_passes_when_no_ingresses(self):
        ctx = k8s_ctx({
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": "c", "namespace": "default"},
            "data": {"k": "v"},
        })
        assert check_k8s043(ctx).passed

    def test_aggregates_multiple_offending_rules(self):
        ctx = k8s_ctx(_ingress("ing", [None, "*.example.com", "api.example.com"]))
        f = check_k8s043(ctx)
        assert not f.passed
        # Two offending rules from one Ingress.
        assert "rules[0]" in f.description or "rules[1]" in f.description
