"""Per-rule tests for K8s RBAC and Service-exposure rules:
K8S-020 (ClusterRoleBinding to cluster-admin / system:masters),
K8S-021 (Role/ClusterRole with wildcard verbs+resources),
K8S-022 (Service exposes SSH on port 22).

Together with K8S-026 (LoadBalancer without source ranges, in
test_host_namespace_and_volumes.py), these rules cover the cluster's
identity-and-perimeter surface: who has cluster-wide power, what a
role can do once granted, and which network surfaces face outward.
"""
from __future__ import annotations

from .conftest import run_check

# ── K8S-020 cluster-admin binding ───────────────────────────────────


class TestK8S020ClusterAdminBinding:
    def test_fails_on_cluster_admin_role_ref(self):
        binding = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "dev-admin"},
            "subjects": [{
                "kind": "User",
                "name": "dev-team",
                "apiGroup": "rbac.authorization.k8s.io",
            }],
            "roleRef": {
                "kind": "ClusterRole",
                "name": "cluster-admin",
                "apiGroup": "rbac.authorization.k8s.io",
            },
        }
        f = run_check(binding, "K8S-020")
        assert not f.passed

    def test_fails_on_system_masters_role_ref(self):
        binding = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "legacy"},
            "subjects": [],
            "roleRef": {
                "kind": "ClusterRole",
                "name": "system:masters",
                "apiGroup": "rbac.authorization.k8s.io",
            },
        }
        f = run_check(binding, "K8S-020")
        assert not f.passed

    def test_passes_on_narrow_cluster_role_ref(self):
        binding = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "auth-delegator"},
            "subjects": [{
                "kind": "ServiceAccount",
                "name": "app-sa",
                "namespace": "apps",
            }],
            "roleRef": {
                "kind": "ClusterRole",
                "name": "system:auth-delegator",
                "apiGroup": "rbac.authorization.k8s.io",
            },
        }
        f = run_check(binding, "K8S-020")
        assert f.passed


# ── K8S-021 wildcard RBAC ───────────────────────────────────────────


class TestK8S021WildcardRBAC:
    def test_fails_on_wildcard_verbs_and_resources(self):
        role = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": "everything"},
            "rules": [{
                "apiGroups": ["*"],
                "resources": ["*"],
                "verbs": ["*"],
            }],
        }
        f = run_check(role, "K8S-021")
        assert not f.passed

    def test_passes_on_narrow_role(self):
        role = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {"name": "configmap-reader", "namespace": "apps"},
            "rules": [{
                "apiGroups": [""],
                "resources": ["configmaps"],
                "verbs": ["get", "list", "watch"],
            }],
        }
        f = run_check(role, "K8S-021")
        assert f.passed


# ── K8S-022 Service exposes SSH ─────────────────────────────────────


class TestK8S022ServiceSSH:
    def test_fails_on_service_port_22(self):
        svc = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "ssh-jumpbox", "namespace": "ops"},
            "spec": {
                "type": "ClusterIP",
                "selector": {"app": "jumpbox"},
                "ports": [{"name": "ssh", "port": 22, "targetPort": 22}],
            },
        }
        f = run_check(svc, "K8S-022")
        assert not f.passed

    def test_fails_on_service_named_ssh_port(self):
        svc = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "jumpbox", "namespace": "ops"},
            "spec": {
                "type": "ClusterIP",
                "ports": [{"name": "ssh", "port": "ssh", "targetPort": 22}],
            },
        }
        f = run_check(svc, "K8S-022")
        assert not f.passed

    def test_passes_on_application_port(self):
        svc = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "app", "namespace": "apps"},
            "spec": {
                "type": "ClusterIP",
                "ports": [{"name": "http", "port": 8080, "targetPort": 8080}],
            },
        }
        f = run_check(svc, "K8S-022")
        assert f.passed
