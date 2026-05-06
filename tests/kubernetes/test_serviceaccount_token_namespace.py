"""Per-rule tests for Kubernetes ServiceAccount, token, and namespace
hygiene rules:
K8S-011 (Pod serviceAccountName unset or 'default'),
K8S-012 (Pod automountServiceAccountToken not false),
K8S-019 (Workload deployed in the 'default' namespace).

These three rules form the SA-isolation triangle: a workload in a
custom namespace, bound to a custom SA with a deliberate
auto-mount choice, is the canonical least-privilege baseline.
Failing any leg gives a process inside the pod a free identity to
attack the API server with.
"""
from __future__ import annotations

from .conftest import pod, run_check

# ── K8S-011 ServiceAccount unset or 'default' ──────────────────────


class TestK8S011ServiceAccount:
    def test_fails_when_service_account_unset(self):
        manifest = pod(name="app", namespace="prod")
        f = run_check(manifest, "K8S-011")
        assert not f.passed

    def test_fails_when_service_account_explicitly_default(self):
        manifest = pod(
            name="app",
            namespace="prod",
            pod_spec_extra={"serviceAccountName": "default"},
        )
        f = run_check(manifest, "K8S-011")
        assert not f.passed

    def test_passes_with_dedicated_service_account(self):
        manifest = pod(
            name="app",
            namespace="prod",
            pod_spec_extra={"serviceAccountName": "app-sa"},
        )
        f = run_check(manifest, "K8S-011")
        assert f.passed


# ── K8S-012 automountServiceAccountToken ────────────────────────────


class TestK8S012AutomountToken:
    def test_fails_when_token_automount_unset(self):
        manifest = pod(
            name="app",
            namespace="prod",
            pod_spec_extra={"serviceAccountName": "app-sa"},
        )
        f = run_check(manifest, "K8S-012")
        assert not f.passed

    def test_fails_when_token_automount_true(self):
        manifest = pod(
            name="app",
            namespace="prod",
            pod_spec_extra={
                "serviceAccountName": "app-sa",
                "automountServiceAccountToken": True,
            },
        )
        f = run_check(manifest, "K8S-012")
        assert not f.passed

    def test_passes_when_token_automount_false(self):
        manifest = pod(
            name="app",
            namespace="prod",
            pod_spec_extra={
                "serviceAccountName": "app-sa",
                "automountServiceAccountToken": False,
            },
        )
        f = run_check(manifest, "K8S-012")
        assert f.passed


# ── K8S-019 default namespace ───────────────────────────────────────


class TestK8S019DefaultNamespace:
    def test_fails_when_namespace_is_default(self):
        manifest = pod(name="app", namespace="default")
        f = run_check(manifest, "K8S-019")
        assert not f.passed

    def test_fails_when_namespace_unset(self):
        manifest = pod(name="app", namespace="")
        f = run_check(manifest, "K8S-019")
        assert not f.passed

    def test_passes_with_dedicated_namespace(self):
        manifest = pod(name="app", namespace="prod")
        f = run_check(manifest, "K8S-019")
        assert f.passed
