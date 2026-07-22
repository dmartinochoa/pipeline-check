"""Regression tests from the 2026-07 rule audit (Kubernetes)."""
from __future__ import annotations

from .conftest import run_check


class TestAudit202607LowKubernetes:
    def test_k8s011_legacy_service_account_alias_is_honored(self):
        # The deprecated ``spec.serviceAccount`` alias binds a dedicated
        # SA (kubectl copies it into ``serviceAccountName``), so a pod
        # that only sets it isn't on the default SA.
        pod = {
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {
                "serviceAccount": "web-sa",
                "containers": [{"name": "c", "image": "nginx"}],
            },
        }
        assert run_check(pod, "K8S-011").passed is True

    def test_k8s011_default_service_account_still_flagged(self):
        pod = {
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {"containers": [{"name": "c", "image": "nginx"}]},
        }
        assert run_check(pod, "K8S-011").passed is False


class TestAudit202607LowKubernetesC2:
    """2026-07 audit LOW findings (kubernetes_c2 chunk)."""

    @staticmethod
    def _deploy(container):
        return {"apiVersion": "apps/v1", "kind": "Deployment",
                "metadata": {"name": "d"},
                "spec": {"template": {"spec": {"containers": [container]}}}}

    def test_k8s017_vendor_example_key_not_flagged(self):
        c = {"name": "c", "image": "nginx", "env": [
            {"name": "AWS_ACCESS_KEY_ID", "value": "AKIAIOSFODNN7EXAMPLE"}]}
        assert run_check(self._deploy(c), "K8S-017").passed is True
        real = {"name": "c", "image": "nginx", "env": [
            {"name": "AWS_ACCESS_KEY_ID", "value": "AKIAZ3MHALF2TESTHIJK"}]}
        assert run_check(self._deploy(real), "K8S-017").passed is False

    def test_k8s024_startup_probe_only_is_noted(self):
        c = {"name": "c", "image": "nginx",
             "startupProbe": {"httpGet": {"path": "/", "port": 8080}}}
        f = run_check(self._deploy(c), "K8S-024")
        assert f.passed is False
        assert "startupProbe" in f.description
