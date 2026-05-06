"""Per-rule tests for Kubernetes host-namespace and volume rules:
K8S-002 (hostNetwork), K8S-003 (hostPID), K8S-004 (hostIPC),
K8S-013 (hostPath volume), K8S-014 (sensitive hostPath path).

Host namespace sharing erases the container/host security boundary;
``hostPath`` volumes mount node-local filesystem state into the
container, with sensitive paths (``docker.sock``, ``/etc``, ``/``)
bypassing the cluster's RBAC entirely.
"""
from __future__ import annotations

from .conftest import pod, run_check

# ── K8S-002 hostNetwork ─────────────────────────────────────────────


class TestK8S002HostNetwork:
    def test_fails_when_host_network_true(self):
        f = run_check(pod(pod_spec_extra={"hostNetwork": True}), "K8S-002")
        assert not f.passed

    def test_passes_when_host_network_unset(self):
        f = run_check(pod(), "K8S-002")
        assert f.passed

    def test_passes_when_host_network_false(self):
        f = run_check(pod(pod_spec_extra={"hostNetwork": False}), "K8S-002")
        assert f.passed


# ── K8S-003 hostPID ─────────────────────────────────────────────────


class TestK8S003HostPID:
    def test_fails_when_host_pid_true(self):
        f = run_check(pod(pod_spec_extra={"hostPID": True}), "K8S-003")
        assert not f.passed

    def test_passes_when_host_pid_unset(self):
        f = run_check(pod(), "K8S-003")
        assert f.passed


# ── K8S-004 hostIPC ─────────────────────────────────────────────────


class TestK8S004HostIPC:
    def test_fails_when_host_ipc_true(self):
        f = run_check(pod(pod_spec_extra={"hostIPC": True}), "K8S-004")
        assert not f.passed

    def test_passes_when_host_ipc_unset(self):
        f = run_check(pod(), "K8S-004")
        assert f.passed


# ── K8S-013 hostPath volume ─────────────────────────────────────────


class TestK8S013HostPathVolume:
    def test_fails_on_any_host_path_volume(self):
        f = run_check(pod(pod_spec_extra={
            "volumes": [{"name": "data", "hostPath": {"path": "/var/log"}}],
        }), "K8S-013")
        assert not f.passed

    def test_passes_with_configmap_volume(self):
        f = run_check(pod(pod_spec_extra={
            "volumes": [{"name": "cfg", "configMap": {"name": "app-config"}}],
        }), "K8S-013")
        assert f.passed

    def test_passes_with_no_volumes(self):
        f = run_check(pod(), "K8S-013")
        assert f.passed


# ── K8S-014 sensitive hostPath ──────────────────────────────────────


class TestK8S014SensitiveHostPath:
    def test_fails_on_docker_sock_mount(self):
        f = run_check(pod(pod_spec_extra={
            "volumes": [{
                "name": "dock",
                "hostPath": {"path": "/var/run/docker.sock"},
            }],
        }), "K8S-014")
        assert not f.passed

    def test_fails_on_etc_mount(self):
        f = run_check(pod(pod_spec_extra={
            "volumes": [{"name": "etc", "hostPath": {"path": "/etc"}}],
        }), "K8S-014")
        assert not f.passed

    def test_fails_on_root_filesystem_mount(self):
        f = run_check(pod(pod_spec_extra={
            "volumes": [{"name": "root", "hostPath": {"path": "/"}}],
        }), "K8S-014")
        assert not f.passed

    def test_passes_on_non_sensitive_host_path(self):
        # /var/log isn't on the sensitive-path list — K8S-013 still
        # fires on the broader hostPath usage, but K8S-014 doesn't
        # flag this specific path.
        f = run_check(pod(pod_spec_extra={
            "volumes": [{"name": "log", "hostPath": {"path": "/var/log"}}],
        }), "K8S-014")
        assert f.passed
