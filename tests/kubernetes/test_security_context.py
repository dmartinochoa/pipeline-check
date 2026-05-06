"""Per-rule tests for Kubernetes pod / container securityContext rules:
K8S-005 (privileged), K8S-006 (allowPrivilegeEscalation),
K8S-007 (runAsNonRoot), K8S-008 (readOnlyRootFilesystem),
K8S-009 (capabilities), K8S-010 (seccompProfile).

These are the six pod-security rules whose default Kubernetes
behavior is unsafe (privileged escalation enabled, root file system
writeable, etc.). Each rule's positive/negative tests document the
exact securityContext shape that triggers a finding.
"""
from __future__ import annotations

from .conftest import pod, run_check

# ── K8S-005 privileged ──────────────────────────────────────────────


class TestK8S005Privileged:
    def test_fails_on_privileged_true(self):
        f = run_check(pod(containers=[{
            "name": "c",
            "image": "nginx@sha256:0000000000000000000000000000000000000000000000000000000000000001",
            "securityContext": {"privileged": True},
        }]), "K8S-005")
        assert not f.passed

    def test_passes_when_privileged_false(self):
        f = run_check(pod(containers=[{
            "name": "c",
            "image": "nginx@sha256:0000000000000000000000000000000000000000000000000000000000000001",
            "securityContext": {"privileged": False},
        }]), "K8S-005")
        assert f.passed

    def test_passes_when_security_context_absent(self):
        # Defaults to non-privileged; rule shouldn't false-positive.
        f = run_check(pod(), "K8S-005")
        assert f.passed


# ── K8S-006 allowPrivilegeEscalation ────────────────────────────────


class TestK8S006AllowPrivilegeEscalation:
    def test_fails_when_allow_priv_escalation_true(self):
        f = run_check(pod(containers=[{
            "name": "c",
            "image": "nginx@sha256:0000000000000000000000000000000000000000000000000000000000000001",
            "securityContext": {"allowPrivilegeEscalation": True},
        }]), "K8S-006")
        assert not f.passed

    def test_passes_when_allow_priv_escalation_false(self):
        f = run_check(pod(containers=[{
            "name": "c",
            "image": "nginx@sha256:0000000000000000000000000000000000000000000000000000000000000001",
            "securityContext": {"allowPrivilegeEscalation": False},
        }]), "K8S-006")
        assert f.passed


# ── K8S-007 runAsNonRoot ────────────────────────────────────────────


class TestK8S007RunAsNonRoot:
    def test_fails_when_run_as_non_root_unset(self):
        # Default Kubernetes behavior is to run as the image's user,
        # which is often root for upstream images. Explicit
        # ``runAsNonRoot: true`` is required.
        f = run_check(pod(containers=[{
            "name": "c",
            "image": "nginx@sha256:0000000000000000000000000000000000000000000000000000000000000001",
        }]), "K8S-007")
        assert not f.passed

    def test_fails_when_run_as_user_zero(self):
        f = run_check(pod(containers=[{
            "name": "c",
            "image": "nginx@sha256:0000000000000000000000000000000000000000000000000000000000000001",
            "securityContext": {"runAsUser": 0},
        }]), "K8S-007")
        assert not f.passed

    def test_passes_when_run_as_non_root_true(self):
        f = run_check(pod(containers=[{
            "name": "c",
            "image": "nginx@sha256:0000000000000000000000000000000000000000000000000000000000000001",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 1001},
        }]), "K8S-007")
        assert f.passed


# ── K8S-008 readOnlyRootFilesystem ──────────────────────────────────


class TestK8S008ReadOnlyRootFilesystem:
    def test_fails_when_read_only_root_fs_unset(self):
        f = run_check(pod(), "K8S-008")
        assert not f.passed

    def test_passes_when_read_only_root_fs_true(self):
        f = run_check(pod(containers=[{
            "name": "c",
            "image": "nginx@sha256:0000000000000000000000000000000000000000000000000000000000000001",
            "securityContext": {"readOnlyRootFilesystem": True},
        }]), "K8S-008")
        assert f.passed


# ── K8S-009 capabilities ────────────────────────────────────────────


class TestK8S009Capabilities:
    def test_fails_when_sys_admin_added(self):
        f = run_check(pod(containers=[{
            "name": "c",
            "image": "nginx@sha256:0000000000000000000000000000000000000000000000000000000000000001",
            "securityContext": {
                "capabilities": {"add": ["SYS_ADMIN"]},
            },
        }]), "K8S-009")
        assert not f.passed

    def test_fails_when_drop_all_missing(self):
        f = run_check(pod(containers=[{
            "name": "c",
            "image": "nginx@sha256:0000000000000000000000000000000000000000000000000000000000000001",
        }]), "K8S-009")
        assert not f.passed

    def test_passes_when_drop_all_with_no_add(self):
        f = run_check(pod(containers=[{
            "name": "c",
            "image": "nginx@sha256:0000000000000000000000000000000000000000000000000000000000000001",
            "securityContext": {
                "capabilities": {"drop": ["ALL"]},
            },
        }]), "K8S-009")
        assert f.passed


# ── K8S-010 seccompProfile ──────────────────────────────────────────


class TestK8S010SeccompProfile:
    def test_fails_when_seccomp_profile_unset(self):
        f = run_check(pod(), "K8S-010")
        assert not f.passed

    def test_passes_with_runtime_default_seccomp_at_pod_level(self):
        f = run_check(pod(pod_spec_extra={
            "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
        }), "K8S-010")
        assert f.passed

    def test_passes_with_runtime_default_seccomp_at_container_level(self):
        f = run_check(pod(containers=[{
            "name": "c",
            "image": "nginx@sha256:0000000000000000000000000000000000000000000000000000000000000001",
            "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
        }]), "K8S-010")
        assert f.passed
