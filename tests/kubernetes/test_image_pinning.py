"""Per-rule test for K8S-001 (container image not digest-pinned)."""
from __future__ import annotations

from .conftest import pod, run_check


class TestK8S001ImagePinning:
    def test_fails_on_floating_tag(self):
        f = run_check(pod(containers=[{
            "name": "c",
            "image": "nginx:1.25.4",
        }]), "K8S-001")
        assert not f.passed

    def test_fails_on_latest_tag(self):
        f = run_check(pod(containers=[{
            "name": "c",
            "image": "nginx:latest",
        }]), "K8S-001")
        assert not f.passed

    def test_fails_when_no_tag(self):
        f = run_check(pod(containers=[{
            "name": "c",
            "image": "nginx",
        }]), "K8S-001")
        assert not f.passed

    def test_passes_with_digest_pin(self):
        f = run_check(pod(containers=[{
            "name": "c",
            "image": "nginx@sha256:0000000000000000000000000000000000000000000000000000000000000001",
        }]), "K8S-001")
        assert f.passed
