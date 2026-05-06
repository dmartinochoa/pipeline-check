"""Unit tests for the four new K8s rules added in v0.4.0 (K8S-023..K8S-026).

Pattern: build a ``KubernetesContext`` from inline manifest dicts, run
the rule's ``check()`` directly, assert ``passed`` reflects the
positive/negative case. Mirrors how the existing K8s fixture tests
exercise the orchestrator end-to-end but at a per-rule grain.
"""
from __future__ import annotations

from typing import Any

import pytest

from pipeline_check.core.checks.kubernetes.base import (
    KubernetesContext,
    Manifest,
)
from pipeline_check.core.checks.kubernetes.rules import (
    k8s023_pod_security_admission as r23,
)
from pipeline_check.core.checks.kubernetes.rules import (
    k8s024_probes_missing as r24,
)
from pipeline_check.core.checks.kubernetes.rules import (
    k8s025_system_priority_class as r25,
)
from pipeline_check.core.checks.kubernetes.rules import (
    k8s026_lb_without_source_ranges as r26,
)


def _ctx(*docs: dict[str, Any]) -> KubernetesContext:
    """Build a context from a sequence of parsed YAML docs."""
    manifests = []
    for idx, doc in enumerate(docs):
        api_version = doc.get("apiVersion", "v1")
        kind = doc.get("kind", "Pod")
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


def _ns(name: str, **labels: str) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {"name": name, "labels": dict(labels)},
    }


def _deployment(
    *,
    name: str = "app",
    namespace: str = "default",
    containers: list[dict[str, Any]] | None = None,
    priority: str | None = None,
) -> dict[str, Any]:
    pod_spec: dict[str, Any] = {
        "containers": containers or [{"name": "c", "image": "x@sha256:1"}],
    }
    if priority is not None:
        pod_spec["priorityClassName"] = priority
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"template": {"spec": pod_spec}},
    }


def _service(
    *,
    name: str = "svc",
    type_: str = "ClusterIP",
    source_ranges: list[str] | None = None,
) -> dict[str, Any]:
    spec: dict[str, Any] = {"type": type_, "ports": [{"port": 80}]}
    if source_ranges is not None:
        spec["loadBalancerSourceRanges"] = source_ranges
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": name, "namespace": "apps"},
        "spec": spec,
    }


# ── K8S-023 ───────────────────────────────────────────────────────────


class TestK8S023PodSecurityAdmission:
    def test_fails_when_namespace_has_no_psa_label(self):
        f = r23.check(_ctx(_ns("apps")))
        assert not f.passed
        assert "apps" in f.description

    def test_fails_when_psa_set_to_privileged(self):
        f = r23.check(_ctx(_ns(
            "apps",
            **{"pod-security.kubernetes.io/enforce": "privileged"},
        )))
        assert not f.passed

    def test_passes_when_psa_set_to_baseline(self):
        f = r23.check(_ctx(_ns(
            "apps",
            **{"pod-security.kubernetes.io/enforce": "baseline"},
        )))
        assert f.passed

    def test_passes_when_psa_set_to_restricted(self):
        f = r23.check(_ctx(_ns(
            "apps",
            **{"pod-security.kubernetes.io/enforce": "restricted"},
        )))
        assert f.passed

    @pytest.mark.parametrize(
        "exempt", ["kube-system", "kube-public", "kube-node-lease"],
    )
    def test_kube_system_namespaces_are_exempt(self, exempt: str):
        # Even without a PSA label these system namespaces should pass.
        f = r23.check(_ctx(_ns(exempt)))
        assert f.passed

    def test_passes_when_no_namespace_manifests_present(self):
        f = r23.check(_ctx(_deployment()))
        assert f.passed


# ── K8S-024 ───────────────────────────────────────────────────────────


class TestK8S024ProbesMissing:
    def test_fails_when_container_has_no_probes(self):
        f = r24.check(_ctx(_deployment()))
        assert not f.passed

    def test_passes_when_container_has_liveness(self):
        f = r24.check(_ctx(_deployment(containers=[
            {"name": "c", "image": "x@sha256:1",
             "livenessProbe": {"httpGet": {"path": "/", "port": 80}}},
        ])))
        assert f.passed

    def test_passes_when_container_has_readiness(self):
        f = r24.check(_ctx(_deployment(containers=[
            {"name": "c", "image": "x@sha256:1",
             "readinessProbe": {"httpGet": {"path": "/", "port": 80}}},
        ])))
        assert f.passed

    def test_jobs_are_exempt(self):
        # A Job's lifecycle is "run-to-completion"; probing it doesn't
        # make sense and the rule should not fire.
        job = {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {"name": "j", "namespace": "default"},
            "spec": {"template": {"spec": {
                "containers": [{"name": "c", "image": "x@sha256:1"}],
            }}},
        }
        f = r24.check(_ctx(job))
        assert f.passed

    def test_init_containers_dont_count(self):
        # An init container without a probe shouldn't fire the rule
        # — only main containers need probes.
        depl = _deployment(containers=[
            {"name": "c", "image": "x@sha256:1",
             "livenessProbe": {"httpGet": {"path": "/", "port": 80}}},
        ])
        depl["spec"]["template"]["spec"]["initContainers"] = [
            {"name": "init", "image": "init@sha256:2"},
        ]
        f = r24.check(_ctx(depl))
        assert f.passed


# ── K8S-025 ───────────────────────────────────────────────────────────


class TestK8S025SystemPriorityClass:
    def test_fails_for_system_cluster_critical_outside_kube_system(self):
        f = r25.check(_ctx(_deployment(
            namespace="apps", priority="system-cluster-critical",
        )))
        assert not f.passed

    def test_fails_for_system_node_critical_outside_kube_system(self):
        f = r25.check(_ctx(_deployment(
            namespace="apps", priority="system-node-critical",
        )))
        assert not f.passed

    def test_passes_when_priority_class_is_user_defined(self):
        f = r25.check(_ctx(_deployment(
            namespace="apps", priority="high-priority",
        )))
        assert f.passed

    def test_kube_system_workloads_can_use_system_priority(self):
        f = r25.check(_ctx(_deployment(
            namespace="kube-system", priority="system-cluster-critical",
        )))
        assert f.passed

    def test_passes_when_priority_class_is_unset(self):
        f = r25.check(_ctx(_deployment(namespace="apps")))
        assert f.passed


# ── K8S-026 ───────────────────────────────────────────────────────────


class TestK8S026LBWithoutSourceRanges:
    def test_fails_for_lb_without_source_ranges(self):
        f = r26.check(_ctx(_service(type_="LoadBalancer")))
        assert not f.passed

    def test_fails_for_lb_with_empty_source_ranges(self):
        f = r26.check(_ctx(_service(
            type_="LoadBalancer", source_ranges=[],
        )))
        assert not f.passed

    def test_passes_for_lb_with_source_ranges(self):
        f = r26.check(_ctx(_service(
            type_="LoadBalancer",
            source_ranges=["10.0.0.0/8"],
        )))
        assert f.passed

    def test_clusterip_services_are_exempt(self):
        f = r26.check(_ctx(_service(type_="ClusterIP")))
        assert f.passed

    def test_nodeport_services_are_exempt(self):
        # NodePort still exposes externally but K8S-026's specific
        # remediation (loadBalancerSourceRanges) doesn't apply.
        f = r26.check(_ctx(_service(type_="NodePort")))
        assert f.passed
