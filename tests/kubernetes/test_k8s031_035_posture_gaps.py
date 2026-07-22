"""Per-rule unit tests for K8S-031..035.

K8S-031 (PSA warn label), K8S-032 (default-deny NetworkPolicy),
K8S-033 (ResourceQuota / LimitRange), K8S-034 (SA automount),
K8S-035 (runAsUser: 0). The rules cover both per-manifest checks
(K8S-031 / K8S-034 / K8S-035) and cross-document checks
(K8S-032 / K8S-033 — they walk multiple kinds in the same scan).
"""
from __future__ import annotations

from typing import Any

import pytest

from pipeline_check.core.checks.kubernetes.rules.k8s031_psa_warn_missing import (
    check as check_k8s031,
)
from pipeline_check.core.checks.kubernetes.rules.k8s032_networkpolicy_default_deny import (
    check as check_k8s032,
)
from pipeline_check.core.checks.kubernetes.rules.k8s033_resourcequota_missing import (
    check as check_k8s033,
)
from pipeline_check.core.checks.kubernetes.rules.k8s034_serviceaccount_automount import (
    check as check_k8s034,
)
from pipeline_check.core.checks.kubernetes.rules.k8s035_run_as_uid_zero import (
    check as check_k8s035,
)

from .conftest import k8s_ctx


def _ns(name: str, labels: dict[str, str] | None = None) -> dict[str, Any]:
    md: dict[str, Any] = {"name": name}
    if labels is not None:
        md["labels"] = labels
    return {"apiVersion": "v1", "kind": "Namespace", "metadata": md}


def _deployment_in(ns: str, name: str = "app") -> dict[str, Any]:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": ns},
        "spec": {"template": {"spec": {
            "containers": [{
                "name": "c",
                "image": "nginx@sha256:" + "0" * 64,
            }],
        }}},
    }


# ──────────────────────────────────────────────────────────────────
# K8S-031 — PSA warn label
# ──────────────────────────────────────────────────────────────────


class TestK8S031:
    def test_namespace_with_warn_label_passes(self):
        ctx = k8s_ctx(_ns("app", labels={
            "pod-security.kubernetes.io/enforce": "baseline",
            "pod-security.kubernetes.io/warn": "restricted",
        }))
        assert check_k8s031(ctx).passed

    def test_namespace_without_warn_label_fails(self):
        ctx = k8s_ctx(_ns("app", labels={
            "pod-security.kubernetes.io/enforce": "baseline",
        }))
        f = check_k8s031(ctx)
        assert not f.passed
        assert "Namespace/app" in f.description

    def test_namespace_without_any_labels_fails(self):
        ctx = k8s_ctx(_ns("app"))
        assert not check_k8s031(ctx).passed

    def test_kube_system_exempt(self):
        # control-plane namespace shouldn't trip the rule
        ctx = k8s_ctx(_ns("kube-system"))
        assert check_k8s031(ctx).passed

    def test_warn_blank_string_fails(self):
        ctx = k8s_ctx(_ns("app", labels={
            "pod-security.kubernetes.io/warn": "  ",
        }))
        assert not check_k8s031(ctx).passed


# ──────────────────────────────────────────────────────────────────
# K8S-032 — default-deny NetworkPolicy
# ──────────────────────────────────────────────────────────────────


def _default_deny_np(ns: str) -> dict[str, Any]:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "default-deny", "namespace": ns},
        "spec": {
            "podSelector": {},
            "policyTypes": ["Ingress", "Egress"],
        },
    }


class TestK8S032:
    def test_namespace_with_workload_and_default_deny_passes(self):
        ctx = k8s_ctx(
            _ns("app"),
            _deployment_in("app"),
            _default_deny_np("app"),
        )
        assert check_k8s032(ctx).passed

    def test_namespace_with_workload_but_no_np_fails(self):
        ctx = k8s_ctx(_ns("app"), _deployment_in("app"))
        f = check_k8s032(ctx)
        assert not f.passed
        assert "namespace/app" in f.description

    def test_empty_namespace_does_not_fire(self):
        # No workloads -> nothing to deny
        ctx = k8s_ctx(_ns("app"))
        assert check_k8s032(ctx).passed

    def test_kube_system_exempt(self):
        ctx = k8s_ctx(_ns("kube-system"), _deployment_in("kube-system"))
        assert check_k8s032(ctx).passed

    def test_np_with_allow_rules_does_not_count_as_default_deny(self):
        np = _default_deny_np("app")
        np["spec"]["ingress"] = [{"from": [{"podSelector": {}}]}]
        ctx = k8s_ctx(_ns("app"), _deployment_in("app"), np)
        assert not check_k8s032(ctx).passed

    def test_np_with_non_empty_pod_selector_does_not_count(self):
        # A NetworkPolicy targeting a specific app isn't a default-deny.
        np = _default_deny_np("app")
        np["spec"]["podSelector"] = {"matchLabels": {"app": "frontend"}}
        ctx = k8s_ctx(_ns("app"), _deployment_in("app"), np)
        assert not check_k8s032(ctx).passed

    def test_ingress_only_policy_is_not_full_default_deny(self):
        # policyTypes: [Ingress] leaves egress wide open, so it is not a
        # full default-deny (2026-07 audit LOW FN).
        np = _default_deny_np("app")
        np["spec"]["policyTypes"] = ["Ingress"]
        ctx = k8s_ctx(_ns("app"), _deployment_in("app"), np)
        assert not check_k8s032(ctx).passed

    def test_absent_policy_types_is_not_full_default_deny(self):
        # An absent policyTypes defaults to [Ingress] in Kubernetes.
        np = _default_deny_np("app")
        del np["spec"]["policyTypes"]
        ctx = k8s_ctx(_ns("app"), _deployment_in("app"), np)
        assert not check_k8s032(ctx).passed


# ──────────────────────────────────────────────────────────────────
# K8S-033 — ResourceQuota / LimitRange
# ──────────────────────────────────────────────────────────────────


def _resource_quota(ns: str) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "ResourceQuota",
        "metadata": {"name": "rq", "namespace": ns},
        "spec": {"hard": {"cpu": "10", "memory": "20Gi"}},
    }


def _limit_range(ns: str) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "LimitRange",
        "metadata": {"name": "lr", "namespace": ns},
        "spec": {"limits": [{"type": "Container",
                              "default": {"cpu": "500m", "memory": "512Mi"}}]},
    }


class TestK8S033:
    def test_namespace_with_quota_and_limit_range_passes(self):
        ctx = k8s_ctx(
            _ns("app"),
            _deployment_in("app"),
            _resource_quota("app"),
            _limit_range("app"),
        )
        assert check_k8s033(ctx).passed

    def test_namespace_with_workload_and_no_quota_fails(self):
        ctx = k8s_ctx(_ns("app"), _deployment_in("app"))
        f = check_k8s033(ctx)
        assert not f.passed
        assert "ResourceQuota" in f.description
        assert "LimitRange" in f.description

    def test_quota_present_limit_range_missing_partially_fails(self):
        ctx = k8s_ctx(
            _ns("app"),
            _deployment_in("app"),
            _resource_quota("app"),
        )
        f = check_k8s033(ctx)
        assert not f.passed
        # The "missing: ..." parenthetical names only the missing
        # kind, even though the rule's title still mentions both.
        assert "missing: LimitRange" in f.description
        assert "missing: ResourceQuota" not in f.description

    def test_empty_namespace_does_not_fire(self):
        ctx = k8s_ctx(_ns("app"))
        assert check_k8s033(ctx).passed

    def test_kube_system_exempt(self):
        ctx = k8s_ctx(_ns("kube-system"), _deployment_in("kube-system"))
        assert check_k8s033(ctx).passed


# ──────────────────────────────────────────────────────────────────
# K8S-034 — ServiceAccount automount
# ──────────────────────────────────────────────────────────────────


def _sa(name: str, ns: str = "default", automount: Any = "ABSENT") -> dict[str, Any]:
    doc: dict[str, Any] = {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {"name": name, "namespace": ns},
    }
    if automount != "ABSENT":
        doc["automountServiceAccountToken"] = automount
    return doc


class TestK8S034:
    def test_explicit_false_passes(self):
        ctx = k8s_ctx(_sa("default", automount=False))
        assert check_k8s034(ctx).passed

    def test_explicit_true_fails(self):
        ctx = k8s_ctx(_sa("default", automount=True))
        assert not check_k8s034(ctx).passed

    def test_absent_field_fails(self):
        ctx = k8s_ctx(_sa("default"))
        f = check_k8s034(ctx)
        assert not f.passed
        assert "ServiceAccount/default/default" in f.description

    def test_namespace_field_present_in_offender(self):
        ctx = k8s_ctx(_sa("custom", ns="prod"))
        f = check_k8s034(ctx)
        assert "ServiceAccount/prod/custom" in f.description

    def test_no_serviceaccounts_passes(self):
        ctx = k8s_ctx(_ns("app"))
        assert check_k8s034(ctx).passed


# ──────────────────────────────────────────────────────────────────
# K8S-035 — runAsUser: 0
# ──────────────────────────────────────────────────────────────────


def _deploy_with_uid(uid: Any, *, level: str = "container") -> dict[str, Any]:
    """Build a Deployment whose securityContext.runAsUser is *uid*.

    *level* is "container" (per-container) or "pod" (pod-level
    inheritance).
    """
    container: dict[str, Any] = {
        "name": "c",
        "image": "nginx@sha256:" + "0" * 64,
    }
    pod_sc: dict[str, Any] = {}
    if level == "container" and uid != "ABSENT":
        container["securityContext"] = {"runAsUser": uid}
    elif level == "pod" and uid != "ABSENT":
        pod_sc = {"runAsUser": uid}
    spec: dict[str, Any] = {"containers": [container]}
    if pod_sc:
        spec["securityContext"] = pod_sc
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "app", "namespace": "default"},
        "spec": {"template": {"spec": spec}},
    }


class TestK8S035:
    def test_explicit_zero_at_container_fails(self):
        ctx = k8s_ctx(_deploy_with_uid(0))
        f = check_k8s035(ctx)
        assert not f.passed
        assert "runAsUser=0" in f.description

    def test_explicit_zero_at_pod_fails(self):
        ctx = k8s_ctx(_deploy_with_uid(0, level="pod"))
        assert not check_k8s035(ctx).passed

    def test_non_zero_uid_passes(self):
        ctx = k8s_ctx(_deploy_with_uid(1000))
        assert check_k8s035(ctx).passed

    def test_absent_runAsUser_passes_at_this_rule(self):
        # K8S-007 covers the runAsNonRoot: false case; this rule
        # only fires on the explicit 0 shape.
        ctx = k8s_ctx(_deploy_with_uid("ABSENT"))
        assert check_k8s035(ctx).passed

    def test_container_overrides_pod_level(self):
        # Pod sets uid 1000 but container overrides to 0 -> fail
        deploy: dict[str, Any] = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "app", "namespace": "default"},
            "spec": {"template": {"spec": {
                "securityContext": {"runAsUser": 1000},
                "containers": [{
                    "name": "c",
                    "image": "nginx@sha256:" + "0" * 64,
                    "securityContext": {"runAsUser": 0},
                }],
            }}},
        }
        ctx = k8s_ctx(deploy)
        assert not check_k8s035(ctx).passed


# ──────────────────────────────────────────────────────────────────
# Orchestrator smoke
# ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("rule_id", ["K8S-031", "K8S-032", "K8S-033", "K8S-034", "K8S-035"])
def test_rule_in_orchestrator(rule_id):
    """Each new rule lights up via KubernetesManifestChecks."""
    from pipeline_check.core.checks.kubernetes.manifests import KubernetesManifestChecks

    ctx = k8s_ctx(_ns("app"), _deployment_in("app"))
    findings = KubernetesManifestChecks(ctx).run()
    assert any(f.check_id == rule_id for f in findings)
