"""Per-rule tests for ARGOCD-014, ARGOCD-015, and ARGOCD-017.

ID 016 is intentionally unused; this provider deepening implemented
014, 015, and 017 only.
"""
from __future__ import annotations

from .conftest import run_check

# --- ARGOCD-014: web terminal exec.enabled -----------------------------------


def test_argocd014_exec_enabled_fires() -> None:
    f = run_check(
        """
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: argocd-cm
          namespace: argocd
        data:
          exec.enabled: "true"
        """,
        "ARGOCD-014",
    )
    assert f.passed is False
    assert f.severity == "CRITICAL"
    assert "terminal" in f.description.lower()


def test_argocd014_exec_enabled_boolean_true_fires() -> None:
    f = run_check(
        """
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: argocd-cm
          namespace: argocd
        data:
          exec.enabled: true
        """,
        "ARGOCD-014",
    )
    assert f.passed is False


def test_argocd014_exec_disabled_passes() -> None:
    f = run_check(
        """
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: argocd-cm
          namespace: argocd
        data:
          exec.enabled: "false"
        """,
        "ARGOCD-014",
    )
    assert f.passed is True


# --- ARGOCD-015: kustomize --enable-helm -------------------------------------


def test_argocd015_enable_helm_fires() -> None:
    f = run_check(
        """
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: argocd-cm
          namespace: argocd
        data:
          kustomize.buildOptions: "--enable-helm --load-restrictor LoadRestrictionsNone"
        """,
        "ARGOCD-015",
    )
    assert f.passed is False
    assert f.severity == "HIGH"


def test_argocd015_without_enable_helm_passes() -> None:
    f = run_check(
        """
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: argocd-cm
          namespace: argocd
        data:
          kustomize.buildOptions: "--load-restrictor LoadRestrictionsNone"
        """,
        "ARGOCD-015",
    )
    assert f.passed is True


def test_argocd015_no_build_options_passes() -> None:
    f = run_check(
        """
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: argocd-cm
          namespace: argocd
        data:
          url: https://argocd.example.com
        """,
        "ARGOCD-015",
    )
    assert f.passed is True


# --- ARGOCD-017: in-cluster mutable source -----------------------------------


def test_argocd017_in_cluster_mutable_source_fires() -> None:
    f = run_check(
        """
        apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata:
          name: platform
          namespace: argocd
        spec:
          source:
            repoURL: https://github.com/example/platform-manifests
            targetRevision: main
            path: cluster
          destination:
            server: https://kubernetes.default.svc
            namespace: argocd
        """,
        "ARGOCD-017",
    )
    assert f.passed is False
    assert f.severity == "HIGH"


def test_argocd017_in_cluster_pinned_sha_passes() -> None:
    f = run_check(
        """
        apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata:
          name: platform
          namespace: argocd
        spec:
          source:
            repoURL: https://github.com/example/platform-manifests
            targetRevision: 7b83187abc456def012345abcdef0123456789ab
            path: cluster
          destination:
            server: https://kubernetes.default.svc
            namespace: argocd
        """,
        "ARGOCD-017",
    )
    assert f.passed is True


def test_argocd017_remote_cluster_mutable_source_passes() -> None:
    # Mutable ref, but a remote destination, so this rule stays quiet
    # (ARGOCD-010 still flags the mutable ref).
    f = run_check(
        """
        apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata:
          name: payments
          namespace: argocd
        spec:
          source:
            repoURL: https://github.com/example/payments-manifests
            targetRevision: main
            path: overlays/prod
          destination:
            server: https://prod.example.com
            namespace: prod
        """,
        "ARGOCD-017",
    )
    assert f.passed is True
