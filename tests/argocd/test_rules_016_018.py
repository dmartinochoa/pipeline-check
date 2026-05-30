"""Per-rule tests for ARGOCD-016 (remote Helm valueFiles) and
ARGOCD-018 (custom resource health / action Lua)."""
from __future__ import annotations

from .conftest import run_check

# --- ARGOCD-016: remote Helm valueFiles --------------------------------------


def test_argocd016_remote_value_file_fires() -> None:
    f = run_check(
        """
        apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata:
          name: app
        spec:
          source:
            repoURL: https://github.com/org/charts
            targetRevision: abc123
            path: charts/app
            helm:
              valueFiles:
                - https://values.example.test/prod.yaml
        """,
        "ARGOCD-016",
    )
    assert f.passed is False
    assert "values.example.test" in f.description


def test_argocd016_local_value_file_passes() -> None:
    f = run_check(
        """
        apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata:
          name: app
        spec:
          source:
            repoURL: https://github.com/org/charts
            path: charts/app
            helm:
              valueFiles:
                - values-prod.yaml
        """,
        "ARGOCD-016",
    )
    assert f.passed is True


def test_argocd016_no_helm_passes() -> None:
    f = run_check(
        """
        apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata:
          name: app
        spec:
          source:
            repoURL: https://github.com/org/charts
            path: manifests
        """,
        "ARGOCD-016",
    )
    assert f.passed is True


# --- ARGOCD-018: custom resource health / action Lua -------------------------


def test_argocd018_health_lua_fires() -> None:
    f = run_check(
        """
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: argocd-cm
          namespace: argocd
        data:
          resource.customizations.health.argoproj.io_Application: |
            hs = {}
            hs.status = "Healthy"
            return hs
        """,
        "ARGOCD-018",
    )
    assert f.passed is False
    assert "resource.customizations" in f.description


def test_argocd018_actions_lua_fires() -> None:
    f = run_check(
        """
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: argocd-cm
          namespace: argocd
        data:
          resource.customizations.actions.apps_Deployment: |
            actions = {}
            return actions
        """,
        "ARGOCD-018",
    )
    assert f.passed is False


def test_argocd018_aggregate_block_fires() -> None:
    f = run_check(
        """
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: argocd-cm
          namespace: argocd
        data:
          resource.customizations: |
            apps/Deployment:
              health.lua: |
                return {}
        """,
        "ARGOCD-018",
    )
    assert f.passed is False


def test_argocd018_no_customizations_passes() -> None:
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
        "ARGOCD-018",
    )
    assert f.passed is True
