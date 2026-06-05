"""Tests for ARGOCD-019 (drift detection disabled on a sensitive field)."""
from __future__ import annotations

from .conftest import run_check


class TestARGOCD019DriftDetectionDisabled:
    def test_fails_on_ignore_image(self):
        f = run_check("""
        apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata: {name: payments, namespace: argocd}
        spec:
          source: {repoURL: https://x, path: k8s, targetRevision: v1}
          destination: {server: https://kubernetes.default.svc, namespace: p}
          ignoreDifferences:
            - group: apps
              kind: Deployment
              jsonPointers: [/spec/template/spec/containers/0/image]
        """, "ARGOCD-019")
        assert not f.passed

    def test_fails_on_validate_false(self):
        f = run_check("""
        apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata: {name: a, namespace: argocd}
        spec:
          source: {repoURL: https://x}
          syncPolicy:
            syncOptions: [Validate=false]
        """, "ARGOCD-019")
        assert not f.passed

    def test_fails_on_ignore_rbac_rules_via_jqpath(self):
        f = run_check("""
        apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata: {name: a, namespace: argocd}
        spec:
          source: {repoURL: https://x}
          ignoreDifferences:
            - group: rbac.authorization.k8s.io
              kind: ClusterRole
              jqPathExpressions: ['.rules']
        """, "ARGOCD-019")
        assert not f.passed

    def test_passes_on_replica_count_ignore(self):
        f = run_check("""
        apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata: {name: a, namespace: argocd}
        spec:
          source: {repoURL: https://x}
          ignoreDifferences:
            - group: apps
              kind: Deployment
              jsonPointers: [/spec/replicas]
        """, "ARGOCD-019")
        assert f.passed

    def test_passes_on_crd_kind_containing_role(self):
        # A custom resource whose kind merely contains "role"
        # (``ControllerRole``) with a non-sensitive ignored path must not
        # fire: the kind is matched exactly, not as a substring.
        f = run_check("""
        apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata: {name: a, namespace: argocd}
        spec:
          source: {repoURL: https://x}
          ignoreDifferences:
            - group: example.com
              kind: ControllerRole
              jsonPointers: [/spec/replicas]
        """, "ARGOCD-019")
        assert f.passed

    def test_fails_on_ignore_service_account_name_field(self):
        # ``serviceAccountName`` is matched by the ``serviceaccount``
        # token as a path-segment prefix (not exact), so a longer field
        # name still fires.
        f = run_check("""
        apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata: {name: a, namespace: argocd}
        spec:
          source: {repoURL: https://x}
          ignoreDifferences:
            - group: apps
              kind: Deployment
              jsonPointers: [/spec/template/spec/serviceAccountName]
        """, "ARGOCD-019")
        assert not f.passed

    def test_passes_without_ignore_or_validate(self):
        f = run_check("""
        apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata: {name: a, namespace: argocd}
        spec:
          source: {repoURL: https://x}
          syncPolicy:
            automated: {selfHeal: true}
        """, "ARGOCD-019")
        assert f.passed
