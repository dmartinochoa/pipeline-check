"""Regression tests for false-negative fixes in the Argo CD rule pack.

Each class documents one audit finding (batch / rule), covers:
  (a) the previously-missed violation now fires,
  (b) a related benign input still passes,
  (c) existing true-positive shapes still fire.
"""
from __future__ import annotations

from .conftest import run_check

# ---------------------------------------------------------------------------
# ARGOCD-010 — ApplicationSet template sources with mutable targetRevision
# ---------------------------------------------------------------------------


class TestARGOCD010ApplicationSet:
    """FN fix: ARGOCD-010 previously skipped ApplicationSet docs entirely.
    An ApplicationSet whose template source carries a mutable ref generates
    Applications that all track that same branch, so the check must fire."""

    def test_fires_on_applicationset_template_branch_revision(self) -> None:
        """(a) Previously-missed violation: ApplicationSet template with HEAD."""
        y = """
        apiVersion: argoproj.io/v1alpha1
        kind: ApplicationSet
        metadata:
          name: team-apps
          namespace: argocd
        spec:
          generators:
            - list:
                elements:
                  - cluster: prod
          template:
            metadata:
              name: '{{cluster}}-app'
            spec:
              source:
                repoURL: https://github.com/example/manifests
                targetRevision: HEAD
                path: overlays/prod
              destination:
                server: https://kubernetes.default.svc
                namespace: prod
        """
        f = run_check(y, "ARGOCD-010")
        assert not f.passed

    def test_fires_on_applicationset_template_branch_name(self) -> None:
        """(a) Previously-missed violation: ApplicationSet template with branch name."""
        y = """
        apiVersion: argoproj.io/v1alpha1
        kind: ApplicationSet
        metadata:
          name: team-apps
          namespace: argocd
        spec:
          generators:
            - list:
                elements:
                  - cluster: prod
          template:
            metadata:
              name: '{{cluster}}-app'
            spec:
              source:
                repoURL: https://github.com/example/manifests
                targetRevision: main
                path: overlays/prod
              destination:
                server: https://kubernetes.default.svc
                namespace: prod
        """
        f = run_check(y, "ARGOCD-010")
        assert not f.passed

    def test_passes_on_applicationset_template_sha_pinned(self) -> None:
        """(b) Benign: ApplicationSet template pinned to a commit SHA passes."""
        y = """
        apiVersion: argoproj.io/v1alpha1
        kind: ApplicationSet
        metadata:
          name: team-apps
          namespace: argocd
        spec:
          generators:
            - list:
                elements:
                  - cluster: prod
          template:
            metadata:
              name: '{{cluster}}-app'
            spec:
              source:
                repoURL: https://github.com/example/manifests
                targetRevision: 7b83187abc456def012345abcdef0123456789ab
                path: overlays/prod
              destination:
                server: https://kubernetes.default.svc
                namespace: prod
        """
        f = run_check(y, "ARGOCD-010")
        assert f.passed

    def test_passes_on_applicationset_template_semver_pinned(self) -> None:
        """(b) Benign: ApplicationSet template using a SemVer chart version passes."""
        y = """
        apiVersion: argoproj.io/v1alpha1
        kind: ApplicationSet
        metadata:
          name: helm-apps
          namespace: argocd
        spec:
          generators:
            - list:
                elements:
                  - env: prod
          template:
            metadata:
              name: '{{env}}-redis'
            spec:
              source:
                chart: redis
                repoURL: https://charts.bitnami.com/bitnami
                targetRevision: 17.0.0
              destination:
                server: https://kubernetes.default.svc
                namespace: prod
        """
        f = run_check(y, "ARGOCD-010")
        assert f.passed

    def test_fires_on_applicationset_template_missing_revision(self) -> None:
        """(a) Previously-missed: ApplicationSet template with no targetRevision."""
        y = """
        apiVersion: argoproj.io/v1alpha1
        kind: ApplicationSet
        metadata:
          name: team-apps
          namespace: argocd
        spec:
          generators:
            - list:
                elements:
                  - cluster: prod
          template:
            metadata:
              name: '{{cluster}}-app'
            spec:
              source:
                repoURL: https://github.com/example/manifests
                path: overlays/prod
              destination:
                server: https://kubernetes.default.svc
                namespace: prod
        """
        f = run_check(y, "ARGOCD-010")
        assert not f.passed

    def test_existing_application_branch_still_fires(self) -> None:
        """(c) Existing true-positive: Application with mutable ref still fires."""
        y = """
        apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata: { name: payments, namespace: argocd }
        spec:
          source:
            repoURL: https://github.com/example/m
            targetRevision: main
            path: overlays/prod
          destination: { server: https://kubernetes.default.svc, namespace: prod }
        """
        f = run_check(y, "ARGOCD-010")
        assert not f.passed

    def test_existing_application_sha_still_passes(self) -> None:
        """(c) Existing true-negative: Application with SHA pin still passes."""
        y = """
        apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata: { name: payments, namespace: argocd }
        spec:
          source:
            repoURL: https://github.com/example/m
            targetRevision: 7b83187abc456def012345abcdef0123456789ab
            path: overlays/prod
          destination: { server: https://kubernetes.default.svc, namespace: prod }
        """
        f = run_check(y, "ARGOCD-010")
        assert f.passed

    def test_mixed_application_and_applicationset_fires(self) -> None:
        """(a) Mix: one pinned Application + one mutable ApplicationSet fires."""
        y = """
        apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata: { name: pinned-app, namespace: argocd }
        spec:
          source:
            repoURL: https://github.com/example/m
            targetRevision: 7b83187abc456def012345abcdef0123456789ab
            path: overlays/prod
          destination: { server: https://kubernetes.default.svc, namespace: prod }
        ---
        apiVersion: argoproj.io/v1alpha1
        kind: ApplicationSet
        metadata:
          name: mutable-set
          namespace: argocd
        spec:
          generators:
            - list:
                elements:
                  - cluster: prod
          template:
            metadata:
              name: '{{cluster}}-app'
            spec:
              source:
                repoURL: https://github.com/example/manifests
                targetRevision: develop
                path: overlays/prod
              destination:
                server: https://kubernetes.default.svc
                namespace: prod
        """
        f = run_check(y, "ARGOCD-010")
        assert not f.passed


# ---------------------------------------------------------------------------
# ARGOCD-019 — ApplicationSet whose spec is authored as a YAML list
# ---------------------------------------------------------------------------


class TestARGOCD019ListSpec:
    """Crash fix: an ApplicationSet with a list-shaped ``spec`` made
    ``_app_spec`` call ``.get`` on a list, raising and (via the per-rule
    guard) degrading ARGOCD-019 to a silent pass. It must evaluate the
    document without crashing instead."""

    def test_list_spec_does_not_crash(self):
        y = """
        apiVersion: argoproj.io/v1alpha1
        kind: ApplicationSet
        metadata:
          name: x
        spec:
          - generators: []
        """
        f = run_check(y, "ARGOCD-019")
        assert "could not be evaluated" not in (f.description or "")
        assert f.passed is True
