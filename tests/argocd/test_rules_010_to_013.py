"""Per-rule unit tests for ARGOCD-010..013 (extended pack)."""
from __future__ import annotations

from .conftest import run_check

# ── ARGOCD-010 ──────────────────────────────────────────────────


class TestARGOCD010:
    def test_passes_on_sha_pinned_revision(self):
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

    def test_passes_on_semver_revision(self):
        y = """
        apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata: { name: payments, namespace: argocd }
        spec:
          source:
            chart: redis
            repoURL: https://charts.bitnami.com/bitnami
            targetRevision: 17.0.0
          destination: { server: https://kubernetes.default.svc, namespace: prod }
        """
        f = run_check(y, "ARGOCD-010")
        assert f.passed

    def test_fires_on_branch_revision(self):
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

    def test_fires_on_missing_revision(self):
        y = """
        apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata: { name: payments, namespace: argocd }
        spec:
          source:
            repoURL: https://github.com/example/m
            path: overlays/prod
          destination: { server: https://kubernetes.default.svc, namespace: prod }
        """
        f = run_check(y, "ARGOCD-010")
        assert not f.passed

    def test_passes_with_no_applications(self):
        y = """
        apiVersion: argoproj.io/v1alpha1
        kind: AppProject
        metadata: { name: default, namespace: argocd }
        spec:
          sourceRepos: ['*']
        """
        f = run_check(y, "ARGOCD-010")
        assert f.passed


# ── ARGOCD-011 ──────────────────────────────────────────────────


class TestARGOCD011:
    def test_passes_on_empty_whitelist(self):
        y = """
        apiVersion: argoproj.io/v1alpha1
        kind: AppProject
        metadata: { name: workloads, namespace: argocd }
        spec:
          sourceRepos: ['*']
          clusterResourceWhitelist: []
        """
        f = run_check(y, "ARGOCD-011")
        assert f.passed

    def test_passes_on_explicit_allowlist(self):
        y = """
        apiVersion: argoproj.io/v1alpha1
        kind: AppProject
        metadata: { name: workloads, namespace: argocd }
        spec:
          sourceRepos: ['*']
          clusterResourceWhitelist:
            - { group: rbac.authorization.k8s.io, kind: ClusterRole }
        """
        f = run_check(y, "ARGOCD-011")
        assert f.passed

    def test_fires_on_full_wildcard(self):
        y = """
        apiVersion: argoproj.io/v1alpha1
        kind: AppProject
        metadata: { name: workloads, namespace: argocd }
        spec:
          sourceRepos: ['*']
          clusterResourceWhitelist:
            - { group: '*', kind: '*' }
        """
        f = run_check(y, "ARGOCD-011")
        assert not f.passed

    def test_fires_on_group_wildcard(self):
        y = """
        apiVersion: argoproj.io/v1alpha1
        kind: AppProject
        metadata: { name: workloads, namespace: argocd }
        spec:
          sourceRepos: ['*']
          clusterResourceWhitelist:
            - { group: '*', kind: ClusterRole }
        """
        f = run_check(y, "ARGOCD-011")
        assert not f.passed


# ── ARGOCD-012 ──────────────────────────────────────────────────


class TestARGOCD012:
    def test_fires_on_prod_project_without_windows(self):
        y = """
        apiVersion: argoproj.io/v1alpha1
        kind: AppProject
        metadata: { name: prod-workloads, namespace: argocd }
        spec:
          sourceRepos: ['*']
          destinations:
            - server: https://kubernetes.default.svc
              namespace: prod
        """
        f = run_check(y, "ARGOCD-012")
        assert not f.passed

    def test_passes_on_prod_project_with_windows(self):
        y = """
        apiVersion: argoproj.io/v1alpha1
        kind: AppProject
        metadata: { name: prod-workloads, namespace: argocd }
        spec:
          sourceRepos: ['*']
          destinations:
            - server: https://kubernetes.default.svc
              namespace: prod
          syncWindows:
            - kind: deny
              schedule: "0 18 * * 1-5"
              duration: 14h
              applications: ['*']
              manualSync: true
        """
        f = run_check(y, "ARGOCD-012")
        assert f.passed

    def test_passes_on_non_prod_project(self):
        y = """
        apiVersion: argoproj.io/v1alpha1
        kind: AppProject
        metadata: { name: staging, namespace: argocd }
        spec:
          sourceRepos: ['*']
          destinations:
            - server: https://kubernetes.default.svc
              namespace: staging
        """
        f = run_check(y, "ARGOCD-012")
        assert f.passed

    def test_passes_on_products_namespace_substring(self):
        # ``products`` merely embeds ``prod``; a staging project for a
        # "products" service must not be treated as production (Part-C
        # FP: bare substring match).
        y = """
        apiVersion: argoproj.io/v1alpha1
        kind: AppProject
        metadata: { name: products, namespace: argocd }
        spec:
          sourceRepos: ['*']
          destinations:
            - server: https://kubernetes.default.svc
              namespace: product-catalog
        """
        f = run_check(y, "ARGOCD-012")
        assert f.passed

    def test_fires_on_delimited_prod_namespace(self):
        # ``prod-eu`` is a real production namespace (delimited token).
        y = """
        apiVersion: argoproj.io/v1alpha1
        kind: AppProject
        metadata: { name: eu, namespace: argocd }
        spec:
          sourceRepos: ['*']
          destinations:
            - server: https://kubernetes.default.svc
              namespace: prod-eu
        """
        f = run_check(y, "ARGOCD-012")
        assert not f.passed


# ── ARGOCD-013 ──────────────────────────────────────────────────


class TestARGOCD013:
    def test_passes_with_explicit_cap(self):
        y = """
        apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata: { name: payments, namespace: argocd }
        spec:
          source:
            repoURL: https://github.com/example/m
            targetRevision: main
          destination: { server: https://kubernetes.default.svc, namespace: prod }
          revisionHistoryLimit: 10
        """
        f = run_check(y, "ARGOCD-013")
        assert f.passed

    def test_fires_without_cap(self):
        y = """
        apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata: { name: payments, namespace: argocd }
        spec:
          source:
            repoURL: https://github.com/example/m
            targetRevision: main
          destination: { server: https://kubernetes.default.svc, namespace: prod }
        """
        f = run_check(y, "ARGOCD-013")
        assert not f.passed

    def test_explicit_zero_passes(self):
        # ``revisionHistoryLimit: 0`` is a valid int, so the check passes
        # it (only a missing / null value fires). This pins the documented
        # behavior after the docs_note was corrected to drop the wrong
        # "explicit 0 also fires" claim.
        y = """
        apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata: { name: payments, namespace: argocd }
        spec:
          source:
            repoURL: https://github.com/example/m
            targetRevision: main
          destination: { server: https://kubernetes.default.svc, namespace: prod }
          revisionHistoryLimit: 0
        """
        f = run_check(y, "ARGOCD-013")
        assert f.passed
