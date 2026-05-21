"""Per-rule tests for every ARGOCD-* check."""
from __future__ import annotations

from .conftest import argocd_ctx, run_check
from pipeline_check.core.checks.argocd.pipelines import ArgoCDChecks


# ── ARGOCD-001 AppProject sourceRepos wildcard ─────────────────────────


class TestARGOCD001SourceReposWildcard:
    def test_fails_with_star_repo(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: AppProject
        metadata:
          name: default
          namespace: argocd
        spec:
          sourceRepos: ['*']
          destinations:
            - { server: https://kubernetes.default.svc, namespace: payments }
        """
        f = run_check(cfg, "ARGOCD-001")
        assert not f.passed

    def test_fails_when_sourceRepos_missing(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: AppProject
        metadata: { name: default, namespace: argocd }
        spec:
          destinations:
            - { server: https://kubernetes.default.svc, namespace: payments }
        """
        f = run_check(cfg, "ARGOCD-001")
        assert not f.passed

    def test_passes_with_explicit_repo_list(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: AppProject
        metadata: { name: payments, namespace: argocd }
        spec:
          sourceRepos:
            - https://github.com/example/payments-manifests
          destinations:
            - { server: https://kubernetes.default.svc, namespace: payments }
        """
        f = run_check(cfg, "ARGOCD-001")
        assert f.passed


# ── ARGOCD-002 destinations wildcard ───────────────────────────────────


class TestARGOCD002DestinationsWildcard:
    def test_fails_with_star_server(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: AppProject
        metadata: { name: p, namespace: argocd }
        spec:
          sourceRepos: [https://github.com/example/r]
          destinations:
            - { server: '*', namespace: '*' }
        """
        f = run_check(cfg, "ARGOCD-002")
        assert not f.passed

    def test_passes_with_explicit_destinations(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: AppProject
        metadata: { name: p, namespace: argocd }
        spec:
          sourceRepos: [https://github.com/example/r]
          destinations:
            - { server: https://kubernetes.default.svc, namespace: payments-prod }
            - { server: https://kubernetes.default.svc, namespace: payments-stg }
        """
        f = run_check(cfg, "ARGOCD-002")
        assert f.passed


# ── ARGOCD-003 auto-sync prune without selfHeal ────────────────────────


class TestARGOCD003UnsafeAutoSync:
    def test_fails_with_prune_and_no_selfheal(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata: { name: payments, namespace: argocd }
        spec:
          project: payments
          source: { repoURL: https://github.com/example/r, path: ., targetRevision: HEAD }
          destination: { server: https://kubernetes.default.svc, namespace: payments-prod }
          syncPolicy:
            automated:
              prune: true
        """
        f = run_check(cfg, "ARGOCD-003")
        assert not f.passed

    def test_passes_with_prune_and_selfheal(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata: { name: payments, namespace: argocd }
        spec:
          syncPolicy:
            automated:
              prune: true
              selfHeal: true
        """
        f = run_check(cfg, "ARGOCD-003")
        assert f.passed

    def test_passes_without_automated(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata: { name: payments, namespace: argocd }
        spec:
          syncPolicy:
            syncOptions: ['CreateNamespace=true']
        """
        f = run_check(cfg, "ARGOCD-003")
        assert f.passed


# ── ARGOCD-004 RBAC wildcard policy ────────────────────────────────────


class TestARGOCD004RBACWildcard:
    def test_fails_with_wildcard_allow(self):
        cfg = """
        apiVersion: v1
        kind: ConfigMap
        metadata: { name: argocd-rbac-cm, namespace: argocd }
        data:
          policy.csv: |
            # platform admins
            p, role:org-admin, *, *, *, allow
            g, my-org:everyone, role:org-admin
        """
        f = run_check(cfg, "ARGOCD-004")
        assert not f.passed

    def test_passes_with_scoped_policy(self):
        cfg = """
        apiVersion: v1
        kind: ConfigMap
        metadata: { name: argocd-rbac-cm, namespace: argocd }
        data:
          policy.csv: |
            # commented-out wildcard line stays inert
            # p, role:everyone, *, *, *, allow
            p, role:payments-deployer, applications, sync, payments/*, allow
            p, role:payments-deployer, applications, get, payments/*, allow
            g, my-org:payments-oncall, role:payments-deployer
        """
        f = run_check(cfg, "ARGOCD-004")
        assert f.passed


# ── ARGOCD-005 repo plaintext credentials ──────────────────────────────


class TestARGOCD005RepoPlaintextSecret:
    def test_fails_with_literal_password(self):
        cfg = """
        apiVersion: v1
        kind: ConfigMap
        metadata: { name: argocd-cm, namespace: argocd }
        data:
          repositories: |
            - url: https://github.com/example/private
              type: git
              username: deploy-bot
              password: hunter2hunter2hunter2
        """
        f = run_check(cfg, "ARGOCD-005")
        assert not f.passed

    def test_passes_with_secret_indirection(self):
        cfg = """
        apiVersion: v1
        kind: ConfigMap
        metadata: { name: argocd-cm, namespace: argocd }
        data:
          repositories: |
            - url: https://github.com/example/private
              type: git
              usernameSecret: { name: repo-creds, key: username }
              passwordSecret: { name: repo-creds, key: password }
        """
        f = run_check(cfg, "ARGOCD-005")
        assert f.passed


# ── ARGOCD-006 ApplicationSet untrusted generator ──────────────────────


class TestARGOCD006ApplicationSetPRGenerator:
    def test_fails_with_pr_generator_default_project_no_filter(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: ApplicationSet
        metadata: { name: previews, namespace: argocd }
        spec:
          generators:
            - pullRequest:
                github:
                  owner: example-corp
                  repo: app
          template:
            metadata: { name: '{{branch}}' }
            spec:
              project: default
              source: { repoURL: https://github.com/example/r, targetRevision: '{{branch}}', path: . }
              destination: { server: https://kubernetes.default.svc, namespace: '{{branch}}' }
        """
        f = run_check(cfg, "ARGOCD-006")
        assert not f.passed

    def test_passes_with_pr_generator_filtered_and_static_project(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: ApplicationSet
        metadata: { name: previews, namespace: argocd }
        spec:
          generators:
            - pullRequest:
                github:
                  owner: example-corp
                  repo: app
                  labels: ['preview']
                requeueAfterSeconds: 300
          template:
            spec:
              project: previews
              source: { repoURL: https://github.com/example/r, targetRevision: '{{branch}}', path: . }
              destination: { server: https://kubernetes.default.svc, namespace: previews }
        """
        f = run_check(cfg, "ARGOCD-006")
        assert f.passed


# ── ARGOCD-007 Helm generator interpolation without goTemplate ─────────


class TestARGOCD007HelmParamInterpolation:
    def test_fails_with_placeholder_and_no_goTemplate(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: ApplicationSet
        metadata: { name: previews, namespace: argocd }
        spec:
          generators:
            - pullRequest: { github: { owner: example, repo: app } }
          template:
            spec:
              project: previews
              source:
                repoURL: https://github.com/example/charts
                path: chart
                helm:
                  valueFiles:
                    - values-{{branch}}.yaml
                  parameters:
                    - { name: image.tag, value: '{{branch}}' }
              destination: { server: https://kubernetes.default.svc, namespace: previews }
        """
        f = run_check(cfg, "ARGOCD-007")
        assert not f.passed

    def test_passes_when_goTemplate_true(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: ApplicationSet
        metadata: { name: previews, namespace: argocd }
        spec:
          goTemplate: true
          generators:
            - pullRequest: { github: { owner: example, repo: app } }
          template:
            spec:
              source:
                helm:
                  valueFiles: ['values-{{.branch}}.yaml']
                  parameters: [{ name: image.tag, value: '{{.branch}}' }]
              destination: { server: https://kubernetes.default.svc, namespace: previews }
        """
        f = run_check(cfg, "ARGOCD-007")
        assert f.passed


# ── ARGOCD-008 CMP plugin invocation ───────────────────────────────────


class TestARGOCD008CMPPlugin:
    def test_fails_when_plugin_block_present(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata: { name: payments, namespace: argocd }
        spec:
          source:
            repoURL: https://github.com/example/r
            path: .
            plugin:
              name: my-cmp
        """
        f = run_check(cfg, "ARGOCD-008")
        assert not f.passed

    def test_passes_for_pure_helm_source(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Application
        metadata: { name: payments, namespace: argocd }
        spec:
          source:
            repoURL: https://github.com/example/r
            path: chart
            helm: { valueFiles: [values.yaml] }
        """
        f = run_check(cfg, "ARGOCD-008")
        assert f.passed


# ── ARGOCD-009 anonymous access ────────────────────────────────────────


class TestARGOCD009Anonymous:
    def test_fails_when_anonymous_true(self):
        cfg = """
        apiVersion: v1
        kind: ConfigMap
        metadata: { name: argocd-cm, namespace: argocd }
        data:
          users.anonymous.enabled: "true"
        """
        f = run_check(cfg, "ARGOCD-009")
        assert not f.passed

    def test_passes_when_anonymous_false(self):
        cfg = """
        apiVersion: v1
        kind: ConfigMap
        metadata: { name: argocd-cm, namespace: argocd }
        data:
          users.anonymous.enabled: "false"
        """
        f = run_check(cfg, "ARGOCD-009")
        assert f.passed


# ── Orchestrator-level invariants ─────────────────────────────────────


def test_empty_context_every_rule_passes():
    """No docs -> every rule short-circuits to passed=True. Mirrors the
    same contract every other provider's rules carry."""
    findings = ArgoCDChecks(argocd_ctx("")).run()
    assert findings, "expected at least one finding from the empty-context run"
    for f in findings:
        assert f.passed, f"{f.check_id} did not short-circuit on empty context"


def test_appproject_wildcards_fire_both_rules():
    """Cross-check: an AppProject with both axes wildcarded must fire
    ARGOCD-001 AND ARGOCD-002 and no other AppProject rule."""
    cfg = """
    apiVersion: argoproj.io/v1alpha1
    kind: AppProject
    metadata: { name: default, namespace: argocd }
    spec:
      sourceRepos: ['*']
      destinations:
        - { server: '*', namespace: '*' }
    """
    ctx = argocd_ctx(cfg)
    findings = {f.check_id: f for f in ArgoCDChecks(ctx).run()}
    assert not findings["ARGOCD-001"].passed
    assert not findings["ARGOCD-002"].passed
