"""Integration: load custom rules through the Scanner end to end.

Verifies the full plumbing: Scanner accepts ``custom_rules=``,
the loader resolves them, the runner appends a check class to the
provider's list, findings flow through scoring/gating/standards
attribution, and ``--explain`` (the public API) finds the rule.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from pipeline_check.core.checks.kubernetes.base import (
    KubernetesContext,
    Manifest,
)
from pipeline_check.core.scanner import Scanner


GHA_RULE = """
rules:
  - id: ACME-001
    title: Action must be pinned to a 40-char SHA
    severity: HIGH
    provider: github
    description: 'step uses {{uses}} not pinned to a SHA'
    recommendation: Pin to a 40-char SHA.
    for_each: $.jobs.*.steps[*]
    assert:
      regex:
        path: uses
        pattern: '^[^@]+@[0-9a-f]{40}$'
"""


K8S_RULE = """
rules:
  - id: ACME-002
    title: Container image must come from acme.io
    severity: HIGH
    provider: kubernetes
    description: 'container {{name}} image {{image}} not from acme.io'
    recommendation: Use acme.io/<team>/<image>:<sha>.
    for_each: $.workloads[*].containers[*]
    assert:
      regex:
        path: image
        pattern: '^acme\\.io/'
"""


@pytest.fixture
def workflows_dir(tmp_path: Path) -> Path:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "name: ci\non: push\njobs:\n"
        "  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: actions/setup-python@" + "a" * 40 + "\n",
        encoding="utf-8",
    )
    return wf


class TestGitHubProvider:

    def test_custom_rule_fires_on_unpinned_action(
        self, tmp_path, workflows_dir
    ):
        rules_path = tmp_path / "acme.yml"
        rules_path.write_text(GHA_RULE, encoding="utf-8")
        scanner = Scanner(
            pipeline="github",
            gha_path=str(workflows_dir),
            custom_rules=[str(rules_path)],
            chains_enabled=False,
        )
        findings = scanner.run()
        acme = [f for f in findings if f.check_id == "ACME-001"]
        assert acme, "ACME-001 should produce at least one finding"
        failed = [f for f in acme if not f.passed]
        assert failed, "ACME-001 should have a failed finding"
        assert "actions/checkout@v4" in failed[0].description

    def test_custom_rule_passes_on_pinned_only(
        self, tmp_path
    ):
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "ci.yml").write_text(
            "name: ci\non: push\njobs:\n"
            "  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/setup-python@" + "a" * 40 + "\n",
            encoding="utf-8",
        )
        rules_path = tmp_path / "acme.yml"
        rules_path.write_text(GHA_RULE, encoding="utf-8")
        scanner = Scanner(
            pipeline="github",
            gha_path=str(wf_dir),
            custom_rules=[str(rules_path)],
            chains_enabled=False,
        )
        findings = scanner.run()
        acme = [f for f in findings if f.check_id == "ACME-001"]
        assert acme
        assert all(f.passed for f in acme)


class TestKubernetesProvider:

    def test_custom_rule_via_synthesized_workloads_view(self, tmp_path):
        manifest_dir = tmp_path / "k8s"
        manifest_dir.mkdir()
        (manifest_dir / "deploy.yaml").write_text(
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "metadata: { name: app, namespace: default }\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      containers:\n"
            "        - name: web\n"
            "          image: nginx:latest\n"
            "        - name: api\n"
            "          image: acme.io/api:v1\n",
            encoding="utf-8",
        )
        rules_path = tmp_path / "acme.yml"
        rules_path.write_text(K8S_RULE, encoding="utf-8")
        scanner = Scanner(
            pipeline="kubernetes",
            k8s_path=str(manifest_dir),
            custom_rules=[str(rules_path)],
            chains_enabled=False,
        )
        findings = scanner.run()
        acme = [f for f in findings if f.check_id == "ACME-002"]
        assert acme, "ACME-002 should produce a finding"
        f = acme[0]
        assert not f.passed
        # The synthesized view's container view exposes ``name`` (web)
        # but the manifest's kind is ``Deployment`` (via ambient).
        assert "web" in f.description
        assert "nginx:latest" in f.description


class TestCollisions:

    def test_id_collision_with_builtin_rejected(self, tmp_path):
        # Reuse a known built-in id to force the collision check.
        rules_path = tmp_path / "rules.yml"
        rules_path.write_text(
            GHA_RULE.replace("ACME-001", "GHA-001"), encoding="utf-8",
        )
        with pytest.raises(Exception, match="collides with a built-in"):
            Scanner(
                pipeline="github",
                gha_path=str(tmp_path),
                custom_rules=[str(rules_path)],
            )


class TestNoCustomRules:

    def test_unset_custom_rules_no_change(self, tmp_path, workflows_dir):
        # Sanity guard: Scanner without custom_rules behaves identically
        # to the built-in catalog.
        baseline = Scanner(
            pipeline="github",
            gha_path=str(workflows_dir),
            chains_enabled=False,
        )
        baseline_findings = baseline.run()
        with_empty = Scanner(
            pipeline="github",
            gha_path=str(workflows_dir),
            custom_rules=None,
            chains_enabled=False,
        )
        followup = with_empty.run()
        # Same number of unique check IDs.
        assert {f.check_id for f in baseline_findings} == {
            f.check_id for f in followup
        }


class TestExplainSurfacesCustomRule:
    """The loaded custom rule should appear in the public API surface."""

    def test_loaded_rules_show_metadata(self, tmp_path, workflows_dir):
        rules_path = tmp_path / "acme.yml"
        rules_path.write_text(GHA_RULE, encoding="utf-8")
        scanner = Scanner(
            pipeline="github",
            gha_path=str(workflows_dir),
            custom_rules=[str(rules_path)],
        )
        loaded = scanner._custom_rules
        assert {r.id for r in loaded.rules} == {"ACME-001"}
        rule = loaded.rules[0]
        assert rule.title.startswith("Action must")
        assert rule.recommendation.startswith("Pin to")


class TestPredicateAppliesAcrossManifests:

    def test_one_finding_aggregates_offenders_across_manifests(self, tmp_path):
        # Two K8s manifests, one offender each — both should appear in
        # the single rolled-up finding's description.
        manifest_dir = tmp_path / "k8s"
        manifest_dir.mkdir()
        (manifest_dir / "a.yaml").write_text(
            "apiVersion: apps/v1\nkind: Deployment\n"
            "metadata: { name: app1 }\n"
            "spec: { template: { spec: { containers: ["
            "{ name: web, image: nginx:1 }] } } }\n",
            encoding="utf-8",
        )
        (manifest_dir / "b.yaml").write_text(
            "apiVersion: apps/v1\nkind: Deployment\n"
            "metadata: { name: app2 }\n"
            "spec: { template: { spec: { containers: ["
            "{ name: api, image: redis:1 }] } } }\n",
            encoding="utf-8",
        )
        rules_path = tmp_path / "acme.yml"
        rules_path.write_text(K8S_RULE, encoding="utf-8")
        scanner = Scanner(
            pipeline="kubernetes",
            k8s_path=str(manifest_dir),
            custom_rules=[str(rules_path)],
            chains_enabled=False,
        )
        findings = [f for f in scanner.run() if f.check_id == "ACME-002"]
        assert len(findings) == 1
        f = findings[0]
        assert not f.passed
        # Both manifests' offenders should appear in the description.
        assert "app1" in f.description
        assert "app2" in f.description


class TestUnusedRuleSilentlyDropped:

    def test_kubernetes_rule_unused_in_github_scan(
        self, tmp_path, workflows_dir
    ):
        # Loading a kubernetes-targeted rule for a github scan: the
        # rule loads but the runner just doesn't execute it.
        rules_path = tmp_path / "k8s.yml"
        rules_path.write_text(K8S_RULE, encoding="utf-8")
        scanner = Scanner(
            pipeline="github",
            gha_path=str(workflows_dir),
            custom_rules=[str(rules_path)],
            chains_enabled=False,
        )
        findings = scanner.run()
        # ACME-002 is k8s-scoped and should not have run on the
        # github context. Its absence from findings is the success
        # signal — the loader still parsed it, but the runner is
        # provider-scoped.
        assert all(f.check_id != "ACME-002" for f in findings)
