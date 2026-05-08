"""Per-rule unit tests for HELM-001 / HELM-002 / HELM-003.

The rules score the parsed ``Chart.yaml`` / ``Chart.lock`` content,
not the rendered manifests, so the tests build :class:`Chart` records
directly and call each rule's ``check`` against a synthesized
:class:`HelmContext`. This keeps the tests fast and independent of
the ``helm`` binary.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from pipeline_check.core.checks.helm.base import HelmContext
from pipeline_check.core.checks.helm.charts import Chart, parse_chart
from pipeline_check.core.checks.helm.charts_check import HelmChartChecks
from pipeline_check.core.checks.helm.rules.helm001_chart_api_version_v1 import (
    check as check_helm001,
)
from pipeline_check.core.checks.helm.rules.helm002_chart_lock_digests import (
    check as check_helm002,
)
from pipeline_check.core.checks.helm.rules.helm003_dependency_repo_https import (
    check as check_helm003,
)


def _ctx_with_charts(*charts: Chart) -> HelmContext:
    ctx = HelmContext([])
    ctx.charts = list(charts)
    return ctx


def _chart(
    name: str = "demo",
    api_version: str = "v2",
    dependencies: list[dict[str, Any]] | None = None,
    chart_lock: dict[str, Any] | None = None,
) -> Chart:
    """Build a Chart record without touching the disk."""
    cy: dict[str, Any] = {"name": name, "apiVersion": api_version}
    if dependencies is not None:
        cy["dependencies"] = dependencies
    return Chart(
        path=f"/fake/{name}",
        chart_yaml_path=f"/fake/{name}/Chart.yaml",
        chart_yaml=cy,
        chart_lock_path=f"/fake/{name}/Chart.lock" if chart_lock is not None else None,
        chart_lock=chart_lock,
    )


# ──────────────────────────────────────────────────────────────────
# HELM-001
# ──────────────────────────────────────────────────────────────────


class TestHELM001:

    def test_v2_chart_passes(self):
        ctx = _ctx_with_charts(_chart(api_version="v2"))
        f = check_helm001(ctx)
        assert f.passed
        assert "v2" in f.description.lower() or "every chart" in f.description.lower()

    def test_v1_chart_fails(self):
        ctx = _ctx_with_charts(_chart(name="legacy", api_version="v1"))
        f = check_helm001(ctx)
        assert not f.passed
        assert "legacy" in f.description
        assert any(loc.path.endswith("Chart.yaml") for loc in f.locations)

    def test_passes_with_no_charts(self):
        # Edge case: a path with no parseable charts. Nothing to flag.
        ctx = _ctx_with_charts()
        assert check_helm001(ctx).passed

    def test_missing_apiversion_does_not_fire(self):
        # apiVersion absent → not a v1 chart per this rule. (Helm
        # itself would reject the chart at render time, which is a
        # different failure mode.)
        ctx = _ctx_with_charts(_chart(api_version=""))
        # Chart.api_version would resolve to "" via the helper above —
        # we want a finding only on the literal "v1" string.
        assert check_helm001(ctx).passed


# ──────────────────────────────────────────────────────────────────
# HELM-002
# ──────────────────────────────────────────────────────────────────


_VALID_DIGEST = "sha256:" + "a" * 64


class TestHELM002:

    def test_v2_chart_with_no_dependencies_passes(self):
        ctx = _ctx_with_charts(_chart(dependencies=[]))
        assert check_helm002(ctx).passed

    def test_v2_chart_with_deps_no_lock_fails(self):
        deps = [{"name": "redis", "version": "17.0.0"}]
        ctx = _ctx_with_charts(_chart(dependencies=deps, chart_lock=None))
        f = check_helm002(ctx)
        assert not f.passed
        assert "no Chart.lock" in f.description

    def test_v2_chart_with_lock_missing_entry_fails(self):
        deps = [
            {"name": "redis", "version": "17.0.0"},
            {"name": "postgres", "version": "12.0.0"},
        ]
        # Lock has redis but not postgres — drift after editing
        # Chart.yaml without re-running ``helm dependency update``.
        chart_lock = {
            "dependencies": [
                {"name": "redis", "version": "17.0.0", "repository": "https://x", "digest": _VALID_DIGEST},
            ],
        }
        ctx = _ctx_with_charts(_chart(dependencies=deps, chart_lock=chart_lock))
        f = check_helm002(ctx)
        assert not f.passed
        assert "missing entries" in f.description
        assert "postgres" in f.description

    def test_v2_chart_with_lock_missing_digest_fails(self):
        deps = [{"name": "redis", "version": "17.0.0"}]
        chart_lock = {
            "dependencies": [
                {"name": "redis", "version": "17.0.0", "digest": ""},
            ],
        }
        ctx = _ctx_with_charts(_chart(dependencies=deps, chart_lock=chart_lock))
        f = check_helm002(ctx)
        assert not f.passed
        assert "without sha256 digest" in f.description

    def test_v2_chart_with_complete_lock_passes(self):
        deps = [{"name": "redis", "version": "17.0.0"}]
        chart_lock = {
            "dependencies": [
                {"name": "redis", "version": "17.0.0", "digest": _VALID_DIGEST},
            ],
        }
        ctx = _ctx_with_charts(_chart(dependencies=deps, chart_lock=chart_lock))
        assert check_helm002(ctx).passed

    def test_v1_chart_skipped(self):
        # HELM-001 catches v1 directly; HELM-002 doesn't second-guess.
        deps = [{"name": "redis", "version": "17.0.0"}]
        ctx = _ctx_with_charts(_chart(api_version="v1", dependencies=deps))
        assert check_helm002(ctx).passed

    def test_non_sha256_digest_is_rejected(self):
        deps = [{"name": "redis", "version": "17.0.0"}]
        chart_lock = {
            "dependencies": [
                {"name": "redis", "version": "17.0.0", "digest": "md5:abc"},
            ],
        }
        ctx = _ctx_with_charts(_chart(dependencies=deps, chart_lock=chart_lock))
        f = check_helm002(ctx)
        assert not f.passed


# ──────────────────────────────────────────────────────────────────
# HELM-003
# ──────────────────────────────────────────────────────────────────


class TestHELM003:

    @pytest.mark.parametrize("repo", [
        "https://charts.example.com",
        "oci://registry.example.com/charts",
        "file://../sibling-chart",
        "@stable",  # local helm-repo alias
        "",  # empty -> caller chose not to declare; out of scope
    ])
    def test_safe_repo_passes(self, repo):
        deps = [{"name": "redis", "version": "17.0.0", "repository": repo}]
        ctx = _ctx_with_charts(_chart(dependencies=deps))
        assert check_helm003(ctx).passed, repo

    @pytest.mark.parametrize("repo", [
        "http://charts.example.com",
        "git://example.com/chart-repo",
        "ftp://internal/charts",
    ])
    def test_unsafe_repo_fails(self, repo):
        deps = [{"name": "redis", "version": "17.0.0", "repository": repo}]
        ctx = _ctx_with_charts(_chart(dependencies=deps))
        f = check_helm003(ctx)
        assert not f.passed, repo
        assert repo in f.description

    def test_non_string_repository_skipped(self):
        deps = [{"name": "redis", "version": "17.0.0", "repository": None}]
        ctx = _ctx_with_charts(_chart(dependencies=deps))
        assert check_helm003(ctx).passed

    def test_v1_chart_skipped(self):
        deps = [{"name": "redis", "repository": "http://example.com"}]
        ctx = _ctx_with_charts(_chart(api_version="v1", dependencies=deps))
        assert check_helm003(ctx).passed


# ──────────────────────────────────────────────────────────────────
# Orchestrator smoke
# ──────────────────────────────────────────────────────────────────


class TestHelmChartChecksOrchestrator:

    def test_runs_all_three_rules(self):
        ctx = _ctx_with_charts(_chart())
        findings = HelmChartChecks(ctx).run()
        ids = sorted(f.check_id for f in findings)
        assert ids == ["HELM-001", "HELM-002", "HELM-003"]

    def test_attaches_cwe_metadata(self):
        ctx = _ctx_with_charts(_chart())
        findings = HelmChartChecks(ctx).run()
        helm002 = next(f for f in findings if f.check_id == "HELM-002")
        assert "CWE-494" in helm002.cwe


# ──────────────────────────────────────────────────────────────────
# Chart parser — disk path
# ──────────────────────────────────────────────────────────────────


class TestParseChart:

    def test_reads_fixture_chart(self):
        chart_dir = Path(__file__).parent.parent / "fixtures" / "helm" / "sample"
        chart = parse_chart(chart_dir)
        assert chart is not None
        assert chart.name == "sample"
        assert chart.api_version == "v2"
        # Fixture chart has no dependencies, so no Chart.lock.
        assert chart.chart_lock is None
        assert chart.dependencies == []

    def test_returns_none_on_dir_without_chart_yaml(self, tmp_path):
        assert parse_chart(tmp_path) is None

    def test_reads_chart_lock_when_present(self, tmp_path):
        (tmp_path / "Chart.yaml").write_text(
            "apiVersion: v2\nname: demo\nversion: 0.1.0\n"
            "dependencies:\n  - name: redis\n    version: 17.0.0\n"
            "    repository: https://x\n",
            encoding="utf-8",
        )
        (tmp_path / "Chart.lock").write_text(
            "dependencies:\n  - name: redis\n    version: 17.0.0\n"
            "    repository: https://x\n"
            f"    digest: {_VALID_DIGEST}\n"
            "digest: sha256:0\n"
            "generated: 2026-05-01T00:00:00Z\n",
            encoding="utf-8",
        )
        chart = parse_chart(tmp_path)
        assert chart is not None
        assert chart.chart_lock is not None
        assert chart.chart_lock["dependencies"][0]["digest"] == _VALID_DIGEST

    def test_skips_unparseable_chart_yaml(self, tmp_path):
        (tmp_path / "Chart.yaml").write_text(
            "this: is\n  not: [valid yaml",
            encoding="utf-8",
        )
        chart = parse_chart(tmp_path)
        assert chart is None
