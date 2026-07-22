"""Per-rule unit tests for HELM-011..014 (extended chart pack)."""
from __future__ import annotations

from typing import Any

from pipeline_check.core.checks.helm.base import HelmContext
from pipeline_check.core.checks.helm.charts import Chart
from pipeline_check.core.checks.helm.rules.helm011_dependency_url_credentials import (
    check as check_helm011,
)
from pipeline_check.core.checks.helm.rules.helm012_deprecated_without_alternative import (
    check as check_helm012,
)
from pipeline_check.core.checks.helm.rules.helm013_chart_type_invalid import (
    check as check_helm013,
)
from pipeline_check.core.checks.helm.rules.helm014_compromised_dependency import (
    check as check_helm014,
)


def _ctx(*charts: Chart) -> HelmContext:
    ctx = HelmContext([])
    ctx.charts = list(charts)
    return ctx


def _chart(
    name: str = "demo",
    api_version: str = "v2",
    dependencies: list[dict[str, Any]] | None = None,
    chart_type: str | None = None,
    deprecated: bool | None = None,
    home: str | None = None,
    sources: list[str] | None = None,
    annotations: dict[str, str] | None = None,
) -> Chart:
    cy: dict[str, Any] = {"name": name, "apiVersion": api_version}
    if dependencies is not None:
        cy["dependencies"] = dependencies
    if chart_type is not None:
        cy["type"] = chart_type
    if deprecated is not None:
        cy["deprecated"] = deprecated
    if home is not None:
        cy["home"] = home
    if sources is not None:
        cy["sources"] = sources
    if annotations is not None:
        cy["annotations"] = annotations
    return Chart(
        path=f"/fake/{name}",
        chart_yaml_path=f"/fake/{name}/Chart.yaml",
        chart_yaml=cy,
    )


# ── HELM-011 ────────────────────────────────────────────────────


class TestHELM011:
    def test_fires_on_credentials_in_dependency_url(self):
        chart = _chart(dependencies=[{
            "name": "redis",
            "version": "17.0.0",
            "repository": "https://user:pass@charts.corp/private/",
        }])
        f = check_helm011(_ctx(chart))
        assert not f.passed
        assert "user@charts.corp" in f.description

    def test_passes_on_clean_dependency_url(self):
        chart = _chart(dependencies=[{
            "name": "redis",
            "version": "17.0.0",
            "repository": "https://charts.example.com",
        }])
        f = check_helm011(_ctx(chart))
        assert f.passed

    def test_passes_when_no_dependencies(self):
        chart = _chart()
        f = check_helm011(_ctx(chart))
        assert f.passed

    def test_skips_env_var_placeholder(self):
        chart = _chart(dependencies=[{
            "name": "redis",
            "version": "17.0.0",
            "repository": "https://${TOKEN}@charts.corp/private/",
        }])
        f = check_helm011(_ctx(chart))
        assert f.passed


# ── HELM-012 ────────────────────────────────────────────────────


class TestHELM012:
    def test_fires_on_deprecated_without_successor(self):
        chart = _chart(name="legacy", deprecated=True)
        f = check_helm012(_ctx(chart))
        assert not f.passed
        assert "legacy" in f.description

    def test_passes_when_not_deprecated(self):
        chart = _chart()
        f = check_helm012(_ctx(chart))
        assert f.passed

    def test_passes_with_home_url_set(self):
        chart = _chart(
            deprecated=True,
            home="https://example.com/migration-guide",
        )
        f = check_helm012(_ctx(chart))
        assert f.passed

    def test_passes_with_sources_set(self):
        chart = _chart(
            deprecated=True,
            sources=["https://github.com/example/successor-chart"],
        )
        f = check_helm012(_ctx(chart))
        assert f.passed

    def test_passes_with_replacement_annotation(self):
        chart = _chart(
            deprecated=True,
            annotations={
                "helm.sh/replacement": "corp-charts/myapp-v2",
            },
        )
        f = check_helm012(_ctx(chart))
        assert f.passed


# ── HELM-013 ────────────────────────────────────────────────────


class TestHELM013:
    def test_passes_on_application(self):
        chart = _chart(chart_type="application")
        f = check_helm013(_ctx(chart))
        assert f.passed

    def test_passes_on_library(self):
        chart = _chart(chart_type="library")
        f = check_helm013(_ctx(chart))
        assert f.passed

    def test_missing_type_passes(self):
        # A missing type: is Helm's ``application`` default (legitimate,
        # common); the rule no longer flags it (2026-07 audit LOW FP).
        chart = _chart(chart_type=None)
        f = check_helm013(_ctx(chart))
        assert f.passed

    def test_fires_on_invalid_type(self):
        chart = _chart(chart_type="something-else")
        f = check_helm013(_ctx(chart))
        assert not f.passed

    def test_skips_v1_charts(self):
        # Helm 2 (v1) charts don't have a type field; HELM-001 owns that.
        chart = _chart(api_version="v1", chart_type=None)
        f = check_helm013(_ctx(chart))
        assert f.passed


# ── HELM-014 ────────────────────────────────────────────────────


class TestHELM014:
    def test_passes_with_no_compromised_match(self):
        chart = _chart(dependencies=[{
            "name": "redis",
            "version": "17.0.0",
            "repository": "https://charts.example.com",
        }])
        f = check_helm014(_ctx(chart))
        assert f.passed

    def test_fires_on_known_compromised(self):
        # Use the seeded synthetic entry.
        from pipeline_check.core.checks.helm._compromised_charts import (
            COMPROMISED,
        )
        seed = COMPROMISED[0]
        chart = _chart(dependencies=[{
            "name": seed.chart_name,
            "version": seed.malicious_versions[0],
            "repository": "https://charts.example.com",
        }])
        f = check_helm014(_ctx(chart))
        assert not f.passed
        assert seed.advisory in f.description
