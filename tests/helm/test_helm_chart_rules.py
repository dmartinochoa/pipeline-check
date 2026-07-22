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
from pipeline_check.core.checks.helm.rules.helm004_dependency_version_pinning import (
    check as check_helm004,
)
from pipeline_check.core.checks.helm.rules.helm005_maintainers_missing import (
    check as check_helm005,
)
from pipeline_check.core.checks.helm.rules.helm006_kubeversion_missing import (
    check as check_helm006,
)
from pipeline_check.core.checks.helm.rules.helm007_description_missing import (
    check as check_helm007,
)
from pipeline_check.core.checks.helm.rules.helm008_chart_lock_stale import (
    check as check_helm008,
)
from pipeline_check.core.checks.helm.rules.helm009_home_sources_https import (
    check as check_helm009,
)
from pipeline_check.core.checks.helm.rules.helm010_appversion_missing import (
    check as check_helm010,
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
    maintainers: list[dict[str, Any]] | None = None,
    kube_version: str | None = None,
    description: str | None = None,
    home: str | None = None,
    sources: list[str] | None = None,
    app_version: str | None = None,
    chart_type: str | None = None,
) -> Chart:
    """Build a Chart record without touching the disk."""
    cy: dict[str, Any] = {"name": name, "apiVersion": api_version}
    if dependencies is not None:
        cy["dependencies"] = dependencies
    if maintainers is not None:
        cy["maintainers"] = maintainers
    if kube_version is not None:
        cy["kubeVersion"] = kube_version
    if description is not None:
        cy["description"] = description
    if home is not None:
        cy["home"] = home
    if sources is not None:
        cy["sources"] = sources
    if app_version is not None:
        cy["appVersion"] = app_version
    if chart_type is not None:
        cy["type"] = chart_type
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
# HELM-004
# ──────────────────────────────────────────────────────────────────


class TestHELM004:

    @pytest.mark.parametrize("ver", [
        "1.2.3",
        "v1.2.3",
        "0.0.1",
        "1.2.3-rc1",
        "1.2.3-alpha.1",
        "1.2.3+build.5",
    ])
    def test_exact_pin_passes(self, ver):
        deps = [{"name": "redis", "version": ver}]
        ctx = _ctx_with_charts(_chart(dependencies=deps))
        assert check_helm004(ctx).passed, ver

    @pytest.mark.parametrize("ver", [
        "^1.2.3",
        "~1.2",
        ">=1.2.3",
        ">=1.2 <2",
        "1.x",
        "*",
        "1.2.3 || 1.2.4",
        # Two- / one-component versions are Masterminds ranges, not pins
        # (2026-07 audit LOW FN).
        "1.2",
        "1",
    ])
    def test_range_or_wildcard_fails(self, ver):
        deps = [{"name": "redis", "version": ver}]
        ctx = _ctx_with_charts(_chart(dependencies=deps))
        f = check_helm004(ctx)
        assert not f.passed, ver
        assert ver in f.description

    def test_v1_chart_skipped(self):
        deps = [{"name": "redis", "version": "^17.0.0"}]
        ctx = _ctx_with_charts(_chart(api_version="v1", dependencies=deps))
        assert check_helm004(ctx).passed

    def test_chart_with_no_deps_passes(self):
        ctx = _ctx_with_charts(_chart(dependencies=[]))
        assert check_helm004(ctx).passed


# ──────────────────────────────────────────────────────────────────
# HELM-005
# ──────────────────────────────────────────────────────────────────


class TestHELM005:

    def test_maintainer_with_email_passes(self):
        ctx = _ctx_with_charts(_chart(
            maintainers=[{"name": "Maintainer One", "email": "m@example.com"}],
        ))
        assert check_helm005(ctx).passed

    def test_maintainer_with_url_passes(self):
        ctx = _ctx_with_charts(_chart(
            maintainers=[{"name": "M", "url": "https://example.com/m"}],
        ))
        assert check_helm005(ctx).passed

    def test_missing_block_fails(self):
        ctx = _ctx_with_charts(_chart())
        f = check_helm005(ctx)
        assert not f.passed
        assert "demo" in f.description

    def test_empty_block_fails(self):
        ctx = _ctx_with_charts(_chart(maintainers=[]))
        assert not check_helm005(ctx).passed

    def test_blank_name_fails(self):
        ctx = _ctx_with_charts(_chart(
            maintainers=[{"name": "", "email": "m@example.com"}],
        ))
        assert not check_helm005(ctx).passed

    def test_name_without_contact_fails(self):
        ctx = _ctx_with_charts(_chart(
            maintainers=[{"name": "M"}],
        ))
        assert not check_helm005(ctx).passed

    def test_first_unusable_then_usable_passes(self):
        ctx = _ctx_with_charts(_chart(maintainers=[
            {"name": ""},
            {"name": "M", "email": "m@example.com"},
        ]))
        assert check_helm005(ctx).passed


# ──────────────────────────────────────────────────────────────────
# HELM-006
# ──────────────────────────────────────────────────────────────────


class TestHELM006:

    def test_kubeversion_set_passes(self):
        ctx = _ctx_with_charts(_chart(kube_version=">= 1.25.0 < 1.32.0"))
        assert check_helm006(ctx).passed

    def test_missing_kubeversion_fails(self):
        ctx = _ctx_with_charts(_chart())
        assert not check_helm006(ctx).passed

    def test_blank_kubeversion_fails(self):
        ctx = _ctx_with_charts(_chart(kube_version="   "))
        assert not check_helm006(ctx).passed


# ──────────────────────────────────────────────────────────────────
# HELM-007 — chart description empty
# ──────────────────────────────────────────────────────────────────


class TestHELM007:

    def test_description_set_passes(self):
        ctx = _ctx_with_charts(_chart(description="Postgres 14 cluster"))
        assert check_helm007(ctx).passed

    def test_description_missing_fails(self):
        ctx = _ctx_with_charts(_chart())
        f = check_helm007(ctx)
        assert not f.passed
        assert "demo" in f.description

    def test_description_blank_fails(self):
        ctx = _ctx_with_charts(_chart(description="   "))
        assert not check_helm007(ctx).passed


# ──────────────────────────────────────────────────────────────────
# HELM-008 — Chart.lock stale > 90 days
# ──────────────────────────────────────────────────────────────────


from datetime import UTC, datetime, timedelta  # noqa: E402


class TestHELM008:

    NOW = datetime(2026, 5, 8, tzinfo=UTC)

    def _lock(self, generated: str | None) -> dict[str, Any]:
        return {"generated": generated} if generated is not None else {}

    def test_recent_lock_passes(self):
        # Lock generated 30 days ago — within the 90-day window.
        ts = (self.NOW - timedelta(days=30)).isoformat()
        ctx = _ctx_with_charts(_chart(chart_lock=self._lock(ts)))
        assert check_helm008(ctx, _now=self.NOW).passed

    def test_stale_lock_fails(self):
        ts = (self.NOW - timedelta(days=120)).isoformat()
        ctx = _ctx_with_charts(_chart(chart_lock=self._lock(ts)))
        f = check_helm008(ctx, _now=self.NOW)
        assert not f.passed
        assert "120 days ago" in f.description

    def test_no_lock_skipped(self):
        # No Chart.lock at all -> HELM-002's territory, not this rule's.
        ctx = _ctx_with_charts(_chart())
        assert check_helm008(ctx, _now=self.NOW).passed

    def test_helm_lock_with_z_suffix(self):
        # Helm sometimes writes ``2024-01-02T15:04:05.000Z`` — the
        # parser must accept the ``Z`` form.
        ts = (self.NOW - timedelta(days=120)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        ctx = _ctx_with_charts(_chart(chart_lock=self._lock(ts)))
        assert not check_helm008(ctx, _now=self.NOW).passed

    def test_stale_lock_as_datetime_object_fails(self):
        # ``yaml.safe_load`` turns an *unquoted* ISO-8601 ``generated:``
        # into a ``datetime`` (the Helm default is unquoted). The parser
        # must accept that, not just string timestamps (Part-C FN: the
        # staleness check silently skipped every unquoted lock).
        ts = self.NOW - timedelta(days=120)
        ctx = _ctx_with_charts(_chart(chart_lock={"generated": ts}))
        assert not check_helm008(ctx, _now=self.NOW).passed

    def test_recent_lock_as_naive_datetime_passes(self):
        # A naive datetime (no tz) is treated as UTC.
        ts = (self.NOW - timedelta(days=10)).replace(tzinfo=None)
        ctx = _ctx_with_charts(_chart(chart_lock={"generated": ts}))
        assert check_helm008(ctx, _now=self.NOW).passed

    def test_unparseable_generated_silently_passes(self):
        # Garbage timestamp -> can't decide, don't false-positive.
        ctx = _ctx_with_charts(_chart(chart_lock=self._lock("garbage")))
        assert check_helm008(ctx, _now=self.NOW).passed

    def test_missing_generated_field_silently_passes(self):
        ctx = _ctx_with_charts(_chart(chart_lock={"dependencies": []}))
        assert check_helm008(ctx, _now=self.NOW).passed

    def test_exactly_at_threshold_passes(self):
        # 90 days exactly is within the threshold (>, not >=).
        ts = (self.NOW - timedelta(days=90)).isoformat()
        ctx = _ctx_with_charts(_chart(chart_lock=self._lock(ts)))
        assert check_helm008(ctx, _now=self.NOW).passed


# ──────────────────────────────────────────────────────────────────
# HELM-009 — chart home / sources non-HTTPS
# ──────────────────────────────────────────────────────────────────


class TestHELM009:

    @pytest.mark.parametrize("url", [
        "https://example.com",
        "https://example.com/charts",
        "git+ssh://github.com/foo/bar",
        "",  # empty -> nothing to flag
    ])
    def test_safe_home_passes(self, url):
        ctx = _ctx_with_charts(_chart(home=url))
        assert check_helm009(ctx).passed, url

    @pytest.mark.parametrize("url", [
        "http://example.com",
        "ftp://example.com",
        "git://example.com",
    ])
    def test_unsafe_home_fails(self, url):
        ctx = _ctx_with_charts(_chart(home=url))
        f = check_helm009(ctx)
        assert not f.passed, url
        assert url in f.description

    def test_unsafe_sources_entry_fails(self):
        ctx = _ctx_with_charts(_chart(
            home="https://safe.example.com",
            sources=["https://safe.example.com/repo", "http://insecure.example.com/mirror"],
        ))
        f = check_helm009(ctx)
        assert not f.passed
        assert "http://insecure.example.com/mirror" in f.description

    def test_no_urls_passes(self):
        ctx = _ctx_with_charts(_chart())
        assert check_helm009(ctx).passed


# ──────────────────────────────────────────────────────────────────
# HELM-010 — chart appVersion empty
# ──────────────────────────────────────────────────────────────────


class TestHELM010:

    def test_appversion_set_passes(self):
        ctx = _ctx_with_charts(_chart(app_version="17.2"))
        assert check_helm010(ctx).passed

    def test_appversion_missing_fails(self):
        ctx = _ctx_with_charts(_chart())
        assert not check_helm010(ctx).passed

    def test_appversion_blank_fails(self):
        ctx = _ctx_with_charts(_chart(app_version="   "))
        assert not check_helm010(ctx).passed

    def test_library_chart_skipped(self):
        ctx = _ctx_with_charts(_chart(chart_type="library"))
        assert check_helm010(ctx).passed

    def test_numeric_appversion_accepted(self):
        # YAML may parse 1.0 as a float; accept that as populated.
        chart = Chart(
            path="/fake/x",
            chart_yaml_path="/fake/x/Chart.yaml",
            chart_yaml={"name": "x", "apiVersion": "v2", "appVersion": 1.0},
        )
        ctx = _ctx_with_charts(chart)
        assert check_helm010(ctx).passed


# ──────────────────────────────────────────────────────────────────
# Orchestrator smoke
# ──────────────────────────────────────────────────────────────────


class TestHelmChartChecksOrchestrator:

    def test_runs_all_rules(self):
        ctx = _ctx_with_charts(_chart())
        findings = HelmChartChecks(ctx).run()
        ids = sorted(f.check_id for f in findings)
        assert ids == [
            "HELM-001", "HELM-002", "HELM-003",
            "HELM-004", "HELM-005", "HELM-006",
            "HELM-007", "HELM-008", "HELM-009",
            "HELM-010", "HELM-011", "HELM-012",
            "HELM-013", "HELM-014", "HELM-015",
            "HELM-016", "HELM-017",
        ]

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
