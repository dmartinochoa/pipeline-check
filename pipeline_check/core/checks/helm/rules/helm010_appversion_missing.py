"""HELM-010 — ``Chart.yaml`` ``appVersion`` field is empty or missing.

``appVersion:`` is the version of the application packaged inside
the chart, distinct from ``version:`` (which is the chart's own
version). The two move independently — a chart at ``version: 1.4.2``
might package an app at ``appVersion: 17.2.0`` (Postgres 17.2,
Redis 7.4, etc.).

When ``appVersion`` is empty, downstream consumers can't tell which
app version they're getting from the chart name alone. The
distinction matters for CVE tracking: a CVE filed against
"Postgres 17.0" needs the application version to confirm whether
this chart's deployment is exposed.
"""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import HelmContext

RULE = Rule(
    id="HELM-010",
    title="Chart.yaml appVersion field is empty or missing",
    severity=Severity.LOW,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PROV-INTEGRITY",),
    cwe=("CWE-1059",),
    recommendation=(
        "Set ``appVersion:`` in ``Chart.yaml`` to the version of "
        "the application the chart packages (e.g. ``appVersion: "
        "\"17.2\"`` for a Postgres-17.2 chart at ``version: "
        "1.4.2``). When the upstream application releases, bump "
        "``appVersion`` and re-cut the chart. Helm's CLI displays "
        "``appVersion`` alongside the chart version in ``helm "
        "list``, so downstream operators can see which app version "
        "is running where."
    ),
    docs_note=(
        "Library charts (``Chart.yaml`` ``type: library``) "
        "legitimately don't have an ``appVersion`` because they "
        "package no application — those are exempted. For "
        "application charts (``type: application``, the default), "
        "``appVersion`` is required for CVE tracking and "
        "release-tracking; without it, ``helm list`` shows ``-`` "
        "in the AppVersion column and downstream consumers have "
        "no signal."
    ),
)


def check(ctx: HelmContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for chart in ctx.charts:
        chart_type = chart.chart_yaml.get("type")
        # Library charts intentionally have no app to version.
        if isinstance(chart_type, str) and chart_type.lower() == "library":
            continue
        app_version = chart.chart_yaml.get("appVersion")
        # Helm tolerates ``appVersion: 1.0`` as a YAML number; we
        # accept any non-empty string or numeric value, fire only
        # when the field is absent / empty / blank.
        if isinstance(app_version, (int, float)):
            continue
        if not isinstance(app_version, str) or not app_version.strip():
            offenders.append(f"{chart.name} ({chart.chart_yaml_path})")
            locations.append(Location(path=chart.chart_yaml_path))
    passed = not offenders
    desc = (
        "Every application chart declares an ``appVersion``."
        if passed else
        f"{len(offenders)} chart(s) ship without an ``appVersion`` "
        f"field: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="helm/charts",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
