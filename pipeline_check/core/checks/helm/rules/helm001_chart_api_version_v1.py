"""HELM-001, ``Chart.yaml`` declares the legacy ``apiVersion: v1``.

Helm 2's chart format. Helm 3 still renders ``v1`` charts, but the
shape carries real supply-chain hazards: dependencies live in a
sibling ``requirements.yaml`` (no in-file lock-able view of the
dependency graph), library charts aren't supported, and ``Chart.lock``
isn't expected, so HELM-002's "every dep must have a digest" check
can't get traction. Bumping a chart to ``apiVersion: v2`` is the
prerequisite for the rest of the chart-supply-chain controls.
"""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import HelmContext

RULE = Rule(
    id="HELM-001",
    title="Chart.yaml declares legacy apiVersion: v1",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS",),
    cwe=("CWE-1104",),
    recommendation=(
        "Bump ``Chart.yaml`` to ``apiVersion: v2`` and migrate any "
        "sibling ``requirements.yaml`` entries into the ``dependencies:`` "
        "list inside ``Chart.yaml``. Run ``helm dependency update`` to "
        "regenerate ``Chart.lock`` so HELM-002's per-dependency digest "
        "check has something to read. Helm 3 has been the default "
        "shipping channel since November 2019; the v1 format is "
        "kept for read-compat but blocks lockfile-based supply-chain "
        "controls."
    ),
    docs_note=(
        "``apiVersion`` lives at the top of ``Chart.yaml``. ``v1`` is "
        "Helm 2's format and uses a sibling ``requirements.yaml`` for "
        "dependencies; ``v2`` is Helm 3's format and inlines them in "
        "``Chart.yaml`` alongside a ``Chart.lock`` for digest pinning. "
        "Without v2 there is no in-tree dependency manifest to lock, "
        "which is why HELM-002 only fires on v2 charts."
    ),
)


def check(ctx: HelmContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for chart in ctx.charts:
        api_version = chart.api_version
        if api_version == "v1":
            offenders.append(f"{chart.name} ({chart.chart_yaml_path})")
            locations.append(Location(path=chart.chart_yaml_path))
    passed = not offenders
    desc = (
        "Every chart declares ``apiVersion: v2`` (Helm 3 format)."
        if passed else
        f"{len(offenders)} chart(s) still on ``apiVersion: v1``: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="helm/charts",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
