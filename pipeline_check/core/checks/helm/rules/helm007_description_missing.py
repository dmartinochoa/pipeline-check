"""HELM-007 — ``Chart.yaml`` ``description`` field empty or missing.

The ``description:`` field is what Helm registries display to chart
consumers (ArtifactHub, the ``helm search`` CLI, internal chart
museums). Without it, the chart shows up in listings as the bare
chart name, with no hint at what the chart does — anyone browsing
the registry has to read the README to figure it out.

Like HELM-005 (maintainers), this is chart-listing hygiene rather
than a direct security control. A chart published to a shared
registry without a description is anonymous in the same way a
maintainers-less chart is — discovery and trust both suffer.
"""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import HelmContext

RULE = Rule(
    id="HELM-007",
    title="Chart.yaml description field is empty or missing",
    severity=Severity.LOW,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PROV-INTEGRITY",),
    cwe=("CWE-1059",),
    recommendation=(
        "Set ``description:`` in ``Chart.yaml`` to a one-sentence "
        "summary of what the chart deploys (e.g. ``description: "
        "Postgres 14 cluster with WAL-G backups and a Prometheus "
        "exporter``). Helm registries display this string in chart "
        "listings; without it, anyone browsing has to read the "
        "README to figure out what the chart does."
    ),
    docs_note=(
        "Walks ``Chart.yaml`` ``description:`` and fires when the "
        "field is missing, ``None``, or a string that's empty after "
        "stripping whitespace. The Helm chart spec doesn't enforce "
        "the field but every chart published to ArtifactHub or "
        "the upstream stable repo populates it; production charts "
        "that ship without it are usually a copy-paste-from-template "
        "oversight."
    ),
)


def check(ctx: HelmContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for chart in ctx.charts:
        desc = chart.chart_yaml.get("description")
        if not isinstance(desc, str) or not desc.strip():
            offenders.append(f"{chart.name} ({chart.chart_yaml_path})")
            locations.append(Location(path=chart.chart_yaml_path))
    passed = not offenders
    desc_text = (
        "Every chart declares a non-empty description."
        if passed else
        f"{len(offenders)} chart(s) ship with an empty / missing "
        f"``description:`` field: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="helm/charts",
        description=desc_text,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
