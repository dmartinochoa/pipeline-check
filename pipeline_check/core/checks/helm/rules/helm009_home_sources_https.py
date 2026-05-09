"""HELM-009. Chart ``home`` / ``sources`` URLs use a non-HTTPS scheme.

``home:`` and ``sources:`` in ``Chart.yaml`` are the chart's
landing page and source-repository links, displayed by chart
registries (ArtifactHub, ``helm search``) and embedded into the
chart's metadata. A consumer browsing the registry follows these
URLs to verify the chart's provenance, clicking through to a
``http://`` link drops them into a session vulnerable to an
on-path attacker rewriting the page (or, more commonly, a 301
redirect to a typo-squat).

Mirrors HELM-003's stance for dependency repositories: the
plaintext-fetch problem applies equally to "where the chart claims
to live" as to "where the chart's deps come from".
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import HelmContext

RULE = Rule(
    id="HELM-009",
    title="Chart home / sources URL uses a non-HTTPS scheme",
    severity=Severity.LOW,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PROV-INTEGRITY", "ESF-S-TRUSTED-REG"),
    cwe=("CWE-319",),
    recommendation=(
        "Switch every ``home:`` URL and every entry in ``sources:`` "
        "to ``https://``. Most chart-listing UIs display these as "
        "click-through links from a public chart registry; serving "
        "them over plaintext is a confused-deputy footgun for "
        "anyone evaluating the chart's provenance. ``http://`` "
        "URLs against ``localhost`` are not exempted, production "
        "charts shouldn't ship references to a developer-local "
        "endpoint anyway."
    ),
    docs_note=(
        "Walks ``Chart.yaml`` ``home:`` (single string) and "
        "``sources:`` (list of strings). Fires on any value whose "
        "scheme is ``http://``, ``ftp://``, or other plaintext "
        "form. Empty / missing fields pass, the rule only "
        "evaluates URLs that are *populated* with the wrong scheme. "
        "HELM-003 covers the same risk for dependency-repo URLs."
    ),
)


def _is_safe_url(url: str) -> bool:
    s = url.strip()
    if not s:
        return True  # empty -> nothing to flag
    lower = s.lower()
    return lower.startswith("https://") or lower.startswith("git+ssh://")


def _iter_offenders(chart_yaml: dict[str, Any]) -> list[str]:
    out: list[str] = []
    home = chart_yaml.get("home")
    if isinstance(home, str) and not _is_safe_url(home):
        out.append(f"home={home}")
    sources = chart_yaml.get("sources")
    if isinstance(sources, list):
        for src in sources:
            if isinstance(src, str) and not _is_safe_url(src):
                out.append(f"sources entry={src}")
    return out


def check(ctx: HelmContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for chart in ctx.charts:
        chart_offenders = _iter_offenders(chart.chart_yaml)
        if chart_offenders:
            for entry in chart_offenders:
                offenders.append(f"{chart.name}: {entry}")
            locations.append(Location(path=chart.chart_yaml_path))
    passed = not offenders
    desc = (
        "Every chart's home / sources URL uses HTTPS."
        if passed else
        f"{len(offenders)} chart URL(s) use a non-HTTPS scheme: "
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
