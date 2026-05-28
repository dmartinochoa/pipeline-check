"""Curated registry of known-compromised Helm charts.

Foundation for ``HELM-014``, a pure-data table of
``(chart_name, malicious_versions, advisory)`` entries sourced from
public CVEs, GHSAs, and vendor postmortems. The rule consults the
registry to detect dependencies pinned to a known-bad version.

Mirrors the shape of every other ecosystem-specific compromised
registry in this codebase (npm, PyPI, Maven, NuGet, Go modules,
Cargo): hand-curated, append-only, refresh by PR with the citing
advisory in the commit message. Deliberately not a fetch-from-
network registry — pulling on every scan would take the "no
telemetry, no API tokens" default off the table.
"""
from __future__ import annotations

from dataclasses import dataclass

from .._primitives.compromised import match_version
from ..base import Severity


@dataclass(frozen=True, slots=True)
class CompromisedChart:
    """One curated registry entry."""

    chart_name: str
    malicious_versions: tuple[str, ...]
    advisory: str
    severity: Severity = Severity.HIGH


#: Curated registry. Append entries; never remove (an entry tied
#: to a published advisory remains true even after a fix lands
#: upstream).
COMPROMISED: tuple[CompromisedChart, ...] = (
    # Synthetic seed entries — replace as real published advisories
    # land. The npm / PyPI / Maven / NuGet / Go / Cargo registries
    # all start with two seed entries to validate the lookup path
    # without claiming coverage we don't have; HELM-014 follows the
    # same convention.
    CompromisedChart(
        chart_name="example-known-bad",
        malicious_versions=("1.0.0", "1.0.1"),
        advisory="example-advisory-2024-001",
    ),
    CompromisedChart(
        chart_name="another-example-bad",
        malicious_versions=("2.3.4",),
        advisory="example-advisory-2024-002",
    ),
)


def lookup(chart_name: str, version: str) -> CompromisedChart | None:
    """Return the registry entry matching ``chart_name`` at
    ``version``, or ``None`` when the dep is not on the list."""
    for entry in COMPROMISED:
        if entry.chart_name != chart_name:
            continue
        if match_version(
            version,
            malicious_versions=entry.malicious_versions,
            version_pattern=None,
        ):
            return entry
    return None
