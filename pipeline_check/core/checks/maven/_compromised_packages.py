"""Curated registry of known-compromised Maven Central artifacts.

Foundation for ``MVN-006``, a pure-data table of
``(group_id, artifact_id, malicious_versions, advisory)`` entries
sourced from public CVEs, GHSAs, and vendor postmortems. The rule
consults this registry to detect dependencies pinned to a known-bad
version (the post-incident detection angle complementing ``MVN-001``'s
floating-range prevention).

Mirrors the shape of ``npm._compromised_packages`` and
``pypi._compromised_packages``: hand-curated, append-only, refresh
by PR with the citing advisory in the commit message. Deliberately
not a fetch-from-network registry, pulling the list on every scan
would take the "no telemetry, no API tokens" default off the table.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..base import Severity


@dataclass(frozen=True, slots=True)
class CompromisedPackage:
    """One curated Maven Central compromise entry."""

    group_id: str
    artifact_id: str
    malicious_versions: tuple[str, ...]
    advisory: str
    severity: Severity = Severity.CRITICAL
    version_pattern: re.Pattern[str] | None = None

    def matches(self, version: str) -> bool:
        if any(version == bad for bad in self.malicious_versions):
            return True
        if self.version_pattern is not None and self.version_pattern.search(version):
            return True
        return False


# ── Curated registry ─────────────────────────────────────────────────


#: Append-only list. New entries land via PR with the citing advisory
#: in the commit message. Comparisons are case-insensitive on
#: group_id / artifact_id and exact on version literals.
_REGISTRY: tuple[CompromisedPackage, ...] = (
    # Log4Shell, CVE-2021-44228. Not a maintainer compromise but the
    # canonical Maven-side advisory contributors expect to see flagged.
    # Listed at the rule-level severity for the affected range so a
    # build resolving to 2.0..2.14.1 fires CRITICAL.
    CompromisedPackage(
        group_id="org.apache.logging.log4j",
        artifact_id="log4j-core",
        malicious_versions=(
            "2.0", "2.0.1", "2.0.2", "2.1", "2.2", "2.3", "2.4",
            "2.4.1", "2.5", "2.6", "2.6.1", "2.6.2",
            "2.7", "2.8", "2.8.1", "2.8.2", "2.9.0", "2.9.1",
            "2.10.0", "2.11.0", "2.11.1", "2.11.2",
            "2.12.0", "2.12.1", "2.13.0", "2.13.1", "2.13.2", "2.13.3",
            "2.14.0", "2.14.1",
        ),
        advisory=(
            "CVE-2021-44228 (Log4Shell): JNDI lookup substitution in "
            "log4j-core 2.0 through 2.14.1 enables unauthenticated RCE. "
            "Fix: 2.17.1 or later. "
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
        ),
        severity=Severity.CRITICAL,
    ),

    # Spring4Shell, CVE-2022-22965 (spring-beans). Affected versions:
    # 5.3.0..5.3.17 and 5.2.0..5.2.19. RCE via the data-binding path.
    CompromisedPackage(
        group_id="org.springframework",
        artifact_id="spring-beans",
        malicious_versions=(
            "5.2.0", "5.2.1", "5.2.2", "5.2.3", "5.2.4", "5.2.5",
            "5.2.6", "5.2.7", "5.2.8", "5.2.9", "5.2.10", "5.2.11",
            "5.2.12", "5.2.13", "5.2.14", "5.2.15", "5.2.16",
            "5.2.17", "5.2.18", "5.2.19",
            "5.3.0", "5.3.1", "5.3.2", "5.3.3", "5.3.4", "5.3.5",
            "5.3.6", "5.3.7", "5.3.8", "5.3.9", "5.3.10", "5.3.11",
            "5.3.12", "5.3.13", "5.3.14", "5.3.15", "5.3.16", "5.3.17",
        ),
        advisory=(
            "CVE-2022-22965 (Spring4Shell): data-binding RCE in "
            "spring-beans on JDK 9+ when deployed as WAR. "
            "Fix: 5.3.18 / 5.2.20. "
            "https://nvd.nist.gov/vuln/detail/CVE-2022-22965"
        ),
        severity=Severity.CRITICAL,
    ),

    # Apache Commons Text, CVE-2022-42889 (Text4Shell). RCE via the
    # StringSubstitutor `script:` lookup. Affected: 1.5..1.9.
    CompromisedPackage(
        group_id="org.apache.commons",
        artifact_id="commons-text",
        malicious_versions=("1.5", "1.6", "1.7", "1.8", "1.9"),
        advisory=(
            "CVE-2022-42889 (Text4Shell): commons-text 1.5-1.9 "
            "StringSubstitutor evaluates script: lookups. Fix: 1.10.0. "
            "https://nvd.nist.gov/vuln/detail/CVE-2022-42889"
        ),
        severity=Severity.HIGH,
    ),
)


def lookup(group_id: str, artifact_id: str, version: str) -> CompromisedPackage | None:
    """Return the first registry entry that matches the coordinate, or ``None``.

    Matching is case-insensitive on group_id / artifact_id and routed
    through ``CompromisedPackage.matches()`` for the version (exact
    literal or optional regex). Returns the entry so callers can
    surface the advisory string and per-entry severity.
    """
    g = group_id.lower()
    a = artifact_id.lower()
    for entry in _REGISTRY:
        if entry.group_id.lower() != g or entry.artifact_id.lower() != a:
            continue
        if entry.matches(version):
            return entry
    return None


__all__ = ["CompromisedPackage", "lookup"]
