"""Curated registry of known-compromised NuGet packages.

Foundation for NUGET-005 -- a pure-data table of ``(name,
malicious_versions, advisory)`` entries sourced from public CVEs,
GHSAs, and vendor postmortems. The rule consults this registry to
detect PackageReference entries pinned to a known-bad version (the
post-incident detection angle complementing NUGET-001's floating-range
prevention and NUGET-006's lockfile hygiene).

Mirrors the shape of ``npm._compromised_packages`` and
``pypi._compromised_packages``: hand-curated, append-only, refresh
by PR with the citing advisory in the commit message. Deliberately
not a fetch-from-network registry -- pulling the list on every scan
would take the "no telemetry, no API tokens" default off the table.

NuGet package names are case-insensitive per the NuGet specification.
The registry stores canonical mixed-case names and the lookup helper
compares via ``str.lower()`` on both sides.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .._primitives.compromised import match_version
from ..base import Severity


@dataclass(frozen=True, slots=True)
class CompromisedPackage:
    """One curated NuGet-package-compromise entry."""

    name: str
    malicious_versions: tuple[str, ...]
    advisory: str
    severity: Severity = Severity.CRITICAL
    version_pattern: re.Pattern[str] | None = None

    def matches(self, version: str) -> bool:
        return match_version(
            version,
            malicious_versions=self.malicious_versions,
            version_pattern=self.version_pattern,
        )


# -- Curated registry -----------------------------------------------------


#: Append-only list. Order doesn't matter (lookup is by name); the
#: rule layer iterates entries that match a PackageReference name. New
#: entries land via PR with the citing advisory in the commit message.
_REGISTRY: tuple[CompromisedPackage, ...] = (
    # SolarWinds Orion SUNBURST backdoor (December 2020). Attacker
    # (UNC2452 / Cozy Bear) compromised the SolarWinds build pipeline
    # and inserted a backdoored DLL into the Orion update. The
    # affected NuGet package shipped the trojanized SolarWinds.Orion.Core
    # assembly. CVE-2020-10148.
    CompromisedPackage(
        name="SolarWinds.Orion.Core",
        malicious_versions=("2020.2.1",),
        advisory=(
            "CVE-2020-10148 (SUNBURST): SolarWinds.Orion.Core "
            "2020.2.1 shipped a backdoored DLL inserted via a "
            "compromised build pipeline (UNC2452 / Cozy Bear). "
            "https://nvd.nist.gov/vuln/detail/CVE-2020-10148"
        ),
    ),

    # Microsoft.Data.OData namespace hijack (2024). An attacker
    # claimed the previously unreserved NuGet namespace and published
    # a package that shadowed the legitimate Microsoft assembly. No
    # CVE assigned yet.
    CompromisedPackage(
        name="Microsoft.Data.OData",
        malicious_versions=("5.8.5",),
        advisory=(
            "2024 NuGet namespace hijack advisory: "
            "Microsoft.Data.OData 5.8.5 published by an attacker who "
            "claimed the unreserved namespace, shadowing the "
            "legitimate Microsoft assembly."
        ),
    ),
)


def lookup(name: str, version: str) -> CompromisedPackage | None:
    """Return the matching :class:`CompromisedPackage` or ``None``.

    Match logic: case-insensitive on package name (NuGet names are
    case-insensitive per spec), exact on version literal or regex via
    ``version_pattern``. Returns the first matching registry entry.
    """
    n_lc = name.lower()
    for entry in _REGISTRY:
        if entry.name.lower() != n_lc:
            continue
        if not entry.malicious_versions and entry.version_pattern is None:
            continue
        if entry.matches(version):
            return entry
    return None


def registry_size() -> int:
    """Number of registry entries. Tests consult this so a removed
    entry trips the suite."""
    return len(_REGISTRY)


def known_names() -> frozenset[str]:
    """Set of (lower-cased) package names the registry covers."""
    return frozenset(e.name.lower() for e in _REGISTRY)
