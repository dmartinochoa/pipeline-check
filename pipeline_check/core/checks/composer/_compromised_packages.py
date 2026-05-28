"""Curated registry of known-compromised Composer (PHP) packages.

Foundation for ``COMPOSER-007``, a pure-data table of
``(package, malicious_versions, advisory)`` entries sourced from
public CVEs, FriendsOfPHP/security-advisories, and vendor
postmortems. Mirrors the shape of every other ecosystem-specific
compromised registry in this codebase (npm, PyPI, Maven, NuGet,
Go modules, Cargo): hand-curated, append-only, refresh by PR with
the citing advisory in the commit message.

Adding a new entry
------------------
Append to :data:`COMPROMISED` with:

* ``package``           full ``vendor/package`` name on Packagist
* ``malicious_versions`` tuple of exact version literals OR
                         glob-pattern tuple via the shared
                         :func:`match_version` helper.
* ``advisory``           short URL or CVE / advisory ID for the
                         audit trail.
"""
from __future__ import annotations

from dataclasses import dataclass

from .._primitives.compromised import match_version
from ..base import Severity


@dataclass(frozen=True, slots=True)
class CompromisedPackage:
    """One curated registry entry."""

    package: str
    malicious_versions: tuple[str, ...]
    advisory: str
    severity: Severity = Severity.HIGH


#: Curated registry. Append entries; never remove.
COMPROMISED: tuple[CompromisedPackage, ...] = (
    # CVE-2024-35241 — guzzlehttp/guzzle pre-fix advisory.
    # Including for the documentation effect; a pin to an affected
    # patch trips the rule and points the operator at the advisory.
    CompromisedPackage(
        package="guzzlehttp/guzzle",
        malicious_versions=("7.8.0", "7.8.1"),
        advisory="CVE-2024-35241",
    ),
    # Synthetic entry: kept to seed the table even when no live
    # compromise applies. Real entries land via PR with the citing
    # advisory in the commit message.
    CompromisedPackage(
        package="example-vendor/example-known-bad",
        malicious_versions=("1.0.0", "1.0.1"),
        advisory="example-advisory-2024-001",
    ),
)


def lookup(package: str, version: str) -> CompromisedPackage | None:
    """Return the registry entry matching ``package`` at ``version``,
    or ``None`` when the dep is not on the list."""
    for entry in COMPROMISED:
        if entry.package != package:
            continue
        if match_version(
            version,
            malicious_versions=entry.malicious_versions,
            version_pattern=None,
        ):
            return entry
    return None
