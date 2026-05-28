"""Curated registry of known-compromised RubyGems.

Foundation for ``GEM-006``, a pure-data table of
``(gem, malicious_versions, advisory)`` entries sourced from
public CVEs, RubySec advisories, and vendor postmortems.
Mirrors the shape of every other ecosystem-specific compromised
registry in this codebase (npm, PyPI, Maven, NuGet, Go modules,
Cargo, Composer): hand-curated, append-only, refresh by PR with
the citing advisory in the commit message.

Adding a new entry
------------------
Append to :data:`COMPROMISED` with:

* ``gem``                gem name as published to rubygems.org
* ``malicious_versions`` tuple of exact version literals OR
                         glob-pattern tuple via the shared
                         :func:`match_version` helper.
* ``advisory``           short URL or RubySec / CVE ID for the
                         audit trail.
"""
from __future__ import annotations

from dataclasses import dataclass

from .._primitives.compromised import match_version
from ..base import Severity


@dataclass(frozen=True, slots=True)
class CompromisedGem:
    """One curated registry entry."""

    gem: str
    malicious_versions: tuple[str, ...]
    advisory: str
    severity: Severity = Severity.HIGH


#: Curated registry. Append entries; never remove.
COMPROMISED: tuple[CompromisedGem, ...] = (
    # rest-client 1.6.10-1.6.13 — Aug 2019 maintainer-token compromise.
    # The compromised version exfiltrated env vars and opened a remote
    # shell. The advisory was the canonical RubyGems supply-chain
    # incident of the era.
    CompromisedGem(
        gem="rest-client",
        malicious_versions=("1.6.10", "1.6.11", "1.6.12", "1.6.13"),
        advisory="CVE-2019-15224",
    ),
    # strong_password 0.0.7 — Jun 2019 backdoored gem (eval'd remote
    # Pastebin payload at boot).
    CompromisedGem(
        gem="strong_password",
        malicious_versions=("0.0.7",),
        advisory="CVE-2019-13354",
    ),
    # Synthetic entry: kept to seed the table even when no live
    # compromise applies. Real entries land via PR with the citing
    # advisory in the commit message.
    CompromisedGem(
        gem="example-known-bad",
        malicious_versions=("1.0.0", "1.0.1"),
        advisory="example-advisory-2024-001",
    ),
)


def lookup(gem: str, version: str) -> CompromisedGem | None:
    """Return the registry entry matching ``gem`` at ``version``, or
    ``None`` when the dep is not on the list."""
    for entry in COMPROMISED:
        if entry.gem != gem:
            continue
        if match_version(
            version,
            malicious_versions=entry.malicious_versions,
            version_pattern=None,
        ):
            return entry
    return None
