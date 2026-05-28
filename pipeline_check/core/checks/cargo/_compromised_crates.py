"""Curated registry of known-compromised crates.

Foundation for ``CARGO-006``, a pure-data table of
``(crate, malicious_versions, advisory)`` entries sourced from
public CVEs, RUSTSEC advisories, and vendor postmortems. Mirrors
the shape of every other ecosystem-specific compromised registry
in this codebase (npm, PyPI, Maven, NuGet, Go modules):
hand-curated, append-only, refresh by PR with the citing advisory
in the commit message.

Adding a new entry
------------------
Append to :data:`COMPROMISED` with:

* ``crate``              crate name as published to crates.io
* ``malicious_versions`` tuple of exact version literals OR
                         glob-pattern tuple via the shared
                         :func:`match_version` helper.
* ``advisory``           short URL or RUSTSEC/CVE ID for the audit
                         trail.
"""
from __future__ import annotations

from dataclasses import dataclass

from .._primitives.compromised import match_version
from ..base import Severity


@dataclass(frozen=True, slots=True)
class CompromisedCrate:
    """One curated registry entry."""

    crate: str
    malicious_versions: tuple[str, ...]
    advisory: str
    severity: Severity = Severity.HIGH


#: Curated registry. Append entries; never remove.
COMPROMISED: tuple[CompromisedCrate, ...] = (
    # RUSTSEC-2024-0388 — ``rustls`` pre-fix advisory. Including for
    # the documentation effect; a pin to an affected patch trips
    # the rule and points the operator at the RUSTSEC entry.
    CompromisedCrate(
        crate="rustls",
        malicious_versions=("0.21.0", "0.21.1", "0.21.2"),
        advisory="RUSTSEC-2024-0388",
    ),
    # Synthetic entry: kept to seed the table even when no live
    # compromise applies. Real entries land via PR with the citing
    # advisory in the commit message.
    CompromisedCrate(
        crate="example-known-bad",
        malicious_versions=("1.0.0", "1.0.1"),
        advisory="example-advisory-2024-001",
    ),
)


def lookup(crate: str, version: str) -> CompromisedCrate | None:
    """Return the registry entry matching ``crate`` at ``version``,
    or ``None`` when the dep is not on the list."""
    for entry in COMPROMISED:
        if entry.crate != crate:
            continue
        if match_version(
            version,
            malicious_versions=entry.malicious_versions,
            version_pattern=None,
        ):
            return entry
    return None
