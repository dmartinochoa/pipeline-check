"""Curated registry of known-compromised Go modules.

Foundation for ``GOMOD-006``, a pure-data table of
``(module_path, malicious_versions, advisory)`` entries sourced
from public CVEs, GHSAs, GO vulnerability database entries, and
vendor postmortems. The rule consults this registry to detect
dependencies pinned to a known-bad version.

Mirrors ``npm/_compromised_packages.py``, ``pypi/_compromised_packages.py``,
``maven/_compromised_packages.py``, and ``nuget/_compromised_packages.py``:
hand-curated, append-only, refresh by PR with the citing advisory in
the commit message. Deliberately not a fetch-from-network registry,
pulling the list on every scan would take the "no telemetry, no API
tokens" default off the table.

Adding a new entry
------------------
Append to :data:`COMPROMISED` with:

* ``module_path``       the canonical Go module path
                        (``golang.org/x/text``, ``github.com/foo/bar``)
* ``malicious_versions`` a tuple of exact version literals OR a
                        glob-pattern tuple via :func:`match_version`
* ``advisory``          short URL or CVE/GHSA ID for the audit trail

Each entry should include a comment naming the incident so future
maintainers can audit the table by reading the file linearly.
"""
from __future__ import annotations

from dataclasses import dataclass

from .._primitives.compromised import match_version
from ..base import Severity


@dataclass(frozen=True, slots=True)
class CompromisedModule:
    """One curated registry entry."""

    module_path: str
    malicious_versions: tuple[str, ...]
    advisory: str
    severity: Severity = Severity.HIGH


#: Curated registry. Append entries; never remove (an entry tied to a
#: published CVE remains true even after a fix lands upstream).
COMPROMISED: tuple[CompromisedModule, ...] = (
    # CVE-2025-22869 — golang.org/x/crypto pre-fix ScalarMult
    # vulnerability shipped in several patch versions before the
    # 0.32.0 fix. Including for the documentation effect; an
    # exact-pin to an affected patch trips the rule and points
    # the operator at the GHSA.
    CompromisedModule(
        module_path="golang.org/x/crypto",
        malicious_versions=("v0.0.0-20240909161250-f395bea34c2d",),
        advisory="GHSA-v778-237x-gjrc",
    ),
    # Synthetic entry: kept to seed the table even when no live
    # compromise applies to the operator's project. Real entries
    # land via PR with the citing advisory in the commit message.
    CompromisedModule(
        module_path="github.com/example/known-bad",
        malicious_versions=("v1.0.0", "v1.0.1"),
        advisory="example-advisory-2024-001",
    ),
)


def lookup(module_path: str, version: str) -> CompromisedModule | None:
    """Return the registry entry matching ``module_path`` at
    ``version``, or ``None`` when the dependency is not on the list.

    Matching is exact on the module path; the version comparison
    delegates to the shared :func:`match_version` helper so a
    future regex-fallback extension lands once in
    ``_primitives/compromised.py`` and every ecosystem picks it up.
    """
    for entry in COMPROMISED:
        if entry.module_path != module_path:
            continue
        if match_version(
            version,
            malicious_versions=entry.malicious_versions,
            version_pattern=None,
        ):
            return entry
    return None
