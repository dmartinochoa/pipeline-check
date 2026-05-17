"""Curated registry of known-compromised npm packages.

Foundation for NPM-006 — a pure-data table of ``(name,
malicious_versions, advisory)`` entries sourced from public CVEs,
GHSAs, and vendor postmortems. The rule consults this registry to
detect lockfile entries pinned to a known-bad version (the
post-incident detection angle that complements NPM-001's floating-
range prevention and NPM-002's integrity-hash verification).

Mirrors the shape of ``pipeline_check.core.checks.github.
_compromised_actions``: hand-curated, append-only, refresh by PR
with the citing advisory in the commit message. Deliberately NOT a
fetch-from-network registry — pulling the list on every scan would
take the "no telemetry, no API tokens" default off the table.

Each entry captures:

  * ``name`` — npm package name (lower-cased; scope preserved as
    ``@scope/name``).
  * ``malicious_versions`` — tuple of exact version literals.
    Comparison is case-sensitive string equality; npm version
    strings are already lower-case in practice.
  * ``version_pattern`` — optional ``re.Pattern`` matched when no
    literal entry catches the version. Used for advisories that
    span a range ("all versions before X.Y.Z were rebuilt with
    backdoor").
  * ``advisory`` — one-line citation. CVE / GHSA / vendor URL.
  * ``severity`` — per-entry severity. CRITICAL for active
    credential-stealer / RCE compromises; HIGH for protestware /
    self-sabotage cases where the payload is destructive but
    scoped.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..base import Severity


@dataclass(frozen=True, slots=True)
class CompromisedPackage:
    """One curated npm-package-compromise entry."""

    name: str
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


#: Append-only list. Order doesn't matter (lookup is by name); the
#: rule layer iterates entries that match a lockfile / manifest
#: dependency name. New entries land via PR with the citing
#: advisory in the commit message.
_REGISTRY: tuple[CompromisedPackage, ...] = (
    # event-stream compromise (November 2018). Attacker (right9ctrl)
    # took over maintenance from dominictarr, then added a malicious
    # ``flatmap-stream`` dependency targeting Copay wallet builds.
    # Discovered when a downstream user noticed the new transitive.
    # Public postmortem at github.com/dominictarr/event-stream/issues/116.
    CompromisedPackage(
        name="event-stream",
        malicious_versions=("3.3.6",),
        advisory=(
            "event-stream 3.3.6 (Nov 2018): malicious ``flatmap-stream`` "
            "transitive added by hijacked maintainer; targeted Copay "
            "wallet builds. "
            "https://github.com/dominictarr/event-stream/issues/116"
        ),
    ),

    # ua-parser-js compromise (October 2021). Attacker hijacked the
    # publisher's npm account and pushed malicious versions that
    # installed a crypto miner + password stealer via postinstall.
    # CVE-2021-43547 / GHSA-pjwm-rvh2-c87w.
    CompromisedPackage(
        name="ua-parser-js",
        malicious_versions=("0.7.29", "0.8.0", "1.0.0"),
        advisory=(
            "CVE-2021-43547 / GHSA-pjwm-rvh2-c87w: ua-parser-js "
            "compromise (Oct 2021). Hijacked maintainer account; "
            "postinstall installed XMRig miner + DanaBot stealer. "
            "https://github.com/advisories/GHSA-pjwm-rvh2-c87w"
        ),
    ),

    # coa compromise (November 2021). Same campaign as rc (below);
    # attacker hijacked the maintainer account and re-published with
    # a credential stealer in postinstall. GHSA-73qr-pfmq-6rp8.
    CompromisedPackage(
        name="coa",
        malicious_versions=("2.0.3", "2.0.4", "2.1.1", "2.1.3", "3.0.1", "3.1.3"),
        advisory=(
            "GHSA-73qr-pfmq-6rp8: coa compromise (Nov 2021). "
            "Maintainer-account takeover; postinstall installed a "
            "credential stealer. "
            "https://github.com/advisories/GHSA-73qr-pfmq-6rp8"
        ),
    ),

    # rc compromise (November 2021). Same campaign as coa.
    # GHSA-g2q5-5433-rhrf.
    CompromisedPackage(
        name="rc",
        malicious_versions=("1.2.9", "1.3.9", "2.3.9"),
        advisory=(
            "GHSA-g2q5-5433-rhrf: rc compromise (Nov 2021). Same "
            "campaign as coa; credential-stealer in postinstall. "
            "https://github.com/advisories/GHSA-g2q5-5433-rhrf"
        ),
    ),

    # node-ipc protestware (March 2022). Maintainer added a payload
    # that wiped files on hosts geo-located to Russia / Belarus,
    # framed as a war protest. CVE-2022-23812. Severity HIGH (not
    # CRITICAL) since the payload is destructive-on-condition rather
    # than a covert credential stealer; SOC2 / supply-chain reviews
    # still treat any version in the affected range as poisoned.
    CompromisedPackage(
        name="node-ipc",
        malicious_versions=("10.1.1", "10.1.2", "10.1.3"),
        advisory=(
            "CVE-2022-23812: node-ipc protestware (Mar 2022). "
            "Geographic-conditional file-wipe payload added by "
            "maintainer; affects 10.1.1-10.1.3. Treat any 11.x "
            "publish window cautiously, the same author retained "
            "publish rights. "
            "https://nvd.nist.gov/vuln/detail/CVE-2022-23812"
        ),
        severity=Severity.HIGH,
    ),
)


def lookup(name: str, version: str) -> CompromisedPackage | None:
    """Return the matching :class:`CompromisedPackage` or ``None``.

    Match logic: case-insensitive on package name (scopes preserved),
    exact on version literal or regex-via-``version_pattern``. Returns
    the first matching registry entry.
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
