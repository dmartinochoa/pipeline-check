"""Curated registry of known-compromised PyPI packages.

Foundation for PYPI-006 — a pure-data table of ``(name,
malicious_versions, advisory)`` entries sourced from public CVEs,
GHSAs, and vendor postmortems. Mirrors the npm-side registry
shape (``pipeline_check.core.checks.npm._compromised_packages``)
and the GHA-040 ``_compromised_actions`` template.

PyPI normalizes package names per PEP 503: lowercase, underscore
and dot folded to hyphen, so ``Pillow``, ``pillow``, and
``PIL_LOW`` resolve to the same install. The registry stores
normalized names and the lookup helper normalizes its input
before comparison.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..base import Severity


@dataclass(frozen=True, slots=True)
class CompromisedPackage:
    """One curated PyPI-package-compromise entry."""

    name: str  #: PEP 503-normalized package name.
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


_PEP503_RE = re.compile(r"[-_.]+")


def _normalize(name: str) -> str:
    """PEP 503 name normalization. ``Pillow``, ``pillow``, ``Pil_low``
    → ``pillow``."""
    return _PEP503_RE.sub("-", name.strip()).lower()


# ── Curated registry ─────────────────────────────────────────────────


#: Append-only list. Order doesn't matter (lookup is by name); the
#: rule layer iterates entries that match a requirement line. New
#: entries land via PR with the citing advisory in the commit
#: message.
_REGISTRY: tuple[CompromisedPackage, ...] = (
    # ctx package compromise (May 2022). Attacker republished the
    # abandoned ``ctx`` package with a payload that exfiltrated
    # environment variables (AWS keys, GH tokens) to a controlled
    # endpoint. Affected versions republished within a 24-hour
    # window before PyPI took the package down. Public postmortem
    # at the SANS ISC diary; advisory tracked in PyPI advisory DB.
    CompromisedPackage(
        name="ctx",
        malicious_versions=(
            "0.2.2", "0.2.3", "0.2.4", "0.2.5", "0.2.6", "0.2.7", "0.2.8",
        ),
        advisory=(
            "ctx package compromise (May 2022): the abandoned package "
            "was claimed by an attacker who republished it with an "
            "env-var exfiltration payload targeting AWS keys / GH "
            "tokens. PyPI removed the malicious versions. "
            "https://isc.sans.edu/diary/28772"
        ),
    ),

    # requests-darwin-lite typosquat / scope leak (May 2024). The
    # package name pretended to be a macOS-specific build of
    # ``requests``; the published wheel embedded the Geneva malware
    # framework. GHSA-7gjg-3qcj-9jvg.
    CompromisedPackage(
        name="requests-darwin-lite",
        malicious_versions=("2.27.1",),
        advisory=(
            "GHSA-7gjg-3qcj-9jvg: requests-darwin-lite 2.27.1 "
            "(May 2024). Typosquat-flavored package masquerading as "
            "a macOS-specific ``requests`` variant; wheel embedded "
            "the Geneva malware framework. "
            "https://github.com/advisories/GHSA-7gjg-3qcj-9jvg"
        ),
    ),
)


def lookup(name: str, version: str) -> CompromisedPackage | None:
    """Return the matching :class:`CompromisedPackage` or ``None``.

    Name matching is PEP 503-normalized on both sides so callers
    don't have to pre-normalize.
    """
    n_norm = _normalize(name)
    for entry in _REGISTRY:
        if entry.name != n_norm:
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
    """Set of PEP 503-normalized package names the registry covers."""
    return frozenset(e.name for e in _REGISTRY)
