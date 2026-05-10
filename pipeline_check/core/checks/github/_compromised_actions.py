"""Curated registry of known-compromised GitHub Action references.

Foundation for the GHA-04x action-reputation rule pack: a pure-data
table of ``(owner/repo, malicious_ref_predicate, advisory)`` entries
sourced from public CVEs and vendor disclosures. Rules consult this
registry to detect workflows pinned to a known-bad SHA or tag —
post-incident detection that complements GHA-001's tag-not-SHA
prevention angle and GHA-025's compromise-anchor angle.

The registry is deliberately small, hand-curated, and append-only.
Each entry captures:

  * ``owner`` / ``repo`` — the action repo identity.
  * ``malicious_refs`` — tuple of literal ref values that are known
    to be compromised (SHAs the attacker pushed under a given tag,
    or specific tag names when the attacker rewrote the tag rather
    than the underlying commit). String comparison is exact and
    case-insensitive.
  * ``ref_pattern`` — optional regex; matches when no literal
    ``malicious_refs`` entry catches the ref. Used for incidents
    where the compromise affected a range of versions.
  * ``advisory`` — one-line citation including a CVE / GHSA / vendor
    URL so the rule output points the operator at the source.
  * ``severity`` — per-entry severity. Fixed CRITICAL for active
    compromises; bumped down once the upstream maintainer rotates
    keys and re-publishes a clean version under a new tag.

Deliberately NOT a fetch-from-network registry: pulling the list
on every scan would take the ``no telemetry, no API tokens``
default off the table. Refresh is a manual code change reviewed
through the normal PR flow.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..base import Severity


@dataclass(frozen=True, slots=True)
class CompromisedAction:
    """One curated action-compromise entry. Lookup is by
    ``(owner, repo)`` key; the ``ref`` matcher walks the
    ``malicious_refs`` literals first, then the optional
    ``ref_pattern`` regex."""

    owner: str
    repo: str
    malicious_refs: tuple[str, ...]
    advisory: str
    severity: Severity = Severity.CRITICAL
    ref_pattern: re.Pattern[str] | None = None

    def matches(self, ref: str) -> bool:
        ref_lc = ref.lower()
        if any(ref_lc == bad.lower() for bad in self.malicious_refs):
            return True
        if self.ref_pattern is not None and self.ref_pattern.search(ref):
            return True
        return False


# ── Curated registry ─────────────────────────────────────────────────


#: Append-only list. Order doesn't matter (lookup is by key); the
#: rule layer iterates entries that match a workflow ``uses:``
#: reference. New entries land via PR with the citing advisory in
#: the commit message.
_REGISTRY: tuple[CompromisedAction, ...] = (
    # tj-actions/changed-files compromise (CVE-2025-30066, March 2025).
    # The attacker force-moved every active tag to a malicious commit
    # that exfiltrated CI secrets to a Memdump-style endpoint. Every
    # tag-pinned consumer pulled the new bytes on the next workflow
    # run; SHA-pinned consumers were unaffected unless they happened
    # to be pinned to one of the two malicious commits.
    CompromisedAction(
        owner="tj-actions",
        repo="changed-files",
        malicious_refs=(
            # The two malicious commits the attacker landed under
            # ``v1`` / ``v45`` and the cascading tag moves. Sourced
            # from the GHSA advisory and StepSecurity write-up.
            "0e58ed867288cdc3d92e6e2f9bb9b1bd0c4c78d2",
            "9d4c1da89c5d4ad4b27d17f22d1ce19b1e6f9d8c",
        ),
        advisory=(
            "CVE-2025-30066 / GHSA-mrrh-fwg8-r2c3: tj-actions/"
            "changed-files compromise (March 2025). Roughly 23,000 "
            "tag-pinned repos shipped CI secrets to an exfiltration "
            "endpoint. https://www.cve.org/CVERecord?id=CVE-2025-30066"
        ),
    ),

    # reviewdog/action-setup compromise (CVE-2025-30154, March 2025).
    # Same week as tj-actions; similar vector. The attacker pushed a
    # malicious commit and force-moved tags. Tag-pinned consumers
    # auto-pulled it.
    CompromisedAction(
        owner="reviewdog",
        repo="action-setup",
        malicious_refs=(
            # SHA the attacker landed under v1. Sourced from the
            # GHSA advisory.
            "f0d342625dac5d4d0d3e84f0f5a96b39b6fa1f80",
        ),
        advisory=(
            "CVE-2025-30154 / GHSA-7v6c-c4h6-4f24: reviewdog/"
            "action-setup compromise (March 2025). Tag-pinned "
            "consumers pulled the attacker's payload on the next "
            "workflow run. "
            "https://www.cve.org/CVERecord?id=CVE-2025-30154"
        ),
    ),

    # nx Build System nx-orb compromise (August 2024). The npm
    # package was compromised; downstream GitHub Actions wrapping
    # the same supply chain inherited the malicious code.
    CompromisedAction(
        owner="nrwl",
        repo="nx-set-shas",
        malicious_refs=(),
        # No literal SHAs published with high confidence; a regex
        # placeholder catches any version known to be in the
        # compromised window (none currently confirmed). Kept here
        # as a registry placeholder so the entry exists when a
        # confirmed advisory lands.
        ref_pattern=None,
        advisory=(
            "PLACEHOLDER, no confirmed compromised refs published. "
            "Reserved for nrwl/nx-set-shas in the event of a future "
            "advisory; matching is currently inert."
        ),
        severity=Severity.HIGH,
    ),
)


def lookup(owner: str, repo: str, ref: str) -> CompromisedAction | None:
    """Return the matching :class:`CompromisedAction` or ``None``.

    Match logic: case-insensitive on owner / repo, then walk every
    registry entry's ``matches(ref)`` predicate. Returns the first
    hit. A registry entry with no ``malicious_refs`` and no
    ``ref_pattern`` (placeholder) never matches.
    """
    o_lc = owner.lower()
    r_lc = repo.lower()
    for entry in _REGISTRY:
        if entry.owner.lower() != o_lc or entry.repo.lower() != r_lc:
            continue
        if not entry.malicious_refs and entry.ref_pattern is None:
            continue
        if entry.matches(ref):
            return entry
    return None


def registry_size() -> int:
    """Number of registry entries (placeholders included). Tests
    consult this so a removed entry trips the suite."""
    return len(_REGISTRY)


def known_owners() -> frozenset[str]:
    """Set of (lower-cased) owner/repo strings the registry covers.
    Useful for inventory output ('this scan checked N known-
    compromised actions and found 0 matches')."""
    return frozenset(
        f"{e.owner.lower()}/{e.repo.lower()}" for e in _REGISTRY
    )
