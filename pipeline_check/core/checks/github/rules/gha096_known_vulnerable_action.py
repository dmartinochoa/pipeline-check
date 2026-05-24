"""GHA-096. Action reference has a known vulnerability in the GHSA database.

Widens GHA-040 (curated compromised-SHA list) from the static
registry to the live GitHub Advisory Database.  GHA-040 fires on
active compromises (malicious code injected), GHA-096 fires on
known vulnerabilities (CVEs, security bugs) that the advisory
ecosystem tracks.  The overlap is minimal: GHA-040 is hand-seeded
for high-confidence incidents, GHA-096 queries the full GHSA
corpus.

Network-dependent: gated on ``--resolve-remote``.  The same
``ActionMetadataFetcher`` pass that populates
``ctx.action_metadata`` for the reputation rules now also queries
``GET /advisories?type=reviewed&ecosystem=actions&affects=o/r``
and stores the result on
``ActionRepoMetadata.ghsa_advisories``.  When the flag is off the
rule passes silently with a one-line nudge.

Version matching: when the ``uses:`` ref looks like a tag with a
parseable version (``v4.2.0``, ``4.2``), the rule checks each
advisory's ``vulnerable_version_range`` and only fires on a
match.  When the version cannot be extracted (SHA pin, branch
ref, major-only tag like ``v4``), the rule still fires but at
MEDIUM confidence with a note that the version could not be
verified.  This conservative posture accepts a small false-
positive surface (the action *has* advisories, we just can't
confirm the pinned version is in the affected range) in exchange
for never silently passing an actually-vulnerable pin.
"""
from __future__ import annotations

from typing import Any

from ..._primitives.version_range import any_range_matches, parse_version
from ...base import Confidence, Finding, Severity
from ...rule import Rule
from .._action_reputation import ActionAdvisory
from ..base import GitHubContext, Workflow, iter_jobs, iter_steps
from ..uses_parser import parse_uses

RULE = Rule(
    id="GHA-096",
    title="Action reference has a known GHSA vulnerability",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-VERIFY-DEPS", "ESF-S-PIN-DEPS"),
    cwe=("CWE-1395", "CWE-829"),
    recommendation=(
        "Update the ``uses:`` reference to a version at or above "
        "the first patched version listed in the advisory. If no "
        "patch is available, evaluate whether the vulnerability is "
        "reachable in your workflow's context and consider vendoring "
        "a fork with the fix applied. Pin to the patched SHA so a "
        "tag rewrite can't walk you back into the vulnerable range."
    ),
    docs_note=(
        "Queries the GitHub Advisory Database "
        "(``GET /advisories?type=reviewed&ecosystem=actions``) for "
        "each action referenced by the loaded workflows. Gated on "
        "``--resolve-remote``; the offline default stays no-network. "
        "Version matching compares the tag-extracted version against "
        "each advisory's ``vulnerable_version_range``. SHA-pinned or "
        "major-tag refs fire at MEDIUM confidence when the action has "
        "any advisory, since the exact version cannot be confirmed. "
        "Pairs with GHA-040 (curated compromised-SHA list, fires on "
        "active compromises rather than CVE-tracked vulnerabilities)."
    ),
    known_fp=(
        "Major-version tags (``@v4``) fire at MEDIUM confidence "
        "because the rule cannot resolve which patch level the tag "
        "currently points at. If the tag follows the latest release "
        "and the advisory is already patched, suppress per-finding "
        "with a rationale noting the tag is current. SHA pins with "
        "no version comment also fire conservatively; adding a "
        "``# vX.Y.Z`` comment lets the rule match precisely.",
    ),
    incident_refs=(
        "actions/download-artifact path traversal "
        "([CVE-2024-42471](https://www.cve.org/CVERecord?id=CVE-2024-42471), "
        "August 2024): versions < 4.1.7 allowed a malicious artifact "
        "to write files outside the intended directory, reachable via "
        "any workflow that downloads untrusted artifacts. Fixed in "
        "4.1.7.",
    ),
    exploit_example=(
        "# Vulnerable: pinned to a version with a known advisory.\n"
        "- uses: actions/download-artifact@v4.1.6\n"
        "\n"
        "# Safe: updated past the patched version.\n"
        "- uses: actions/download-artifact@v4.1.7\n"
        "\n"
        "# Also safe: SHA-pinned to the patched commit.\n"
        "- uses: actions/download-artifact@<patched-sha>  # v4.1.7"
    ),
)


def _extract_version_from_ref(ref: str) -> str | None:
    """Try to pull a parseable version out of a ``uses:`` ref.

    Returns the raw ref string when it looks like a version
    (``v4.2.0``, ``4.2``, ``v1.0.0-beta``), ``None`` otherwise
    (40-char SHA, branch name, major-only tag like ``v4``).
    """
    if parse_version(ref) is None:
        return None
    # Major-only tags ("v4", "4") are ambiguous: they float to the
    # latest patch.  Return None so the caller fires at lower
    # confidence rather than comparing "4.0.0" against the range.
    stripped = ref.lstrip("vV")
    if "." not in stripped:
        return None
    return ref


def _format_advisory(adv: ActionAdvisory) -> str:
    label = adv.ghsa_id
    if adv.cve_id:
        label = f"{adv.cve_id} / {adv.ghsa_id}"
    patched = [p for p in adv.patched_versions if p]
    fix = f" (fix: {', '.join(patched)})" if patched else ""
    return f"{label}{fix}"


def check(
    path: str, doc: dict[str, Any], wf: Workflow, ctx: GitHubContext,
) -> Finding:
    confirmed: list[str] = []
    unverified: list[str] = []
    advisory_labels: set[str] = set()
    seen: set[str] = set()

    def _scan(value: Any) -> None:
        ref = parse_uses(value)
        if ref is None:
            return
        if ref.kind not in {"remote-action", "remote-workflow"}:
            return
        if not ref.owner or not ref.repo or not ref.ref:
            return
        key = f"{ref.owner.lower()}/{ref.repo.lower()}"
        if key in seen:
            return
        seen.add(key)
        meta = ctx.action_metadata.get(key)
        if meta is None or meta.ghsa_advisories is None:
            return
        if not meta.ghsa_advisories:
            return
        version_str = _extract_version_from_ref(ref.ref)
        if version_str is not None:
            all_ranges: list[str] = []
            for adv in meta.ghsa_advisories:
                all_ranges.extend(adv.vulnerable_ranges)
            matched, _ = any_range_matches(version_str, all_ranges)
            if matched:
                for adv in meta.ghsa_advisories:
                    hit, _ = any_range_matches(
                        version_str, list(adv.vulnerable_ranges),
                    )
                    if hit:
                        confirmed.append(
                            f"{ref.owner}/{ref.repo}@{ref.ref}"
                        )
                        advisory_labels.add(_format_advisory(adv))
            # Version parsed and NOT in any range -> safe, skip.
        else:
            for adv in meta.ghsa_advisories:
                advisory_labels.add(_format_advisory(adv))
            unverified.append(f"{ref.owner}/{ref.repo}@{ref.ref}")

    for _, job in iter_jobs(doc):
        _scan(job.get("uses"))
        for step in iter_steps(job):
            _scan(step.get("uses"))

    if not ctx.action_metadata:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "No action metadata available. Rerun with "
                "``--resolve-remote`` (and optionally ``--gh-token`` "
                "for the higher rate-limit ceiling) to enable "
                "known-vulnerability detection via the GitHub "
                "Advisory Database."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    if confirmed:
        sample = ", ".join(sorted(set(confirmed))[:3])
        if len(set(confirmed)) > 3:
            sample += f" (+{len(set(confirmed)) - 3} more)"
        adv_text = "; ".join(sorted(advisory_labels)[:5])
        if len(advisory_labels) > 5:
            adv_text += f" (+{len(advisory_labels) - 5} more)"
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                f"{len(confirmed)} action reference(s) pinned to a "
                f"version inside a known-vulnerable range: {sample}. "
                f"Advisory: {adv_text}"
            ),
            recommendation=RULE.recommendation, passed=False,
            confidence=Confidence.HIGH,
        )

    if unverified:
        sample = ", ".join(sorted(set(unverified))[:3])
        if len(set(unverified)) > 3:
            sample += f" (+{len(set(unverified)) - 3} more)"
        adv_text = "; ".join(sorted(advisory_labels)[:5])
        if len(advisory_labels) > 5:
            adv_text += f" (+{len(advisory_labels) - 5} more)"
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                f"{len(unverified)} action reference(s) target an "
                f"action with known GHSA advisories but the pinned "
                f"version could not be verified (SHA or major-tag "
                f"ref): {sample}. Advisory: {adv_text}. Add a "
                f"``# vX.Y.Z`` version comment or pin to a specific "
                f"patch-level tag so the rule can match precisely."
            ),
            recommendation=RULE.recommendation, passed=False,
            confidence=Confidence.MEDIUM,
        )

    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path,
        description=(
            "No referenced action has a known vulnerability in the "
            "GitHub Advisory Database."
        ),
        recommendation=RULE.recommendation, passed=True,
    )
