"""GHA-025, reusable workflow ``uses:`` must pin a 40-char SHA.

GHA-001 already covers step-level ``uses:`` references. Reusable
workflows live at the job level (``jobs.<id>.uses:``), a distinct
surface GHA-001 doesn't walk. Same SHA-pin contract, different host:
the `.yml` referenced by ``uses:`` executes with the caller's token
so an upstream tag move is an RCE vector.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import job_location
from ..uses_parser import parse_uses

RULE = Rule(
    id="GHA-025",
    title="Reusable workflow not pinned to commit SHA",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "Pin every ``jobs.<id>.uses:`` reference to a 40-char commit "
        "SHA (``owner/repo/.github/workflows/foo.yml@<sha>``). Tag "
        "refs (``@v1``, ``@main``) can be silently repointed by "
        "whoever controls the callee repository."
    ),
    docs_note=(
        "A reusable workflow runs with the caller's ``GITHUB_TOKEN`` "
        "and secrets by default. If ``uses: org/repo/.github/workflows/"
        "release.yml@v1`` resolves to an attacker-modified commit, "
        "their code executes with your repository's permissions. "
        "This is the same threat model as unpinned step actions "
        "(GHA-001) but over a different ``uses:`` surface."
    ),
    exploit_example=(
        "# Vulnerable: a tag reference can be silently repointed by\n"
        "# whoever controls the callee repo. If\n"
        "# ``org/release-tools/.github/workflows/release.yml@v1`` is\n"
        "# later force-pushed (or the ``v1`` tag deleted and re-\n"
        "# created against a different commit), every caller that\n"
        "# inherits secrets runs the new code with their own token\n"
        "# and secret set in scope on the next workflow run.\n"
        "jobs:\n"
        "  release:\n"
        "    uses: org/release-tools/.github/workflows/release.yml@v1\n"
        "    secrets: inherit\n"
        "\n"
        "# Safe: pin to a 40-char commit SHA. The trailing comment\n"
        "# documents which tag / version the SHA was at so version\n"
        "# bumps stay reviewable. Dependabot's ``github-actions``\n"
        "# ecosystem updates these in PRs like any other dep.\n"
        "jobs:\n"
        "  release:\n"
        "    uses: org/release-tools/.github/workflows/release.yml@0123456789abcdef0123456789abcdef01234567  # v1.4.2\n"
        "    secrets: inherit"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Workflow declares no jobs.",
            recommendation="No action required.", passed=True,
        )
    unpinned: list[str] = []
    locations: list[Location] = []
    # Preserve insertion order so the anchor set is reproducible across
    # runs. AC-012 intersects this with GHA-034's anchors to confirm
    # the unpinned reusable-workflow call AND the ``secrets: inherit``
    # land on the same call site, the tight tag-move-to-credential-
    # exfil reachability.
    anchor_jobs: dict[str, None] = {}
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        ref = parse_uses(job.get("uses"))
        if ref is None or ref.kind != "remote-workflow":
            continue
        if not ref.is_pinned_to_sha:
            unpinned.append(f"{job_id}: {ref.raw}")
            locations.append(job_location(path, job))
            anchor_jobs[job_id] = None
    passed = not unpinned
    desc = (
        "Every reusable workflow reference is pinned to a commit SHA."
        if passed else
        f"{len(unpinned)} reusable workflow reference(s) are pinned to "
        f"a tag or branch, not a commit SHA: "
        f"{'; '.join(sorted(set(unpinned))[:3])}"
        f"{'...' if len(set(unpinned)) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
        job_anchors=tuple(anchor_jobs),
    )
