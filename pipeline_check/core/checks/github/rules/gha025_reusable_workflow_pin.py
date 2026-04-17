"""GHA-025 — reusable workflow ``uses:`` must pin a 40-char SHA.

GHA-001 already covers step-level ``uses:`` references. Reusable
workflows live at the job level (``jobs.<id>.uses:``) — a distinct
surface GHA-001 doesn't walk. Same SHA-pin contract, different host:
the `.yml` referenced by ``uses:`` executes with the caller's token
so an upstream tag move is an RCE vector.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ._helpers import SHA_RE

RULE = Rule(
    id="GHA-025",
    title="Reusable workflow not pinned to commit SHA",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
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
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        uses = job.get("uses")
        if not isinstance(uses, str) or "@" not in uses:
            continue
        # Local refs (``./.github/workflows/foo.yml``) inherit the
        # caller's commit — no upstream pinning to verify.
        if uses.startswith(("./", "/")):
            continue
        ref = uses.rsplit("@", 1)[1]
        if not SHA_RE.match(ref):
            unpinned.append(f"{job_id}: {uses}")
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
    )
