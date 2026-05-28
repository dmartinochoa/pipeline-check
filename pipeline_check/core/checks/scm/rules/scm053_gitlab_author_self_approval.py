"""SCM-053. GitLab merge requests allow the author to approve their own MR."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    SCMRepoSnapshot,
    gitlab_only_skip,
    repo_resource,
)

RULE = Rule(
    id="SCM-053",
    title="GitLab merge requests allow the author to approve their own MR",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1", "CICD-SEC-4"),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-269",),
    recommendation=(
        "On the project Settings -> Merge requests -> Approvals "
        "panel, disable ``Allow author of merge request to approve "
        "their own merge request``. The API surfaces this as "
        "``merge_requests_author_approval: false`` on "
        "``PUT /projects/:id`` (the inverted boolean: ``false`` "
        "*disables* author approval, which is the safe posture). "
        "Combined with ``approvals_before_merge >= 1`` (already "
        "audited by SCM-002 on the universal-rules side), the "
        "approval gate becomes meaningful: the author can't "
        "self-merge by clicking Approve and bypassing review."
    ),
    docs_note=(
        "Reads ``repo_meta._gitlab_project.merge_requests_author_"
        "approval`` and fires when True (the unsafe value). "
        "GitLab inverts the field semantics: ``true`` means "
        "author approval is permitted, ``false`` means it's "
        "disabled. The rule normalizes this so a passing finding "
        "reflects the safe posture regardless of the API's "
        "boolean polarity. Together with SCM-002 (required "
        "approval count >= 1) this catches the full self-merge "
        "bypass; either rule alone is insufficient."
    ),
    known_fp=(
        "Single-maintainer projects (personal repos, small "
        "experimental projects) by design have no reviewer pool, "
        "so author approval is the only signal available. "
        "Suppress per-repo for those cases with a rationale "
        "naming the project's single-author posture.",
    ),
    incident_refs=(
        "Classic self-merge bypass: an attacker with a single "
        "maintainer-account compromise pushes a MR, approves it "
        "themselves, and merges. With author-approval disabled "
        "the approve-button click is rejected at the API level "
        "and a second reviewer is forced.",
    ),
    exploit_example=(
        "# Vulnerable: project allows authors to approve their MRs.\n"
        "GET /projects/group%2Fproject\n"
        "{\n"
        "  \"approvals_before_merge\": 1,\n"
        "  \"merge_requests_author_approval\": true\n"
        "}\n"
        "\n"
        "# Attack: compromised maintainer pushes branch with a\n"
        "# malicious commit, opens MR, hits Approve, hits Merge.\n"
        "# Approvals count: 1 (the author themselves). Pipeline\n"
        "# passes. Code lands without any second human in the\n"
        "# loop -- the entire approval gate was self-served.\n"
        "\n"
        "# Safe: set ``merge_requests_author_approval: false``.\n"
        "# The Approve button is hidden on the author's own MR;\n"
        "# the merge cannot proceed until a different user\n"
        "# approves."
    ),
)


def check(snapshot: SCMRepoSnapshot) -> Finding:
    if skip := gitlab_only_skip(snapshot):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=skip,
            recommendation=RULE.recommendation, passed=True,
        )
    meta = snapshot.repo_meta if isinstance(snapshot.repo_meta, dict) else {}
    project: Any = meta.get("_gitlab_project")
    if not isinstance(project, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description="GitLab project metadata unavailable.",
            recommendation=RULE.recommendation, passed=True,
        )
    allowed = bool(project.get("merge_requests_author_approval"))
    passed = not allowed
    desc = (
        "Author cannot self-approve their MR "
        "(``merge_requests_author_approval: false``)."
        if passed else
        "Author can approve their own MR "
        "(``merge_requests_author_approval: true``). A "
        "compromised maintainer can self-approve and self-merge, "
        "bypassing the approval gate entirely."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
