"""SCM-021. Actions can submit pull-request reviews (self-approval)."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    SCMRepoSnapshot,
    archived_state_label,
    github_only_skip,
    repo_resource,
)

RULE = Rule(
    id="SCM-021",
    title="Actions can approve pull requests (self-approval bypass)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1", "CICD-SEC-4"),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-863", "CWE-269"),
    recommendation=(
        "In repo Settings → Actions → General → Workflow "
        "permissions, uncheck ``Allow GitHub Actions to create and "
        "approve pull requests``. With it on, any workflow whose "
        "``GITHUB_TOKEN`` includes ``pull-requests: write`` can "
        "submit an approving review on a PR — including its own. "
        "Required-review controls (SCM-002), CODEOWNERS reviews "
        "(SCM-011), and last-push approval (SCM-014) all become "
        "advisory once Actions can satisfy their own gate. A "
        "compromised dependency that opens a PR can immediately "
        "approve and merge it without any human in the loop."
    ),
    docs_note=(
        "Reads ``can_approve_pull_request_reviews`` from "
        "``GET /repos/{owner}/{repo}/actions/permissions/workflow``. "
        "``True`` is the fail signal; ``False`` (or absent) passes. "
        "Requires admin scope on the repo. Complements SCM-002 / "
        "SCM-011 / SCM-014 — without SCM-021, those rules document "
        "intent rather than enforcement, because Actions can fulfill "
        "the review requirement itself."
    ),
    known_fp=(
        "Some orgs allow Actions self-approval as part of a "
        "tightly-scoped automation flow (e.g., a code-formatter "
        "bot that opens-and-merges its own PRs). The safer "
        "pattern is to grant the bot a dedicated PAT scoped to "
        "PR-create-and-approve, not the repo-wide GITHUB_TOKEN. "
        "Suppress only when the trade-off has been documented.",
    ),
    exploit_example=(
        "# Vulnerable: ``can_approve_pull_request_reviews: true``\n"
        "# means a workflow's ``GITHUB_TOKEN`` (or an installation\n"
        "# token) can approve a pull request. Combined with the\n"
        "# required-reviews protection, a malicious workflow self-\n"
        "# approves its own PR and lands code into ``main`` without\n"
        "# a human reviewer.\n"
        "# GET /repos/myorg/myrepo/actions/permissions/workflow:\n"
        "{\n"
        "  \"can_approve_pull_request_reviews\": true\n"
        "}\n"
        "\n"
        "# Safe: actions cannot approve PRs. Human approval is\n"
        "# the gating signal; automation can comment / label /\n"
        "# trigger checks but cannot satisfy the review\n"
        "# requirement.\n"
        "# PUT /repos/myorg/myrepo/actions/permissions/workflow:\n"
        "{\n"
        "  \"can_approve_pull_request_reviews\": false\n"
        "}"
    ),
)


def check(snapshot: SCMRepoSnapshot) -> Finding:
    skip = github_only_skip(snapshot)
    if skip is not None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=skip,
            recommendation=RULE.recommendation, passed=True,
        )
    if label := archived_state_label(snapshot):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                f"Repo is {label}; Actions-review check skipped."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    awp = snapshot.actions_workflow_permissions
    if not isinstance(awp, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "actions/permissions/workflow endpoint unavailable "
                "(token likely lacks ``admin`` scope)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    can_approve = awp.get("can_approve_pull_request_reviews")
    if not can_approve:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "Actions cannot submit PR reviews; required-review "
                "controls cannot be self-satisfied by workflows."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot),
        description=(
            "Actions can submit PR reviews "
            "(``can_approve_pull_request_reviews: true``). Every "
            "required-review control on this repo is advisory — any "
            "workflow with ``pull-requests: write`` can approve its "
            "own PR, bypassing SCM-002 / SCM-011 / SCM-014."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
