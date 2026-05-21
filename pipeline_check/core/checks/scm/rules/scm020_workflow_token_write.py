"""SCM-020. Default workflow GITHUB_TOKEN has ``write`` permission."""
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
    id="SCM-020",
    title="Default workflow GITHUB_TOKEN has write permission",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2", "CICD-SEC-5"),
    esf=("ESF-D-CODE-INTEGRITY",),
    cwe=("CWE-269", "CWE-913"),
    recommendation=(
        "In repo Settings → Actions → General → Workflow "
        "permissions, set the default to ``Read repository "
        "contents and packages permissions``. Workflows that "
        "genuinely need to push, comment on PRs, or modify "
        "issues opt in explicitly via the workflow-file "
        "``permissions:`` block. The default ``write`` setting "
        "gives every workflow's ``GITHUB_TOKEN`` write access to "
        "every API surface the repo exposes (contents, issues, "
        "PRs, actions, packages, deployments), so a single "
        "compromised dependency in any job is one step away from "
        "the GHA-048 / GHA-049 worm-propagation primitives "
        "(workflow self-mutation, cross-repo push) the rule "
        "pack catches at the workflow-YAML layer. Setting the "
        "default to ``read`` is the org-side complement: even if "
        "a workflow forgets to declare ``permissions:`` and the "
        "compromised dep tries to push, GitHub refuses the "
        "operation."
    ),
    docs_note=(
        "Reads ``default_workflow_permissions`` from "
        "``GET /repos/{owner}/{repo}/actions/permissions/workflow``. "
        "Values are ``\"read\"`` (safe) or ``\"write\"`` (fail). "
        "Requires the token to have ``admin`` scope on the repo; "
        "without it GitHub returns 403 and the rule passes "
        "silently with an unavailability note. Complements GHA-"
        "048 / GHA-049 — those catch the *workflow* asking for "
        "write; SCM-020 catches the *org / repo* handing out "
        "write by default."
    ),
    known_fp=(
        "Repos where every workflow legitimately needs write "
        "access (release-publishing automation, mirror-sync "
        "jobs) may set the default to ``write`` deliberately. "
        "The right pattern is still to keep the default at "
        "``read`` and grant write at the workflow level — that "
        "way a new workflow (added by a future contributor) "
        "starts safe. Suppress only when every workflow in the "
        "repo carries an explicit ``permissions:`` block.",
    ),
    incident_refs=(
        "Shai-Hulud npm worm (2026): the worm's propagation "
        "primitive was a stolen ``GITHUB_TOKEN`` with ``contents: "
        "write`` and ``workflows: write``. Repos whose default "
        "workflow permissions were ``read`` were unaffected even "
        "when their workflows ran a compromised npm dep; ``write``-"
        "default repos handed the worm the keys.",
    ),
    exploit_example=(
        "# Vulnerable: ``default_workflow_permissions: write``\n"
        "# means every workflow's ``GITHUB_TOKEN`` starts with\n"
        "# repo-write authority. A typo'd ``run:`` (or an\n"
        "# injection per GHA-003) can ``git push`` to any branch,\n"
        "# open issues, comment on PRs, write packages — the\n"
        "# attack surface of every action expands by default.\n"
        "# GET /repos/myorg/myrepo/actions/permissions/workflow:\n"
        "{\n"
        "  \"default_workflow_permissions\": \"write\",\n"
        "  \"can_approve_pull_request_reviews\": false\n"
        "}\n"
        "\n"
        "# Safe: ``read`` default. Workflows that genuinely need\n"
        "# elevated rights declare per-job ``permissions:`` blocks\n"
        "# that scope the token to the specific verbs they need\n"
        "# (``contents: write`` for a release publisher,\n"
        "# ``packages: write`` for a registry push, etc.).\n"
        "# PUT /repos/myorg/myrepo/actions/permissions/workflow:\n"
        "{\n"
        "  \"default_workflow_permissions\": \"read\",\n"
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
                f"Repo is {label}; workflow-permissions check skipped."
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
                "(token likely lacks ``admin`` scope). Workflow "
                "permissions cannot be evaluated; pass --gh-token "
                "with an admin-scoped PAT to enable."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    default = awp.get("default_workflow_permissions")
    if default == "read":
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "Default workflow GITHUB_TOKEN scope is ``read``; "
                "workflows that need write opt in explicitly."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    if default != "write":
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                f"actions/permissions/workflow returned an "
                f"unrecognized ``default_workflow_permissions`` "
                f"value: {default!r}. Treating as unavailable."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot),
        description=(
            "Default workflow GITHUB_TOKEN scope is ``write``. Every "
            "workflow run that doesn't declare its own "
            "``permissions:`` block gets write access to every API "
            "surface the repo exposes — the GHA-048 / GHA-049 worm-"
            "propagation primitive at the org / repo level."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
