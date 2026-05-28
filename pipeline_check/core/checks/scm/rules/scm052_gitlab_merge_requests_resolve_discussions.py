"""SCM-052. GitLab merge requests can land with unresolved discussions."""
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
    id="SCM-052",
    title="GitLab merge requests can land with unresolved discussions",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-1023",),
    recommendation=(
        "On the project Settings -> General -> Merge requests panel, "
        "enable ``All threads must be resolved`` (API field "
        "``only_allow_merge_if_all_discussions_are_resolved: true`` "
        "on ``PUT /projects/:id``). The setting blocks merge until "
        "every code-review thread is marked resolved, closing the "
        "gap where a reviewer raises a security concern in a "
        "discussion but the merge happens before the author "
        "addresses it. The GitHub analog is ``required_conversation_"
        "resolution`` (covered by SCM-013 on the GitHub side)."
    ),
    docs_note=(
        "Reads ``repo_meta._gitlab_project."
        "only_allow_merge_if_all_discussions_are_resolved`` and "
        "fires when the field is False or missing. The flag is "
        "exposed on the standard ``GET /projects/:id`` endpoint, "
        "so this rule needs no extra API call beyond what the "
        "GitLab hydrator already issues."
    ),
    known_fp=(
        "Projects that gate merge entirely on approvals + status "
        "checks (a separate, equally valid posture) may "
        "deliberately leave discussion-resolution off so that "
        "informal threads don't block deploys. Suppress per-repo "
        "when the merge gate is well-covered by other rules.",
    ),
    incident_refs=(
        "Common review-bypass pattern: a reviewer asks for a "
        "secret to be rotated or a regex to be tightened, the "
        "author replies inline but doesn't change the code, and "
        "the MR is merged before the discussion is closed. "
        "Without ``only_allow_merge_if_all_discussions_are_"
        "resolved``, the platform doesn't enforce that the "
        "unresolved feedback is addressed.",
    ),
    exploit_example=(
        "# Vulnerable: project allows merge with open discussions.\n"
        "GET /projects/group%2Fproject\n"
        "{\n"
        "  \"only_allow_merge_if_pipeline_succeeds\": true,\n"
        "  \"only_allow_merge_if_all_discussions_are_resolved\": false\n"
        "}\n"
        "\n"
        "# Attack scenario: a maintainer asks 'should this take a\n"
        "# user-supplied path? please add validation' as a thread\n"
        "# on the MR. The author replies 'good point, will fix in\n"
        "# follow-up', the thread stays open. Pipeline passes\n"
        "# (the security gap isn't a test failure). MR is merged.\n"
        "# Follow-up never lands.\n"
        "\n"
        "# Safe: set\n"
        "# ``only_allow_merge_if_all_discussions_are_resolved:\n"
        "# true``. The Merge button is disabled until every\n"
        "# thread is resolved; the reviewer's concern has to be\n"
        "# addressed (or explicitly dismissed) before the merge."
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
    required = bool(
        project.get("only_allow_merge_if_all_discussions_are_resolved")
    )
    passed = required
    desc = (
        "Merge requires every discussion thread to be resolved "
        "(``only_allow_merge_if_all_discussions_are_resolved: true``)."
        if passed else
        "Merge can land with open discussion threads "
        "(``only_allow_merge_if_all_discussions_are_resolved: false`` "
        "or missing). Reviewer-raised security concerns can be "
        "merged past without being addressed."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
