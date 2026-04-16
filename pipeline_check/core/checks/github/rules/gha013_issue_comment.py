"""GHA-013 — issue_comment trigger must guard on author association."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import workflow_triggers

RULE = Rule(
    id="GHA-013",
    title="issue_comment trigger without author guard",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    recommendation=(
        "Add an `if:` condition that checks "
        "`github.event.comment.author_association` (e.g. "
        "`contains('OWNER MEMBER COLLABORATOR', ...)`), "
        "`github.event.sender.login`, or `github.actor` against an "
        "allowlist. Without a guard, any GitHub user can trigger the "
        "workflow by posting a comment."
    ),
    docs_note=(
        "`on: issue_comment` (and `discussion_comment`) fires for "
        "every comment on every issue or discussion in the repository. "
        "On public repos this means any GitHub user can trigger "
        "workflow execution. If the workflow runs commands, deploys, "
        "or accesses secrets, the attacker controls timing and can "
        "inject payloads through the comment body."
    ),
)

# Guards that restrict comment-triggered execution to trusted actors.
_AUTHOR_GUARD_RE = re.compile(
    r"github\.event\.(?:comment\.author_association|sender\.login)"
    r"|github\.actor",
)

_COMMENT_TRIGGERS = frozenset({
    "issue_comment",
    "discussion_comment",
})


def check(path: str, doc: dict[str, Any]) -> Finding:
    triggers = set(workflow_triggers(doc))
    if not triggers & _COMMENT_TRIGGERS:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Workflow is not triggered by issue_comment.",
            recommendation="No action required.", passed=True,
        )
    # Look for author-association or actor guards in job/workflow if: conditions.
    guarded = False
    # Check workflow-level if: (uncommon but valid).
    # Scan entire doc as text for the guard patterns — they must appear
    # in an `if:` expression somewhere to be effective.
    from ...base import blob_lower
    blob = blob_lower(doc)
    if _AUTHOR_GUARD_RE.search(blob):
        guarded = True
    passed = guarded
    active = sorted(triggers & _COMMENT_TRIGGERS)
    desc = (
        f"Comment-triggered workflow ({', '.join(active)}) gates "
        f"execution on author association or actor identity."
        if passed else
        f"Workflow triggers on {', '.join(active)} without checking "
        f"`github.event.comment.author_association`, "
        f"`github.event.sender.login`, or `github.actor`. Any GitHub "
        f"user can post a comment and trigger this workflow."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
