"""SCM-051. GitLab push rules do not enforce committer-email check."""
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
    id="SCM-051",
    title="GitLab push rules do not enforce committer-email check",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1", "CICD-SEC-6"),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-345",),
    recommendation=(
        "On the project Settings -> Repository -> Push Rules panel, "
        "enable ``Reject unverified users`` (API field "
        "``commit_committer_check: true``). The check rejects any "
        "push whose committer email doesn't match a verified "
        "address on the pusher's GitLab account, blocking the "
        "common spoofing pattern where a stolen credential pushes "
        "commits attributed to a different maintainer. Pair with "
        "``reject_unsigned_commits`` (see SCM-006) for "
        "defense-in-depth: signed commits bind to a maintained "
        "key, committer-check binds to a verified email."
    ),
    docs_note=(
        "Reads ``repo_meta._gitlab_push_rule.commit_committer_check`` "
        "and fires when False or missing. Endpoint is GitLab "
        "Premium / Ultimate; passes silently on CE / Free with a "
        "skip note. The committer-check guard is independent of "
        "signed commits: an unsigned commit with a verified "
        "committer email passes here but is caught by SCM-006; "
        "a signed commit with a spoofed committer email passes "
        "SCM-006 but is caught here. Both controls together "
        "produce the same posture GitHub achieves via vigilant "
        "mode + required signed commits."
    ),
    known_fp=(
        "GitLab CE / self-managed Free installations don't expose "
        "push rules; this rule passes silently on those snapshots. "
        "Mirror infrastructure repos that intentionally permit "
        "unverified committer emails (cross-org mirrors, "
        "third-party import flows) may also legitimately leave "
        "this off; suppress per-repo with a rationale.",
    ),
    incident_refs=(
        "Maintainer-account compromise scenarios where the "
        "attacker pushes commits attributed to a different "
        "trusted contributor by setting ``committer.email``; "
        "without the check the platform accepts the push as-is, "
        "and the audit trail shows the wrong author until "
        "someone notices the missing verification badge.",
    ),
    exploit_example=(
        "# Vulnerable: ``commit_committer_check`` is off.\n"
        "GET /projects/group%2Fproject/push_rule\n"
        "{\n"
        "  \"id\": 1,\n"
        "  \"prevent_secrets\": true,\n"
        "  \"reject_unsigned_commits\": false,\n"
        "  \"commit_committer_check\": false\n"
        "}\n"
        "\n"
        "# Attack: an attacker with stolen push credentials on a\n"
        "# new account configures ``git config user.email\n"
        "# trusted.maintainer@example.com`` and pushes. GitLab\n"
        "# records the commit as authored by the trusted\n"
        "# maintainer; the audit log entry for the push still\n"
        "# names the real (attacker) account but the commit\n"
        "# itself is misattributed in every UI.\n"
        "\n"
        "# Safe: enable ``commit_committer_check``. The push is\n"
        "# rejected with a server-side message naming the email\n"
        "# mismatch; the attacker cannot spoof committer identity."
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
    push_rule: Any = meta.get("_gitlab_push_rule")
    if not isinstance(push_rule, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "Push-rule endpoint unavailable (GitLab Free / CE)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    enforced = bool(push_rule.get("commit_committer_check"))
    passed = enforced
    desc = (
        "Push rules enforce committer-email verification "
        "(``commit_committer_check: true``)."
        if passed else
        "Push rules do not verify committer email "
        "(``commit_committer_check: false`` or missing). A pusher "
        "with stolen credentials can set ``committer.email`` to a "
        "trusted maintainer's address and the platform attributes "
        "the commit to that maintainer in every UI."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
