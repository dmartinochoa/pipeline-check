"""SCM-015. Secret scanning push protection is not enabled.

Maps to CIS Software Supply Chain Security Guide section 1.5.1.
Push protection is the *prevent* step that pairs with SCM-004's
*detect* step: GitHub blocks the push at the git-server side
before the secret hits commit history. Even when secret scanning
is on (SCM-004 passes), without push protection the credential
still lands in history and triggers an after-the-fact alert
rather than a refused push.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    SCMRepoSnapshot,
    archived_state_label,
    repo_resource,
    security_feature_state,
)

RULE = Rule(
    id="SCM-015",
    title="Secret scanning push protection is not enabled",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798",),
    recommendation=(
        "Enable secret scanning push protection under the "
        "repository's Settings -> Code security -> Push protection. "
        "Pushes containing matched credential patterns are refused "
        "by GitHub before the commit is accepted, so the credential "
        "never enters git history. Authors get an immediate "
        "remediation prompt; the bypass-with-justification flow "
        "preserves the audit trail when a legitimate test-case "
        "credential needs to land."
    ),
    docs_note=(
        "Reads ``security_and_analysis.secret_scanning_push_"
        "protection.status`` from the repo metadata payload. Fires "
        "when the value is anything other than ``enabled``. "
        "Strongly paired with SCM-004 (secret scanning enabled): "
        "SCM-004 catches credentials after the push, SCM-015 stops "
        "them at the push. Both should be on for high-trust repos."
    ),
    known_fp=(
        "When the scanning token lacks ``admin`` scope on the repo, "
        "the ``security_and_analysis`` block is omitted from the API "
        "response and this rule cannot tell ``disabled`` from "
        "``unknown``. Re-run with admin scope to confirm.",
        "Push protection covers the GitHub-managed pattern set "
        "(~200 token patterns from major providers). Custom-pattern "
        "support requires GitHub Advanced Security on private repos; "
        "public repos get the GitHub-managed set free.",
    ),
    exploit_example=(
        "# Vulnerable: secret scanning is enabled but push\n"
        "# protection is off. Secrets are surfaced AFTER they hit\n"
        "# the remote — the credential is already in history,\n"
        "# already mirrored to backups, already visible to anyone\n"
        "# who fetched between push and rotation. Rotation is the\n"
        "# only fix.\n"
        "# GET /repos/myorg/myrepo (vulnerable response):\n"
        "{\n"
        "  \"security_and_analysis\": {\n"
        "    \"secret_scanning\": {\"status\": \"enabled\"},\n"
        "    \"secret_scanning_push_protection\": {\"status\": \"disabled\"}\n"
        "  }\n"
        "}\n"
        "\n"
        "# Safe: both on. Push protection refuses pushes that\n"
        "# carry a recognized credential pattern; the developer\n"
        "# sees the rejection at ``git push`` time and rotates\n"
        "# BEFORE the secret enters history.\n"
        "# PATCH /repos/myorg/myrepo:\n"
        "{\n"
        "  \"security_and_analysis\": {\n"
        "    \"secret_scanning\": {\"status\": \"enabled\"},\n"
        "    \"secret_scanning_push_protection\": {\"status\": \"enabled\"}\n"
        "  }\n"
        "}"
    ),
)


def check(snapshot: SCMRepoSnapshot) -> Finding:
    if state_label := archived_state_label(snapshot):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                f"Repo is {state_label}; GitHub auto-disables "
                f"secret-scanning push protection on {state_label} "
                f"repos. Skipped."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    state = security_feature_state(
        snapshot, "secret_scanning_push_protection",
    )
    passed = state == "enabled"
    if state is None:
        desc = (
            "Secret-scanning push-protection state is unavailable "
            "from the API response (token may lack ``admin`` scope). "
            "Treating as not-enabled; re-run with admin scope to "
            "confirm."
        )
    elif passed:
        desc = (
            "Secret scanning push protection is enabled — pushes "
            "containing matched credential patterns are blocked at "
            "the git-server side."
        )
    else:
        desc = (
            f"Secret scanning push protection is not enabled (state="
            f"``{state}``). Credentials that match a known pattern "
            f"land in git history first, then trigger an "
            f"after-the-fact alert; rotation cost stays high."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
