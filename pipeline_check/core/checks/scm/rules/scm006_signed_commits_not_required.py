"""SCM-006. Default branch protection does not require signed commits.

Maps to CIS Software Supply Chain Security Guide section 1.1.6
(ensure any change to code is signed). Required signatures bind a
commit to a verifiable maintainer identity (GPG, S/MIME, or SSH);
without them, a maintainer-account compromise that still preserves
write access can land commits indistinguishable from real ones.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMRepoSnapshot, default_branch_name, repo_resource

RULE = Rule(
    id="SCM-006",
    title="Default branch protection does not require signed commits",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1", "CICD-SEC-6"),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-345",),
    recommendation=(
        "In the default-branch protection rule, enable ``Require "
        "signed commits``. Configure GPG, SSH, or S/MIME signatures "
        "for every contributor's git client (``git config "
        "commit.gpgsign true`` plus an uploaded public key). Pair "
        "with branch protection's ``Restrict who can push to matching "
        "branches`` so only signed commits from authorized identities "
        "land on the default branch."
    ),
    docs_note=(
        "Reads ``required_signatures.enabled`` from the branch "
        "protection payload. Fires when the field is missing or "
        "False. Required signatures don't validate signature "
        "authenticity (the GitHub web UI does that lazily on render), "
        "but a missing signature is rejected at push time, which "
        "blocks the most common compromise pattern: a stolen "
        "personal access token used to push under the maintainer's "
        "name without their signing key."
    ),
)


def check(snapshot: SCMRepoSnapshot) -> Finding:
    branch = default_branch_name(snapshot)
    if snapshot.platform == "bitbucket":
        # Bitbucket Cloud has no per-branch signed-commit enforcement, so
        # the recommendation ("enable Require signed commits") isn't
        # actionable there. Skip with a note (matching the pack's
        # platform-skip convention) rather than fail every Bitbucket repo.
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "Signed-commit enforcement is not a per-branch protection "
                "setting on Bitbucket Cloud; SCM-006 is not applicable and "
                f"is skipped on the {snapshot.platform} snapshot."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    protection = snapshot.default_branch_protection
    if not isinstance(protection, dict):
        # SCM-001 owns the no-protection case; pass silently to
        # avoid cascading duplicates from a single root cause.
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                f"Default branch ``{branch}`` has no protection rule "
                f"to evaluate. See SCM-001."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    sig = protection.get("required_signatures")
    enabled = False
    if isinstance(sig, dict):
        enabled = bool(sig.get("enabled"))
    passed = enabled
    desc = (
        f"Default branch ``{branch}`` requires signed commits."
        if passed else
        f"Default branch ``{branch}`` does not require signed "
        f"commits. A stolen access token can push under a "
        f"maintainer's name with no signature, indistinguishable "
        f"from a real commit until someone notices the missing "
        f"verification badge in the UI."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
