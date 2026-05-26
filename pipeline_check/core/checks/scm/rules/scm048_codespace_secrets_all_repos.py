"""SCM-048. Org codespace secrets visible to all repos."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    SCMRepoSnapshot,
    github_only_skip,
    repo_resource,
)

RULE = Rule(
    id="SCM-048",
    title="Org codespace secret scoped to all repos",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-269", "CWE-732"),
    recommendation=(
        "Scope each org-level codespace secret to only the repos that "
        "need it: Organization Settings > Codespaces > Secrets > edit "
        "the secret > change Visibility from 'All repositories' to "
        "'Selected repositories' and pick the specific repos. A "
        "secret visible to every repo in the org means any developer "
        "who opens a codespace in any repo (including forks of public "
        "repos, if codespaces are enabled for those) can read the "
        "value via ``${{ secrets.NAME }}`` or the ``CODESPACE_*`` "
        "environment."
    ),
    docs_note=(
        "Reads ``GET /orgs/{owner}/codespaces/secrets`` and flags "
        "every secret whose ``visibility`` field is ``\"all\"``. "
        "Requires ``admin:org`` scope on the token; without it "
        "GitHub returns 404 and the rule passes silently with an "
        "unavailability note.\n\n"
        "Secrets with ``visibility: \"private\"`` (all private repos) "
        "or ``visibility: \"selected\"`` (named repo list) are not "
        "flagged. The ``private`` tier is a middle ground some orgs "
        "accept; ``selected`` is the tightest scope GitHub offers."
    ),
    known_fp=(
        "Organizations that genuinely need a secret in every repo "
        "(rare — examples include a shared telemetry token or an "
        "internal-CA certificate) should suppress with a rationale "
        "naming the secret and confirming the blast radius is "
        "accepted.",
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
    secrets = snapshot.codespace_secrets
    if secrets is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "orgs/codespaces/secrets endpoint unavailable (token "
                "may lack ``admin:org`` scope or the owner is a user "
                "account, not an organization)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    if not secrets:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description="No org-level codespace secrets configured.",
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    for secret in secrets:
        visibility = secret.get("visibility")
        name = secret.get("name", "(unnamed)")
        if visibility == "all":
            offenders.append(name)
    passed = not offenders
    desc = (
        f"All {len(secrets)} org codespace secret(s) are scoped to "
        f"selected or private repos."
        if passed else
        f"{len(offenders)} org codespace secret(s) visible to ALL "
        f"repos: {', '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}. Any developer who "
        f"opens a codespace in any repo in the org can read these "
        f"values."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
