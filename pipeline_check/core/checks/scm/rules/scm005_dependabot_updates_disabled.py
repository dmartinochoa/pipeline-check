"""SCM-005. Dependabot security updates are not enabled.

Maps to CIS Software Supply Chain Security Guide section 1.1.8
(scanners in place to identify and prevent vulnerabilities) and
to the OpenSSF Scorecard ``Dependency-Update-Tool`` and
``Vulnerabilities`` checks. Dependabot security updates open PRs
to bump the minimum-required version of a dependency the moment a
known CVE lands against the in-use range.
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
    id="SCM-005",
    title="Dependabot security updates are not enabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-10"),
    esf=("ESF-V-VULN-MGMT",),
    cwe=("CWE-1104",),
    recommendation=(
        "Enable Dependabot security updates under the repository's "
        "Settings -> Code security -> Dependabot. The bot opens a PR "
        "with the minimum-required upgrade for each open advisory "
        "against an in-use dependency. Pair with version-update "
        "config (``.github/dependabot.yml``) so routine bumps don't "
        "rely on the security-update path."
    ),
    docs_note=(
        "Reads ``security_and_analysis.dependabot_security_updates."
        "status`` from the repo metadata payload. Fires when the "
        "value is anything other than ``enabled``. Without security "
        "updates, the team has to discover and triage CVEs against "
        "their dependency graph manually — a delay measured in days "
        "or weeks even on attentive teams, vs hours when the bot "
        "opens the PR for them."
    ),
    known_fp=(
        "When the scanning token lacks ``admin`` scope on the repo, "
        "the ``security_and_analysis`` block is omitted from the API "
        "response and this rule cannot tell ``disabled`` from "
        "``unknown``. Re-run with admin scope to confirm.",
        "Repos that delegate dependency-update PRs to Renovate, "
        "Snyk, or another bot get equivalent coverage without "
        "Dependabot. Suppress via ignore-file rather than removing "
        "the rule.",
    ),
)


def check(snapshot: SCMRepoSnapshot) -> Finding:
    # Archived/disabled-repo guard: GitHub auto-disables Dependabot
    # security updates on archived repos. Without this guard SCM-005
    # FPs on every archived repo regardless of historical posture.
    if state_label := archived_state_label(snapshot):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                f"Repo is {state_label}; GitHub auto-disables "
                f"Dependabot on {state_label} repos. Skipped."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    state = security_feature_state(
        snapshot, "dependabot_security_updates",
    )
    passed = state == "enabled"
    if state is None:
        desc = (
            "Dependabot security-update state is unavailable from the "
            "API response (token may lack ``admin`` scope). Treating "
            "as not-enabled; re-run with admin scope to confirm."
        )
    elif passed:
        desc = "Dependabot security updates are enabled."
    else:
        desc = (
            f"Dependabot security updates are not enabled (state="
            f"``{state}``). New CVEs against in-use dependencies "
            f"require manual triage, which on most teams adds days "
            f"of exposure per advisory."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
