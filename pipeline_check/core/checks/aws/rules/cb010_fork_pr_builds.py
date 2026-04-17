"""CB-010 — CodeBuild webhook allows fork-PR builds without actor filtering."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CB-010",
    title="CodeBuild webhook allows fork-PR builds without actor filtering",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    cwe=("CWE-284",),
    recommendation=(
        "Add an ``ACTOR_ACCOUNT_ID`` filter pattern to every webhook filter "
        "group that accepts ``PULL_REQUEST_CREATED`` / ``PULL_REQUEST_UPDATED`` "
        "/ ``PULL_REQUEST_REOPENED``, or remove those PR event types. Without "
        "actor filtering, any fork can trigger a build that runs with the "
        "project's service role."
    ),
    docs_note=(
        "GitHub/Bitbucket webhook filter groups that fire on pull-request "
        "events will build forks by default. Because CodeBuild runs with the "
        "project's own IAM role (not the PR author's), a fork PR can execute "
        "arbitrary code with CI privileges and exfiltrate secrets. Restrict "
        "to known contributors with an ``ACTOR_ACCOUNT_ID`` pattern group."
    ),
)

_PR_EVENTS = {
    "PULL_REQUEST_CREATED",
    "PULL_REQUEST_UPDATED",
    "PULL_REQUEST_REOPENED",
}


def _group_covers_pr(group: list[dict]) -> bool:
    for filt in group:
        if filt.get("type") != "EVENT":
            continue
        pattern = filt.get("pattern", "") or ""
        events = {e.strip() for e in pattern.split(",") if e.strip()}
        if events & _PR_EVENTS:
            return True
    return False


def _group_has_actor_filter(group: list[dict]) -> bool:
    return any(filt.get("type") == "ACTOR_ACCOUNT_ID" for filt in group)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for project in catalog.codebuild_projects():
        name = project.get("name", "<unnamed>")
        webhook = project.get("webhook")
        if not webhook:
            continue
        groups = webhook.get("filterGroups") or []
        offenders = [
            i for i, g in enumerate(groups)
            if _group_covers_pr(g) and not _group_has_actor_filter(g)
        ]
        passed = not offenders
        if passed:
            desc = (
                f"Webhook on '{name}' either does not build PRs or pins an "
                "ACTOR_ACCOUNT_ID filter on every PR-triggering group."
            )
        else:
            desc = (
                f"Webhook on '{name}' builds PRs via groups {offenders} but "
                "none of those groups filter by ACTOR_ACCOUNT_ID. Any fork "
                "can trigger a build that runs with the project service role."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
