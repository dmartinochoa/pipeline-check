"""CCM-001 — CodeCommit repository has no approval rule template attached."""
from __future__ import annotations

from botocore.exceptions import ClientError

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CCM-001",
    title="CodeCommit repository has no approval rule template attached",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1",),
    cwe=("CWE-284",),
    recommendation=(
        "Create a CodeCommit approval-rule template requiring at least one "
        "approval from a designated pool of reviewers and associate it with "
        "every repository. Without one, any PR author with push rights can "
        "self-approve and merge."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    client = catalog.client("codecommit")
    for repo in catalog.codecommit_repositories():
        name = repo.get("repositoryName", "<unnamed>")
        try:
            resp = client.list_associated_approval_rule_templates_for_repository(
                repositoryName=name,
            )
        except ClientError:
            continue
        templates = resp.get("approvalRuleTemplateNames", [])
        passed = bool(templates)
        desc = (
            f"Repo '{name}' has approval rule template(s) attached: {templates}."
            if passed else
            f"Repo '{name}' has no approval rule templates; PRs can be "
            "merged without any reviewer approval."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
