"""CCM-001. CodeCommit repository has no approval rule template attached."""
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
    docs_note=(
        "Approval-rule templates are CodeCommit's analog of GitHub's "
        "branch-protection require-review. Without one associated, "
        "the repository accepts merges from any push-permitted "
        "principal, including the PR author themselves, without "
        "any second-pair-of-eyes gate."
    ),
    exploit_example=(
        "# Vulnerable: a CodeCommit repository with no approval\n"
        "# rule template attached. Pull requests merge without\n"
        "# any reviewer requirement; a single contributor with\n"
        "# write access can ship code into the default branch\n"
        "# without review.\n"
        "import boto3\n"
        "cc = boto3.client('codecommit')\n"
        "# Empty list returned:\n"
        "cc.list_associated_approval_rule_templates_for_repository(\n"
        "    repositoryName='my-repo'\n"
        ")  # -> {'approvalRuleTemplateNames': []}\n"
        "\n"
        "# Safe: create an approval rule template (at least one\n"
        "# reviewer required) and attach it to the repository.\n"
        "cc.create_approval_rule_template(\n"
        "    approvalRuleTemplateName='require-1-reviewer',\n"
        "    approvalRuleTemplateContent='''{\"Version\": \"2018-11-08\",\n"
        "      \"DestinationReferences\": [\"refs/heads/main\"],\n"
        "      \"Statements\": [{\"Type\": \"Approvers\",\n"
        "        \"NumberOfApprovalsNeeded\": 1,\n"
        "        \"ApprovalPoolMembers\": [\"arn:aws:sts::123:assumed-role/Developers/*\"]}]}'''\n"
        ")\n"
        "cc.associate_approval_rule_template_with_repository(\n"
        "    approvalRuleTemplateName='require-1-reviewer',\n"
        "    repositoryName='my-repo'\n"
        ")"
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
