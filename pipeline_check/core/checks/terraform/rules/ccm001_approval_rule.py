"""CCM-001 (Terraform). CodeCommit repository has no approval rule."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..services import _codecommit

RULE = Rule(
    id="CCM-001",
    title="CodeCommit repository has no approval rule template attached",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1",),
    cwe=("CWE-862",),
    recommendation=(
        "Create an ``aws_codecommit_approval_rule_template`` requiring "
        "at least one reviewer from a named team, then associate it "
        "with the repository via "
        "``aws_codecommit_approval_rule_template_association``."
    ),
    docs_note=(
        "Looks for at least one "
        "``aws_codecommit_approval_rule_template_association`` joined "
        "to the repository by ``repository_name``. Without an "
        "approval rule, the merge gate every reviewer assumes exists "
        "doesn't."
    ),
    exploit_example=(
        "# Vulnerable: CodeCommit repo has no approval rule.\n"
        "# A single developer can merge directly to the default\n"
        "# branch without any review.\n"
        'resource "aws_codecommit_repository" "backend" {\n'
        '  repository_name = "backend"\n'
        "}\n"
        "# (no aws_codecommit_approval_rule_template_association)\n"
        "\n"
        "# Safe: require at least one approval.\n"
        'resource "aws_codecommit_approval_rule_template" "one_approval" {\n'
        '  name    = "require-one-approval"\n'
        "  content = jsonencode({\n"
        "    Version               = \"2018-11-08\"\n"
        "    Statements = [{\n"
        "      Type                = \"Approvers\"\n"
        "      NumberOfApprovalsNeeded = 1\n"
        "    }]\n"
        "  })\n"
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [f for f in _codecommit(ctx) if f.check_id == "CCM-001"]
