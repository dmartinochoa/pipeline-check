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
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [f for f in _codecommit(ctx) if f.check_id == "CCM-001"]
