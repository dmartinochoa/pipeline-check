"""CP-005 (CloudFormation). Production stage has no preceding approval."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..phase3 import _pbac005_cp005_cp007

RULE = Rule(
    id="CP-005",
    title="Production Deploy stage has no preceding ManualApproval",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    cwe=("CWE-862",),
    recommendation=(
        "Add a ``Manual`` approval action in the stage that "
        "precedes any stage whose name contains ``prod`` / "
        "``production`` / ``live`` and contains a Deploy action."
    ),
    docs_note=(
        "A stricter version of CP-001 scoped to production-named "
        "stages. Walks ``Stages[*].Name`` for ``prod`` / "
        "``production`` / ``live`` substrings and requires a "
        "preceding ``Approval`` action."
    ),
    exploit_example=(
        "# Vulnerable: a production Deploy stage with no approval before it.\n"
        "Resources:\n"
        "  Release:\n"
        "    Type: AWS::CodePipeline::Pipeline\n"
        "    Properties:\n"
        "      Stages:\n"
        "        # ... Source + Build ...\n"
        "        - Name: DeployProd\n"
        "          Actions:\n"
        "            - Name: Deploy\n"
        "              ActionTypeId: { Category: Deploy, Owner: AWS, Provider: CodeDeploy, Version: \"1\" }\n"
        "\n"
        "# Attack: nothing gates the production stage, so every change\n"
        "# that reaches it deploys to prod automatically. An unreviewed\n"
        "# merge (or a poisoned upstream artifact) ships straight to\n"
        "# production with no human sign-off and no auditable approval\n"
        "# event.\n"
        "\n"
        "# Safe: add a Manual approval action in the stage before prod.\n"
        "        - Name: Approve\n"
        "          Actions:\n"
        "            - Name: ManualApproval\n"
        "              ActionTypeId: { Category: Approval, Owner: AWS, Provider: Manual, Version: \"1\" }"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [
        f for f in _pbac005_cp005_cp007(ctx) if f.check_id == "CP-005"
    ]
