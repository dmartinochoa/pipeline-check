"""CP-005 (Terraform). Production stage has no preceding approval."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..phase3 import _pbac005_cp005_cp007

RULE = Rule(
    id="CP-005",
    title="Production Deploy stage has no preceding ManualApproval",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    cwe=("CWE-862",),
    recommendation=(
        "Add a ``Manual`` approval action in the stage that precedes "
        "any stage whose name contains ``prod``, ``production``, or "
        "``live`` and contains a Deploy action. Approval surfaces the "
        "release decision as an auditable event."
    ),
    docs_note=(
        "A stricter version of CP-001 scoped to production-named "
        "stages. Walks ``stage[*].name`` for ``prod`` / ``production`` "
        "/ ``live`` substrings and requires a preceding "
        "``Approval`` action — even pipelines that pass CP-001 "
        "globally often skip the gate on the production stage."
    ),
    exploit_example=(
        "# Vulnerable: a production Deploy stage with no approval before it.\n"
        "resource \"aws_codepipeline\" \"release\" {\n"
        "  # ... source + build stages ...\n"
        "  stage {\n"
        "    name = \"DeployProd\"\n"
        "    action {\n"
        "      name     = \"Deploy\"\n"
        "      category = \"Deploy\"\n"
        "      # ...\n"
        "    }\n"
        "  }\n"
        "}\n"
        "\n"
        "# Attack: nothing gates the production stage, so every change\n"
        "# that reaches it deploys to prod automatically. An unreviewed\n"
        "# merge (or a poisoned upstream artifact) ships straight to\n"
        "# production with no human sign-off and no auditable approval\n"
        "# event.\n"
        "\n"
        "# Safe: add a Manual approval action in the stage before prod.\n"
        "  stage {\n"
        "    name = \"Approve\"\n"
        "    action {\n"
        "      name     = \"ManualApproval\"\n"
        "      category = \"Approval\"\n"
        "      provider = \"Manual\"\n"
        "    }\n"
        "  }"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [
        f for f in _pbac005_cp005_cp007(ctx) if f.check_id == "CP-005"
    ]
