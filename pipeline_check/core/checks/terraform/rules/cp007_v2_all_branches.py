"""CP-007 (Terraform). V2 pipeline PR trigger accepts every branch."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..phase3 import _pbac005_cp005_cp007

RULE = Rule(
    id="CP-007",
    title="CodePipeline v2 PR trigger accepts all branches",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    cwe=("CWE-863",),
    recommendation=(
        "Set ``trigger.git_configuration.push[*].branches.includes`` "
        "or ``trigger.git_configuration.pull_request[*].branches."
        "includes`` to the specific branches the pipeline expects. "
        "An empty include list runs on every branch event, including "
        "fork-PR rebases."
    ),
    docs_note=(
        "Inspects v2 pipelines (``pipeline_type = \"V2\"``) whose "
        "``trigger.git_configuration`` declares a "
        "``pull_request`` block without ``branches.includes``. The "
        "trigger then matches every PR, fork-source PRs included."
    ),
    exploit_example=(
        "# Vulnerable: v2 pipeline triggers on all branches.\n"
        "# Any branch push or fork PR kicks off the pipeline.\n"
        'resource "aws_codepipeline" "app" {\n'
        '  name          = "app-pipeline"\n'
        '  pipeline_type = "V2"\n'
        "  role_arn      = aws_iam_role.pipeline.arn\n"
        "  trigger {\n"
        "    git_configuration {\n"
        "      source_action_name = \"Source\"\n"
        "      pull_request {\n"
        "        events = [\"OPEN\", \"UPDATED\"]\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n"
        "\n"
        "# Safe: restrict the trigger to the main branch.\n"
        "# trigger {\n"
        "#   git_configuration {\n"
        "#     source_action_name = \"Source\"\n"
        "#     pull_request {\n"
        "#       events = [\"OPEN\", \"UPDATED\"]\n"
        "#       branches {\n"
        '#         includes = ["main"]\n'
        "#       }\n"
        "#     }\n"
        "#   }\n"
        "# }"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [
        f for f in _pbac005_cp005_cp007(ctx) if f.check_id == "CP-007"
    ]
