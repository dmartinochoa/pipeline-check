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
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [
        f for f in _pbac005_cp005_cp007(ctx) if f.check_id == "CP-007"
    ]
