"""CP-007 (CloudFormation). V2 pipeline PR trigger accepts every branch."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..phase3 import _pbac005_cp005_cp007

RULE = Rule(
    id="CP-007",
    title="CodePipeline v2 PR trigger accepts all branches",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    cwe=("CWE-863",),
    recommendation=(
        "Set ``Triggers[*].GitConfiguration.PullRequest[*]."
        "Branches.Includes`` to the specific branches the pipeline "
        "expects. An empty include list runs on every branch event, "
        "including fork-PR rebases."
    ),
    docs_note=(
        "Inspects v2 pipelines (``PipelineType: V2``) whose "
        "``Triggers[*].GitConfiguration`` declares a "
        "``PullRequest`` block without ``Branches.Includes``."
    ),
    exploit_example=(
        "# Vulnerable: a CodePipeline v2 PR trigger with no\n"
        "# branch filter accepts PRs from any branch. A fork PR\n"
        "# triggers a build with the pipeline's full role.\n"
        "Resources:\n"
        "  Pipeline:\n"
        "    Type: AWS::CodePipeline::Pipeline\n"
        "    Properties:\n"
        "      PipelineType: V2\n"
        "      Triggers:\n"
        "        - ProviderType: CodeStarSourceConnection\n"
        "          GitConfiguration:\n"
        "            SourceActionName: SourceAction\n"
        "            PullRequest:\n"
        "              - Events: [OPEN, UPDATED]\n"
        "                # no Branches filter\n"
        "\n"
        "# Safe: filter PR triggers to a specific branch (the\n"
        "# release / hotfix branch).\n"
        "Resources:\n"
        "  Pipeline:\n"
        "    Type: AWS::CodePipeline::Pipeline\n"
        "    Properties:\n"
        "      PipelineType: V2\n"
        "      Triggers:\n"
        "        - ProviderType: CodeStarSourceConnection\n"
        "          GitConfiguration:\n"
        "            SourceActionName: SourceAction\n"
        "            PullRequest:\n"
        "              - Events: [OPEN, UPDATED]\n"
        "                Branches:\n"
        "                  Includes: [main]"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [
        f for f in _pbac005_cp005_cp007(ctx) if f.check_id == "CP-007"
    ]
