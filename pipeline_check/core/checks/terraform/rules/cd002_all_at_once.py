"""CD-002 (Terraform). CodeDeploy uses AllAtOnce, no canary or rolling."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..codedeploy import _cd002_all_at_once, _custom_all_at_once_config_names

RULE = Rule(
    id="CD-002",
    title="AllAtOnce deployment config, no canary or rolling strategy",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1",),
    cwe=("CWE-754",),
    recommendation=(
        "Switch ``deployment_config_name`` to a canary or linear "
        "config (e.g. ``CodeDeployDefault.LambdaCanary10Percent5Minutes``). "
        "A staged rollout gives alarm-based rollback a window to catch "
        "regressions before they hit 100% of traffic."
    ),
    docs_note=(
        "Reads ``aws_codedeploy_deployment_group.deployment_config_name``. "
        "Fires when the value is a managed all-at-once config "
        "(``CodeDeployDefault.AllAtOnce``, ``LambdaAllAtOnce``, "
        "``ECSAllAtOnce``) or a custom ``aws_codedeploy_deployment_config`` "
        "in the same plan that is semantically all-at-once "
        "(``minimum_healthy_hosts`` value 0, or a ``traffic_routing_config`` "
        "of type ``AllAtOnce``). These route every request to the new "
        "revision simultaneously, leaving no canary validation window."
    ),
    exploit_example=(
        "# Vulnerable: CodeDeploy group deploys to all instances\n"
        "# at once. A bad deployment takes down the entire fleet.\n"
        'resource "aws_codedeploy_deployment_group" "prod" {\n'
        "  deployment_config_name = \"CodeDeployDefault.AllAtOnce\"\n"
        "  app_name              = aws_codedeploy_app.app.name\n"
        '  deployment_group_name = "prod"\n'
        "}\n"
        "\n"
        "# Safe: use a rolling or blue/green strategy.\n"
        'resource "aws_codedeploy_deployment_group" "prod" {\n'
        "  deployment_config_name = \"CodeDeployDefault.OneAtATime\"\n"
        "  app_name              = aws_codedeploy_app.app.name\n"
        '  deployment_group_name = "prod"\n'
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    findings: list[Finding] = []
    custom_all_at_once = _custom_all_at_once_config_names(ctx)
    for r in ctx.resources("aws_codedeploy_deployment_group"):
        app = r.values.get("app_name", "")
        group = r.values.get("deployment_group_name", "") or r.name
        resource = f"{app}/{group}" if app else group
        findings.append(_cd002_all_at_once(r.values, resource, custom_all_at_once))
    return findings
