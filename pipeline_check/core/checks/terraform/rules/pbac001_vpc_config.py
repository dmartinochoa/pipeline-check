"""PBAC-001 (Terraform). CodeBuild project has no VPC configuration."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..pbac import _pbac001_vpc_config

RULE = Rule(
    id="PBAC-001",
    title="CodeBuild project has no VPC configuration",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-5",),
    cwe=("CWE-1327",),
    recommendation=(
        "Set ``vpc_config { vpc_id = …, subnets = […], "
        "security_group_ids = […] }`` on every "
        "``aws_codebuild_project``. Use private subnets with egress "
        "scoped to the package mirrors and AWS endpoints the build "
        "actually needs."
    ),
    docs_note=(
        "Reads ``aws_codebuild_project.vpc_config[0]"
        ".{vpc_id,subnets,security_group_ids}``. All three must be "
        "set. Without VPC config, build nodes run in AWS-managed "
        "infrastructure with unrestricted outbound internet — every "
        "exfiltration path is open."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    findings: list[Finding] = []
    for r in sorted(
        ctx.resources("aws_codebuild_project"),
        key=lambda x: x.values.get("name") or x.name,
    ):
        name = r.values.get("name") or r.name
        findings.append(_pbac001_vpc_config(r.values, name))
    return findings
