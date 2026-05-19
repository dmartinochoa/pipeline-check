"""PBAC-001 (CloudFormation). CodeBuild project has no VpcConfig."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext, as_str
from ..pbac import _pbac001_vpc_config

RULE = Rule(
    id="PBAC-001",
    title="CodeBuild project has no VPC configuration",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-5",),
    cwe=("CWE-1327",),
    recommendation=(
        "Set ``VpcConfig.VpcId``, ``VpcConfig.Subnets``, and "
        "``VpcConfig.SecurityGroupIds`` on every "
        "``AWS::CodeBuild::Project``. Use private subnets with "
        "egress scoped to the package mirrors and AWS endpoints the "
        "build actually needs."
    ),
    docs_note=(
        "Reads ``AWS::CodeBuild::Project."
        "Properties.VpcConfig.{VpcId,Subnets,SecurityGroupIds}``. "
        "All three must be set. Without VPC config, build nodes "
        "run in AWS-managed infrastructure with unrestricted "
        "outbound internet."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    findings: list[Finding] = []
    for r in sorted(
        ctx.resources("AWS::CodeBuild::Project"),
        key=lambda x: as_str(x.properties.get("Name")) or x.logical_id,
    ):
        name = as_str(r.properties.get("Name")) or r.logical_id
        findings.append(_pbac001_vpc_config(r.properties, name))
    return findings
