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
    exploit_example=(
        "# Vulnerable: a CodeBuild project with no ``VpcConfig``.\n"
        "# Runs in AWS's shared VPC with unrestricted egress;\n"
        "# no VPC flow logs for incident response.\n"
        "Resources:\n"
        "  Build:\n"
        "    Type: AWS::CodeBuild::Project\n"
        "    Properties:\n"
        "      Environment: {...}\n"
        "      Source: {...}\n"
        "      # no VpcConfig\n"
        "\n"
        "# Safe: attach to an org-controlled VPC. Egress goes\n"
        "# via NAT + endpoints; VPC flow logs capture every\n"
        "# outbound packet.\n"
        "Resources:\n"
        "  Build:\n"
        "    Type: AWS::CodeBuild::Project\n"
        "    Properties:\n"
        "      VpcConfig:\n"
        "        VpcId: !Ref VPC\n"
        "        Subnets: [!Ref PrivateSubnetA, !Ref PrivateSubnetB]\n"
        "        SecurityGroupIds: [!Ref BuildSG]"
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
