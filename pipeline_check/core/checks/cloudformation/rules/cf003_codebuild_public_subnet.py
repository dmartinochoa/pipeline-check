"""CF-003 (CloudFormation-only). CodeBuild VPC config references public subnet."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..phase4 import _cf003_codebuild_public_subnet

RULE = Rule(
    id="CF-003",
    title="CodeBuild VPC config references a public subnet",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    cwe=("CWE-1327",),
    recommendation=(
        "Place CodeBuild projects in private subnets "
        "(``MapPublicIpOnLaunch: false``) with egress routed "
        "through a NAT gateway or VPC interface endpoints. Public "
        "subnets put the build host on a public IP for the "
        "duration of the build."
    ),
    docs_note=(
        "When ``AWS::CodeBuild::Project.Properties.VpcConfig.VpcId`` "
        "resolves to a concrete reference, walks every "
        "``AWS::EC2::Subnet`` in the same VPC and fires if any has "
        "``MapPublicIpOnLaunch: true``."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return _cf003_codebuild_public_subnet(ctx)
