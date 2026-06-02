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
    exploit_example=(
        "# Vulnerable: the CodeBuild project's VpcConfig points\n"
        "# at a subnet whose ``MapPublicIpOnLaunch: true``. The\n"
        "# build host gets a public IP for the duration of the\n"
        "# build; outbound traffic doesn't go through NAT, and\n"
        "# the host is reachable inbound (modulo SG rules).\n"
        "Resources:\n"
        "  Subnet:\n"
        "    Type: AWS::EC2::Subnet\n"
        "    Properties:\n"
        "      VpcId: vpc-0abc1234567890000\n"
        "      CidrBlock: 10.0.1.0/24\n"
        "      MapPublicIpOnLaunch: true\n"
        "  Build:\n"
        "    Type: AWS::CodeBuild::Project\n"
        "    Properties:\n"
        "      VpcConfig:\n"
        "        VpcId: vpc-0abc1234567890000\n"
        "        Subnets: [!Ref Subnet]\n"
        "        SecurityGroupIds: [sg-00000000000000001]\n"
        "\n"
        "# Safe: route the project through a private subnet.\n"
        "# Egress goes via a NAT gateway; no public IP on the\n"
        "# build host.\n"
        "Resources:\n"
        "  PrivateSubnet:\n"
        "    Type: AWS::EC2::Subnet\n"
        "    Properties:\n"
        "      VpcId: vpc-0abc1234567890000\n"
        "      CidrBlock: 10.0.10.0/24\n"
        "      MapPublicIpOnLaunch: false\n"
        "  Build:\n"
        "    Type: AWS::CodeBuild::Project\n"
        "    Properties:\n"
        "      VpcConfig:\n"
        "        VpcId: vpc-0abc1234567890000\n"
        "        Subnets: [!Ref PrivateSubnet]\n"
        "        SecurityGroupIds: [sg-00000000000000001]"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return _cf003_codebuild_public_subnet(ctx)
