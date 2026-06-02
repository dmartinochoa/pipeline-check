"""PBAC-003 (CloudFormation). CodeBuild SG allows 0.0.0.0/0 all-port egress."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..phase3 import _pbac003

RULE = Rule(
    id="PBAC-003",
    title="Security group allows 0.0.0.0/0 all-port egress",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-5",),
    cwe=("CWE-1327",),
    recommendation=(
        "Scope egress to the specific destinations the build needs. "
        "Drop the catch-all "
        "``SecurityGroupEgress: { CidrIp: 0.0.0.0/0, IpProtocol: -1 }``."
    ),
    docs_note=(
        "Walks ``AWS::EC2::SecurityGroup.Properties.SecurityGroupEgress`` "
        "for every ``AWS::EC2::SecurityGroup`` in the template (not only "
        "CodeBuild-attached ones). Fires on any rule that allows "
        "``0.0.0.0/0`` (or ``::/0``) on the full port range, a "
        "completely open exfiltration channel."
    ),
    exploit_example=(
        "# Vulnerable: the CodeBuild VPC security group allows all egress.\n"
        "Resources:\n"
        "  BuildSG:\n"
        "    Type: AWS::EC2::SecurityGroup\n"
        "    Properties:\n"
        "      SecurityGroupEgress:\n"
        "        - CidrIp: 0.0.0.0/0\n"
        "          IpProtocol: \"-1\"\n"
        "\n"
        "# Attack: the build runs inside the VPC but can open a\n"
        "# connection to any host on any port. A compromised build step\n"
        "# (malicious dependency, injected command) streams the source,\n"
        "# secrets, and assumed-role credentials out to an attacker\n"
        "# endpoint with no egress control to stop it.\n"
        "\n"
        "# Safe: scope egress to the destinations the build needs.\n"
        "      SecurityGroupEgress:\n"
        "        - CidrIp: 10.0.0.0/16\n"
        "          FromPort: 443\n"
        "          ToPort: 443\n"
        "          IpProtocol: tcp"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return _pbac003(ctx)
