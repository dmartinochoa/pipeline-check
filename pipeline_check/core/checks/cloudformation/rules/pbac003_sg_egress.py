"""PBAC-003 (CloudFormation). CodeBuild SG allows 0.0.0.0/0 all-port egress."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..phase3 import _pbac003

RULE = Rule(
    id="PBAC-003",
    title="CodeBuild security group allows 0.0.0.0/0 all-port egress",
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
        "for every SG attached to a CodeBuild project's "
        "``VpcConfig``. Fires on any rule that allows ``0.0.0.0/0`` "
        "on the full port range — that's a completely open "
        "exfiltration channel."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return _pbac003(ctx)
