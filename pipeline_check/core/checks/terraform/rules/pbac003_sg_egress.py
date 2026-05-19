"""PBAC-003 (Terraform). CodeBuild SG allows 0.0.0.0/0 all-port egress."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..phase3 import _pbac003

RULE = Rule(
    id="PBAC-003",
    title="CodeBuild security group allows 0.0.0.0/0 all-port egress",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-5",),
    cwe=("CWE-1327",),
    recommendation=(
        "Scope egress to the specific destinations the build needs "
        "(package mirrors, AWS endpoints via VPC interface endpoints). "
        "Drop the catch-all ``egress { cidr_blocks = "
        "[\"0.0.0.0/0\"], from_port = 0, to_port = 0, protocol = "
        "\"-1\" }``."
    ),
    docs_note=(
        "Walks ``aws_security_group.egress[*]`` for every SG attached "
        "to a CodeBuild project's ``vpc_config``. Fires on any rule "
        "that allows ``0.0.0.0/0`` on the full port range — that's a "
        "completely open exfiltration channel."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return _pbac003(ctx)
