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
    exploit_example=(
        "# Vulnerable: the CodeBuild VPC security group allows all egress.\n"
        "resource \"aws_security_group\" \"build\" {\n"
        "  egress {\n"
        "    from_port   = 0\n"
        "    to_port     = 0\n"
        "    protocol    = \"-1\"\n"
        "    cidr_blocks = [\"0.0.0.0/0\"]\n"
        "  }\n"
        "}\n"
        "\n"
        "# Attack: the build runs inside the VPC but can open a\n"
        "# connection to any host on any port. A compromised build step\n"
        "# (malicious dependency, injected command) streams the source,\n"
        "# secrets, and assumed-role credentials out to an attacker\n"
        "# endpoint with no egress control to stop it.\n"
        "\n"
        "# Safe: scope egress to the destinations the build needs\n"
        "# (package mirrors, AWS endpoints via VPC interface endpoints).\n"
        "  egress {\n"
        "    from_port       = 443\n"
        "    to_port         = 443\n"
        "    protocol        = \"tcp\"\n"
        "    prefix_list_ids = [aws_vpc_endpoint.s3.prefix_list_id]\n"
        "  }"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return _pbac003(ctx)
