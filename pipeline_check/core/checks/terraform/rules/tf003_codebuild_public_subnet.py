"""TF-003 (Terraform-only). CodeBuild VPC subnet auto-assigns public IP."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..phase4 import _tf003_codebuild_public_subnet

RULE = Rule(
    id="TF-003",
    title="CodeBuild VPC config references a public subnet",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    cwe=("CWE-1327",),
    recommendation=(
        "Place CodeBuild projects in private subnets "
        "(``map_public_ip_on_launch = false``) with egress routed "
        "through a NAT gateway or VPC interface endpoints. Public "
        "subnets put the build host on a public IP for the duration "
        "of the build."
    ),
    docs_note=(
        "When ``aws_codebuild_project.vpc_config[0].vpc_id`` resolves "
        "to a concrete string, walks every ``aws_subnet`` in the same "
        "VPC and fires if any has ``map_public_ip_on_launch = true``. "
        "Silent when ``vpc_id`` is unresolved (``known after apply``)."
    ),
    exploit_example=(
        "# Vulnerable: ``map_public_ip_on_launch = true`` on the\n"
        "# subnet means CodeBuild containers get a public IP for the\n"
        "# duration of the build. The build host is now reachable\n"
        "# inbound from the internet (modulo the security group),\n"
        "# and outbound traffic uses that public IP rather than\n"
        "# being NATed. Build-time RCE escalates straight to a\n"
        "# direct internet-facing host.\n"
        "resource \"aws_subnet\" \"build\" {\n"
        "  vpc_id                  = aws_vpc.main.id\n"
        "  cidr_block              = \"10.0.1.0/24\"\n"
        "  map_public_ip_on_launch = true\n"
        "}\n"
        "\n"
        "resource \"aws_codebuild_project\" \"app\" {\n"
        "  name = \"app-build\"\n"
        "  vpc_config {\n"
        "    vpc_id             = aws_vpc.main.id\n"
        "    subnets            = [aws_subnet.build.id]\n"
        "    security_group_ids = [aws_security_group.build.id]\n"
        "  }\n"
        "  # ... source / artifacts / environment elided\n"
        "}\n"
        "\n"
        "# Safe: private subnet routed to a NAT for outbound egress.\n"
        "# No public IP on the build host; inbound from the internet\n"
        "# is impossible regardless of the security group. Build-\n"
        "# time RCE has to chain a separate primitive (kubelet, IMDS,\n"
        "# another in-VPC service) before reaching the internet.\n"
        "resource \"aws_subnet\" \"build\" {\n"
        "  vpc_id                  = aws_vpc.main.id\n"
        "  cidr_block              = \"10.0.10.0/24\"\n"
        "  map_public_ip_on_launch = false\n"
        "}\n"
        "\n"
        "resource \"aws_route_table_association\" \"build\" {\n"
        "  subnet_id      = aws_subnet.build.id\n"
        "  route_table_id = aws_route_table.private_nat.id\n"
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return _tf003_codebuild_public_subnet(ctx)
