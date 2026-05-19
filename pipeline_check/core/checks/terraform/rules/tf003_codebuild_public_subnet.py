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
)


def check(ctx: TerraformContext) -> list[Finding]:
    return _tf003_codebuild_public_subnet(ctx)
