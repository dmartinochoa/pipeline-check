"""PBAC-001 — CodeBuild project has no VPC configuration."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="PBAC-001",
    title="CodeBuild project has no VPC configuration",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-5",),
    cwe=("CWE-284",),
    recommendation=(
        "Configure the CodeBuild project to run inside a VPC with "
        "appropriate subnets and security groups. Use a NAT gateway or "
        "VPC endpoints to control outbound internet access and restrict "
        "build nodes to only the network resources they require."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for project in sorted(catalog.codebuild_projects(), key=lambda p: p.get("name", "")):
        name = project.get("name", "<unnamed>")
        vpc_cfg = project.get("vpcConfig", {}) or {}
        # Require all three fields so a stub vpcConfig with empty subnets
        # doesn't pass. Real AWS rejects incomplete VPC configs at creation
        # time, but defence-in-depth is cheap here.
        has_vpc = bool(
            vpc_cfg.get("vpcId")
            and vpc_cfg.get("subnets")
            and vpc_cfg.get("securityGroupIds")
        )
        if has_vpc:
            desc = (
                f"Project '{name}' runs inside VPC '{vpc_cfg['vpcId']}', "
                f"providing network segmentation for build traffic."
            )
        else:
            desc = (
                f"Project '{name}' has no VPC configuration (or an incomplete "
                f"one). Build nodes run in AWS-managed infrastructure with "
                f"unrestricted outbound internet access. A compromised build "
                f"can exfiltrate secrets or reach internal services without "
                f"network controls."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=has_vpc,
        ))
    return findings
