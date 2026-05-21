"""PBAC-001. CodeBuild project has no VPC configuration."""
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
    docs_note=(
        "A CodeBuild project with no VPC configuration runs in "
        "AWS-managed network space, egress to the public internet "
        "is unrestricted, every package registry / CDN / arbitrary "
        "endpoint is reachable. Inside a VPC, security-group + "
        "VPC-endpoint policies become the egress gate, which is the "
        "only practical way to limit a compromised build's "
        "exfiltration paths."
    ),
    exploit_example=(
        "# Vulnerable: a CodeBuild project with no VPC config.\n"
        "# The build container runs in AWS's shared VPC with\n"
        "# unrestricted outbound internet — exactly the egress\n"
        "# path a compromised build uses to exfiltrate secrets\n"
        "# or pull a second-stage payload. No VPC flow logs to\n"
        "# correlate either.\n"
        "import boto3\n"
        "cb = boto3.client('codebuild')\n"
        "cb.create_project(\n"
        "    name='my-build',\n"
        "    # no vpcConfig — runs in AWS's shared VPC\n"
        "    environment={...},\n"
        "    source={...},\n"
        ")\n"
        "\n"
        "# Safe: attach the project to an org-controlled VPC.\n"
        "# Egress goes through a NAT + VPC endpoints + (optional)\n"
        "# egress firewall; VPC flow logs capture every outbound\n"
        "# packet for incident response.\n"
        "cb.update_project(\n"
        "    name='my-build',\n"
        "    vpcConfig={\n"
        "        'vpcId': 'vpc-abc123',\n"
        "        'subnets': ['subnet-private-1', 'subnet-private-2'],\n"
        "        'securityGroupIds': ['sg-codebuild-egress'],\n"
        "    },\n"
        ")"
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for project in sorted(catalog.codebuild_projects(), key=lambda p: p.get("name", "")):
        name = project.get("name", "<unnamed>")
        vpc_cfg = project.get("vpcConfig", {}) or {}
        # Require all three fields so a stub vpcConfig with empty subnets
        # doesn't pass. Real AWS rejects incomplete VPC configs at creation
        # time, but defense-in-depth is cheap here.
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
