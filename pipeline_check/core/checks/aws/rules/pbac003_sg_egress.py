"""PBAC-003 — CodeBuild security group allows 0.0.0.0/0 all-port egress."""
from __future__ import annotations

from botocore.exceptions import ClientError

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="PBAC-003",
    title="CodeBuild security group allows 0.0.0.0/0 all-port egress",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-5",),
    cwe=("CWE-862",),
    recommendation=(
        "Restrict CodeBuild security-group egress to the specific "
        "endpoints builds need (package registries, artifact repositories, "
        "STS). A wildcard egress rule lets a compromised build exfiltrate "
        "to anywhere on the internet."
    ),
)


def _open_egress(perms: list[dict]) -> bool:
    for perm in perms:
        ranges = perm.get("IpRanges") or []
        proto = perm.get("IpProtocol")
        if any(r.get("CidrIp") == "0.0.0.0/0" for r in ranges):
            # All-protocol OR all-ports egress.
            if proto in (-1, "-1") or (
                perm.get("FromPort") in (0, None) and perm.get("ToPort") in (65535, None)
            ):
                return True
    return False


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    sg_ids: set[str] = set()
    for project in catalog.codebuild_projects():
        for sg in (project.get("vpcConfig") or {}).get("securityGroupIds") or []:
            sg_ids.add(sg)
    if not sg_ids:
        return []
    try:
        client = catalog.client("ec2")
        groups = client.describe_security_groups(GroupIds=list(sg_ids)).get("SecurityGroups", [])
    except ClientError:
        return []
    for sg in groups:
        if _open_egress(sg.get("IpPermissionsEgress", [])):
            findings.append(Finding(
                check_id=RULE.id, title=RULE.title, severity=RULE.severity,
                resource=sg.get("GroupId", "<unknown>"),
                description=(
                    f"Security group {sg.get('GroupId')} has an egress rule "
                    "allowing 0.0.0.0/0 on all ports."
                ),
                recommendation=RULE.recommendation, passed=False,
            ))
    return findings
