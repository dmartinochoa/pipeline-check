"""CloudFormation PBAC checks — PBAC-001 (VPC), PBAC-002 (shared role)."""
from __future__ import annotations

from collections import defaultdict

from ..base import Finding, Severity
from .base import CloudFormationBaseCheck, as_str


def _service_role_key(value) -> str:
    """Return a stable key for a ServiceRole value.

    CFN accepts literal ARNs, ``{"Ref": "X"}``, ``{"Fn::GetAtt":
    ["X", "Arn"]}``. Dereference Ref/GetAtt to the logical id so
    two projects pointing at the same role resource coalesce.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        if "Ref" in value:
            return f"ref:{value['Ref']}"
        if "Fn::GetAtt" in value:
            att = value["Fn::GetAtt"]
            if isinstance(att, list) and att:
                return f"ref:{att[0]}"
            if isinstance(att, str):
                return f"ref:{att.split('.', 1)[0]}"
    return ""


class PBACChecks(CloudFormationBaseCheck):

    def run(self) -> list[Finding]:
        projects = list(self.ctx.resources("AWS::CodeBuild::Project"))
        if not projects:
            return []

        role_map: dict[str, list[str]] = defaultdict(list)
        for r in projects:
            name = as_str(r.properties.get("Name")) or r.logical_id
            key = _service_role_key(r.properties.get("ServiceRole"))
            if key:
                role_map[key].append(name)

        findings: list[Finding] = []
        for r in sorted(projects, key=lambda x: as_str(x.properties.get("Name")) or x.logical_id):
            name = as_str(r.properties.get("Name")) or r.logical_id
            findings.append(_pbac001_vpc_config(r.properties, name))
            findings.append(_pbac002_shared_role(r.properties, name, role_map))
        return findings


def _pbac001_vpc_config(properties: dict, name: str) -> Finding:
    vpc = properties.get("VpcConfig") or {}
    has_vpc = bool(
        vpc.get("VpcId")
        and vpc.get("Subnets")
        and vpc.get("SecurityGroupIds")
    )
    desc = (
        f"Project '{name}' has a VpcConfig ({vpc.get('VpcId')})."
        if has_vpc else
        f"Project '{name}' has no VpcConfig (or an incomplete one). "
        "Build nodes run in AWS-managed infrastructure with unrestricted egress."
    )
    return Finding(
        check_id="PBAC-001",
        title="CodeBuild project has no VPC configuration",
        severity=Severity.HIGH,
        resource=name,
        description=desc,
        recommendation=(
            "Set VpcConfig with VpcId, Subnets, and SecurityGroupIds appropriate "
            "for your network segmentation needs."
        ),
        passed=has_vpc,
    )


def _pbac002_shared_role(
    properties: dict, name: str, role_map: dict[str, list[str]],
) -> Finding:
    key = _service_role_key(properties.get("ServiceRole"))
    sharing = role_map.get(key, []) if key else []
    passed = len(sharing) <= 1
    if passed:
        desc = f"Project '{name}' uses a dedicated ServiceRole."
    else:
        others = sorted(p for p in sharing if p != name)
        desc = (
            f"Project '{name}' shares ServiceRole '{key}' with "
            f"{len(others)} other project(s): {', '.join(others)}."
        )
    return Finding(
        check_id="PBAC-002",
        title="CodeBuild service role shared across multiple projects",
        severity=Severity.MEDIUM,
        resource=name,
        description=desc,
        recommendation="Create a dedicated IAM service role for each CodeBuild project.",
        passed=passed,
    )
