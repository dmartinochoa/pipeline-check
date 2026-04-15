"""Terraform PBAC checks (PBAC-001, PBAC-002)."""
from __future__ import annotations

from collections import defaultdict

from .base import TerraformBaseCheck
from ..base import Finding, Severity


def _first(block_list: list | None) -> dict:
    if not block_list:
        return {}
    return block_list[0] or {}


class PBACChecks(TerraformBaseCheck):

    def run(self) -> list[Finding]:
        projects = list(self.ctx.resources("aws_codebuild_project"))
        if not projects:
            return []

        # Build role-to-projects map for PBAC-002.
        role_map: dict[str, list[str]] = defaultdict(list)
        for r in projects:
            role = r.values.get("service_role", "")
            name = r.values.get("name") or r.name
            if role:
                role_map[role].append(name)

        findings: list[Finding] = []
        for r in sorted(projects, key=lambda x: x.values.get("name") or x.name):
            name = r.values.get("name") or r.name
            findings.append(_pbac001_vpc_config(r.values, name))
            findings.append(_pbac002_shared_role(r.values, name, role_map))
        return findings


def _pbac001_vpc_config(values: dict, name: str) -> Finding:
    vpc = _first(values.get("vpc_config"))
    has_vpc = bool(
        vpc.get("vpc_id")
        and vpc.get("subnets")
        and vpc.get("security_group_ids")
    )
    desc = (
        f"Project '{name}' runs inside VPC '{vpc.get('vpc_id')}', providing "
        f"network segmentation for build traffic."
        if has_vpc else
        f"Project '{name}' has no VPC configuration (or an incomplete one). "
        f"Build nodes run in AWS-managed infrastructure with unrestricted "
        f"outbound internet access."
    )
    return Finding(
        check_id="PBAC-001",
        title="CodeBuild project has no VPC configuration",
        severity=Severity.HIGH,
        resource=name,
        description=desc,
        recommendation=(
            "Configure a vpc_config block with vpc_id, subnets, and "
            "security_group_ids appropriate for your network segmentation needs."
        ),
        passed=has_vpc,
    )


def _pbac002_shared_role(values: dict, name: str, role_map: dict[str, list[str]]) -> Finding:
    role = values.get("service_role", "")
    sharing = role_map.get(role, []) if role else []
    passed = len(sharing) <= 1

    if passed:
        desc = f"Project '{name}' uses a dedicated service role."
    else:
        others = sorted(p for p in sharing if p != name)
        desc = (
            f"Project '{name}' shares service role '{role}' with "
            f"{len(others)} other project(s): {', '.join(others)}. "
            f"A compromised build can access the same resources as all others."
        )
    return Finding(
        check_id="PBAC-002",
        title="CodeBuild service role shared across multiple projects",
        severity=Severity.MEDIUM,
        resource=name,
        description=desc,
        recommendation=(
            "Create a dedicated IAM service role for each CodeBuild project, "
            "scoped to only the permissions it requires."
        ),
        passed=passed,
    )
