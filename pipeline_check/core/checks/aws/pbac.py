"""Pipeline-Based Access Control (PBAC) checks.

PBAC-001  CodeBuild project has no VPC configuration          HIGH    CICD-SEC-5
PBAC-002  CodeBuild service role is shared across projects     MEDIUM  CICD-SEC-5
"""

from collections import defaultdict

from botocore.exceptions import ClientError

from .base import AWSBaseCheck, Finding, Severity


class PBACChecks(AWSBaseCheck):
    """Runs PBAC-XXX checks across every CodeBuild project in the region."""

    def run(self) -> list[Finding]:
        client = self.client("codebuild")

        try:
            project_names = self._list_projects(client)
        except ClientError as exc:
            return [Finding(
                check_id="PBAC-000",
                title="CodeBuild API access failed (PBAC)",
                severity=Severity.INFO,
                resource="codebuild",
                description=(
                    f"Could not list CodeBuild projects: {exc}. "
                    "PBAC checks were skipped."
                ),
                recommendation=(
                    "Ensure the IAM principal has codebuild:ListProjects and "
                    "codebuild:BatchGetProjects permissions."
                ),
                passed=False,
            )]

        if not project_names:
            return []

        projects: list[dict] = []
        for i in range(0, len(project_names), 100):
            batch = project_names[i : i + 100]
            try:
                response = client.batch_get_projects(names=batch)
                projects.extend(response.get("projects", []))
            except ClientError:
                continue

        if not projects:
            return []

        findings: list[Finding] = []
        findings.extend(self._pbac001_vpc_config(projects))
        findings.extend(self._pbac002_shared_service_role(projects))
        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _list_projects(client) -> list[str]:
        names: list[str] = []
        paginator = client.get_paginator("list_projects")
        for page in paginator.paginate():
            names.extend(page.get("projects", []))
        return names

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    @staticmethod
    def _pbac001_vpc_config(projects: list[dict]) -> list[Finding]:
        """Each build project should run inside a VPC for network segmentation."""
        findings: list[Finding] = []
        for project in sorted(projects, key=lambda p: p["name"]):
            name: str = project["name"]
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
                check_id="PBAC-001",
                title="CodeBuild project has no VPC configuration",
                severity=Severity.HIGH,
                resource=name,
                description=desc,
                recommendation=(
                    "Configure the CodeBuild project to run inside a VPC with "
                    "appropriate subnets and security groups. Use a NAT gateway or "
                    "VPC endpoints to control outbound internet access and restrict "
                    "build nodes to only the network resources they require."
                ),
                passed=has_vpc,
            ))

        return findings

    @staticmethod
    def _pbac002_shared_service_role(projects: list[dict]) -> list[Finding]:
        """Multiple projects sharing one service role widens the blast radius of a compromise."""
        role_to_projects: dict[str, list[str]] = defaultdict(list)
        for project in projects:
            role_arn = project.get("serviceRole", "")
            if role_arn:
                role_to_projects[role_arn].append(project["name"])

        findings: list[Finding] = []
        for project in sorted(projects, key=lambda p: p["name"]):
            name: str = project["name"]
            role_arn = project.get("serviceRole", "")
            if not role_arn:
                continue

            sharing = role_to_projects[role_arn]
            passed = len(sharing) <= 1

            if passed:
                desc = f"Project '{name}' uses a dedicated service role."
            else:
                others = sorted(p for p in sharing if p != name)
                others_str = ", ".join(others)
                desc = (
                    f"Project '{name}' shares service role '{role_arn}' with "
                    f"{len(others)} other project(s): {others_str}. "
                    f"A compromised build in any of these projects can access "
                    f"the same secrets, S3 buckets, and AWS resources as all others "
                    f"using the same role."
                )

            findings.append(Finding(
                check_id="PBAC-002",
                title="CodeBuild service role shared across multiple projects",
                severity=Severity.MEDIUM,
                resource=name,
                description=desc,
                recommendation=(
                    "Create a dedicated IAM service role for each CodeBuild project, "
                    "scoped to only the permissions that specific project requires. "
                    "This limits the blast radius if one project's build is compromised."
                ),
                passed=passed,
            ))

        return findings
