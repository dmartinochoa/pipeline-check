"""PBAC-002 (CloudFormation). CodeBuild ServiceRole shared across projects."""
from __future__ import annotations

from collections import defaultdict

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext, as_str
from ..pbac import _pbac002_shared_role, _service_role_key

RULE = Rule(
    id="PBAC-002",
    title="CodeBuild service role shared across multiple projects",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-5",),
    cwe=("CWE-269",),
    recommendation=(
        "Create one ``AWS::IAM::Role`` per "
        "``AWS::CodeBuild::Project`` and reference it via "
        "``ServiceRole``. Per-project roles cap the blast radius of "
        "a hijacked build."
    ),
    docs_note=(
        "Counts ``AWS::CodeBuild::Project.ServiceRole`` collisions "
        "(``Ref`` / ``Fn::GetAtt`` references are resolved to the "
        "target logical id so identical-target references coalesce). "
        "When two or more projects point at the same role, a build "
        "compromise in any one inherits the others' permissions."
    ),
    exploit_example=(
        "# Vulnerable: two CodeBuild projects share one ServiceRole.\n"
        "Resources:\n"
        "  ApiProject:\n"
        "    Type: AWS::CodeBuild::Project\n"
        "    Properties:\n"
        "      Name: api\n"
        "      ServiceRole: !Ref SharedRole\n"
        "  InfraProject:\n"
        "    Type: AWS::CodeBuild::Project\n"
        "    Properties:\n"
        "      Name: infra\n"
        "      ServiceRole: !Ref SharedRole\n"
        "\n"
        "# Attack: the shared role is the union of what every project\n"
        "# needs (api's S3 + secrets, infra's deploy permissions). A\n"
        "# build compromise in ApiProject (a malicious dependency, an\n"
        "# injected buildspec command) assumes the shared role and now\n"
        "# wields infra's deploy permissions too, so a low-value project\n"
        "# becomes the pivot into the high-value one.\n"
        "\n"
        "# Safe: one least-privilege role per project caps the blast\n"
        "# radius to that project's own resources.\n"
        "  ApiProject:\n"
        "    Properties:\n"
        "      ServiceRole: !Ref ApiRole\n"
        "  InfraProject:\n"
        "    Properties:\n"
        "      ServiceRole: !Ref InfraRole"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    projects = list(ctx.resources("AWS::CodeBuild::Project"))
    role_map: dict[str, list[str]] = defaultdict(list)
    for r in projects:
        name = as_str(r.properties.get("Name")) or r.logical_id
        key = _service_role_key(r.properties.get("ServiceRole"))
        if key:
            role_map[key].append(name)
    findings: list[Finding] = []
    for r in sorted(
        projects, key=lambda x: as_str(x.properties.get("Name")) or x.logical_id,
    ):
        name = as_str(r.properties.get("Name")) or r.logical_id
        findings.append(_pbac002_shared_role(r.properties, name, role_map))
    return findings
