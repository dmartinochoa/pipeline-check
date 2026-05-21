"""CB-002 (CloudFormation). CodeBuild privileged mode enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..codebuild import _cb002_privileged_mode

RULE = Rule(
    id="CB-002",
    title="Privileged mode enabled",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    cwe=("CWE-250",),
    recommendation=(
        "Set ``Environment.PrivilegedMode: false`` (or omit it; the "
        "CFN default is ``false``). Where Docker-in-Docker is "
        "unavoidable, consider Kaniko or BuildKit and keep the "
        "buildspec under branch protection."
    ),
    docs_note=(
        "Reads ``AWS::CodeBuild::Project."
        "Properties.Environment.PrivilegedMode``. Privileged mode "
        "grants the build container root-level access to the Docker "
        "daemon on the host."
    ),
    exploit_example=(
        "# Vulnerable: ``PrivilegedMode: true`` on a CodeBuild\n"
        "# project gives the build container privileged Docker\n"
        "# access on the host. A poisoned buildspec gets root on\n"
        "# the host kernel; CodeBuild hosts are shared.\n"
        "Resources:\n"
        "  Build:\n"
        "    Type: AWS::CodeBuild::Project\n"
        "    Properties:\n"
        "      Environment:\n"
        "        Type: LINUX_CONTAINER\n"
        "        Image: aws/codebuild/standard:7.0\n"
        "        ComputeType: BUILD_GENERAL1_SMALL\n"
        "        PrivilegedMode: true\n"
        "\n"
        "# Safe: ``PrivilegedMode: false`` (default). For image\n"
        "# builds, use Kaniko inside the container so no host-\n"
        "# runtime access is needed.\n"
        "Resources:\n"
        "  Build:\n"
        "    Type: AWS::CodeBuild::Project\n"
        "    Properties:\n"
        "      Environment:\n"
        "        Type: LINUX_CONTAINER\n"
        "        Image: aws/codebuild/standard:7.0\n"
        "        ComputeType: BUILD_GENERAL1_SMALL\n"
        "        PrivilegedMode: false"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [
        _cb002_privileged_mode(r.properties, r.address)
        for r in ctx.resources("AWS::CodeBuild::Project")
    ]
