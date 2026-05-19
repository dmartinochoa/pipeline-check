"""CB-002 (Terraform). CodeBuild privileged mode enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..codebuild import _cb002_privileged_mode

RULE = Rule(
    id="CB-002",
    title="Privileged mode enabled",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    cwe=("CWE-250",),
    recommendation=(
        "Disable ``environment[0].privileged_mode`` unless the project "
        "genuinely needs Docker-in-Docker. Where DinD is unavoidable, "
        "consider Kaniko or BuildKit's rootless mode and keep the "
        "buildspec under branch protection."
    ),
    docs_note=(
        "Reads ``aws_codebuild_project.environment[0].privileged_mode``. "
        "Privileged mode hands the build container root-level access to "
        "the Docker daemon on the host. A compromised build can escape "
        "the container, modify other in-flight builds on the same host, "
        "or steal credentials mounted on the instance."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [
        _cb002_privileged_mode(r.values, r.address)
        for r in ctx.resources("aws_codebuild_project")
    ]
