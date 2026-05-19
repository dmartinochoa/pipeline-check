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
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [
        _cb002_privileged_mode(r.properties, r.address)
        for r in ctx.resources("AWS::CodeBuild::Project")
    ]
