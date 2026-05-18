"""CA-004 (Terraform). CodeArtifact repo policy grants codeartifact:*."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..services import _codeartifact

RULE = Rule(
    id="CA-004",
    title="CodeArtifact repo policy grants codeartifact:* with Resource '*'",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-269",),
    recommendation=(
        "Enumerate specific actions (``codeartifact:GetPackageVersion``, "
        "``codeartifact:DescribePackageVersion``) and resources "
        "(specific package ARNs) instead of "
        "``codeartifact:*`` with ``Resource = \"*\"``."
    ),
    docs_note=(
        "Parses "
        "``aws_codeartifact_repository_permissions_policy.policy_document``. "
        "Fires when an ``Allow`` statement pairs ``codeartifact:*`` "
        "(or ``*``) with ``Resource = \"*\"``. That combination lets "
        "the principal publish, delete, and rewrite every package "
        "version in the repo."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [f for f in _codeartifact(ctx) if f.check_id == "CA-004"]
