"""CA-004 (CloudFormation). CodeArtifact repo policy grants codeartifact:*."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..services import _codeartifact

RULE = Rule(
    id="CA-004",
    title="CodeArtifact repo policy grants codeartifact:* with Resource '*'",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-269",),
    recommendation=(
        "Enumerate specific actions and resources instead of "
        "``codeartifact:*`` with ``Resource: \"*\"``."
    ),
    docs_note=(
        "Parses ``AWS::CodeArtifact::Repository."
        "Properties.PermissionsPolicyDocument``. Fires when an "
        "``Allow`` statement pairs ``codeartifact:*`` (or ``*``) "
        "with ``Resource: \"*\"``. That combination lets the "
        "principal publish, delete, and rewrite every package "
        "version in the repo."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _codeartifact(ctx) if f.check_id == "CA-004"]
