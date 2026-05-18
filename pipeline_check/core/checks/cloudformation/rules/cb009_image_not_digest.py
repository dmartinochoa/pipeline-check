"""CB-009 (CloudFormation). CodeBuild image not pinned by digest."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..extended import _codebuild

RULE = Rule(
    id="CB-009",
    title="CodeBuild image not pinned by digest",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    cwe=("CWE-1357",),
    recommendation=(
        "Pin ``Environment.Image`` by ``@sha256:<digest>`` rather "
        "than a mutable tag. AWS-managed "
        "``aws/codebuild/standard:N`` images are exempted."
    ),
    docs_note=(
        "Classifies ``Environment.Image`` using the same shared "
        "image classifier the workflow providers use. Mutable tags "
        "let an upstream image swap execute on the next build with "
        "no template change."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _codebuild(ctx) if f.check_id == "CB-009"]
