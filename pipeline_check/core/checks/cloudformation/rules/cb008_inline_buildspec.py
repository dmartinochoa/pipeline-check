"""CB-008 (CloudFormation). CodeBuild buildspec is inline (or from S3)."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..extended import _codebuild

RULE = Rule(
    id="CB-008",
    title="CodeBuild buildspec is inline (not sourced from a protected repo)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    cwe=("CWE-1357",),
    recommendation=(
        "Move buildspec content into a ``buildspec.yml`` inside the "
        "source repository, under branch protection. Reference it "
        "from ``Source.BuildSpec`` only by relative path."
    ),
    docs_note=(
        "Inspects ``AWS::CodeBuild::Project.Properties.Source.BuildSpec``. "
        "Flags multi-line literal values or values that begin with "
        "YAML preamble (``version:``, ``phases:``) — those indicate "
        "an inline spec that any principal with "
        "``codebuild:UpdateProject`` can rewrite without going "
        "through code review."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _codebuild(ctx) if f.check_id == "CB-008"]
