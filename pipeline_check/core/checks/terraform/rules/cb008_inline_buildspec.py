"""CB-008 (Terraform). CodeBuild buildspec is inline (or from S3)."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..extended import _cb008

RULE = Rule(
    id="CB-008",
    title="CodeBuild buildspec is inline (not sourced from a protected repo)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    cwe=("CWE-1357",),
    recommendation=(
        "Move buildspec content into a ``buildspec.yml`` (or similar) "
        "inside the source repository, under branch protection. "
        "Reference it from ``source.buildspec`` only by relative path."
    ),
    docs_note=(
        "Inspects ``aws_codebuild_project.source[0].buildspec``. Flags "
        "multi-line literal values or values that begin with YAML "
        "preamble (``version:``, ``phases:``) — those indicate an "
        "inline spec that any principal with "
        "``codebuild:UpdateProject`` can rewrite without going through "
        "code review."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [
        _cb008(r.values, r.address)
        for r in ctx.resources("aws_codebuild_project")
    ]
