"""CB-005 (Terraform). Outdated AWS-managed CodeBuild image."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..codebuild import _cb005_image_version

RULE = Rule(
    id="CB-005",
    title="Outdated managed build image",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    cwe=("CWE-1104",),
    recommendation=(
        "Update ``environment[0].image`` to the latest "
        "``aws/codebuild/standard:<major>.0`` release. For custom or "
        "third-party images, pin by ``@sha256:<digest>`` instead of "
        "a mutable tag (see CB-009)."
    ),
    docs_note=(
        "Matches ``environment[0].image`` against "
        "``aws/codebuild/standard:<major>.<minor>``. Older managed "
        "images carry unpatched OS packages, runtimes, and build "
        "tools, every artifact they produce inherits those gaps."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [
        _cb005_image_version(r.values, r.address)
        for r in ctx.resources("aws_codebuild_project")
    ]
