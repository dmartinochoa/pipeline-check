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
    exploit_example=(
        "# Vulnerable: buildspec is inline in the Terraform config.\n"
        "# Anyone with write access to the Terraform state can\n"
        "# inject commands without a code review.\n"
        'resource "aws_codebuild_project" "ci" {\n'
        "  source {\n"
        '    type      = "NO_SOURCE"\n'
        "    buildspec = <<-SPEC\n"
        "      version: 0.2\n"
        "      phases:\n"
        "        build:\n"
        "          commands:\n"
        "            - make all\n"
        "    SPEC\n"
        "  }\n"
        "}\n"
        "\n"
        "# Safe: source the buildspec from the repo.\n"
        'resource "aws_codebuild_project" "ci" {\n'
        "  source {\n"
        '    type     = "GITHUB"\n'
        '    location = "https://github.com/org/repo.git"\n'
        "  }\n"
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [
        _cb008(r.values, r.address)
        for r in ctx.resources("aws_codebuild_project")
    ]
