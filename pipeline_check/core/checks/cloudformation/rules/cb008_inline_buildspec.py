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
    exploit_example=(
        "# Vulnerable: ``Source.BuildSpec`` is an inline JSON\n"
        "# string. Anyone with ``cloudformation:UpdateStack`` can\n"
        "# rewrite the build steps without code review on the\n"
        "# repo side.\n"
        "Resources:\n"
        "  Build:\n"
        "    Type: AWS::CodeBuild::Project\n"
        "    Properties:\n"
        "      Source:\n"
        "        Type: NO_SOURCE\n"
        "        BuildSpec: |\n"
        "          version: 0.2\n"
        "          phases:\n"
        "            build:\n"
        "              commands:\n"
        "                - inline; runs at will\n"
        "\n"
        "# Safe: source ``buildspec.yml`` from a protected repo.\n"
        "# Changes to the build go through PR review on the SCM\n"
        "# side; AWS-side ``UpdateStack`` no longer carries the\n"
        "# build's logic.\n"
        "Resources:\n"
        "  Build:\n"
        "    Type: AWS::CodeBuild::Project\n"
        "    Properties:\n"
        "      Source:\n"
        "        Type: GITHUB\n"
        "        Location: https://github.com/myorg/myrepo.git\n"
        "        BuildSpec: ci/buildspec.yml"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _codebuild(ctx) if f.check_id == "CB-008"]
