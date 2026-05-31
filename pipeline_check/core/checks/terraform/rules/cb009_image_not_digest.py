"""CB-009 (Terraform). CodeBuild image not pinned by digest."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..extended import _cb009

RULE = Rule(
    id="CB-009",
    title="CodeBuild image not pinned by digest",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    cwe=("CWE-1357",),
    recommendation=(
        "Pin ``environment[0].image`` by ``@sha256:<digest>`` rather "
        "than a mutable tag. AWS-managed ``aws/codebuild/standard:N`` "
        "images are exempted (AWS owns the rotation contract)."
    ),
    docs_note=(
        "Classifies ``environment[0].image`` using the same shared "
        "image classifier the GitLab / Jenkins / Azure DevOps "
        "providers use. Mutable tags let an upstream image swap "
        "execute on the next build with no plan change."
    ),
    exploit_example=(
        "# Vulnerable: the build image is pinned by a mutable tag.\n"
        "resource \"aws_codebuild_project\" \"ci\" {\n"
        "  environment {\n"
        "    image = \"acme/build-tools:3.4\"\n"
        "    # ...\n"
        "  }\n"
        "}\n"
        "\n"
        "# Attack: the tag `3.4` is mutable. Whoever controls that\n"
        "# registry repo (the publisher, or an attacker who compromises\n"
        "# the account) repoints `3.4` to a malicious image. The next\n"
        "# build pulls it with no Terraform plan change and runs the\n"
        "# whole build inside attacker-controlled tooling with the\n"
        "# project's IAM role.\n"
        "\n"
        "# Safe: pin the image to an immutable digest.\n"
        "    image = \"acme/build-tools@sha256:<digest>\""
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [
        _cb009(r.values, r.address)
        for r in ctx.resources("aws_codebuild_project")
    ]
