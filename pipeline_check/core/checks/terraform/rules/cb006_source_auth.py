"""CB-006 (Terraform). CodeBuild source auth uses long-lived token."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..codebuild import _cb006_source_auth

RULE = Rule(
    id="CB-006",
    title="CodeBuild source auth uses long-lived token",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-798",),
    recommendation=(
        "Replace ``OAUTH`` / ``PERSONAL_ACCESS_TOKEN`` / ``BASIC_AUTH`` "
        "with an AWS CodeConnections (CodeStar) connection and "
        "reference it from ``source.location``. Tokens stored via "
        "``aws_codebuild_source_credential`` or inline ``source.auth`` "
        "don't rotate and survive the engineer who created them."
    ),
    docs_note=(
        "Reads ``source[0].{type,auth[0].type}`` plus any "
        "``aws_codebuild_source_credential.{server_type,auth_type}`` "
        "side resource. Fires when an external VCS source "
        "(``GITHUB``, ``GITHUB_ENTERPRISE``, ``BITBUCKET``) is "
        "authenticated with a long-lived OAuth/PAT/BASIC_AUTH credential."
    ),
    exploit_example=(
        "# Vulnerable: source auth uses PERSONAL_ACCESS_TOKEN\n"
        "# stored in the project config. The token is visible\n"
        "# in the Terraform state and CloudTrail.\n"
        'resource "aws_codebuild_project" "ci" {\n'
        "  source {\n"
        '    type      = "GITHUB"\n'
        '    location  = "https://github.com/org/repo.git"\n'
        '    auth {\n'
        '      type     = "PERSONAL_ACCESS_TOKEN"\n'
        '      resource = "ghp_exampletoken123"\n'
        "    }\n"
        "  }\n"
        "}\n"
        "\n"
        "# Safe: use a CodeStar connection (OAuth) instead.\n"
        'resource "aws_codebuild_source_credential" "github" {\n'
        '  auth_type   = "CODECONNECTIONS"\n'
        '  server_type = "GITHUB"\n'
        '  token       = "arn:aws:codeconnections:us-east-1:123:connection/abc"\n'
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    source_creds: dict[str, str] = {}
    for r in ctx.resources("aws_codebuild_source_credential"):
        server = r.values.get("server_type", "")
        auth = r.values.get("auth_type", "")
        if server and auth:
            source_creds[server] = auth
    return [
        _cb006_source_auth(r.values, source_creds, r.address)
        for r in ctx.resources("aws_codebuild_project")
    ]
