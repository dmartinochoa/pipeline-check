"""CB-006 (CloudFormation). CodeBuild source uses long-lived token."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext, as_str
from ..codebuild import _cb006_source_auth

RULE = Rule(
    id="CB-006",
    title="CodeBuild source auth uses long-lived token",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-798",),
    recommendation=(
        "Replace ``OAUTH`` / ``PERSONAL_ACCESS_TOKEN`` / "
        "``BASIC_AUTH`` with an AWS CodeConnections (CodeStar) "
        "connection. Tokens stored via "
        "``AWS::CodeBuild::SourceCredential`` or inline "
        "``Source.Auth`` don't rotate."
    ),
    docs_note=(
        "Reads ``Source.Type`` and ``Source.Auth.Type`` plus any "
        "``AWS::CodeBuild::SourceCredential.{ServerType,AuthType}`` "
        "side resource. Fires when an external VCS source "
        "(``GITHUB``, ``GITHUB_ENTERPRISE``, ``BITBUCKET``) is "
        "authenticated with a long-lived credential."
    ),
    exploit_example=(
        "# Vulnerable: CodeBuild source auth uses a stored long-\n"
        "# lived token (``OAUTH`` / ``PERSONAL_ACCESS_TOKEN`` /\n"
        "# ``BASIC_AUTH``). The credential never rotates and\n"
        "# isn't revocable from the AWS side.\n"
        "Resources:\n"
        "  Build:\n"
        "    Type: AWS::CodeBuild::Project\n"
        "    Properties:\n"
        "      Source:\n"
        "        Type: GITHUB\n"
        "        Location: https://github.com/myorg/myrepo.git\n"
        "        Auth:\n"
        "          Type: OAUTH   # long-lived stored token\n"
        "\n"
        "# Safe: use a CodeStar / CodeConnections ARN. The GitHub\n"
        "# user can revoke the connection without AWS-side\n"
        "# coordination; AWS refreshes the underlying token.\n"
        "Resources:\n"
        "  Build:\n"
        "    Type: AWS::CodeBuild::Project\n"
        "    Properties:\n"
        "      Source:\n"
        "        Type: GITHUB\n"
        "        Location: https://github.com/myorg/myrepo.git\n"
        "        Auth:\n"
        "          Type: CODECONNECTIONS\n"
        "          Resource: !Ref GitHubConnection"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    source_creds: dict[str, str] = {}
    for r in ctx.resources("AWS::CodeBuild::SourceCredential"):
        server = as_str(r.properties.get("ServerType"))
        auth = as_str(r.properties.get("AuthType"))
        if server and auth:
            source_creds[server] = auth
    return [
        _cb006_source_auth(r.properties, source_creds, r.address)
        for r in ctx.resources("AWS::CodeBuild::Project")
    ]
