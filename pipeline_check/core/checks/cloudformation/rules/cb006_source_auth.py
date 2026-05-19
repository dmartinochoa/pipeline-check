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
