"""CP-004. Legacy ThirdParty/GitHub (v1) source action, authenticated via OAuth token."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CP-004",
    title="Legacy ThirdParty/GitHub source action (OAuth token)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-798",),
    recommendation=(
        "Migrate to owner=AWS, provider=CodeStarSourceConnection and "
        "reference a CodeConnections connection ARN."
    ),
    docs_note=(
        "The legacy ThirdParty/GitHub source-action provider stores a "
        "long-lived OAuth token in the pipeline's action "
        "configuration. The token has whatever scope the granting "
        "GitHub user has, never rotates, and isn't directly "
        "revocable from the AWS side. CodeConnections (formerly "
        "CodeStar Connections) replaces this with an AWS-managed "
        "connection that the GitHub user can revoke."
    ),
    exploit_example=(
        "# Vulnerable: a CodePipeline source action of type\n"
        "# ``ThirdParty`` / ``GitHub`` (v1). This is the legacy\n"
        "# integration that stores a long-lived OAuth token on\n"
        "# the action configuration. The token has whatever\n"
        "# scope the granting GitHub user had, never rotates,\n"
        "# and isn't directly revocable from the AWS side.\n"
        "import boto3\n"
        "cp = boto3.client('codepipeline')\n"
        "# Action shape (from get_pipeline):\n"
        "{\n"
        "    'actionTypeId': {\n"
        "        'category': 'Source',\n"
        "        'owner': 'ThirdParty',\n"
        "        'provider': 'GitHub',\n"
        "        'version': '1',\n"
        "    },\n"
        "    'configuration': {'OAuthToken': 'ghp_long_lived...'}\n"
        "}\n"
        "\n"
        "# Safe: migrate to ``owner: AWS`` with the\n"
        "# ``CodeStarSourceConnection`` provider. The action\n"
        "# references a CodeConnections (formerly CodeStar) ARN;\n"
        "# the GitHub user can revoke the connection, AWS\n"
        "# refreshes the underlying token, and the action\n"
        "# configuration no longer carries a long-lived secret.\n"
        "{\n"
        "    'actionTypeId': {\n"
        "        'category': 'Source',\n"
        "        'owner': 'AWS',\n"
        "        'provider': 'CodeStarSourceConnection',\n"
        "        'version': '1',\n"
        "    },\n"
        "    'configuration': {\n"
        "        'ConnectionArn': 'arn:aws:codestar-connections:us-east-1:123:connection/...',\n"
        "        'FullRepositoryId': 'myorg/myrepo',\n"
        "        'BranchName': 'main',\n"
        "    },\n"
        "}"
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for pipeline in catalog.codepipeline_pipelines():
        name = pipeline.get("name", "<unnamed>")
        legacy: list[str] = []
        for stage in pipeline.get("stages", []) or []:
            for action in stage.get("actions", []) or []:
                type_id = action.get("actionTypeId", {}) or {}
                if (
                    type_id.get("owner") == "ThirdParty"
                    and type_id.get("provider") == "GitHub"
                ):
                    legacy.append(action.get("name", "unnamed"))
        passed = not legacy
        desc = (
            "No legacy ThirdParty/GitHub (v1) source actions detected."
            if passed else
            f"Source action(s) {legacy} use the deprecated ThirdParty/GitHub v1 "
            f"provider, which authenticates via a long-lived OAuth token."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
