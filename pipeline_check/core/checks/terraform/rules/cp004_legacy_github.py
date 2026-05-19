"""CP-004 (Terraform). Pipeline uses legacy ThirdParty/GitHub source."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..codepipeline import _cp004_legacy_github

RULE = Rule(
    id="CP-004",
    title="Legacy ThirdParty/GitHub source action (OAuth token)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-798",),
    recommendation=(
        "Migrate the source action to "
        "``owner = \"AWS\", provider = \"CodeStarSourceConnection\"`` and "
        "point ``configuration.ConnectionArn`` at an "
        "``aws_codestarconnections_connection``. The connection brokers "
        "short-lived OIDC credentials in place of the embedded OAuth "
        "token."
    ),
    docs_note=(
        "Fires on any ``stage[*].action[*]`` with "
        "``category = \"Source\"``, ``owner = \"ThirdParty\"``, "
        "``provider = \"GitHub\"``. The v1 GitHub action authenticates "
        "with a long-lived OAuth token literally stored in the pipeline "
        "configuration, anyone with ``codepipeline:GetPipeline`` reads "
        "it."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    findings: list[Finding] = []
    for r in ctx.resources("aws_codepipeline"):
        name = r.values.get("name") or r.name
        stages = r.values.get("stage", []) or []
        findings.append(_cp004_legacy_github(stages, name))
    return findings
