"""CP-004 — Legacy ThirdParty/GitHub (v1) source action, authenticated via OAuth token."""
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
