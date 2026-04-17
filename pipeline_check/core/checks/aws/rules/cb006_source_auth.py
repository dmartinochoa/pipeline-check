"""CB-006 — CodeBuild external source authenticates with a long-lived token."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

_LONG_LIVED_TOKEN_AUTH = {"OAUTH", "PERSONAL_ACCESS_TOKEN", "BASIC_AUTH"}
_EXTERNAL_SOURCE_TYPES = {"GITHUB", "GITHUB_ENTERPRISE", "BITBUCKET"}

# Map project source.type to the serverType values list_source_credentials returns.
_SOURCE_TYPE_TO_SERVER_TYPE = {
    "GITHUB": "GITHUB",
    "GITHUB_ENTERPRISE": "GITHUB_ENTERPRISE",
    "BITBUCKET": "BITBUCKET",
}

RULE = Rule(
    id="CB-006",
    title="CodeBuild source auth uses long-lived token",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-798",),
    recommendation=(
        "Switch to an AWS CodeConnections (CodeStar) connection and "
        "reference it from the source configuration. Delete any stored "
        "source credentials of type OAUTH, PERSONAL_ACCESS_TOKEN, or "
        "BASIC_AUTH via delete_source_credentials."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    source_creds = catalog.codebuild_source_credentials()
    for project in catalog.codebuild_projects():
        name = project.get("name", "<unnamed>")
        source = project.get("source", {}) or {}
        src_type = source.get("type", "") or ""
        if src_type not in _EXTERNAL_SOURCE_TYPES:
            findings.append(Finding(
                check_id=RULE.id, title=RULE.title, severity=RULE.severity,
                resource=name,
                description=(
                    f"Source type is {src_type or 'not external'}; check not applicable."
                ),
                recommendation="No action required.",
                passed=True,
            ))
            continue
        inline_auth = (source.get("auth") or {}).get("type", "")
        stored_auths = source_creds.get(
            _SOURCE_TYPE_TO_SERVER_TYPE.get(src_type, src_type), set(),
        )
        stored_offending = sorted(stored_auths & _LONG_LIVED_TOKEN_AUTH)
        inline_offending = inline_auth in _LONG_LIVED_TOKEN_AUTH
        passed = not (inline_offending or stored_offending)
        if passed:
            desc = f"Source ({src_type}) auth type is {inline_auth or 'not set'}."
        else:
            parts = []
            if inline_offending:
                parts.append(f"inline auth {inline_auth}")
            if stored_offending:
                parts.append(
                    f"account-level source credential(s) "
                    f"({', '.join(stored_offending)}) for {src_type}"
                )
            desc = (
                f"Source ({src_type}) authenticates via long-lived token(s): "
                f"{'; '.join(parts)}. These don't rotate and expose the pipeline "
                f"to credential theft."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
