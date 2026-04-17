"""SM-001 — Secrets Manager secrets referenced by CI/CD have no rotation."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="SM-001",
    title="Secrets Manager secret has no rotation configured",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-798",),
    recommendation=(
        "Enable automatic rotation on every Secrets Manager secret referenced "
        "by a CodeBuild project or CodePipeline. Unrotated secrets persist "
        "indefinitely, so a single leak (e.g. a build log that echoed the "
        "value) compromises the secret for its full lifetime."
    ),
    docs_note=(
        "Only secrets actually referenced by CodeBuild are checked — secrets "
        "used purely by application workloads are out of scope for a CI/CD "
        "scanner."
    ),
)


def _referenced_secret_names(catalog: ResourceCatalog) -> set[str]:
    """Return the set of Secrets Manager secret IDs referenced by CodeBuild."""
    refs: set[str] = set()
    for project in catalog.codebuild_projects():
        env = project.get("environment") or {}
        for ev in env.get("environmentVariables", []):
            if ev.get("type") == "SECRETS_MANAGER":
                value = ev.get("value")
                if isinstance(value, str) and value:
                    # Strip any version/stage suffix for matching.
                    refs.add(value.split(":")[0] if value.startswith("arn:") else value)
    return refs


def check(catalog: ResourceCatalog) -> list[Finding]:
    referenced = _referenced_secret_names(catalog)
    if not referenced:
        return []
    findings: list[Finding] = []
    for secret in catalog.secrets():
        name = secret.get("Name", "")
        arn = secret.get("ARN", "")
        if not any(ref == name or ref == arn or ref in arn for ref in referenced):
            continue
        last_rotated = secret.get("LastRotatedDate")
        rotation = secret.get("RotationEnabled", False)
        passed = bool(rotation)
        if passed:
            desc = (
                f"Secret '{name}' has rotation enabled "
                f"(last rotated: {last_rotated or 'never'})."
            )
        else:
            desc = (
                f"Secret '{name}' is referenced by CodeBuild but has no "
                "rotation configured."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
