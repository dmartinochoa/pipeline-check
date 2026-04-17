"""CB-002 — CodeBuild project runs with Docker privileged mode."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CB-002",
    title="Privileged mode enabled",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    cwe=("CWE-269",),
    recommendation=(
        "Disable privileged mode unless the project explicitly requires "
        "Docker-in-Docker builds. If required, ensure the buildspec is "
        "tightly controlled, peer-reviewed, and sourced from a trusted "
        "repository with branch protection."
    ),
    docs_note=(
        "Privileged mode grants the build container root access to the "
        "host's Docker daemon. A compromised build can escape the "
        "container or tamper with the host. Only flip this on for real "
        "Docker-in-Docker workloads and keep the buildspec under "
        "branch-protected review."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for project in catalog.codebuild_projects():
        name = project.get("name", "<unnamed>")
        privileged = project.get("environment", {}).get("privilegedMode", False)
        if not privileged:
            desc = "Privileged mode is not enabled on this project."
        else:
            desc = (
                "Privileged mode is enabled. This grants the build container "
                "root-level access to the Docker daemon on the host, which is only "
                "necessary for Docker-in-Docker builds. A compromised build could "
                "escape the container or tamper with the host."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=not privileged,
        ))
    return findings
