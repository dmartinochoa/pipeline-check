"""CB-004. CodeBuild project runs at the AWS maximum (480 min) timeout."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

# Projects with a timeout at or above this are considered unconstrained.
_MAX_SENSIBLE_TIMEOUT = 480  # minutes (AWS maximum)

RULE = Rule(
    id="CB-004",
    title="Build timeout missing or at the AWS maximum (480 min)",
    severity=Severity.LOW,
    owasp=("CICD-SEC-7",),
    cwe=("CWE-400",),
    recommendation=(
        "Set a build timeout appropriate for your expected build duration "
        "(typically 15\u201360 minutes) to limit the blast radius of a runaway "
        "or abused build."
    ),
    docs_note=(
        "A CodeBuild project at AWS's 480-minute maximum is rarely "
        "deliberate. Without a tighter ceiling, a runaway test loop, "
        "a fork-PR cryptomining payload, or a build that hangs on "
        "stdin keeps the build host (and its IAM role) live for the "
        "full eight hours, racking up cost and extending the "
        "compromise window."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for project in catalog.codebuild_projects():
        name = project.get("name", "<unnamed>")
        timeout = project.get("timeoutInMinutes")
        # Flag if timeout is at the AWS maximum (480 min), which suggests the
        # operator accepted the ceiling without setting a tighter bound.
        passed = timeout is not None and timeout < _MAX_SENSIBLE_TIMEOUT
        if passed:
            desc = f"Build timeout is set to {timeout} minutes."
        else:
            t_str = str(timeout) if timeout is not None else "default"
            desc = (
                f"Build timeout is {t_str} minutes (AWS maximum). Runaway or "
                f"abused builds can drive up costs and delay detection of a "
                f"compromised pipeline."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
