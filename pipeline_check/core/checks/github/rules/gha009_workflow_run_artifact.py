"""GHA-009 — workflow_run must verify artifacts before consumption."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, workflow_triggers

RULE = Rule(
    id="GHA-009",
    title="workflow_run downloads upstream artifact unverified",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-494",),
    recommendation=(
        "Add a verification step BEFORE consuming the artifact: "
        "`cosign verify-attestation --type slsaprovenance ...`, "
        "`gh attestation verify --owner $OWNER ./artifact`, or "
        "publish a checksum manifest from the trusted producer "
        "and `sha256sum -c` it. Treat any download from a fork "
        "as untrusted input."
    ),
    docs_note=(
        "`on: workflow_run` runs in the privileged context of the "
        "default branch (write GITHUB_TOKEN, secrets accessible) but "
        "consumes artifacts produced by the triggering workflow — "
        "which is often a fork PR with no trust boundary. Classic "
        "PPE: a malicious PR uploads a tampered artifact, the "
        "privileged workflow_run downloads and executes it."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    triggers = workflow_triggers(doc)
    if "workflow_run" not in triggers:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Workflow is not triggered by workflow_run.",
            recommendation="No action required.", passed=True,
        )
    downloads_artifact = False
    verified = False
    for _, job in iter_jobs(doc):
        for step in iter_steps(job):
            uses = step.get("uses") or ""
            run = step.get("run") or ""
            blob = f"{uses} {run}".lower()
            if (
                isinstance(uses, str) and "actions/download-artifact" in uses
                or "gh run download" in blob
                or "gh api repos/" in blob and "/artifacts/" in blob
            ):
                downloads_artifact = True
            if (
                "cosign verify" in blob
                or "gh attestation verify" in blob
                or "sha256sum --check" in blob
                or "sha256sum -c" in blob
            ):
                verified = True
    if not downloads_artifact:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "workflow_run trigger present but no artifact download "
                "step detected."
            ),
            recommendation="No action required.", passed=True,
        )
    passed = verified
    desc = (
        "workflow_run downloads an artifact AND verifies its signature."
        if passed else
        "workflow_run trigger ingests an artifact from the upstream "
        "workflow without any verification step (cosign verify, "
        "`gh attestation verify`, or `sha256sum -c`). The upstream "
        "may be a fork PR; whatever it produced now executes inside "
        "the default-branch context with secrets and write access."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
