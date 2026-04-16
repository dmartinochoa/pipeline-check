"""GL-010 — multi-project artifact ingestion must verify upstream output."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, job_scripts

RULE = Rule(
    id="GL-010",
    title="Multi-project pipeline ingests upstream artifact unverified",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"),
    recommendation=(
        "Add a verification step before consuming the artifact: "
        "`cosign verify-attestation`, `sha256sum -c`, or `gpg --verify` "
        "against a manifest signed by the upstream project's release "
        "key. Only consume artifacts produced by upstream pipelines "
        "whose origin you can trust."
    ),
    docs_note=(
        "`needs: { project: ..., artifacts: true }` pulls artifacts "
        "from another project's pipeline. If that upstream project "
        "accepts MR pipelines, the artifact may have been built by "
        "attacker-controlled code."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    ingests = False
    verified = False
    for _name, job in iter_jobs(doc):
        needs = job.get("needs")
        if isinstance(needs, list):
            for n in needs:
                if isinstance(n, dict) and n.get("project") and n.get("artifacts"):
                    ingests = True
        for line in job_scripts(job):
            low = line.lower()
            if (
                "cosign verify" in low
                or "sha256sum --check" in low
                or "sha256sum -c" in low
                or "gpg --verify" in low
            ):
                verified = True
    if not ingests:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Pipeline does not pull artifacts from another project.",
            recommendation="No action required.", passed=True,
        )
    passed = verified
    desc = (
        "Multi-project artifact ingestion is paired with a verification step."
        if passed else
        "Pipeline pulls artifacts from another project via "
        "`needs: { project: ..., artifacts: true }` but no signature "
        "or checksum verification step is present. If the upstream "
        "project accepts MR pipelines, the artifact may have been "
        "built by attacker-controlled code."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
