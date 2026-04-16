"""ADO-010 — cross-pipeline downloads must be verified."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps


RULE = Rule(
    id="ADO-010",
    title="Cross-pipeline `download:` ingestion unverified",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"),
    recommendation=(
        "Add a verification step before consuming the artifact: "
        "`cosign verify-attestation`, `sha256sum -c`, or `gpg "
        "--verify` against a manifest the producing pipeline signed."
    ),
    docs_note=(
        "`resources.pipelines:` declares an upstream pipeline; a "
        "`download: <name>` step pulls its artifacts. If the upstream "
        "accepts PR validation, the artifact may have been built by "
        "PR-controlled code."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    resources = doc.get("resources") or {}
    pipeline_resources: set[str] = set()
    if isinstance(resources, dict):
        for entry in resources.get("pipelines", []) or []:
            if isinstance(entry, dict):
                name = entry.get("pipeline") or entry.get("source")
                if isinstance(name, str):
                    pipeline_resources.add(name)
    if not pipeline_resources:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Pipeline declares no upstream pipeline resources.",
            recommendation="No action required.", passed=True,
        )
    ingests = False
    verified = False
    for _, job in iter_jobs(doc):
        for _, step in iter_steps(job):
            dl = step.get("download")
            if isinstance(dl, str) and dl != "current" and dl in pipeline_resources:
                ingests = True
            for key in ("script", "bash", "pwsh", "powershell"):
                body = step.get(key)
                if isinstance(body, str):
                    low = body.lower()
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
            description=(
                "Pipeline does not download artifacts from a declared "
                "upstream pipeline."
            ),
            recommendation="No action required.", passed=True,
        )
    passed = verified
    desc = (
        "Cross-pipeline download is paired with a verification step."
        if passed else
        "Pipeline downloads artifacts from an upstream "
        "`resources.pipelines` entry but no signature/checksum "
        "verification step is present."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
