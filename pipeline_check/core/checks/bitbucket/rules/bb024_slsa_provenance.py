"""BB-024 — Bitbucket pipeline must emit SLSA provenance attestation."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity, has_provenance, produces_artifacts
from ...rule import Rule

RULE = Rule(
    id="BB-024",
    title="No SLSA provenance attestation produced",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-S-PROVENANCE",),
    cwe=("CWE-345",),
    recommendation=(
        "Add a step that runs ``cosign attest`` against a "
        "``provenance.intoto.jsonl`` statement, or integrate the "
        "TestifySec ``witness run`` attestor. Artifact signing alone "
        "(BB-006) doesn't satisfy SLSA Build L3."
    ),
    docs_note=(
        "Bitbucket has no native SLSA builder; self-hosted attestation "
        "via ``cosign attest`` or ``witness run`` is the usual path. "
        "Pipes like ``atlassian/cosign-attest`` (if published) would "
        "also match."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    if not produces_artifacts(doc):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Pipeline does not produce deployable artifacts.",
            recommendation="No action required.", passed=True,
        )
    passed = has_provenance(doc)
    desc = (
        "SLSA provenance attestation step detected."
        if passed else
        "Pipeline publishes artifacts but does not emit a SLSA provenance "
        "attestation."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
