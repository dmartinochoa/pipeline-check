"""BK-011 — pipeline should emit a SLSA provenance attestation."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity, has_provenance, produces_artifacts
from ...rule import Rule

RULE = Rule(
    id="BK-011",
    title="No SLSA provenance attestation produced",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-S-PROVENANCE",),
    cwe=("CWE-345",),
    recommendation=(
        "Run ``cosign attest --predicate slsa.json`` (or the SLSA-"
        "framework generator from a build-time step) after the build "
        "completes. The predicate records the build inputs and the "
        "agent that produced the artifact. Publish the attestation "
        "alongside the artifact so consumers can verify *how* it was "
        "built, not just *who* signed it."
    ),
    docs_note=(
        "Provenance generation is distinct from signing. A signed "
        "artifact proves *who* published it; a provenance attestation "
        "proves *where / how* it was built. Without it, a leaked "
        "signing key forges identity but a leaked build environment "
        "also forges provenance — you need both for the SLSA L3 non-"
        "falsifiability guarantee. Detection uses the shared "
        "provenance-token catalog (``slsa-framework``, ``cosign "
        "attest``, ``in-toto``, ``attest-build-provenance``)."
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
        "Pipeline publishes artifacts but does not emit a SLSA "
        "provenance attestation (``slsa-framework``, ``cosign "
        "attest``, ``in-toto``, ``attest-build-provenance``)."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
