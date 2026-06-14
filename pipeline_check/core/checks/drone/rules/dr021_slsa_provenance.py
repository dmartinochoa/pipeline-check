"""DR-021. Pipeline should produce SLSA provenance attestation."""
from __future__ import annotations

from ...base import (
    NO_ARTIFACT_DESC,
    Finding,
    Severity,
    has_provenance,
    produces_artifacts,
)
from ...rule import Rule
from ..base import Pipeline

RULE = Rule(
    id="DR-021",
    title="No SLSA provenance attestation produced",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-S-PROVENANCE",),
    cwe=("CWE-345",),
    recommendation=(
        "Emit a signed SLSA provenance attestation for the build: use "
        "``cosign attest --predicate`` with an in-toto / SLSA predicate, or "
        "a provenance generator, so a verifier can confirm which pipeline "
        "and source revision produced the artifact."
    ),
    docs_note=(
        "Detection mirrors GHA-024 / BK-011 / CC-024 / TKN-011, the shared "
        "provenance-token catalog (slsa, provenance, in-toto, attestation, "
        "cosign attest) is searched across every string in the pipeline "
        "document. The rule only fires on artifact-producing pipelines "
        "(``docker build`` / ``docker push`` / ``buildah`` / etc.) so "
        "lint / test-only pipelines don't trip it. The Drone analog of "
        "BK-011 / TKN-011."
    ),
)


def check(pipeline: Pipeline) -> Finding:
    doc = pipeline.data
    if not produces_artifacts(doc):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pipeline.path, description=NO_ARTIFACT_DESC,
            recommendation=RULE.recommendation, passed=True,
        )
    passed = has_provenance(doc)
    desc = (
        "Pipeline emits provenance / SLSA attestation."
        if passed else
        "Pipeline produces build artifacts but emits no SLSA provenance "
        "attestation (slsa, in-toto, cosign attest). A consumer can't "
        "verify which pipeline and source built the artifact."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
