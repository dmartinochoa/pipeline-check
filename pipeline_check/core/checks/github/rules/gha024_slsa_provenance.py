"""GHA-024 — workflow must emit SLSA provenance attestation."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity, has_provenance, produces_artifacts
from ...rule import Rule

RULE = Rule(
    id="GHA-024",
    title="No SLSA provenance attestation produced",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-S-PROVENANCE",),
    cwe=("CWE-345",),
    recommendation=(
        "Call ``slsa-framework/slsa-github-generator`` or "
        "``actions/attest-build-provenance`` after the build step to "
        "emit an in-toto attestation alongside the artifact. "
        "``cosign sign`` alone (covered by GHA-006) signs the artifact "
        "but doesn't record *how* it was built — SLSA Build L3 requires "
        "the provenance statement."
    ),
    docs_note=(
        "Provenance generation is distinct from signing. A signed "
        "artifact proves ``who`` published it; a provenance attestation "
        "proves ``where/how`` it was built. Consumers can then verify "
        "the build happened on a trusted runner, from a specific source "
        "commit, with known parameters. Without it, a leaked signing "
        "key forges identity but a leaked build environment also forges "
        "provenance — you need both for the SLSA L3 non-falsifiability "
        "guarantee."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    # Only apply to artifact-producing workflows — lint/test-only
    # workflows have nothing to attest.
    if not produces_artifacts(doc):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Workflow does not produce deployable artifacts.",
            recommendation="No action required.", passed=True,
        )
    passed = has_provenance(doc)
    desc = (
        "SLSA provenance attestation step detected."
        if passed else
        "Workflow publishes artifacts but does not emit a SLSA provenance "
        "attestation (``slsa-github-generator``, "
        "``actions/attest-build-provenance``, ``cosign attest``)."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
