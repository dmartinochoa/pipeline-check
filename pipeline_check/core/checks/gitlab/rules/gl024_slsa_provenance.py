"""GL-024 — GitLab pipeline must emit SLSA provenance attestation."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity, has_provenance, produces_artifacts
from ...rule import Rule

RULE = Rule(
    id="GL-024",
    title="No SLSA provenance attestation produced",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-S-PROVENANCE",),
    cwe=("CWE-345",),
    recommendation=(
        "Add a job that runs ``cosign attest`` against a "
        "``provenance.intoto.jsonl`` statement, or adopt a SLSA-aware "
        "builder (the SLSA project ships GitLab templates). Signing "
        "the artifact (GL-006) isn't enough for SLSA L3 — the "
        "attestation describes *how* the build ran."
    ),
    docs_note=(
        "``cosign sign`` and ``cosign attest`` look similar but mean "
        "different things: the first binds identity to bytes; the "
        "second binds a structured claim (builder, source, inputs) to "
        "the artifact. SLSA Build L3 verifiers check the latter."
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
        "attestation (``cosign attest`` / ``slsa-framework/slsa-*`` / "
        "``witness run``)."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
