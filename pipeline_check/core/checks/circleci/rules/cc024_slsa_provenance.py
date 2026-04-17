"""CC-024 — CircleCI config must emit SLSA provenance attestation."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity, has_provenance, produces_artifacts
from ...rule import Rule

RULE = Rule(
    id="CC-024",
    title="No SLSA provenance attestation produced",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-S-PROVENANCE",),
    cwe=("CWE-345",),
    recommendation=(
        "Add a ``run: cosign attest`` command against a "
        "``provenance.intoto.jsonl`` statement, or use the "
        "``circleci/attestation`` orb. CC-006 covers signing; this "
        "rule covers the build-provenance step SLSA Build L3 requires."
    ),
    docs_note=(
        "Signing (``cosign sign``) binds identity to bytes; attestation "
        "(``cosign attest``) binds a structured claim about *how* the "
        "artifact was built. SLSA verifiers check the latter so "
        "consumers can enforce builder/source/parameter policies."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    if not produces_artifacts(doc):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Config does not produce deployable artifacts.",
            recommendation="No action required.", passed=True,
        )
    passed = has_provenance(doc)
    desc = (
        "SLSA provenance attestation command detected."
        if passed else
        "Config publishes artifacts but does not emit a SLSA provenance "
        "attestation."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
