"""ADO-024 — Azure DevOps pipeline must emit SLSA provenance attestation."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity, has_provenance, produces_artifacts
from ...rule import Rule

RULE = Rule(
    id="ADO-024",
    title="No SLSA provenance attestation produced",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-S-PROVENANCE",),
    cwe=("CWE-345",),
    recommendation=(
        "Add a task that runs ``cosign attest`` against a "
        "``provenance.intoto.jsonl`` statement, or Microsoft's "
        "``sbom-tool`` in attestation mode. ADO-006 covers signing; "
        "this rule covers the in-toto statement SLSA Build L3 "
        "additionally requires."
    ),
    docs_note=(
        "On Azure Pipelines the common pattern is a ``Bash@3`` task "
        "invoking ``cosign attest --yes --predicate=provenance.json "
        "$(image)``. The native Microsoft SBOM tool emits "
        "``_manifest/spdx_2.2/manifest.spdx.json`` for SBOM but does "
        "not produce provenance on its own."
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
        "SLSA provenance attestation task detected."
        if passed else
        "Pipeline publishes artifacts but does not emit a SLSA provenance "
        "attestation."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
