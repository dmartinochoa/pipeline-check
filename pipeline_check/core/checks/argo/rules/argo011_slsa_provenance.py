"""ARGO-011. Argo workflow should emit a SLSA provenance attestation."""
from __future__ import annotations

from ...base import NO_ARTIFACT_DESC, Finding, Severity, has_provenance, produces_artifacts
from ...rule import Rule
from ..base import ArgoContext, doc_location

RULE = Rule(
    id="ARGO-011",
    title="No SLSA provenance attestation produced",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-S-PROVENANCE", "ESF-D-SIGN-ARTIFACTS"),
    cwe=("CWE-345",),
    recommendation=(
        "Add a ``cosign attest --predicate slsa.json --type "
        "slsaprovenance <ref>`` step after the build template, or "
        "use ``witness run`` to record the build environment. "
        "Publish the attestation alongside the artifact so "
        "consumers can verify *how* it was built, not just *who* "
        "signed it."
    ),
    docs_note=(
        "Provenance generation is distinct from signing. A signed "
        "artifact proves *who* published it; a provenance "
        "attestation proves *where / how* it was built. Detection "
        "uses the shared provenance-token catalog (``slsa-"
        "framework``, ``cosign attest``, ``in-toto-attestation``, "
        "``witness run``, ``attest-build-provenance``)."
    ),
)


def check(ctx: ArgoContext) -> Finding:
    if not ctx.docs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argo",
            description="No Argo documents to check.",
            recommendation="No action required.", passed=True,
        )
    artifact_producers = [d for d in ctx.docs if produces_artifacts(d.data)]
    if not artifact_producers:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argo",
            description=NO_ARTIFACT_DESC,
            recommendation=RULE.recommendation, passed=True,
        )
    no_prov = [d for d in artifact_producers if not has_provenance(d.data)]
    passed = not no_prov
    desc = (
        "Every artifact-producing Argo document emits a SLSA "
        "provenance attestation."
        if passed else
        f"{len(no_prov)} Argo document(s) produce artifacts but do "
        f"not emit a SLSA provenance attestation: "
        f"{', '.join(d.display for d in no_prov[:5])}"
        f"{'…' if len(no_prov) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argo", description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=[doc_location(d) for d in no_prov],
    )
