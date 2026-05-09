"""TKN-011. Tekton Task should emit a SLSA provenance attestation."""
from __future__ import annotations

from ...base import Finding, Severity, has_provenance, produces_artifacts
from ...rule import Rule
from ..base import TektonContext

RULE = Rule(
    id="TKN-011",
    title="No SLSA provenance attestation produced",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-S-PROVENANCE", "ESF-D-SIGN-ARTIFACTS"),
    cwe=("CWE-345",),
    recommendation=(
        "After the build step, run ``cosign attest --predicate "
        "slsa.json --type slsaprovenance <ref>`` (or use the "
        "``tekton-chains`` controller, which signs and attests "
        "every TaskRun automatically when configured). Publish the "
        "attestation alongside the artifact so consumers can verify "
        "*how* it was built, not just *who* signed it."
    ),
    docs_note=(
        "Provenance generation is distinct from signing. A signed "
        "artifact proves *who* published it; a provenance attestation "
        "proves *where / how* it was built. Tekton Chains is the "
        "Tekton-native answer, once enabled on the cluster, every "
        "TaskRun's outputs are signed and attested without per-Task "
        "wiring. Detection uses the shared provenance-token catalog "
        "(``slsa-framework``, ``cosign attest``, ``in-toto``, "
        "``attest-build-provenance``, ``witness run``). Tasks "
        "produced by tekton-chains pass on the ``cosign attest`` "
        "match."
    ),
)


def check(ctx: TektonContext) -> Finding:
    if not ctx.docs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="tekton",
            description="No Tekton documents to check.",
            recommendation="No action required.", passed=True,
        )
    # Only Tasks / ClusterTasks declare the build steps that actually
    # produce artifacts (see TKN-009 for the same rationale).
    artifact_producers = [
        d for d in ctx.docs
        if d.kind in ("Task", "ClusterTask") and produces_artifacts(d.data)
    ]
    if not artifact_producers:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="tekton",
            description="No artifact production detected, check not applicable.",
            recommendation=RULE.recommendation, passed=True,
        )
    no_prov = [d for d in artifact_producers if not has_provenance(d.data)]
    passed = not no_prov
    desc = (
        "Every artifact-producing Tekton document emits a SLSA "
        "provenance attestation."
        if passed else
        f"{len(no_prov)} Tekton document(s) produce artifacts but "
        f"do not emit a SLSA provenance attestation: "
        f"{', '.join(d.display for d in no_prov[:5])}"
        f"{'…' if len(no_prov) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="tekton", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
