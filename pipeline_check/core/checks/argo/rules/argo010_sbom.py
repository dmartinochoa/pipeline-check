"""ARGO-010. Argo workflow should emit an SBOM for produced artifacts."""
from __future__ import annotations

from ...base import NO_ARTIFACT_DESC, Finding, Severity, has_sbom, produces_artifacts
from ...rule import Rule
from ..base import ArgoContext

RULE = Rule(
    id="ARGO-010",
    title="No SBOM generated for build artifacts",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-S-SBOM",),
    cwe=("CWE-1357",),
    recommendation=(
        "Add an SBOM-generation template. ``syft <artifact> -o "
        "cyclonedx-json > /tmp/sbom.json`` runs in any standard "
        "container; ``cyclonedx-cli`` and ``cdxgen`` are alternative "
        "producers. Persist the SBOM as an output artifact so "
        "downstream templates and consumers can read it."
    ),
    docs_note=(
        "An SBOM (CycloneDX or SPDX) records every component baked "
        "into the build. Without one, post-incident triage can't "
        "answer ``did this CVE ship?`` for a given artifact. "
        "Detection uses the shared SBOM-token catalog: syft, "
        "cyclonedx, cdxgen, spdx-tools, microsoft/sbom-tool. Fires "
        "only on artifact-producing Workflows."
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
    no_sbom = [d for d in artifact_producers if not has_sbom(d.data)]
    passed = not no_sbom
    desc = (
        "Every artifact-producing Argo document generates an SBOM."
        if passed else
        f"{len(no_sbom)} Argo document(s) produce artifacts but do "
        f"not generate an SBOM: "
        f"{', '.join(d.display for d in no_sbom[:5])}"
        f"{'…' if len(no_sbom) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argo", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
