"""TKN-010 — Tekton Task should emit an SBOM for produced artifacts."""
from __future__ import annotations

from ...base import Finding, Severity, has_sbom, produces_artifacts
from ...rule import Rule
from ..base import TektonContext

RULE = Rule(
    id="TKN-010",
    title="No SBOM generated for build artifacts",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-S-SBOM",),
    cwe=("CWE-1357",),
    recommendation=(
        "Add an SBOM-generation step. ``syft <artifact> -o cyclonedx-"
        "json > $(workspaces.output.path)/sbom.json`` runs in the "
        "official ``syft`` Tekton catalog Task. ``cyclonedx-cli`` and "
        "``cdxgen`` are alternatives. Publish the SBOM as a Workspace "
        "result so downstream Tasks can consume it."
    ),
    docs_note=(
        "An SBOM (CycloneDX or SPDX) records every component baked "
        "into the build. Without one, post-incident triage can't "
        "answer ``did this CVE ship?`` for a given artifact. "
        "Detection uses the shared SBOM-token catalog: syft, "
        "cyclonedx, cdxgen, spdx-tools, microsoft/sbom-tool. "
        "Fires only on artifact-producing Tasks."
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
            description="No artifact production detected — check not applicable.",
            recommendation=RULE.recommendation, passed=True,
        )
    no_sbom = [d for d in artifact_producers if not has_sbom(d.data)]
    passed = not no_sbom
    desc = (
        "Every artifact-producing Tekton document generates an SBOM "
        "(syft / cyclonedx / cdxgen / spdx-tools)."
        if passed else
        f"{len(no_sbom)} Tekton document(s) produce artifacts but "
        f"do not generate an SBOM: "
        f"{', '.join(d.display for d in no_sbom[:5])}"
        f"{'…' if len(no_sbom) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="tekton", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
