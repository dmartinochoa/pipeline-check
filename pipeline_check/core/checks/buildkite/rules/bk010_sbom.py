"""BK-010, pipeline should emit an SBOM for the build artifact."""
from __future__ import annotations

from typing import Any

from ...base import NO_ARTIFACT_DESC, Finding, Severity, has_sbom, produces_artifacts
from ...rule import Rule

RULE = Rule(
    id="BK-010",
    title="No SBOM generated for build artifacts",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-S-SBOM",),
    cwe=("CWE-1357",),
    recommendation=(
        "Add an SBOM-generation step. ``syft <artifact> -o cyclonedx-"
        "json > sbom.json`` runs in any standard agent image; "
        "``cyclonedx-cli`` and ``cdxgen`` are alternative producers. "
        "Upload the SBOM via ``buildkite-agent artifact upload`` so "
        "downstream consumers (and incident-response tooling) can match "
        "deployed artifacts to the components they were built from."
    ),
    docs_note=(
        "An SBOM (CycloneDX or SPDX) records every component baked "
        "into the build. Without one, post-incident triage can't "
        "answer ``did this CVE ship?`` for a given artifact. Detection "
        "uses the shared SBOM-token catalog, syft, cyclonedx, cdxgen, "
        "spdx-sbom-generator, microsoft/sbom-tool."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    if not produces_artifacts(doc):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=NO_ARTIFACT_DESC,
            recommendation=RULE.recommendation, passed=True,
        )
    passed = has_sbom(doc)
    desc = (
        "Pipeline generates an SBOM (syft / cyclonedx / cdxgen / spdx-tools)."
        if passed else
        "Pipeline produces build artifacts but does not generate an "
        "SBOM. Without one, post-incident vulnerability triage can't "
        "establish whether a given CVE shipped in the artifact."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
