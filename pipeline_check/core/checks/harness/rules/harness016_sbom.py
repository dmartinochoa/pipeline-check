"""HARNESS-016. Pipeline should produce an SBOM (syft / cyclonedx)."""
from __future__ import annotations

from ...base import (
    NO_ARTIFACT_DESC,
    Finding,
    Severity,
    has_sbom,
    produces_artifacts,
)
from ...rule import Rule
from ..base import HarnessPipeline

RULE = Rule(
    id="HARNESS-016",
    title="No SBOM produced (no syft / cyclonedx step)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-S-SBOM",),
    cwe=("CWE-1357",),
    recommendation=(
        "Generate a Software Bill of Materials as part of the build: run "
        "``syft <image> -o cyclonedx-json`` (or ``cyclonedx`` / ``spdx`` "
        "tooling) and publish it alongside the artifact, so consumers can "
        "audit the components and respond to new CVEs without rebuilding. "
        "Harness also offers a built-in SBOM Orchestration step."
    ),
    docs_note=(
        "Detection mirrors GHA-007 / BK-010 / CC-007 / TKN-010 / DR-020, "
        "the shared SBOM-token catalog (``syft``, ``cyclonedx``, "
        "``cdxgen``, ``anchore/sbom-action``, ``spdx-sbom-generator``, "
        "``microsoft/sbom-tool``, or ``trivy`` combined with an "
        "``sbom`` / ``cyclonedx`` flag) is searched across every string in "
        "the pipeline document. The rule only fires on artifact-producing "
        "pipelines (``docker build`` / ``docker push`` / ``buildah`` / "
        "``kaniko`` / Harness ``BuildAndPush*`` step / etc.) so lint / "
        "test-only pipelines don't trip it. The Harness analog of BK-010 "
        "/ TKN-010."
    ),
)


def check(pipeline: HarnessPipeline) -> Finding:
    doc = pipeline.data
    if not produces_artifacts(doc):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pipeline.path, description=NO_ARTIFACT_DESC,
            recommendation=RULE.recommendation, passed=True,
        )
    passed = has_sbom(doc)
    desc = (
        "Pipeline produces an SBOM (syft / cyclonedx / spdx)."
        if passed else
        "Pipeline produces build artifacts but generates no SBOM (syft, "
        "cyclonedx, spdx). Without a bill of materials, consumers can't "
        "audit the shipped components."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
