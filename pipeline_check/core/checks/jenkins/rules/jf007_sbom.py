"""JF-007 — pipeline should produce an SBOM."""
from __future__ import annotations

from ...base import _ARTIFACT_TOKENS, SBOM_DIRECT_TOKENS, Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile

RULE = Rule(
    id="JF-007",
    title="SBOM not produced",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-SBOM",),
    cwe=("CWE-1104",),
    recommendation=(
        "Add a `sh 'syft . -o cyclonedx-json > sbom.json'` step "
        "(or Trivy with `--format cyclonedx`) and archive the "
        "result with `archiveArtifacts`."
    ),
    docs_note=(
        "Passes when a direct SBOM tool token (CycloneDX, syft, "
        "anchore, spdx-sbom-generator, sbom-tool) appears in "
        "executable code, or when Trivy is paired with `sbom` / "
        "`cyclonedx` in the same file. Comments are stripped "
        "before matching."
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    text = jf.text_no_comments.lower()
    direct = any(tok in text for tok in SBOM_DIRECT_TOKENS)
    trivy_sbom = "trivy" in text and ("sbom" in text or "cyclonedx" in text)
    passed = direct or trivy_sbom
    if not passed and not any(tok in jf.text.lower() for tok in _ARTIFACT_TOKENS):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=jf.path,
            description="No artifact production detected — check not applicable.",
            recommendation=RULE.recommendation, passed=True,
        )
    desc = (
        "Pipeline produces an SBOM (CycloneDX / syft / Trivy-SBOM)."
        if passed else
        "Pipeline does not produce a software bill of materials (SBOM)."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
