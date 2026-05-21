"""CC-006. Pipeline should invoke a signing tool (cosign / sigstore / ...)."""
from __future__ import annotations

from typing import Any

from ..._primitives.oci_refs import extract_image_anchors_from_strings
from ...base import NO_ARTIFACT_DESC, Finding, Severity, has_signing, produces_artifacts
from ...rule import Rule

RULE = Rule(
    id="CC-006",
    title="Artifacts not signed (no cosign/sigstore step)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-SIGN-ARTIFACTS",),
    cwe=("CWE-345",),
    recommendation=(
        "Add a signing step to the pipeline, e.g. install cosign and "
        "run `cosign sign`, or use the `sigstore` CLI. Publish the "
        "signature alongside the artifact and verify it at consumption "
        "time."
    ),
    docs_note=(
        "Unsigned artifacts cannot be verified downstream, so a "
        "tampered build is indistinguishable from a legitimate one. "
        "The check recognizes cosign, sigstore, slsa-framework, and "
        "notation-sign as signing tools."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    passed = has_signing(doc)
    if not passed and not produces_artifacts(doc):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=NO_ARTIFACT_DESC,
            recommendation=RULE.recommendation, passed=True,
        )
    desc = (
        "Pipeline invokes a signing tool (cosign / sigstore / notation)."
        if passed else
        "Pipeline does not invoke any signing tool (cosign, sigstore, "
        "slsa-framework, notation). Unsigned artifacts cannot be "
        "verified downstream, so a tampered build is indistinguishable "
        "from a legitimate one."
    )
    # ResourceAnchor phase 1 (AC-005): emit oci_image anchors for
    # images this pipeline tags / pushes. Only on failing finding.
    anchors = extract_image_anchors_from_strings(doc) if not passed else ()
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        resource_anchors=anchors,
    )
