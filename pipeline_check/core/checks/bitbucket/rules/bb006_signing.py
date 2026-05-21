"""BB-006, artifact signing."""
from __future__ import annotations

from typing import Any

from ..._primitives.oci_refs import extract_image_anchors_from_strings
from ...base import NO_ARTIFACT_DESC, Finding, Severity, has_signing, produces_artifacts
from ...rule import Rule

RULE = Rule(
    id="BB-006",
    title="Artifacts not signed",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-SIGN-ARTIFACTS",),
    cwe=("CWE-345",),
    recommendation=(
        "Add a step that runs `cosign sign` against the built image "
        "or archive, using Bitbucket OIDC for keyless signing where "
        "possible. Publish the signature next to the artifact and "
        "verify it at deploy time."
    ),
    docs_note=(
        "Unsigned artifacts can't be verified downstream. Passes "
        "when cosign / sigstore / slsa-* / notation-sign appears in "
        "the pipeline body."
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
        "Pipeline produces build artifacts but does not invoke any "
        "signing tool (cosign, sigstore, notation). Unsigned "
        "artifacts cannot be verified downstream."
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
