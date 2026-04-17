"""GCB-009 — Pipeline should invoke a signing / attestation tool.

Cloud Build pipelines that publish to Artifact Registry or push
container images should attach a cryptographic signature or in-toto
attestation. Without one, downstream consumers cannot distinguish a
tampered image from a legitimate build.

Reuses the cross-provider ``has_signing`` helper so the tool
catalogue (cosign / sigstore / slsa-framework / notation) stays in
sync with GHA-006 / GL-006 / BB-006 / ADO-006 / CC-006 / JF-006.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity, has_signing, produces_artifacts
from ...rule import Rule

RULE = Rule(
    id="GCB-009",
    title="Artifacts not signed (no cosign / sigstore step)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-SIGN-ARTIFACTS",),
    cwe=("CWE-345",),
    recommendation=(
        "Add a signing step before ``images:`` is resolved — for "
        "example, a step with ``name: gcr.io/projectsigstore/cosign`` "
        "that runs ``cosign sign --yes <registry>/<repo>@<digest>``. "
        "Pair with an attestation step (``cosign attest --predicate "
        "sbom.json --type cyclonedx``) so consumers can verify both "
        "the signature and the build provenance."
    ),
    docs_note=(
        "Silent-pass when the pipeline does not appear to produce "
        "artifacts (no ``docker push`` / ``gcloud run deploy`` / "
        "``kubectl apply`` / etc. in any step). The detector matches "
        "cosign, sigstore, slsa-framework, and notation."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    # Cloud Build pipelines almost always produce artifacts (top-level
    # ``images:`` triggers a push even without an explicit step). Treat
    # a non-empty ``images:`` list as artifact-producing so the check
    # applies even to minimal configs that rely on the built-in push.
    produces = produces_artifacts(doc) or bool(doc.get("images"))
    passed = has_signing(doc)
    if not passed and not produces:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="No artifact production detected — check not applicable.",
            recommendation=RULE.recommendation, passed=True,
        )
    desc = (
        "Pipeline invokes a signing tool (cosign / sigstore / notation)."
        if passed else
        "Pipeline does not invoke any signing tool (cosign, sigstore, "
        "slsa-framework, notation). Unsigned images cannot be verified "
        "downstream, so a tampered build is indistinguishable from a "
        "legitimate one."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
