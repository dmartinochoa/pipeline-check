"""GCB-009. Pipeline should invoke a signing / attestation tool.

Cloud Build pipelines that publish to Artifact Registry or push
container images should attach a cryptographic signature or in-toto
attestation. Without one, downstream consumers cannot distinguish a
tampered image from a legitimate build.

Reuses the cross-provider ``has_signing`` helper so the tool
catalog (cosign / sigstore / slsa-framework / notation) stays in
sync with GHA-006 / GL-006 / BB-006 / ADO-006 / CC-006 / JF-006.
"""
from __future__ import annotations

from typing import Any

from ..._primitives.anchors import oci_image
from ..._primitives.oci_refs import extract_publisher_anchors_from_strings
from ...base import NO_ARTIFACT_DESC, Finding, ResourceAnchor, Severity, has_signing, produces_artifacts
from ...rule import Rule
from ..base import pipeline_publishes

RULE = Rule(
    id="GCB-009",
    title="Artifacts not signed (no cosign / sigstore step)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-SIGN-ARTIFACTS",),
    cwe=("CWE-345",),
    recommendation=(
        "Add a signing step before ``images:`` is resolved, for "
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
    produces = produces_artifacts(doc) or pipeline_publishes(doc)
    passed = has_signing(doc)
    if not passed and not produces:
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
        "slsa-framework, notation). Unsigned images cannot be verified "
        "downstream, so a tampered build is indistinguishable from a "
        "legitimate one."
    )
    # ResourceAnchor phase 1 (AC-005): emit oci_image anchors for
    # images this pipeline PUBLISHES. Cloud Build's top-level
    # ``images:`` list is the canonical structured producer field
    # (GCB pushes those implicitly after the build); the text-scan
    # fallback is restricted to publisher-shaped commands
    # (``docker push``, ``buildah push``, ``crane push``,
    # ``skopeo copy``) so deploy-side mentions
    # (``kubectl set image``, ``helm upgrade``, ``gcloud run deploy``)
    # in the same pipeline don't leak into a build-side signing
    # anchor — that would let AC-005 match unrelated runtime images
    # as if they were unsigned build outputs. Only on failing finding.
    anchors: tuple[ResourceAnchor, ...] = ()
    if not passed:
        seen: dict[str, ResourceAnchor] = {}
        images = doc.get("images")
        if isinstance(images, list):
            for item in images:
                if isinstance(item, str):
                    built = oci_image(item)
                    if built is not None:
                        seen[built.identity] = built
        for built in extract_publisher_anchors_from_strings(doc):
            seen[built.identity] = built
        anchors = tuple(seen.values())
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        resource_anchors=anchors,
    )
