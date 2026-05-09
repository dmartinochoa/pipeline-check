"""OCI-002. Image is missing a build attestation manifest."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import OCIManifest, iter_attestation_entries

RULE = Rule(
    id="OCI-002",
    title="Image is missing a build attestation manifest",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-9", "CICD-SEC-10"),
    esf=("ESF-S-PROVENANCE", "ESF-S-SBOM"),
    cwe=("CWE-1357", "CWE-1104"),
    recommendation=(
        "Build the image with ``docker buildx build "
        "--attest=type=provenance,mode=max --attest=type=sbom`` "
        "(or the equivalent BuildKit frontend flags). Both "
        "attestations land as sibling sub-manifests inside the "
        "image index, annotated with "
        "``vnd.docker.reference.type: attestation-manifest`` and "
        "linked to their target manifest via "
        "``vnd.docker.reference.digest``. Verify after pushing "
        "with ``docker buildx imagetools inspect <ref>``, the "
        "``Attestations`` section should list both predicate "
        "types."
    ),
    docs_note=(
        "Build attestations are the canonical place for SLSA "
        "provenance and SBOM data on an OCI image. A multi-platform "
        "image index that ships per-architecture manifests but no "
        "attestation-manifest sibling means there's no signed "
        "record of how the image was built or what's inside it, "
        "so consumers can't enforce SLSA Build-L2+ or feed an SBOM "
        "into vulnerability triage. A single-platform manifest "
        "(no image index) also fails this rule, attestations "
        "require the index-of-manifests shape that BuildKit "
        "produces by default."
    ),
    known_fp=(
        "Intermediate / cache-only images pushed by CI for "
        "later-stage consumption may legitimately ship without "
        "attestations to keep build artifacts small. Suppress via "
        "ignore-file when this is the deliberate shape, the "
        "default expectation for any image that reaches a "
        "production registry is a full attestation set.",
        "Some registries strip the attestation sub-manifests on "
        "pull (``docker pull`` of a single platform unwraps the "
        "index). If the JSON you're scanning came from "
        "``docker manifest inspect`` rather than "
        "``docker buildx imagetools inspect --raw``, attestations "
        "may be invisible even when present upstream.",
    ),
)


def check(manifest: OCIManifest) -> Finding:
    if not manifest.is_index:
        # Single-image manifests can't carry attestations; the
        # attestation contract requires the image-index shape so
        # the attestation manifest can be a sibling of the
        # platform-specific runtime manifests.
        passed = False
        desc = (
            "Image is a single-platform manifest, not an image "
            "index. Build attestations (SLSA provenance + SBOM) "
            "require the image-index shape ``docker buildx`` "
            "produces by default; an ad-hoc single manifest can't "
            "carry them."
        )
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        )
    attestations = list(iter_attestation_entries(manifest))
    passed = bool(attestations)
    desc = (
        f"Image index carries {len(attestations)} attestation "
        f"manifest(s); SLSA provenance and SBOM data are reachable "
        f"via ``docker buildx imagetools inspect``."
        if passed else
        "Image index has no attestation-manifest sub-entries "
        "(no entry annotated with vnd.docker.reference.type: "
        "attestation-manifest). The image ships without signed "
        "build provenance or an SBOM, so consumers can't verify "
        "what produced it or what's inside it."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
