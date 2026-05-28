"""OCI-009. Image manifest is missing OCI 1.1 base-image annotations."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import OCIManifest, primary_image_annotations

RULE = Rule(
    id="OCI-009",
    title="Image manifest is missing OCI base-image annotations",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-10"),
    esf=("ESF-S-PROVENANCE",),
    cwe=("CWE-1104",),
    recommendation=(
        "Stamp the image with "
        "``org.opencontainers.image.base.name`` (the registry "
        "reference of the base image — e.g. "
        "``gcr.io/distroless/static:nonroot``) and "
        "``org.opencontainers.image.base.digest`` (the immutable "
        "sha256 digest of the base image manifest). With "
        "``docker buildx`` these are emitted automatically when "
        "the build uses ``--provenance`` or the "
        "``BUILDKIT_INLINE_BUILDINFO_ATTRS=1`` env var; for "
        "hand-tagged images, pass ``--annotation "
        "org.opencontainers.image.base.name=...`` and "
        "``--annotation org.opencontainers.image.base.digest=...`` "
        "so the values land on the manifest where registries surface "
        "them."
    ),
    docs_note=(
        "Without these two annotations a pulled image can't be tied "
        "back to the immutable base layer it was built on, so a "
        "downstream consumer can't determine which CVEs apply nor "
        "whether the base image was the one the build pipeline "
        "intended (vs a hijacked tag at pull time). The annotations "
        "are part of the OCI image-spec 1.1 attribution surface; "
        "SLSA Build L3 evidence-of-base-image relies on them when "
        "the provenance attestation isn't otherwise available.\n\n"
        "Distinct from OCI-001 (``org.opencontainers.image.source`` "
        "/ ``image.revision``): those identify the source repo the "
        "image was built from; ``image.base.name`` / "
        "``image.base.digest`` identify the base image the build "
        "started on. Both gaps reduce attribution; they're not "
        "substitutes for each other.\n\n"
        "Skipped: ``scratch``-based images (no base to attribute) "
        "and images whose ``image.base.name`` is explicitly empty "
        "(the OCI-spec sentinel for 'no base image'). The rule "
        "treats either as already-attributed."
    ),
    known_fp=(
        "Throwaway / scratch images built without a base "
        "(``FROM scratch`` in the Dockerfile) have no base image to "
        "attribute. The OCI image-spec allows declaring "
        "``image.base.name`` empty (an explicit 'no base' marker); "
        "if the build doesn't set the empty marker, the rule will "
        "flag the absence. Suppress via ignore-file rather than "
        "removing the rule, or set the empty marker at build time "
        "with ``--annotation org.opencontainers.image.base.name=`` "
        "(empty value).",
    ),
)


_REQUIRED: tuple[str, ...] = (
    "org.opencontainers.image.base.name",
    "org.opencontainers.image.base.digest",
)


def check(manifest: OCIManifest) -> Finding:
    annotations = primary_image_annotations(manifest)
    # OCI 1.1 allows ``image.base.name`` to be present-but-empty as
    # the explicit "no base image (scratch)" marker. Treat the
    # presence of the key — even with an empty value — as
    # attributed. The digest is only meaningful when there IS a
    # base, so it's only required when ``image.base.name`` is
    # non-empty.
    base_name_key = "org.opencontainers.image.base.name"
    base_digest_key = "org.opencontainers.image.base.digest"
    has_name_key = base_name_key in annotations
    base_name_value = annotations.get(base_name_key, "")
    has_digest = bool(annotations.get(base_digest_key, ""))
    if has_name_key and not base_name_value:
        # Explicit "scratch / no base" sentinel.
        missing: list[str] = []
    elif has_name_key and base_name_value and has_digest:
        missing = []
    else:
        missing = [k for k in _REQUIRED if not annotations.get(k)]
    passed = not missing
    desc = (
        "Image manifest declares both org.opencontainers.image.base."
        "name and image.base.digest provenance annotations."
        if passed else
        f"Image manifest is missing OCI base-image annotation(s): "
        f"{', '.join(missing)}. Without them a downstream consumer "
        f"can't determine which base image the build started on, so "
        f"CVE attribution and SLSA L3 base-image evidence are "
        f"unrecoverable."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
