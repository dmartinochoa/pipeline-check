"""OCI-001. Image manifest is missing OCI provenance annotations."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import OCIManifest, primary_image_annotations

RULE = Rule(
    id="OCI-001",
    title="Image manifest is missing OCI provenance annotations",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-10"),
    esf=("ESF-S-PROVENANCE", "ESF-S-IMMUTABLE"),
    cwe=("CWE-1104",),
    recommendation=(
        "Stamp the image with at least "
        "``org.opencontainers.image.source`` (the URL of the source "
        "repo) and ``org.opencontainers.image.revision`` (the commit "
        "SHA built into the image). With ``docker buildx`` this is "
        "``--label org.opencontainers.image.source=...`` plus "
        "``--label org.opencontainers.image.revision=...`` at build "
        "time, or set them as image annotations through "
        "``--annotation`` so they appear on the manifest itself "
        "(``manifest.annotations`` is what registries surface to "
        "``manifest inspect``)."
    ),
    docs_note=(
        "Without these two annotations a pulled image can't be "
        "traced back to a source revision, so an incident-response "
        "team has no way to reach the build that produced it. The "
        "rule fires on whichever layer the manifest carries (top-"
        "level for an index, sub-manifest for a per-platform image); "
        "DF-016 catches the same gap at Dockerfile authoring time, "
        "OCI-001 catches it once the image has been built and any "
        "later ``docker buildx --annotation`` overrides have already "
        "been applied."
    ),
    known_fp=(
        "Throwaway / scratch images that never leave a developer's "
        "machine (e.g. ``image inspect`` of an intermediate build "
        "stage) don't need provenance annotations. Suppress via "
        "ignore-file rather than removing the rule.",
    ),
)


_REQUIRED: tuple[str, ...] = (
    "org.opencontainers.image.source",
    "org.opencontainers.image.revision",
)


def check(manifest: OCIManifest) -> Finding:
    annotations = primary_image_annotations(manifest)
    missing = [k for k in _REQUIRED if not annotations.get(k)]
    passed = not missing
    desc = (
        "Image manifest declares both org.opencontainers.image.source "
        "and image.revision provenance annotations."
        if passed else
        f"Image manifest is missing OCI provenance annotation(s): "
        f"{', '.join(missing)}. Without them an image pulled from "
        f"the registry can't be traced back to a source revision."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
