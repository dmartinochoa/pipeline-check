"""OCI-006. Image has an excessive layer count."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import OCIManifest

RULE = Rule(
    id="OCI-006",
    title="Image has an excessive layer count",
    severity=Severity.LOW,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-IMMUTABLE",),
    cwe=("CWE-1037",),
    recommendation=(
        "Squash the image's layer count by collapsing adjacent "
        "``RUN`` directives in the Dockerfile (``RUN apt-get "
        "update && apt-get install ... && rm -rf "
        "/var/lib/apt/lists/*`` is the canonical pattern), "
        "ordering ``COPY`` lines so cache invalidation moves them "
        "as a unit, and using multi-stage builds to drop "
        "build-time-only artifacts before the final ``FROM``. "
        "BuildKit's ``--squash`` flag flattens the result if the "
        "Dockerfile shape can't be restructured. Most well-tuned "
        "production images sit between 5 and 20 layers; anything "
        "past 40 is almost always accidental Dockerfile sprawl, "
        "not intentional layering."
    ),
    docs_note=(
        "Each layer is a content-addressed blob with its own "
        "registry round-trip on pull, its own caching decision, "
        "and its own potential for credential leakage (a ``RUN`` "
        "step that touched a secret leaves the secret in that "
        "layer's tar archive even if a later layer deletes it). "
        "The rule fires above 40 layers, which empirically "
        "captures the ``docker history`` blowout that happens "
        "when a Dockerfile's ``RUN`` lines don't collapse "
        "(``RUN apt-get update`` followed by ``RUN apt-get "
        "install`` followed by ``RUN apt-get clean`` is three "
        "layers where one would do). Indexes don't have layers "
        "of their own, the rule passes on them and applies "
        "instead to each per-platform image manifest a downstream "
        "scan loads."
    ),
    known_fp=(
        "Some legitimately large base images (CUDA / ML "
        "toolchains, fully-built distros) ship with 30-50 layers "
        "by design. Suppress via ignore-file when the layer count "
        "reflects a deliberate base-image choice rather than "
        "Dockerfile RUN-step sprawl.",
    ),
)


_LAYER_COUNT_CEILING = 40


def check(manifest: OCIManifest) -> Finding:
    if manifest.is_index:
        # An image index doesn't have layers itself; the
        # per-platform manifests it points at carry the layer
        # list. Without a registry pull we can't fetch those, so
        # the rule passes on indexes and a downstream scan of the
        # per-platform manifests catches sprawl when it fires.
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                "Image index has no layers of its own, layer-count "
                "hygiene applies to per-platform image manifests."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    layer_count = len(manifest.layers)
    passed = layer_count <= _LAYER_COUNT_CEILING
    desc = (
        f"Image has {layer_count} layers (ceiling "
        f"{_LAYER_COUNT_CEILING})."
        if passed else
        f"Image has {layer_count} layers, exceeding the "
        f"{_LAYER_COUNT_CEILING}-layer ceiling. Each layer is a "
        f"separate registry round-trip on pull and a separate "
        f"potential leakage surface; collapse adjacent RUN steps "
        f"or use multi-stage builds to bring the count down."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
