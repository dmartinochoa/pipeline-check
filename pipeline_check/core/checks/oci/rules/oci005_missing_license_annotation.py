"""OCI-005. Image manifest is missing the ``image.licenses`` annotation."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import OCIManifest, primary_image_annotations

RULE = Rule(
    id="OCI-005",
    title="Image manifest is missing the ``image.licenses`` annotation",
    severity=Severity.LOW,
    owasp=("CICD-SEC-3", "CICD-SEC-10"),
    esf=("ESF-S-PROVENANCE",),
    cwe=("CWE-1104",),
    recommendation=(
        "Stamp ``org.opencontainers.image.licenses`` with the "
        "SPDX expression for the image's contents (e.g. "
        "``Apache-2.0``, ``MIT AND Apache-2.0``, "
        "``Apache-2.0 WITH LLVM-exception``). With "
        "``docker buildx`` the simplest path is to add "
        "``--label org.opencontainers.image.licenses=Apache-2.0`` "
        "(or, for annotation-based propagation onto the manifest, "
        "``--annotation manifest:org.opencontainers.image.licenses="
        "Apache-2.0``). The OCI image-spec annotation is a "
        "well-known SPDX expression carrier, downstream SBOM "
        "generators and registry UIs read it directly without "
        "needing per-tool configuration."
    ),
    docs_note=(
        "Without ``image.licenses`` an SBOM tool either has to "
        "fall back to scanning the layer contents (slow, "
        "best-effort) or simply mark the image as "
        "``license: unknown`` in compliance reports. The same "
        "field is what container registries surface to the "
        "operator UI, so its absence also makes manual license "
        "review harder. The rule is LOW severity because a "
        "missing license is a hygiene gap rather than a security "
        "boundary, but it ratchets up SBOM quality enough that "
        "it's worth catching at scan time."
    ),
    known_fp=(
        "Internal images that never leave a private registry "
        "and aren't subject to OSS license compliance audits "
        "may legitimately omit the annotation. Suppress via "
        "ignore-file when this is the deliberate stance.",
        "Multi-license images with ambiguous coverage (e.g. a "
        "base image plus mixed-license app code) sometimes "
        "skip the annotation rather than emit a misleading "
        "single-license value. In that case, the correct fix "
        "is to emit the SPDX compound expression "
        "(``MIT AND Apache-2.0``); suppression is the wrong "
        "answer.",
    ),
)


_ANNOTATION_KEY = "org.opencontainers.image.licenses"


def check(manifest: OCIManifest) -> Finding:
    annotations = primary_image_annotations(manifest)
    value = annotations.get(_ANNOTATION_KEY, "").strip()
    passed = bool(value)
    desc = (
        f"Image manifest declares "
        f"org.opencontainers.image.licenses={value!r}."
        if passed else
        "Image manifest is missing the "
        "org.opencontainers.image.licenses annotation. SBOM tools "
        "and registry UIs can't surface a license without it."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
