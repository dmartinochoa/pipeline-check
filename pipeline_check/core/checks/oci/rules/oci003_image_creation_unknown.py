"""OCI-003. Image manifest is missing the ``image.created`` annotation."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import OCIManifest, primary_image_annotations

RULE = Rule(
    id="OCI-003",
    title="Image manifest is missing the ``image.created`` annotation",
    severity=Severity.LOW,
    owasp=("CICD-SEC-3", "CICD-SEC-10"),
    esf=("ESF-S-PROVENANCE",),
    cwe=("CWE-1104",),
    recommendation=(
        "Stamp ``org.opencontainers.image.created`` with the build "
        "timestamp (RFC 3339 / ISO 8601, e.g. "
        "``2025-01-30T18:00:00Z``). With ``docker buildx`` either "
        "pass ``--label org.opencontainers.image.created=$(date -u "
        "+%Y-%m-%dT%H:%M:%SZ)`` at build time, or rely on the "
        "BuildKit frontend default which does it automatically when "
        "``SOURCE_DATE_EPOCH`` is unset. The annotation lets "
        "downstream vuln scanners and registries surface image "
        "age, which is the lightest-weight CVE-triage signal "
        "available without pulling the config blob."
    ),
    docs_note=(
        "Image age isn't a security boundary on its own, but a "
        "missing ``image.created`` annotation makes routine triage "
        "questions (\"is this image stale enough to warrant a "
        "rebuild?\", \"was this image built before or after the "
        "CVE-2024-XXXX advisory?\") much harder to answer "
        "automatically. Surfacing the gap as LOW-severity catches "
        "the omission early without overwhelming reports for an "
        "otherwise-well-formed image."
    ),
    known_fp=(
        "Reproducible-build pipelines deliberately omit "
        "``image.created`` (or pin it to ``SOURCE_DATE_EPOCH``) so "
        "the same source produces a byte-identical image. Suppress "
        "via ignore-file when reproducibility is the goal.",
    ),
)


_ANNOTATION_KEY = "org.opencontainers.image.created"


def check(manifest: OCIManifest) -> Finding:
    annotations = primary_image_annotations(manifest)
    value = annotations.get(_ANNOTATION_KEY, "").strip()
    passed = bool(value)
    desc = (
        f"Image manifest declares "
        f"org.opencontainers.image.created={value!r}."
        if passed else
        "Image manifest is missing the "
        "org.opencontainers.image.created annotation. CVE triage "
        "can't determine the image's build date from the manifest "
        "alone."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
