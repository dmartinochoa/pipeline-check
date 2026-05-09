"""GCB-017. Image-producing build does not request SLSA provenance."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="GCB-017",
    title="Image-producing build does not request SLSA provenance",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-10"),
    esf=("ESF-S-PROVENANCE",),
    cwe=("CWE-1104",),
    recommendation=(
        "Set ``options.requestedVerifyOption: VERIFIED`` on builds "
        "that publish container images. Cloud Build then emits a "
        "signed SLSA provenance attestation alongside the image, "
        "which downstream verifiers (Binary Authorization, cosign "
        "verify-attestation, gcloud artifacts docker images "
        "describe) can use to check that an image was built by "
        "the configured pipeline rather than smuggled in from "
        "elsewhere."
    ),
    docs_note=(
        "SLSA Build Level 2 requires that the build platform "
        "produce signed provenance. Cloud Build's ``VERIFIED`` "
        "verify option is the documented way to opt in. The check "
        "is silent when the build does not produce an image (no "
        "top-level ``images:`` and no ``docker push`` / "
        "``gcloud run deploy`` style steps); for those, signing "
        "and provenance aren't applicable."
    ),
)


def _produces_image(doc: dict[str, Any]) -> bool:
    """Best-effort check: does this build emit a container image?"""
    if isinstance(doc.get("images"), list) and doc["images"]:
        return True
    steps = doc.get("steps")
    if not isinstance(steps, list):
        return False
    for step in steps:
        if not isinstance(step, dict):
            continue
        name = step.get("name")
        if isinstance(name, str) and (
            "/docker" in name or "/gcr.io/cloud-builders/docker" in name
        ):
            args = step.get("args")
            if isinstance(args, list):
                joined = " ".join(a for a in args if isinstance(a, str))
                if "push" in joined or "build" in joined:
                    return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    if not _produces_image(doc):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Build does not produce a container image, check not applicable.",
            recommendation=RULE.recommendation, passed=True,
        )
    options = doc.get("options")
    verify_option: Any = None
    if isinstance(options, dict):
        verify_option = options.get("requestedVerifyOption")
    requested = (
        isinstance(verify_option, str)
        and verify_option.strip().upper() == "VERIFIED"
    )
    desc = (
        "Build requests SLSA provenance "
        "(options.requestedVerifyOption: VERIFIED)."
        if requested else
        "Build publishes a container image but does not set "
        "``options.requestedVerifyOption: VERIFIED``. Without it, "
        "Cloud Build does not emit signed SLSA provenance."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=requested,
    )
