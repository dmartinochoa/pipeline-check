"""GCB-001 — Cloud Build step ``name:`` image must be digest-pinned.

Every step in a Cloud Build YAML runs the container referenced by
``name:``. Google-published builder images (``gcr.io/cloud-builders/*``
and ``gcr.io/google.com/cloudsdktool/*``) are updated regularly and a
tag-only reference silently pulls the new content on the next build.
Community images (``docker.io``, ``ghcr.io``, ``quay.io``) are worse:
the publisher can re-point the tag at will.

Reuses the shared ``_primitives.container_image`` classifier so the
digest-recognition regex matches the one used by AWS CB-009, TF
CB-009, and CFN CB-009.
"""
from __future__ import annotations

from typing import Any

from ..._primitives.container_image import classify
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_steps, step_name

RULE = Rule(
    id="GCB-001",
    title="Cloud Build step image not pinned by digest",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "Pin every ``steps[].name`` image to an ``@sha256:<digest>`` "
        "suffix. ``gcr.io/cloud-builders/docker:latest`` is mutable; "
        "Google publishes new builder images frequently and the next "
        "build would pull whatever is current. Resolve the digest "
        "with ``gcloud artifacts docker images describe <ref> "
        "--format='value(image_summary.digest)'`` and pin it."
    ),
    docs_note=(
        "Bare references (``gcr.io/cloud-builders/docker``) are "
        "treated as ``:latest`` by Cloud Build. Tag-only references "
        "(``:20``, ``:latest``) count as unpinned. Only ``@sha256:…`` "
        "suffixes pass."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    unpinned: list[str] = []
    any_step = False
    for idx, step in iter_steps(doc):
        any_step = True
        image = step.get("name")
        if not isinstance(image, str):
            continue
        info = classify(image)
        if info.pinned:
            continue
        unpinned.append(f"{step_name(step, idx)}={image}")
    if not any_step:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="No build steps declared in the document.",
            recommendation="No action required.", passed=True,
        )
    passed = not unpinned
    desc = (
        "Every step image is pinned by sha256 digest."
        if passed else
        f"{len(unpinned)} step image(s) are not digest-pinned: "
        f"{', '.join(unpinned[:5])}"
        f"{'…' if len(unpinned) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
