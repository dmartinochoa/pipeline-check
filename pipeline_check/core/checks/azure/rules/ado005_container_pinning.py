"""ADO-005 — container images must be pinned to a version or digest."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs
from ._helpers import image_reason

RULE = Rule(
    id="ADO-005",
    title="Container image not pinned to specific version",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-TRUSTED-REG"),
    recommendation=(
        "Reference images by `@sha256:<digest>` or at minimum a full "
        "immutable version tag. Avoid `:latest` and untagged refs."
    ),
    docs_note=(
        "Container images can be declared at `resources.containers[]."
        "image` or `job.container` (string or `{image:}`). Floating / "
        "untagged refs let the publisher swap the image contents."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    unpinned: list[str] = []
    resources = doc.get("resources", {})
    if isinstance(resources, dict):
        for rc in resources.get("containers", []) or []:
            if isinstance(rc, dict):
                img = rc.get("image")
                name = rc.get("container", "")
                if isinstance(img, str):
                    reason = image_reason(img)
                    if reason:
                        unpinned.append(f"resources.containers[{name}]: {reason}")
    for job_loc, job in iter_jobs(doc):
        c = job.get("container")
        img = None
        if isinstance(c, str) and (":" in c or "/" in c or "." in c):
            img = c
        elif isinstance(c, dict):
            i = c.get("image")
            if isinstance(i, str):
                img = i
        if img:
            reason = image_reason(img)
            if reason:
                unpinned.append(f"{job_loc}.container: {reason}")
    passed = not unpinned
    desc = (
        "Every container image is pinned to a specific version or digest."
        if passed else
        f"{len(unpinned)} container image(s) are floating / untagged: "
        f"{', '.join(unpinned[:5])}{'…' if len(unpinned) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
