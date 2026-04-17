"""CC-003 — Docker images in jobs/executors must be pinned by sha256 digest."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import get_docker_images
from ._helpers import DIGEST_RE

RULE = Rule(
    id="CC-003",
    title="Docker image not pinned by digest",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "Pin every Docker image to its sha256 digest: "
        "`cimg/node:18@sha256:abc123...`. Tags like `:latest` or "
        "`:18` are mutable — a registry compromise or upstream push "
        "silently replaces the image content."
    ),
    docs_note=(
        "Docker images referenced in `docker:` blocks under jobs or "
        "executors must include an `@sha256:...` digest suffix. Tag-only "
        "references (`:latest`, `:18`) are mutable and can be replaced "
        "at any time by whoever controls the upstream registry."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    images = get_docker_images(doc)
    if not images:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="No Docker images declared in the config.",
            recommendation="No action required.", passed=True,
        )
    unpinned = [img for img in images if not DIGEST_RE.search(img)]
    passed = not unpinned
    desc = (
        "Every Docker image is pinned by sha256 digest."
        if passed else
        f"{len(unpinned)} Docker image(s) are not pinned by digest: "
        f"{', '.join(sorted(set(unpinned))[:5])}"
        f"{'...' if len(set(unpinned)) > 5 else ''}. "
        f"Tag-only references are mutable and can be silently replaced."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
