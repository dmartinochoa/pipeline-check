"""CC-029 — Machine executor image must be pinned to an immutable tag."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs

RULE = Rule(
    id="CC-029",
    title="Machine executor image not pinned",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "Pin every ``machine.image`` to a dated release tag — "
        "``ubuntu-2204:2024.05.1`` rather than ``:current``, ``:edge``, "
        "``:default``, or a bare image name. CircleCI rotates the "
        "``current`` / ``edge`` aliases on its own cadence, so builds "
        "re-run on an image the author never reviewed."
    ),
    docs_note=(
        "CC-003 covers Docker images declared under ``docker:`` blocks "
        "— it does not reach the machine executor, where the image is "
        "on ``machine.image``. A rolling tag (``current``, ``edge``, "
        "``default``) pulls a fresh image whenever CircleCI publishes "
        "one, reintroducing the same supply-chain risk Docker-image "
        "pinning is designed to eliminate."
    ),
)

# Immutable image tags from CircleCI — dated release suffix, e.g.
# ``ubuntu-2204:2024.05.1`` or ``android:2024.01.1-node``. The leading
# four-digit year gates the whole family so we don't have to hard-code
# every current image family.
_IMMUTABLE_TAG_RE = re.compile(r":\d{4}\.\d{1,2}(?:\.\d+)?(?:-[A-Za-z0-9_.-]+)?$")

# Rolling / alias tags that float and should never be relied on.
_ROLLING_TAGS = ("current", "edge", "default", "latest", "stable")


def _image_from_machine(machine: Any) -> str | None:
    """Return the image string from a ``machine:`` block, regardless of shape.

    CircleCI accepts:
      - ``machine: true`` (default image — equivalent to unpinned)
      - ``machine: {image: <ref>}``
      - ``machine: {image: <ref>, docker_layer_caching: ...}``
    """
    if machine is True:
        return "default"
    if isinstance(machine, dict):
        img = machine.get("image")
        return img if isinstance(img, str) else None
    return None


def check(path: str, doc: dict[str, Any]) -> Finding:
    unpinned: list[tuple[str, str]] = []
    saw_machine = False
    for job_id, job in iter_jobs(doc):
        image = _image_from_machine(job.get("machine"))
        if image is None:
            continue
        saw_machine = True
        _, _, suffix = image.partition(":")
        if not suffix or suffix.lower() in _ROLLING_TAGS:
            unpinned.append((job_id, image))
            continue
        if not _IMMUTABLE_TAG_RE.search(image):
            unpinned.append((job_id, image))
    if not saw_machine:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="No machine executor declared in the config.",
            recommendation="No action required.", passed=True,
        )
    passed = not unpinned
    desc = (
        "Every machine executor image is pinned to an immutable tag."
        if passed else
        f"{len(unpinned)} machine executor(s) use a rolling or unpinned "
        f"image: "
        + ", ".join(f"{job}={img!r}" for job, img in unpinned[:5])
        + ("..." if len(unpinned) > 5 else "")
        + ". Rolling tags silently pull whatever CircleCI last published."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
