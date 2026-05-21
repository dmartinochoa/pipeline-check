"""CC-003. Docker images in jobs/executors must be pinned by sha256 digest."""
from __future__ import annotations

from typing import Any

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_docker_image_anchors
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
        "`:18` are mutable, a registry compromise or upstream push "
        "silently replaces the image content."
    ),
    docs_note=(
        "Docker images referenced in `docker:` blocks under jobs or "
        "executors must include an `@sha256:...` digest suffix. Tag-only "
        "references (`:latest`, `:18`) are mutable and can be replaced "
        "at any time by whoever controls the upstream registry."
    ),
    exploit_example=(
        "# Vulnerable: ``cimg/python:3.12`` is a mutable tag.\n"
        "# CircleCI's image team rebuilds it on every Python\n"
        "# point release; a publisher compromise ships code into\n"
        "# every pipeline that uses the tag.\n"
        "version: 2.1\n"
        "jobs:\n"
        "  test:\n"
        "    docker:\n"
        "      - image: cimg/python:3.12\n"
        "    steps:\n"
        "      - run: pytest\n"
        "\n"
        "# Safe: pin to the content-addressable digest.\n"
        "version: 2.1\n"
        "jobs:\n"
        "  test:\n"
        "    docker:\n"
        "      - image: cimg/python@sha256:abc123...  # cimg/python:3.12.1\n"
        "    steps:\n"
        "      - run: pytest"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    pairs = list(iter_docker_image_anchors(doc))
    if not pairs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="No Docker images declared in the config.",
            recommendation="No action required.", passed=True,
        )
    unpinned: list[str] = []
    locations: list[Location] = []
    for img, anchor in pairs:
        if DIGEST_RE.search(img):
            continue
        unpinned.append(img)
        line = _line_of(anchor)
        locations.append(Location(path=path, start_line=line, end_line=line))
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
        locations=locations,
    )
