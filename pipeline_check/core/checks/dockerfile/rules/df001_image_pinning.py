"""DF-001, `FROM` not pinned to ``@sha256:<digest>``."""
from __future__ import annotations

from ..._primitives.anchors import oci_image
from ..._primitives.image_pinning import PinKind, classify
from ...base import Finding, Location, ResourceAnchor, Severity
from ...rule import Rule
from ..base import Dockerfile, from_refs

RULE = Rule(
    id="DF-001",
    title="FROM image not pinned to sha256 digest",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "Resolve every base image to its current digest "
        "(``docker buildx imagetools inspect <ref>`` prints it) and "
        "pin via ``FROM repo@sha256:<digest>``. Automate refreshes "
        "with Renovate or Dependabot. A floating tag (``:latest``, "
        "``:3``, no tag) silently swaps the build base under every "
        "rebuild."
    ),
    docs_note=(
        "Reuses ``_primitives/image_pinning.classify`` so the floating-"
        "tag semantics match GL-001 / JF-009 / ADO-009 / CC-003. "
        "``PINNED_TAG`` (e.g. ``python:3.12.1-slim``) is treated as "
        "unpinned here too, only an explicit ``@sha256:`` survives, "
        "since the tag is mutable on the registry side."
    ),
    incident_refs=(
        "Docker Hub typosquatting / namespace-takeover incidents "
        "(2017 onward): docker-library Sysdig and Aqua research "
        "documented thousands of malicious images uploaded under "
        "near-miss names (``alpine`` vs ``alphine``, etc.) and "
        "occasional namespace recoveries shipping crypto-miners "
        "downstream. Digest-pinned consumers are immune; "
        "tag-pinned consumers pull whatever sits under the name "
        "today.",
        "Codecov ``codecov/codecov-action`` tag-mutation incident "
        "(post-Codecov-Bash-uploader compromise): the upstream "
        "rotated the action's ``@v3`` tag during the fallout, and "
        "consumers pinning to the tag silently re-ran a different "
        "build than before. Digest pinning would have surfaced the "
        "change as a checksum mismatch instead of a silent swap.",
    ),
    exploit_example=(
        "# Vulnerable: ``python:3.12-slim`` is a tag, and tags on\n"
        "# Docker Hub are mutable. Python's publishers can (and do)\n"
        "# repoint the same tag at a new image on every point\n"
        "# release, and namespace takeovers / hijacked publisher\n"
        "# accounts can silently swap a malicious image under the\n"
        "# existing tag. The next rebuild picks up whatever's there\n"
        "# now, with no signal to the consumer that the base\n"
        "# changed.\n"
        "FROM python:3.12-slim\n"
        "COPY . /app\n"
        "RUN pip install --require-hashes -r /app/requirements.txt\n"
        "CMD [\"python\", \"/app/main.py\"]\n"
        "\n"
        "# Safe: pin to the immutable sha256 digest. The leading\n"
        "# comment documents which tag the digest corresponds to.\n"
        "# Renovate / Dependabot's Docker ecosystem updaters resolve\n"
        "# and bump these on a schedule so the pin doesn't drift\n"
        "# behind security patches.\n"
        "# python:3.12.1-slim (refreshed YYYY-MM-DD)\n"
        "FROM python:3.12-slim@sha256:abc123...\n"
        "COPY . /app\n"
        "RUN pip install --require-hashes -r /app/requirements.txt\n"
        "CMD [\"python\", \"/app/main.py\"]"
    ),
)


def check(df: Dockerfile) -> Finding:
    unpinned: list[str] = []
    locations: list[Location] = []
    anchors: list[ResourceAnchor] = []
    seen_identities: set[str] = set()
    for line_no, ref in from_refs(df):
        kind = classify(ref)
        if kind is PinKind.DIGEST:
            continue
        unpinned.append(f"L{line_no}: {ref} ({kind.value})")
        locations.append(Location(
            path=df.path, start_line=line_no, end_line=line_no,
        ))
        # ResourceAnchor phase 1: XPC-002 intersects DF-001 and
        # K8S-001 on the canonical ``oci_image`` identity to confirm
        # the same image flows from build base to runtime workload.
        anchor = oci_image(ref)
        if anchor is not None and anchor.identity not in seen_identities:
            seen_identities.add(anchor.identity)
            anchors.append(anchor)
    passed = not unpinned
    desc = (
        "Every ``FROM`` reference is pinned by sha256 digest."
        if passed else
        f"{len(unpinned)} ``FROM`` reference(s) are not digest-"
        f"pinned: {', '.join(unpinned[:5])}"
        f"{'…' if len(unpinned) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
        resource_anchors=tuple(anchors) if not passed else (),
    )
