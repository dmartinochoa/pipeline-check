"""DF-001, `FROM` not pinned to ``@sha256:<digest>``."""
from __future__ import annotations

from ..._primitives.image_pinning import PinKind, classify
from ...base import Finding, Location, Severity
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
)


def check(df: Dockerfile) -> Finding:
    unpinned: list[str] = []
    locations: list[Location] = []
    for line_no, ref in from_refs(df):
        kind = classify(ref)
        if kind is PinKind.DIGEST:
            continue
        unpinned.append(f"L{line_no}: {ref} ({kind.value})")
        locations.append(Location(
            path=df.path, start_line=line_no, end_line=line_no,
        ))
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
    )
