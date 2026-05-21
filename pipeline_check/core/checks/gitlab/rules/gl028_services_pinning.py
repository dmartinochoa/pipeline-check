"""GL-028, ``services:`` images must be pinned to a version or digest.

GL-001 / GL-009 only look at ``image:``. GitLab also lets jobs (and
the top-level document) declare ``services:`` for docker-in-docker,
databases, caches, and other sidecars, and those containers run in
the build network with the primary job. A ``:latest`` postgres
service is the same supply-chain risk as a ``:latest`` build image,
just historically missed by the pinning checks.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs
from ._helpers import DIGEST_RE, VERSION_TAG_RE

RULE = Rule(
    id="GL-028",
    title="services: image not pinned",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "Pin every ``services:`` entry the same way ``image:`` is "
        "pinned, prefer ``@sha256:<digest>``, or at minimum a full "
        "immutable version tag (``postgres:16.2-alpine``). Avoid "
        "``:latest`` and bare tags like ``:16``."
    ),
    docs_note=(
        "``services:`` entries (top-level or per-job) can be either a "
        "string (``redis:7``) or a dict (``{name: redis:7, alias: "
        "cache}``). Both forms are normalized via ``image_ref``-style "
        "extraction and evaluated with the same floating-tag regex "
        "GL-001 uses for ``image:``."
    ),
    exploit_example=(
        "# Vulnerable: ``services:`` references mutable image\n"
        "# tags. A publisher repoint (or namespace takeover) on\n"
        "# the services image swaps the code that runs alongside\n"
        "# every job using the service.\n"
        "integration:\n"
        "  image: app@sha256:abc123...\n"
        "  services:\n"
        "    - postgres:15\n"
        "    - redis:7\n"
        "  script: [pytest]\n"
        "\n"
        "# Safe: pin every services image to its digest.\n"
        "integration:\n"
        "  image: app@sha256:abc123...\n"
        "  services:\n"
        "    - postgres@sha256:def456...   # postgres:15.4\n"
        "    - redis@sha256:fed987...      # redis:7.2.4\n"
        "  script: [pytest]"
    ),
)


def _service_refs(value: Any) -> list[str]:
    """Return every image reference from a ``services:`` block.

    Accepts the list-of-string, list-of-dict, and mixed-list forms
    documented by GitLab.
    """
    if not isinstance(value, list):
        return []
    refs: list[str] = []
    for entry in value:
        if isinstance(entry, str):
            refs.append(entry)
        elif isinstance(entry, dict):
            name = entry.get("name")
            if isinstance(name, str):
                refs.append(name)
    return refs


def check(path: str, doc: dict[str, Any]) -> Finding:
    unpinned: list[str] = []

    def _inspect(ref: str, where: str) -> None:
        if DIGEST_RE.search(ref):
            return
        if ":" not in ref.rsplit("/", 1)[-1]:
            unpinned.append(f"{where}: {ref} (no tag)")
            return
        tag = ref.rsplit(":", 1)[1]
        if tag == "latest" or not VERSION_TAG_RE.search(ref):
            unpinned.append(f"{where}: {ref}")

    for ref in _service_refs(doc.get("services")):
        _inspect(ref, "<top-level>")
    for name, job in iter_jobs(doc):
        for ref in _service_refs(job.get("services")):
            _inspect(ref, name)

    # No services declared anywhere, silent pass.
    has_any = bool(_service_refs(doc.get("services"))) or any(
        _service_refs(j.get("services")) for _, j in iter_jobs(doc)
    )
    if not has_any:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Pipeline declares no ``services:`` entries.",
            recommendation="No action required.", passed=True,
        )
    passed = not unpinned
    desc = (
        "Every ``services:`` entry is pinned to a specific version or digest."
        if passed else
        f"{len(unpinned)} ``services:`` entr(ies) are floating or untagged: "
        f"{', '.join(unpinned[:5])}{'…' if len(unpinned) > 5 else ''}. "
        f"A ``:latest`` or bare-major sidecar can be silently swapped "
        f"and runs in the same build network as the job itself."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
