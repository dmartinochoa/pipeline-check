"""GL-001 — `image:` must be pinned to a specific version or digest."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs
from ._helpers import DIGEST_RE, VERSION_TAG_RE, image_ref


RULE = Rule(
    id="GL-001",
    title="Image not pinned to specific version or digest",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    recommendation=(
        "Reference images by `@sha256:<digest>` or at minimum a full "
        "immutable version tag (e.g. `python:3.12.1-slim`). Avoid "
        "`:latest` and bare tags like `:3`."
    ),
    docs_note=(
        "Floating tags (`latest` or major-only) can be silently "
        "swapped under the job. Every `image:` reference should pin "
        "a specific version tag or digest."
    ),
)


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

    top = image_ref(doc.get("image"))
    if top:
        _inspect(top, "<top-level>")
    for name, job in iter_jobs(doc):
        ref = image_ref(job.get("image"))
        if ref:
            _inspect(ref, name)

    passed = not unpinned
    desc = (
        "Every `image:` reference is pinned to a specific version or digest."
        if passed else
        f"{len(unpinned)} `image:` reference(s) are floating or untagged: "
        f"{', '.join(unpinned[:5])}{'…' if len(unpinned) > 5 else ''}. "
        f"Floating tags (`latest` or major-only) can be silently swapped "
        f"under the job."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
