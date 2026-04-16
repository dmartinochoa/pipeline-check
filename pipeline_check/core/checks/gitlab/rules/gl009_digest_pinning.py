"""GL-009 — images should be pinned by sha256 digest (strictest tier)."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs
from ._helpers import DIGEST_RE, image_ref


RULE = Rule(
    id="GL-009",
    title="Image pinned to version tag rather than sha256 digest",
    severity=Severity.LOW,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE"),
    recommendation=(
        "Resolve each image to its current digest (`docker buildx "
        "imagetools inspect <ref>` prints it) and replace the tag "
        "with `@sha256:<digest>`. Automate refreshes with Renovate."
    ),
    docs_note=(
        "GL-001 fails floating tags at HIGH; GL-009 is the stricter "
        "tier. Even immutable-looking version tags (`python:3.12.1`) "
        "can be repointed by registry operators. Digest pins are the "
        "only tamper-evident form."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    tagged: list[str] = []

    def _inspect(ref: str, where: str) -> None:
        if DIGEST_RE.search(ref):
            return
        tagged.append(f"{where}: {ref}")

    top = image_ref(doc.get("image"))
    if top:
        _inspect(top, "<top-level>")
    for name, job in iter_jobs(doc):
        ref = image_ref(job.get("image"))
        if ref:
            _inspect(ref, name)

    passed = not tagged
    desc = (
        "Every pinned image uses an sha256 digest."
        if passed else
        f"{len(tagged)} image reference(s) are pinned by version tag "
        f"rather than sha256 digest: {', '.join(tagged[:5])}"
        f"{'…' if len(tagged) > 5 else ''}. Registry operators or "
        f"compromised namespaces can repoint a tag; a digest cannot "
        f"be retargeted."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
