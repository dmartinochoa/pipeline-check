"""ADO-009 — containers should pin by sha256 digest (strictest tier)."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs
from ._helpers import DIGEST_RE


RULE = Rule(
    id="ADO-009",
    title="Container image pinned by tag rather than sha256 digest",
    severity=Severity.LOW,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE"),
    recommendation=(
        "Resolve each image to its current digest and replace the "
        "tag with `@sha256:<digest>`. Schedule regular digest bumps "
        "via Renovate or a scheduled pipeline."
    ),
    docs_note=(
        "ADO-005 fails floating tags at HIGH; ADO-009 is the "
        "stricter tier. Even immutable-looking version tags can be "
        "repointed by registry operators."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    tagged: list[str] = []

    def _inspect(img: str, where: str) -> None:
        if DIGEST_RE.search(img):
            return
        tagged.append(f"{where}: {img}")

    resources = doc.get("resources", {})
    if isinstance(resources, dict):
        for rc in resources.get("containers", []) or []:
            if isinstance(rc, dict):
                img = rc.get("image")
                name = rc.get("container", "")
                if isinstance(img, str):
                    _inspect(img, f"resources.containers[{name}]")
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
            _inspect(img, f"{job_loc}.container")

    passed = not tagged
    desc = (
        "Every container image is pinned by sha256 digest."
        if passed else
        f"{len(tagged)} container image(s) are pinned by version "
        f"tag rather than digest: {', '.join(tagged[:5])}"
        f"{'…' if len(tagged) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
