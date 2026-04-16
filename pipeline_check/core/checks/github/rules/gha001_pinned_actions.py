"""GHA-001 — Actions must be pinned to a 40-char commit SHA."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps
from ._helpers import SHA_RE

RULE = Rule(
    id="GHA-001",
    title="Action not pinned to commit SHA",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    recommendation=(
        "Replace tag/branch references (`@v4`, `@main`) with the full "
        "40-char commit SHA. Use Dependabot or StepSecurity to keep the "
        "pins fresh."
    ),
    docs_note=(
        "Every `uses:` reference should pin a specific 40-char commit "
        "SHA. Tag and branch refs (`@v4`, `@main`) can be silently "
        "moved to malicious commits by whoever controls the upstream "
        "repository — a third-party action compromise will propagate "
        "into the pipeline on the next run."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    unpinned: list[str] = []
    for _, job in iter_jobs(doc):
        for step in iter_steps(job):
            uses = step.get("uses")
            if not isinstance(uses, str) or "@" not in uses:
                continue
            # Docker image refs and local path refs are out of scope.
            if uses.startswith(("docker://", "./", "/")):
                continue
            ref = uses.rsplit("@", 1)[1]
            if not SHA_RE.match(ref):
                unpinned.append(uses)
    passed = not unpinned
    desc = (
        "Every `uses:` reference is pinned to a 40-char commit SHA."
        if passed else
        f"{len(unpinned)} action reference(s) are pinned to a tag or "
        f"branch rather than a commit SHA: "
        f"{', '.join(sorted(set(unpinned))[:5])}"
        f"{'…' if len(set(unpinned)) > 5 else ''}. "
        f"Tags and branches can be moved to malicious commits by "
        f"whoever controls the upstream repository."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
