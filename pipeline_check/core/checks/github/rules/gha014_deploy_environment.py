"""GHA-014 — deploy jobs should bind a GitHub environment."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs

_DEPLOY_RE = re.compile(r"(?i)(deploy|release|publish|promote)")


RULE = Rule(
    id="GHA-014",
    title="Deploy job missing environment binding",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    esf=("ESF-C-APPROVAL", "ESF-C-ENV-SEP"),
    recommendation=(
        "Add `environment: <name>` to jobs that deploy. Configure "
        "required reviewers, wait timers, and branch-protection rules "
        "on the matching GitHub environment."
    ),
    docs_note=(
        "Without an `environment:` binding, a deploy job can't "
        "be gated by required reviewers, deployment-branch policies, "
        "or wait timers. Any push to the triggering branch will "
        "deploy immediately."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    ungated: list[str] = []
    for job_id, job in iter_jobs(doc):
        if not _DEPLOY_RE.search(job_id):
            continue
        if not job.get("environment"):
            ungated.append(job_id)
    passed = not ungated
    desc = (
        "Every deploy-named job binds a GitHub environment."
        if passed else
        f"{len(ungated)} deploy job(s) have no `environment:` binding: "
        f"{', '.join(ungated)}. Without an environment, the job "
        f"cannot be gated by required reviewers or branch policies."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
