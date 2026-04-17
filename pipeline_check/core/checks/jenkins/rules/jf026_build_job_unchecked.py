"""JF-026 — ``build job:`` trigger must wait for and propagate downstream results."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile
from ._helpers import (
    BUILD_JOB_RE,
    BUILD_PROPAGATE_FALSE_RE,
    BUILD_WAIT_FALSE_RE,
)

RULE = Rule(
    id="JF-026",
    title="`build job:` trigger ignores downstream failure",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-4",),
    esf=("ESF-C-APPROVAL",),
    cwe=("CWE-754",),
    recommendation=(
        "Remove ``wait: false`` and ``propagate: false`` from every "
        "``build job:`` step, or replace them with an explicit "
        "``currentBuild.result = build(...).result`` check. A "
        "fire-and-forget trigger can silently ship broken artifacts "
        "because the upstream job reports success regardless of what "
        "the downstream job actually did."
    ),
    docs_note=(
        "The Jenkins Pipeline plugin defaults ``wait`` to ``true`` and "
        "``propagate`` to ``true``, but either can be flipped per call. "
        "``wait: false`` returns immediately; ``propagate: false`` "
        "continues even when the downstream job fails or is aborted. "
        "Both patterns sever the flow-control link between the upstream "
        "approval gate and the work the downstream job is about to do."
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    jobs = BUILD_JOB_RE.findall(jf.text)
    if not jobs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=jf.path,
            description="Pipeline does not trigger downstream jobs via ``build job:``.",
            recommendation="No action required.", passed=True,
        )
    problems: list[str] = []
    if BUILD_WAIT_FALSE_RE.search(jf.text):
        problems.append("wait: false")
    if BUILD_PROPAGATE_FALSE_RE.search(jf.text):
        problems.append("propagate: false")
    passed = not problems
    desc = (
        f"Pipeline triggers downstream job(s) ({', '.join(sorted(set(jobs))[:3])}"
        f"{'…' if len(set(jobs)) > 3 else ''}) but waits for and propagates their result."
        if passed else
        f"Pipeline triggers downstream job(s) with {', '.join(problems)} — "
        "downstream failures won't abort the upstream pipeline."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
