"""GL-002 — scripts must not interpolate attacker-controllable commit/MR vars."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity, is_quoted_assignment
from ...rule import Rule
from ..base import iter_jobs, job_scripts
from ._helpers import UNTRUSTED_VAR_RE


RULE = Rule(
    id="GL-002",
    title="Script injection via untrusted commit/MR context",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    recommendation=(
        "Read these values into intermediate `variables:` entries or "
        "shell variables and quote them defensively (`\"$BRANCH\"`). "
        "Never inline `$CI_COMMIT_MESSAGE` / `$CI_MERGE_REQUEST_TITLE` "
        "into a shell command."
    ),
    docs_note=(
        "CI_COMMIT_MESSAGE / CI_COMMIT_REF_NAME / CI_MERGE_REQUEST_TITLE "
        "and friends are populated from SCM event metadata the attacker "
        "controls. Interpolating them into a shell body executes the "
        "crafted content as part of the build."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for name, job in iter_jobs(doc):
        for line in job_scripts(job):
            if UNTRUSTED_VAR_RE.search(line) and not is_quoted_assignment(line):
                offenders.append(name)
                break
    passed = not offenders
    desc = (
        "No script interpolates attacker-controllable commit/MR metadata."
        if passed else
        f"Script(s) in job(s) {', '.join(sorted(set(offenders)))} "
        f"interpolate attacker-controllable variables "
        f"(CI_COMMIT_MESSAGE, CI_MERGE_REQUEST_TITLE, CI_COMMIT_BRANCH, "
        f"etc.) directly into shell commands."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
