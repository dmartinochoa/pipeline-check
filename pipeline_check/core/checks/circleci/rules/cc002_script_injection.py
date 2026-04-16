"""CC-002 — run: commands must not interpolate attacker-controllable env vars."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_run_commands
from ._helpers import UNTRUSTED_ENV_RE

RULE = Rule(
    id="CC-002",
    title="Script injection via untrusted environment variable",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-78",),
    recommendation=(
        "Do not interpolate attacker-controllable environment variables "
        "(CIRCLE_BRANCH, CIRCLE_TAG, CIRCLE_PR_NUMBER, etc.) directly "
        "into shell commands. Pass them through an intermediate variable "
        "and quote them, or use CircleCI pipeline parameters instead."
    ),
    docs_note=(
        "CircleCI exposes environment variables like `$CIRCLE_BRANCH`, "
        "`$CIRCLE_TAG`, and `$CIRCLE_PR_NUMBER` that are controlled by "
        "the event source (branch name, tag, PR). Interpolating them "
        "unquoted into `run:` commands allows shell injection via "
        "specially crafted branch or tag names."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        for idx, cmd in enumerate(iter_run_commands(job)):
            if UNTRUSTED_ENV_RE.search(cmd):
                offenders.append(f"{job_id}[{idx}]")
    passed = not offenders
    desc = (
        "No `run:` command interpolates attacker-controllable environment "
        "variables."
        if passed else
        f"{len(offenders)} `run:` command(s) interpolate untrusted "
        f"environment variables (CIRCLE_BRANCH, CIRCLE_TAG, etc.): "
        f"{', '.join(offenders)}. These variables can contain shell "
        f"metacharacters that execute as part of the build."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
