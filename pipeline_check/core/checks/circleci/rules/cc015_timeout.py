"""CC-015 — run steps should have no_output_timeout configured."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity, blob_lower
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="CC-015",
    title="No `no_output_timeout` configured",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-BUILD-TIMEOUT",),
    cwe=("CWE-400",),
    recommendation=(
        "Add `no_output_timeout:` to long-running run steps, or set "
        "it at the job level. A reasonable default is 10-30 minutes. "
        "CircleCI's default of 10 minutes may be too long for some "
        "pipelines and absent for others."
    ),
    docs_note=(
        "Without `no_output_timeout`, a hung step can consume "
        "executor time indefinitely. Explicit timeouts cap cost and "
        "the window during which a compromised step has access to "
        "secrets and the build environment."
    ),
)


def _has_timeout(doc: dict[str, Any]) -> bool:
    """Return True if any run step declares ``no_output_timeout``."""
    for _job_id, job in iter_jobs(doc):
        for step in iter_steps(job):
            if isinstance(step, dict):
                run = step.get("run")
                if isinstance(run, dict) and "no_output_timeout" in run:
                    return True
    # Fallback: check blob for the token (covers anchors, orb params, etc.)
    return "no_output_timeout" in blob_lower(doc)


def check(path: str, doc: dict[str, Any]) -> Finding:
    passed = _has_timeout(doc)
    desc = (
        "Config contains `no_output_timeout` configuration."
        if passed else
        "No `no_output_timeout` found in any run step. Hung steps "
        "may run indefinitely."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
