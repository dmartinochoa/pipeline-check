"""ADO-002 — scripts must not interpolate attacker-controllable vars."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity, is_quoted_assignment
from ...rule import Rule
from ..base import iter_jobs, iter_steps
from ._helpers import UNTRUSTED_VAR_RE


RULE = Rule(
    id="ADO-002",
    title="Script injection via attacker-controllable context",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    recommendation=(
        "Pass these values through an intermediate pipeline variable "
        "declared with `readonly: true`, and reference that variable "
        "through an environment variable rather than `$(...)` macro "
        "interpolation. ADO expands `$(…)` before shell quoting, so "
        "inline use is never safe."
    ),
    docs_note=(
        "`$(Build.SourceBranch*)`, `$(Build.SourceVersionMessage)`, "
        "and `$(System.PullRequest.*)` are populated from SCM event "
        "metadata the attacker controls. Inline interpolation into a "
        "script body executes crafted content."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for job_loc, job in iter_jobs(doc):
        for step_loc, step in iter_steps(job):
            for key in ("script", "bash", "pwsh", "powershell"):
                body = step.get(key)
                if not isinstance(body, str):
                    continue
                if UNTRUSTED_VAR_RE.search(body) and not is_quoted_assignment(body):
                    offenders.append(f"{job_loc}.{step_loc}")
                    break
    passed = not offenders
    desc = (
        "No script interpolates attacker-controllable build or PR metadata."
        if passed else
        f"Script(s) in {', '.join(sorted(set(offenders))[:5])} "
        f"interpolate $(Build.SourceBranch*), "
        f"$(Build.SourceVersionMessage), or $(System.PullRequest.*) "
        f"directly into shell commands."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
