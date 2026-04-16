"""ADO-002 — scripts must not interpolate attacker-controllable vars."""
from __future__ import annotations

import re
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
    cwe=("CWE-78",),
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


def _tainted_vars(variables_block: Any) -> set[str]:
    """Return variable names whose values contain untrusted ADO macros."""
    if not isinstance(variables_block, (dict, list)):
        return set()
    tainted: set[str] = set()
    if isinstance(variables_block, dict):
        for name, value in variables_block.items():
            if isinstance(value, str) and UNTRUSTED_VAR_RE.search(value):
                tainted.add(str(name))
    else:
        for item in variables_block:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            value = item.get("value")
            if isinstance(name, str) and isinstance(value, str) and UNTRUSTED_VAR_RE.search(value):
                tainted.add(name)
    return tainted


def _var_ref_in_body(body: str, var_names: set[str]) -> bool:
    """Return True if *body* unsafely references a tainted variable.

    Checks ADO ``$(VAR)`` macro syntax, ``$env:VAR`` (PowerShell),
    and ``$VAR`` / ``${VAR}`` (bash) references.
    """
    for name in var_names:
        ref_re = re.compile(
            rf"\$\(\s*{re.escape(name)}\s*\)"        # $(VAR)
            rf"|\$env:{re.escape(name)}\b"            # $env:VAR
            rf"|\$\{{?{re.escape(name)}\}}?"          # $VAR / ${VAR}
        )
        for line in body.splitlines():
            if not ref_re.search(line):
                continue
            if is_quoted_assignment(line):
                continue
            stripped = re.sub(r'"[^"]*"', "", line)
            if ref_re.search(stripped):
                return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    # Pipeline-level tainted variables.
    pipeline_tainted = _tainted_vars(doc.get("variables"))
    for job_loc, job in iter_jobs(doc):
        job_tainted = pipeline_tainted | _tainted_vars(job.get("variables"))
        for step_loc, step in iter_steps(job):
            for key in ("script", "bash", "pwsh", "powershell"):
                body = step.get(key)
                if not isinstance(body, str):
                    continue
                loc = f"{job_loc}.{step_loc}"
                # 1. Direct interpolation of untrusted ADO macros.
                if UNTRUSTED_VAR_RE.search(body) and not is_quoted_assignment(body):
                    offenders.append(loc)
                    break
                # 2. Indirect: tainted variable referenced unquoted.
                if job_tainted and _var_ref_in_body(body, job_tainted):
                    offenders.append(loc)
                    break
    passed = not offenders
    desc = (
        "No script interpolates attacker-controllable build or PR metadata."
        if passed else
        f"Script(s) in {', '.join(sorted(set(offenders))[:5])} "
        f"interpolate $(Build.SourceBranch*), "
        f"$(Build.SourceVersionMessage), or $(System.PullRequest.*) "
        f"directly or via variables: inheritance into shell commands."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
