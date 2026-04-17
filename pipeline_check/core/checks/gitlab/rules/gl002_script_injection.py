"""GL-002 — scripts must not interpolate attacker-controllable commit/MR vars."""
from __future__ import annotations

import re
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
    cwe=("CWE-78",),
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


def _tainted_vars(variables_block: Any) -> set[str]:
    """Return variable names whose values contain untrusted CI variables."""
    if not isinstance(variables_block, dict):
        return set()
    tainted: set[str] = set()
    for name, value in variables_block.items():
        raw = value
        # GitLab variables can be ``{value: "...", description: "..."}``.
        if isinstance(value, dict):
            raw = value.get("value")
        if isinstance(raw, str) and UNTRUSTED_VAR_RE.search(raw):
            tainted.add(str(name))
    return tainted


def _var_ref_in_scripts(lines: list[str], var_names: set[str]) -> bool:
    """Return True if any *line* unsafely references a tainted variable."""
    for name in var_names:
        ref_re = re.compile(rf"\$\{{?{re.escape(name)}\}}?")
        for line in lines:
            if not ref_re.search(line):
                continue
            if is_quoted_assignment(line):
                continue
            # Remove double-quoted segments and re-check.
            stripped = re.sub(r'"[^"]*"', "", line)
            if ref_re.search(stripped):
                return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    # Pipeline-level tainted variables — inherited by all jobs.
    global_tainted = _tainted_vars(doc.get("variables"))
    for name, job in iter_jobs(doc):
        scripts = job_scripts(job)
        # 1. Direct interpolation of untrusted predefined vars.
        for line in scripts:
            if UNTRUSTED_VAR_RE.search(line) and not is_quoted_assignment(line):
                offenders.append(name)
                break
        else:
            # 2. Indirect: tainted variable set in variables: block then
            #    referenced unquoted in a script line.
            job_tainted = global_tainted | _tainted_vars(job.get("variables"))
            if job_tainted and _var_ref_in_scripts(scripts, job_tainted):
                offenders.append(name)
    passed = not offenders
    desc = (
        "No script interpolates attacker-controllable commit/MR metadata."
        if passed else
        f"Script(s) in job(s) {', '.join(sorted(set(offenders)))} "
        f"interpolate attacker-controllable variables "
        f"(CI_COMMIT_MESSAGE, CI_MERGE_REQUEST_TITLE, CI_COMMIT_BRANCH, "
        f"etc.) directly or via variables: inheritance into shell commands."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
