"""GL-002, scripts must not interpolate attacker-controllable commit/MR vars."""
from __future__ import annotations

import re
from typing import Any

from ..._primitives.tainted_variables import (
    has_direct_taint,
    has_unsafe_reference,
)
from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
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
    """Return variable names whose values reference untrusted CI variables.

    GitLab variable values can be either a plain string or a dict
    ``{value: "...", description: "..."}``, both shapes are accepted.
    """
    if not isinstance(variables_block, dict):
        return set()
    tainted: set[str] = set()
    for name, value in variables_block.items():
        raw = value.get("value") if isinstance(value, dict) else value
        if isinstance(raw, str) and UNTRUSTED_VAR_RE.search(raw):
            tainted.add(str(name))
    return tainted


def _gl_ref_pattern(name: str) -> str:
    """Match GitLab shell reference syntax for *name*: ``$VAR`` / ``${VAR}``."""
    return rf"\$\{{?{re.escape(name)}\}}?"


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    # Pipeline-level tainted variables, inherited by all jobs.
    global_tainted = _tainted_vars(doc.get("variables"))
    for name, job in iter_jobs(doc):
        scripts = job_scripts(job)
        hit = False
        # 1. Direct interpolation of untrusted predefined vars.
        if has_direct_taint(scripts, UNTRUSTED_VAR_RE):
            offenders.append(name)
            hit = True
        else:
            # 2. Indirect: tainted variable set in variables: block then
            #    referenced unquoted in a script line.
            job_tainted = global_tainted | _tainted_vars(job.get("variables"))
            if job_tainted and has_unsafe_reference(
                scripts, job_tainted, ref_pattern=_gl_ref_pattern
            ):
                offenders.append(name)
                hit = True
        if hit:
            line = _line_of(job)
            locations.append(Location(
                path=path, start_line=line, end_line=line,
            ))
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
        locations=locations,
    )
