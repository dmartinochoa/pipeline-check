"""GHA-003 — `run:` blocks must not interpolate attacker-controllable context."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity, is_quoted_assignment
from ...rule import Rule
from ..base import iter_jobs, iter_steps
from ._helpers import UNTRUSTED_CONTEXT_RE

RULE = Rule(
    id="GHA-003",
    title="Script injection via untrusted context",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    recommendation=(
        "Pass untrusted values through an intermediate `env:` variable "
        "and reference that variable from the shell script. GitHub's "
        "expression evaluation happens before shell quoting, so inline "
        "`${{ github.event.* }}` is always unsafe."
    ),
    docs_note=(
        "Interpolating attacker-controlled context fields (PR "
        "title/body, issue body, comment body, commit message, "
        "discussion body, head branch name, `github.ref_name`, "
        "`inputs.*`, release metadata, deployment payloads) directly "
        "into a `run:` block is shell injection. GitHub expands "
        "`${{ ... }}` BEFORE shell quoting, so any backtick, `$()`, "
        "or `;` in the source field executes."
    ),
)


def _tainted_env_vars(env_block: Any) -> set[str]:
    """Return env var names whose values contain untrusted context."""
    if not isinstance(env_block, dict):
        return set()
    tainted: set[str] = set()
    for name, value in env_block.items():
        if isinstance(value, str) and UNTRUSTED_CONTEXT_RE.search(value):
            tainted.add(str(name))
    return tainted


def _env_ref_in_run(run: str, var_names: set[str]) -> bool:
    """Check whether *run* unsafely references any tainted env var.

    References inside double-quoted strings (``"$VAR"``) are safe —
    bash does not re-evaluate command substitution inside variable
    expansion, so the value is treated as a literal.
    """
    for name in var_names:
        # $VAR, ${VAR}, or ${{ env.VAR }}
        ref_re = re.compile(
            rf"(?:\$\{{{name}\}}|\${name}\b|\${{{{[\s]*env\.{name}[\s]*}}}})"
        )
        for line in run.splitlines():
            if not ref_re.search(line):
                continue
            # If every reference on this line sits inside "...", it's safe.
            # Remove double-quoted segments and re-check.
            stripped = re.sub(r'"[^"]*"', "", line)
            if ref_re.search(stripped):
                return True  # unquoted reference found
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    # Workflow-level tainted env vars — inherited by all jobs.
    wf_tainted = _tainted_env_vars(doc.get("env"))
    for job_id, job in iter_jobs(doc):
        # Job-level env inherits workflow-level taint.
        job_tainted = wf_tainted | _tainted_env_vars(job.get("env"))
        for idx, step in enumerate(iter_steps(job)):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            # Step-level env inherits job + workflow taint.
            step_tainted = job_tainted | _tainted_env_vars(step.get("env"))
            # 1. Direct interpolation (existing detection).
            if UNTRUSTED_CONTEXT_RE.search(run) and not all(
                is_quoted_assignment(line) for line in run.splitlines()
                if UNTRUSTED_CONTEXT_RE.search(line)
            ):
                offenders.append(f"{job_id}[{idx}]")
            # 2. Indirect: tainted env var referenced in run block.
            elif step_tainted and _env_ref_in_run(run, step_tainted):
                offenders.append(f"{job_id}[{idx}]")
    passed = not offenders
    desc = (
        "No `run:` block interpolates attacker-controllable context fields."
        if passed else
        f"`run:` blocks interpolate untrusted context (directly or via "
        f"env: inheritance) into shell commands in: "
        f"{', '.join(offenders)}. These fields can contain shell "
        f"metacharacters that execute as part of the build."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
