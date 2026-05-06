"""GHA-003 — `run:` blocks must not interpolate attacker-controllable context."""
from __future__ import annotations

from typing import Any

from ..._primitives.tainted_variables import (
    has_direct_taint,
    has_unsafe_reference,
)
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps
from ._helpers import UNTRUSTED_CONTEXT_RE

RULE = Rule(
    id="GHA-003",
    title="Script injection via untrusted context",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-78",),
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
    """Return env var names whose values reference untrusted context."""
    if not isinstance(env_block, dict):
        return set()
    return {
        str(name)
        for name, value in env_block.items()
        if isinstance(value, str) and UNTRUSTED_CONTEXT_RE.search(value)
    }


def _gha_ref_pattern(name: str) -> str:
    """Match every GHA reference syntax for *name*: ``$VAR``, ``${VAR}``,
    or ``${{ env.VAR }}``."""
    return rf"(?:\$\{{{name}\}}|\${name}\b|\${{{{[\s]*env\.{name}[\s]*}}}})"


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
            lines = run.splitlines()
            # Step-level env inherits job + workflow taint.
            step_tainted = job_tainted | _tainted_env_vars(step.get("env"))
            # 1. Direct interpolation of untrusted context expressions.
            if has_direct_taint(lines, UNTRUSTED_CONTEXT_RE):
                offenders.append(f"{job_id}[{idx}]")
            # 2. Indirect: tainted env var referenced in run block.
            elif step_tainted and has_unsafe_reference(
                lines, step_tainted, ref_pattern=_gha_ref_pattern
            ):
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
