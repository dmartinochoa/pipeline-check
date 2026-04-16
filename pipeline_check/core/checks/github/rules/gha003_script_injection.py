"""GHA-003 — `run:` blocks must not interpolate attacker-controllable context."""
from __future__ import annotations

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


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            # Skip lines that are the safe capture-into-variable idiom.
            if UNTRUSTED_CONTEXT_RE.search(run) and not all(
                is_quoted_assignment(line) for line in run.splitlines()
                if UNTRUSTED_CONTEXT_RE.search(line)
            ):
                offenders.append(f"{job_id}[{idx}]")
    passed = not offenders
    desc = (
        "No `run:` block interpolates attacker-controllable context fields."
        if passed else
        f"`run:` blocks interpolate untrusted github.event fields (PR "
        f"title/body, commit messages, comments) directly into shell "
        f"commands in: {', '.join(offenders)}. These fields can contain "
        f"shell metacharacters that execute as part of the build."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
