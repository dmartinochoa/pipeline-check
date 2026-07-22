"""GL-048. Untrusted MR/commit context reaches an agentic AI CLI.

The GitLab analog of GHA-119, and the AI face of GL-002 (script
injection). An agentic CLI (``claude`` / ``gemini`` / ``cursor-agent`` /
``aider`` / ``openhands`` / ``goose`` / ``q chat``) reads a prompt and then
*acts*: runs shell, writes files, calls tools. When a job's ``script``
feeds attacker-controllable GitLab context (``$CI_MERGE_REQUEST_TITLE`` /
``$CI_MERGE_REQUEST_DESCRIPTION`` / ``$CI_COMMIT_MESSAGE`` / a source-branch
name) into that prompt, anyone who can open an MR can smuggle instructions
the agent then executes ("ignore previous instructions and run ...").

Crucially, the ``variables:`` / shell-quoting indirection that defangs
shell injection (GL-002) does NOT help here: the model ingests the value as
prompt text regardless of how it is quoted or routed, so passing untrusted
content through a quoted variable is not a fix. That is why this is a
separate rule from GL-002.
"""
from __future__ import annotations

import re
from typing import Any

from ..._primitives.agentic_cli import invokes_agentic_cli
from ..._primitives.tainted_variables import has_direct_taint
from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, job_scripts
from ._helpers import UNTRUSTED_VAR_RE

RULE = Rule(
    id="GL-048",
    title="Untrusted MR/commit context reaches an agentic AI CLI (prompt injection)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-94", "CWE-77"),
    recommendation=(
        "Do not place attacker-controllable context (MR / commit / "
        "branch-name metadata) in an agentic CLI's prompt. A quoted "
        "``variables:`` entry does NOT sanitize a prompt the way it does a "
        "shell command, the model still reads the value. If the agent must "
        "see MR content, run it with no write-scoped ``CI_JOB_TOKEN`` and "
        "no tool / shell access on a job gated to no production secrets, "
        "and treat its output as untrusted."
    ),
    docs_note=(
        "The AI analog of GL-002 (script injection). Fires when a job "
        "``script`` line invokes an agentic CLI (claude / gemini / "
        "cursor-agent / aider / openhands / goose / ``q chat``) AND "
        "attacker-controllable GitLab context reaches that line, either a "
        "predefined untrusted variable interpolated directly "
        "(``$CI_MERGE_REQUEST_TITLE``) or a ``variables:`` entry whose value "
        "carries one. Unlike a shell, an LLM ingests a quoted / "
        "variable-routed value as prompt text, so the GL-002 mitigation "
        "(route through a quoted variable) does not apply, which is why "
        "this is a separate rule."
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
    """Match GitLab shell reference syntax for *name*: ``$VAR`` / ``${VAR}``.

    The trailing ``(?![A-Za-z0-9_])`` boundary keeps a tainted name that
    is a prefix of a clean one (``$TITLE`` vs the sanitized
    ``$TITLE_SAFE``) from matching the clean reference.
    """
    return rf"\$\{{?{re.escape(name)}\}}?(?![A-Za-z0-9_])"


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    anchor_jobs: dict[str, None] = {}
    global_tainted = _tainted_vars(doc.get("variables"))
    for job_id, job in iter_jobs(doc):
        job_tainted = global_tainted | _tainted_vars(job.get("variables"))
        for line in job_scripts(job):
            if not invokes_agentic_cli(line):
                continue
            # Unlike GL-002, a referenced tainted variable is unsafe even
            # when shell-quoted: the model ingests the value as prompt text
            # regardless. So check for any reference, not the shell-aware
            # has_unsafe_reference.
            references_tainted = any(
                re.search(_gl_ref_pattern(name), line) for name in job_tainted
            )
            if has_direct_taint([line], UNTRUSTED_VAR_RE) or references_tainted:
                anchor_jobs[job_id] = None
                line_no = _line_of(job)
                locations.append(
                    Location(path=path, start_line=line_no, end_line=line_no)
                )
                break
    offenders = list(anchor_jobs)
    passed = not offenders
    desc = (
        "No agentic-CLI script ingests attacker-controllable MR/commit "
        "context."
        if passed else
        "Attacker-controllable MR/commit context reaches an agentic AI CLI "
        f"prompt (directly or via variables:) in job(s) {', '.join(offenders)}. "
        "An MR author can inject instructions the agent then executes; "
        "quoting / variable routing does not sanitize an LLM prompt."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
        job_anchors=tuple(anchor_jobs),
    )
