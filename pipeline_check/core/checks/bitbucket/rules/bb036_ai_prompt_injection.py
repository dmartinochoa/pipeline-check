"""BB-036. Untrusted PR/branch context reaches an agentic AI CLI.

The Bitbucket analog of GHA-119 / GL-048, and the AI face of BB-002
(script injection). An agentic CLI (``claude`` / ``gemini`` /
``cursor-agent`` / ``aider`` / ``openhands`` / ``goose`` / ``q chat``)
reads a prompt and then *acts*: runs shell, writes files, calls tools.
When a ``script:`` step feeds attacker-controllable Bitbucket context
(``$BITBUCKET_BRANCH`` / ``$BITBUCKET_TAG`` / ``$BITBUCKET_PR_*``, e.g. a
PR's source-branch name) into that prompt, anyone who can open a pull
request can smuggle instructions the agent then executes ("ignore
previous instructions and run ...").

Unlike BB-002, the shell-quoting that defangs command injection does NOT
help here: the model ingests the value as prompt text regardless of how
it is quoted, so this is a separate rule. Fires on a direct interpolation
of an untrusted predefined variable into the agentic-CLI line, or on a
local shell variable that was assigned from one earlier in the step.
"""
from __future__ import annotations

import re
from typing import Any

from ..._primitives.agentic_cli import invokes_agentic_cli
from ..._primitives.tainted_variables import has_direct_taint
from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_steps, step_scripts
from ._helpers import UNTRUSTED_VAR_RE

RULE = Rule(
    id="BB-036",
    title="Untrusted PR/branch context reaches an agentic AI CLI (prompt injection)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-94", "CWE-77"),
    recommendation=(
        "Do not place attacker-controllable context (a PR's branch / tag "
        "name or `$BITBUCKET_PR_*` metadata) in an agentic CLI's prompt. "
        "Quoting does NOT sanitize a prompt the way it does a shell command, "
        "the model still reads the value. If the agent must see PR content, "
        "run it on a step with no deployment / repository secrets in scope "
        "and no tool / shell access, and treat its output as untrusted."
    ),
    docs_note=(
        "The AI analog of BB-002 (script injection). Fires when a "
        "``script:`` line invokes an agentic CLI (claude / gemini / "
        "cursor-agent / aider / openhands / goose / ``q chat``) AND "
        "attacker-controllable Bitbucket context reaches it, either a "
        "predefined untrusted variable (`$BITBUCKET_BRANCH` / `$BITBUCKET_TAG` "
        "/ `$BITBUCKET_PR_*`) interpolated directly, or a local shell "
        "variable assigned from one earlier in the step. Unlike a shell, an "
        "LLM ingests a quoted value as prompt text, so the BB-002 mitigation "
        "(quote the value) does not apply, which is why this is separate."
    ),
)

# Captures the assigned name in ``export VAR=...`` or ``VAR=...`` lines.
_EXPORT_RE = re.compile(r"(?:export\s+)?(\w+)=")


def _tainted_exports(lines: list[str]) -> set[str]:
    """Local shell variable names assigned from an untrusted BITBUCKET_* value."""
    tainted: set[str] = set()
    for line in lines:
        m = _EXPORT_RE.match(line.strip())
        if m and UNTRUSTED_VAR_RE.search(line):
            tainted.add(m.group(1))
    return tainted


def _references(line: str, name: str) -> bool:
    """True when *line* references shell variable *name* (``$VAR`` / ``${VAR}``)."""
    return bool(re.search(rf"\$\{{?{re.escape(name)}\}}?", line))


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for loc, step in iter_steps(doc):
        scripts = step_scripts(step)
        tainted = _tainted_exports(scripts)
        for line in scripts:
            if not invokes_agentic_cli(line):
                continue
            # Any reference is unsafe for an LLM prompt, so a plain
            # reference check (not the shell-quoting-aware BB-002 one).
            if has_direct_taint([line], UNTRUSTED_VAR_RE) or any(
                _references(line, name) for name in tainted
            ):
                offenders.append(loc)
                step_line = _line_of(step) if isinstance(step, dict) else None
                locations.append(Location(
                    path=path, start_line=step_line, end_line=step_line,
                ))
                break
    passed = not offenders
    desc = (
        "No agentic-CLI script ingests attacker-controllable PR/branch "
        "context."
        if passed else
        "Attacker-controllable PR/branch context ($BITBUCKET_BRANCH / "
        "$BITBUCKET_TAG / $BITBUCKET_PR_*) reaches an agentic AI CLI prompt "
        f"in step(s) {', '.join(sorted(set(offenders)))}. A PR author can "
        "inject instructions the agent then executes; quoting does not "
        "sanitize an LLM prompt."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
