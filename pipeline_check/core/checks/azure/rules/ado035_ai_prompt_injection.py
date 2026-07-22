"""ADO-035. Untrusted PR/commit context reaches an agentic AI CLI.

The Azure DevOps analog of GHA-119 / GL-048, and the AI face of ADO-002
(script injection). An agentic CLI (``claude`` / ``gemini`` /
``cursor-agent`` / ``aider`` / ``openhands`` / ``goose`` / ``q chat``)
reads a prompt and then *acts*: runs shell, writes files, calls tools.
When a step's script feeds attacker-controllable Azure context
(``$(Build.SourceVersionMessage)`` / ``$(Build.SourceBranch*)`` /
``$(System.PullRequest.*)``, e.g. a PR's commit message or source branch)
into that prompt, anyone who can open a pull request can smuggle
instructions the agent then executes ("ignore previous instructions and
run ...").

Unlike ADO-002, the shell-quoting / ``env:`` routing that defangs command
injection does NOT help here: the model ingests the value as prompt text
regardless, so this is a separate rule. Fires when an agentic-CLI script
body directly interpolates an untrusted macro, or references a
``variables:`` entry whose value carries one.
"""
from __future__ import annotations

import re
from typing import Any

from ..._primitives.agentic_cli import invokes_agentic_cli
from ..._primitives.tainted_variables import has_direct_taint
from ..._yaml_lines import line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps
from ._helpers import UNTRUSTED_VAR_RE

RULE = Rule(
    id="ADO-035",
    title="Untrusted PR/commit context reaches an agentic AI CLI (prompt injection)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-94", "CWE-77"),
    recommendation=(
        "Do not place attacker-controllable context (a PR's commit message, "
        "source branch, or `$(System.PullRequest.*)` metadata) in an agentic "
        "CLI's prompt. Routing through a quoted `env:` variable does NOT "
        "sanitize a prompt the way it does a shell command, the model still "
        "reads the value. If the agent must see PR content, run it on a job "
        "with no service-connection secrets and no tool / shell access, and "
        "treat its output as untrusted."
    ),
    docs_note=(
        "The AI analog of ADO-002 (script injection). Fires when a step's "
        "script body (``script`` / ``bash`` / ``pwsh`` / ``powershell`` or a "
        "task-based step's ``inputs.script``) invokes an agentic CLI (claude "
        "/ gemini / cursor-agent / aider / openhands / goose / ``q chat``) "
        "AND attacker-controllable Azure context reaches it, either an "
        "untrusted macro (`$(Build.SourceVersionMessage)`) interpolated "
        "directly, or a ``variables:`` entry whose value carries one. Unlike "
        "a shell, an LLM ingests a quoted / env-routed value as prompt text, "
        "so the ADO-002 mitigation does not apply, which is why this is "
        "separate."
    ),
)


def _tainted_vars(variables_block: Any) -> set[str]:
    """Variable names whose values reference an untrusted ADO macro.

    Accepts both the dict (``{NAME: VALUE}``) and list (``- name:``/``value:``)
    shapes Azure allows for ``variables:``.
    """
    tainted: set[str] = set()
    if isinstance(variables_block, dict):
        for name, value in variables_block.items():
            if isinstance(value, str) and UNTRUSTED_VAR_RE.search(value):
                tainted.add(str(name))
    elif isinstance(variables_block, list):
        for item in variables_block:
            if not isinstance(item, dict):
                continue
            name, value = item.get("name"), item.get("value")
            if (
                isinstance(name, str) and isinstance(value, str)
                and UNTRUSTED_VAR_RE.search(value)
            ):
                tainted.add(name)
    return tainted


# ``echo "##vso[task.setvariable variable=NAME]<value>"`` writes a
# pipeline variable at runtime. Capture the name and the trailing value
# so a NAME whose value carries an untrusted macro taints later steps.
_SETVAR_RE = re.compile(
    r"##vso\[task\.setvariable\s+variable=([A-Za-z0-9_.]+)[^\]]*\]"
    r"([^\"'\n]*)",
    re.IGNORECASE,
)


def _ado_ref_re(name: str) -> re.Pattern[str]:
    """Match every ADO reference syntax for *name*: ``$(VAR)`` / ``$env:VAR``
    / ``${VAR}`` / ``$VAR``."""
    n = re.escape(name)
    return re.compile(
        rf"\$\(\s*{n}\s*\)|\$env:{n}\b|\$(?:\{{{n}\}}|{n}\b)"
    )


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    seen_lines: set[int] = set()
    pipeline_tainted = _tainted_vars(doc.get("variables"))
    for job_loc, job in iter_jobs(doc):
        job_tainted = pipeline_tainted | _tainted_vars(job.get("variables"))
        # ``task.setvariable`` names carrying an untrusted macro accumulate
        # across steps in document order (a capture step taints later ones).
        setvar_tainted: set[str] = set()
        for step_loc, step in iter_steps(job):
            bodies: list[str] = [
                step[key] for key in ("script", "bash", "pwsh", "powershell")
                if isinstance(step.get(key), str)
            ]
            inputs = step.get("inputs")
            if isinstance(inputs, dict) and isinstance(inputs.get("script"), str):
                bodies.append(inputs["script"])
            tainted_res = [
                _ado_ref_re(name) for name in (job_tainted | setvar_tainted)
            ]
            for body in bodies:
                if not invokes_agentic_cli(body):
                    continue
                lines = body.splitlines()
                # Any reference is unsafe for an LLM prompt, so a plain
                # reference check rather than the shell-quoting-aware one.
                if has_direct_taint(
                    lines, UNTRUSTED_VAR_RE, paren_is_macro=True
                ) or any(rx.search(body) for rx in tainted_res):
                    offenders.append(f"{job_loc}.{step_loc}")
                    step_line = line_of(step)
                    if step_line is not None and step_line not in seen_lines:
                        seen_lines.add(step_line)
                        locations.append(Location(
                            path=path, start_line=step_line, end_line=step_line,
                        ))
                    break
            # Record any setvariable that stores an untrusted macro so a
            # later step referencing that name is flagged.
            for body in bodies:
                for m in _SETVAR_RE.finditer(body):
                    if UNTRUSTED_VAR_RE.search(m.group(2)):
                        setvar_tainted.add(m.group(1))
    passed = not offenders
    desc = (
        "No agentic-CLI script ingests attacker-controllable build/PR "
        "context."
        if passed else
        "Attacker-controllable build/PR context "
        "($(Build.SourceVersionMessage) / $(Build.SourceBranch*) / "
        "$(System.PullRequest.*)) reaches an agentic AI CLI prompt in "
        f"{', '.join(sorted(set(offenders))[:5])}. A PR author can inject "
        "instructions the agent then executes; quoting / env routing does "
        "not sanitize an LLM prompt."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
