"""CC-037. Untrusted PR/build context reaches an agentic AI CLI.

The CircleCI analog of GHA-119 / GL-048 / BB-036 / ADO-035 / JF-037, and
the AI face of CC-002 (script injection). An agentic CLI (``claude`` /
``gemini`` / ``cursor-agent`` / ``aider`` / ``openhands`` / ``goose`` /
``q chat``) reads a prompt and then *acts*: runs shell, writes files,
calls tools. When a ``run:`` command feeds attacker-controllable CircleCI
context into that prompt, anyone who can open a pull request (or name a
branch / tag) can smuggle instructions the agent then executes ("ignore
previous instructions and run ...").

The attacker-controllable surface is the one CC-002 already tracks:
event-source env vars (``$CIRCLE_BRANCH`` / ``$CIRCLE_TAG`` /
``$CIRCLE_PR_*`` / ``$CIRCLE_PULL_REQUEST``) and the native
``<< pipeline.git.branch >>`` / ``<< pipeline.git.tag >>`` interpolations.

Unlike CC-002, quoting does NOT defang this: the model ingests the value
as prompt text regardless of how the command quotes it, so the CC-002
mitigation (quote the variable) does not apply, which is why this is a
separate rule. ``<< pipeline.parameters.* >>`` stays safe (typed, set by
the triggering workflow, not by a ref name).
"""
from __future__ import annotations

import re
from typing import Any

from ..._primitives.agentic_cli import invokes_agentic_cli
from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_run_commands
from ._helpers import UNTRUSTED_ENV_RE

# Native ``<< pipeline.git.branch|tag >>`` interpolation (attacker-named
# ref), matching CC-002. ``<< pipeline.parameters.* >>`` is deliberately
# excluded as the safe, typed alternative.
_UNTRUSTED_INTERP_RE = re.compile(r"<<\s*pipeline\.git\.(?:branch|tag)\s*>>")

RULE = Rule(
    id="CC-037",
    title="Untrusted PR/build context reaches an agentic AI CLI (prompt injection)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-94", "CWE-77"),
    recommendation=(
        "Do not place attacker-controllable context (a PR's branch / tag, "
        "`$CIRCLE_BRANCH` / `$CIRCLE_TAG` / `$CIRCLE_PR_*`, or a "
        "`<< pipeline.git.* >>` interpolation) in an agentic CLI's prompt. "
        "Quoting does NOT sanitize a prompt the way it does a shell "
        "command, the model still reads the value. If the agent must see "
        "PR content, run it in a job with no context / credentials bound "
        "and no tool / shell access, and treat its output as untrusted. "
        "Pass trusted inputs through typed `<< pipeline.parameters.* >>` "
        "instead."
    ),
    docs_note=(
        "The AI analog of CC-002 (script injection). Fires when a ``run:`` "
        "command invokes an agentic CLI (claude / gemini / cursor-agent / "
        "aider / openhands / goose / ``q chat``) AND "
        "attacker-controllable CircleCI context reaches it: an "
        "event-source env var (`$CIRCLE_BRANCH` / `$CIRCLE_TAG` / "
        "`$CIRCLE_PR_NUMBER` / `$CIRCLE_PULL_REQUEST`) or a "
        "`<< pipeline.git.branch >>` / `<< pipeline.git.tag >>` "
        "interpolation. Unlike CC-002 the value is flagged in any quote "
        "style: an LLM ingests it as prompt text regardless of shell "
        "quoting, so the CC-002 mitigation does not apply. "
        "`<< pipeline.parameters.* >>` is the safe alternative."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    seen_jobs: set[str] = set()
    for job_id, job in iter_jobs(doc):
        for idx, cmd in enumerate(iter_run_commands(job)):
            if not invokes_agentic_cli(cmd):
                continue
            if UNTRUSTED_ENV_RE.search(cmd) or _UNTRUSTED_INTERP_RE.search(cmd):
                offenders.append(f"{job_id}[{idx}]")
                if job_id not in seen_jobs:
                    seen_jobs.add(job_id)
                    line = _line_of(job)
                    locations.append(Location(
                        path=path, start_line=line, end_line=line,
                    ))
    passed = not offenders
    desc = (
        "No agentic-CLI run step ingests attacker-controllable PR/build "
        "context."
        if passed else
        f"{len(offenders)} agentic-CLI run step(s) ingest "
        f"attacker-controllable CircleCI context ($CIRCLE_BRANCH / "
        f"$CIRCLE_TAG / << pipeline.git.* >>) into the prompt: "
        f"{', '.join(offenders)}. A PR author or branch namer can inject "
        f"instructions the agent then executes; quoting does not sanitize "
        f"an LLM prompt."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
