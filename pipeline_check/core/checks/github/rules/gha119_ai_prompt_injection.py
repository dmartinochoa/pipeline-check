"""GHA-119. Untrusted context reaches an agentic AI CLI (prompt injection).

The AI analog of GHA-003. An agentic CLI (claude / gemini / cursor-agent
/ aider / openhands / goose) reads a prompt and then *acts*: runs shell,
writes files, calls tools. When a ``run:`` step feeds
attacker-controllable context (``${{ github.event.pull_request.body }}``,
a comment body, a fork branch name) into that prompt, a fork PR or an
issue comment can smuggle instructions the agent then executes ("ignore
previous instructions and run ...").

Crucially, the ``env:`` indirection that defangs shell injection (GHA-003)
does NOT help here: the model ingests the env value as prompt text
regardless, so routing untrusted content through ``env:`` is not a fix.
"""
from __future__ import annotations

import re
from typing import Any

from ..._primitives.tainted_variables import has_direct_taint
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location
from ._helpers import UNTRUSTED_CONTEXT_RE, step_invokes_agentic_cli

RULE = Rule(
    id="GHA-119",
    title="Untrusted context reaches an agentic AI CLI (prompt injection)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    cwe=("CWE-94", "CWE-77"),
    recommendation=(
        "Do not place attacker-controllable context (PR / issue / comment "
        "bodies, branch names) in an agentic CLI's prompt. Env-var "
        "indirection does NOT sanitize a prompt the way it does a shell "
        "command, the model still reads the value. If the agent must see "
        "PR content, run it with no write token and no tool / shell access "
        "on a sandboxed job behind an environment gate, and treat its "
        "output as untrusted."
    ),
    docs_note=(
        "The AI analog of GHA-003 (script injection). Fires when a ``run:`` "
        "step invokes an agentic CLI (claude / gemini / cursor-agent / "
        "aider / openhands / goose) AND attacker-controllable context "
        "reaches that step, either interpolated directly or via an ``env:`` "
        "variable the command references. Unlike a shell, an LLM ingests an "
        "env-routed value as prompt text, so the GHA-003 mitigation (route "
        "through env) does not apply, which is why this is a separate rule."
    ),
)


def _tainted_env_vars(env_block: Any) -> set[str]:
    """Env var names whose values reference attacker-controllable context."""
    if not isinstance(env_block, dict):
        return set()
    return {
        str(name)
        for name, value in env_block.items()
        if isinstance(value, str) and UNTRUSTED_CONTEXT_RE.search(value)
    }


def _gha_ref_pattern(name: str) -> str:
    """Match ``$VAR`` / ``${VAR}`` / ``${{ env.VAR }}`` for *name*."""
    safe = re.escape(name)
    return rf"(?:\$\{{{safe}\}}|\${safe}\b|\${{{{[\s]*env\.{safe}[\s]*}}}})"


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    anchor_jobs: dict[str, None] = {}
    wf_tainted = _tainted_env_vars(doc.get("env"))
    for job_id, job in iter_jobs(doc):
        job_tainted = wf_tainted | _tainted_env_vars(job.get("env"))
        for idx, step in enumerate(iter_steps(job)):
            run = step.get("run")
            if not isinstance(run, str) or not step_invokes_agentic_cli(run):
                continue
            lines = run.splitlines()
            step_tainted = job_tainted | _tainted_env_vars(step.get("env"))
            # Unlike GHA-003, a *referenced* tainted env var is unsafe even
            # when shell-quoted (``"$PR"``): the model ingests the value as
            # prompt text regardless of shell quoting. So check for any
            # reference, not has_unsafe_reference (which is shell-aware).
            references_tainted = any(
                re.search(_gha_ref_pattern(name), run)
                for name in step_tainted
            )
            reaches = (
                has_direct_taint(lines, UNTRUSTED_CONTEXT_RE)
                or references_tainted
            )
            if reaches:
                offenders.append(f"{job_id}[{idx}]")
                locations.append(step_location(path, step))
                anchor_jobs[job_id] = None
    passed = not offenders
    desc = (
        "No agentic-CLI step ingests attacker-controllable context."
        if passed else
        "Attacker-controllable context reaches an agentic AI CLI prompt "
        f"(directly or via env:) in: {', '.join(offenders)}. A fork PR or "
        "comment can inject instructions the agent then executes; env "
        "routing does not sanitize an LLM prompt."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
        job_anchors=tuple(anchor_jobs),
    )
