"""GHA-103. AI code-review bot on an untrusted trigger without an environment gate.

The HackerBot-Claw campaign (February 2026) demonstrated that prompt
injection via PR descriptions, commit messages, and diff hunks can
hijack AI code-review bots running on ``pull_request_target`` or
``issue_comment`` triggers.  When the bot has write permissions and
no ``environment:`` gate, an attacker's PR can instruct the bot to
approve the PR, dismiss reviews, or leak secrets through review
comments.

Fires when:
  1. The workflow triggers on ``pull_request_target`` or
     ``issue_comment`` (attacker-controlled input).
  2. A step uses a known AI code-review action OR invokes an AI CLI.
  3. The job has write-class permissions (``pull-requests: write``,
     ``contents: write``, or no ``permissions:`` block at all).
  4. The job has no ``environment:`` gate (which would require
     human approval before the bot runs).
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    find_run_command,
    iter_jobs,
    iter_steps,
    step_location,
    workflow_triggers,
)

RULE = Rule(
    id="GHA-103",
    title="AI code-review bot on untrusted trigger without environment gate",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-1", "CICD-SEC-4"),
    esf=("ESF-D-CODE-INTEGRITY", "ESF-D-INJECTION"),
    cwe=("CWE-94", "CWE-269"),
    recommendation=(
        "Gate AI code-review jobs behind a protected ``environment:`` "
        "that requires manual approval. This forces a human to verify "
        "the PR content before the AI bot processes it, blocking "
        "prompt-injection payloads embedded in diffs, PR descriptions, "
        "or commit messages. If the bot only needs read access, drop "
        "``pull-requests: write`` and ``contents: write`` from the "
        "job's ``permissions:`` block. Consider moving to a "
        "``pull_request`` trigger (which runs on the merge base, not "
        "the attacker's HEAD) when write permissions aren't needed."
    ),
    docs_note=(
        "Detects AI code-review actions and CLIs running on "
        "``pull_request_target`` or ``issue_comment`` triggers with "
        "write permissions and no ``environment:`` gate.\n\n"
        "**Known AI review actions** (owner/repo prefix match):\n"
        "``coderabbitai/ai-pr-reviewer``, ``codiumai/pr-agent``, "
        "``sourcery-ai/action``, ``sturdy-dev/codeball-action``, "
        "``github/copilot-*``, ``autofix-ci/*``.\n\n"
        "**CLI detection:** same agentic CLI list as GHA-058 (claude, "
        "gemini, q, cursor-agent, aider, openhands, goose) when "
        "invoked in a ``run:`` step.\n\n"
        "The rule does NOT fire when the job declares an "
        "``environment:`` (the approval gate breaks the attack chain) "
        "or when the job's permissions are strictly read-only."
    ),
    known_fp=(
        "A workflow that triggers on ``pull_request_target`` solely "
        "to label or triage (not to review code) may use an AI bot "
        "with write permissions. If the bot's prompt never includes "
        "attacker-controlled content (diff, PR body, commit messages), "
        "suppress with a rationale explaining the prompt source.",
    ),
    incident_refs=(
        "HackerBot-Claw campaign (February 2026): prompt injection "
        "via PR descriptions hijacked Claude-based code reviewers "
        "running on ``pull_request_target``. The injected prompt "
        "instructed the bot to approve the PR and post secrets in "
        "review comments.",
    ),
    exploit_example=(
        "# Vulnerable: AI review bot on pull_request_target with\n"
        "# write permissions and no environment gate. An attacker's\n"
        "# PR description can contain prompt injection.\n"
        "on: pull_request_target\n"
        "jobs:\n"
        "  review:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: read\n"
        "      pull-requests: write\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - uses: coderabbitai/ai-pr-reviewer@<sha>\n"
        "\n"
        "# Safe: environment gate forces human approval before the\n"
        "# bot processes attacker-controlled content.\n"
        "on: pull_request_target\n"
        "jobs:\n"
        "  review:\n"
        "    runs-on: ubuntu-latest\n"
        "    environment: ai-review-approved\n"
        "    permissions:\n"
        "      contents: read\n"
        "      pull-requests: write\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - uses: coderabbitai/ai-pr-reviewer@<sha>"
    ),
)


_UNTRUSTED_TRIGGERS = frozenset({"pull_request_target", "issue_comment"})

_AI_REVIEW_ACTION_PREFIXES: tuple[str, ...] = (
    "coderabbitai/",
    "codiumai/pr-agent",
    "sourcery-ai/",
    "sturdy-dev/codeball-action",
    "github/copilot-",
    "autofix-ci/",
)

_AI_CLI_RE = re.compile(
    r"\b(?:claude|gemini|q\s+chat|cursor-agent|aider|openhands|goose)\b",
    re.IGNORECASE,
)


def _step_is_ai_review(step: dict[str, Any]) -> str | None:
    """Return a label if *step* invokes an AI review tool, else None."""
    uses = step.get("uses")
    if isinstance(uses, str):
        uses_lc = uses.lower()
        for prefix in _AI_REVIEW_ACTION_PREFIXES:
            if uses_lc.startswith(prefix):
                return uses.split("@")[0]
    run = step.get("run")
    if isinstance(run, str):
        m = find_run_command(run, _AI_CLI_RE)
        if m:
            return m.group(0).lower()
    return None


def _job_has_write_perms(doc: dict[str, Any], job: dict[str, Any]) -> bool:
    perms = job.get("permissions")
    if perms is None:
        perms = doc.get("permissions")
    if perms is None:
        return True
    if isinstance(perms, str):
        return perms.lower() == "write-all"
    if isinstance(perms, dict):
        for v in perms.values():
            if isinstance(v, str) and v.lower() == "write":
                return True
    return False


def _job_has_environment(job: dict[str, Any]) -> bool:
    env = job.get("environment")
    if isinstance(env, str) and env:
        return True
    if isinstance(env, dict) and env.get("name"):
        return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    triggers = set(workflow_triggers(doc))
    if not triggers & _UNTRUSTED_TRIGGERS:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "Workflow does not trigger on pull_request_target or "
                "issue_comment."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    offenders: list[str] = []
    locations = []
    for job_id, job in iter_jobs(doc):
        if _job_has_environment(job):
            continue
        if not _job_has_write_perms(doc, job):
            continue
        for step in iter_steps(job):
            label = _step_is_ai_review(step)
            if label is not None:
                offenders.append(f"{job_id}: {label}")
                locations.append(step_location(path, step))

    if not offenders:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "No AI code-review bot found on untrusted triggers "
                "without an environment gate."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    sample = ", ".join(offenders[:3])
    if len(offenders) > 3:
        sample += f" (+{len(offenders) - 3} more)"
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path,
        description=(
            f"{len(offenders)} AI review bot step(s) run on an "
            f"untrusted trigger ({', '.join(sorted(triggers & _UNTRUSTED_TRIGGERS))}) "
            f"with write permissions and no environment gate: {sample}. "
            f"An attacker can embed prompt injection in a PR description, "
            f"commit message, or diff hunk to hijack the bot."
        ),
        recommendation=RULE.recommendation, passed=False,
        locations=locations,
    )
