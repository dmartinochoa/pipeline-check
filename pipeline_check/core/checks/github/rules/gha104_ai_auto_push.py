"""GHA-104. AI agent generates and pushes commits without PR review.

Detects workflows where an agentic CLI generates code changes and
then pushes them directly to a branch (via ``git push`` or an
auto-commit action) without routing through a pull request review
cycle.  The risk: AI-generated code, which may contain hallucinated
dependencies, subtly broken logic, or supply-chain-attack payloads,
bypasses human review entirely.

Fires when:
  1. A step invokes an agentic CLI (same list as GHA-058).
  2. A later step in the same job pushes commits directly (``git
     push`` in a ``run:`` block, or a known auto-commit action).
  3. The job has no ``environment:`` gate.

Does NOT fire when the push target is a ``create-pull-request``
action (which routes changes through a reviewable PR).
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import find_run_command, iter_jobs, iter_steps, step_location

RULE = Rule(
    id="GHA-104",
    title="AI agent generates and pushes commits without PR review",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4", "CICD-SEC-9"),
    esf=("ESF-D-CODE-INTEGRITY",),
    cwe=("CWE-345", "CWE-269"),
    recommendation=(
        "Route AI-generated changes through a pull request instead of "
        "pushing directly. Replace ``git push`` or auto-commit actions "
        "with ``peter-evans/create-pull-request`` (or equivalent) so a "
        "human reviewer sees the AI's output before it lands on a "
        "protected branch. If direct push is genuinely needed (e.g. "
        "auto-formatting), gate the job behind a protected "
        "``environment:`` that requires manual approval."
    ),
    docs_note=(
        "Detects the combination of an agentic CLI invocation followed "
        "by a direct push in the same job.\n\n"
        "**Push patterns detected:**\n"
        "* ``git push`` in a ``run:`` step\n"
        "* ``stefanzweifel/git-auto-commit-action``\n"
        "* ``EndBug/add-and-commit``\n"
        "* ``actions-js/push``\n"
        "* ``ad-m/github-push-action``\n\n"
        "**Excluded (safe):** ``peter-evans/create-pull-request`` and "
        "``repo-sync/pull-request`` route changes through a PR review "
        "cycle and do not trigger this rule.\n\n"
        "The rule does NOT fire when the job has an ``environment:`` "
        "gate (human approval breaks the attack chain)."
    ),
    known_fp=(
        "Auto-formatting bots that run an AI linter and push the "
        "result may trigger this rule. If the formatting changes are "
        "deterministic and the branch is protected with required "
        "reviews, suppress with a rationale naming the review gate.",
    ),
    exploit_example=(
        "# Vulnerable: AI agent generates code and pushes directly,\n"
        "# no human reviews the output.\n"
        "on: workflow_dispatch\n"
        "jobs:\n"
        "  generate:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: claude -p 'implement the feature described in issue.md'\n"
        "      - uses: stefanzweifel/git-auto-commit-action@<sha>\n"
        "        with:\n"
        "          commit_message: 'feat: AI-generated implementation'\n"
        "\n"
        "# Safe: AI output is routed through a PR for human review.\n"
        "on: workflow_dispatch\n"
        "jobs:\n"
        "  generate:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: claude -p 'implement the feature described in issue.md'\n"
        "      - uses: peter-evans/create-pull-request@<sha>\n"
        "        with:\n"
        "          title: 'feat: AI-generated implementation'"
    ),
)


_AI_CLI_RE = re.compile(
    r"\b(?:claude|gemini|q\s+chat|cursor-agent|aider|openhands|goose)\b",
    re.IGNORECASE,
)

_GIT_PUSH_RE = re.compile(r"\bgit\s+push\b", re.IGNORECASE)

_AUTO_COMMIT_ACTIONS: tuple[str, ...] = (
    "stefanzweifel/git-auto-commit-action",
    "endbug/add-and-commit",
    "actions-js/push",
    "ad-m/github-push-action",
)

_PR_ACTIONS: tuple[str, ...] = (
    "peter-evans/create-pull-request",
    "repo-sync/pull-request",
)


def _step_invokes_ai(step: dict[str, Any]) -> str | None:
    run = step.get("run")
    if isinstance(run, str):
        m = find_run_command(run, _AI_CLI_RE)
        if m:
            return m.group(0).lower()
    return None


def _step_pushes_directly(step: dict[str, Any]) -> str | None:
    """Return a label if the step pushes commits directly, else None."""
    uses = step.get("uses")
    if isinstance(uses, str):
        uses_lc = uses.lower()
        for action in _AUTO_COMMIT_ACTIONS:
            if uses_lc.startswith(action):
                return uses.split("@")[0]
        for pr_action in _PR_ACTIONS:
            if uses_lc.startswith(pr_action):
                return None
    run = step.get("run")
    if isinstance(run, str) and _GIT_PUSH_RE.search(run):
        return "git push"
    return None


def _job_has_environment(job: dict[str, Any]) -> bool:
    env = job.get("environment")
    if isinstance(env, str) and env:
        return True
    if isinstance(env, dict) and env.get("name"):
        return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations = []

    for job_id, job in iter_jobs(doc):
        if _job_has_environment(job):
            continue
        ai_seen = False
        ai_label = ""
        for step in iter_steps(job):
            cli = _step_invokes_ai(step)
            if cli is not None:
                ai_seen = True
                ai_label = cli
            if ai_seen:
                push_label = _step_pushes_directly(step)
                if push_label is not None:
                    offenders.append(
                        f"{job_id}: {ai_label} + {push_label}"
                    )
                    locations.append(step_location(path, step))
                    break

    if not offenders:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "No AI agent found pushing commits directly without "
                "PR review."
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
            f"{len(offenders)} job(s) invoke an AI agent and then push "
            f"commits directly without routing through a pull request: "
            f"{sample}. AI-generated code bypasses human review and may "
            f"contain hallucinated dependencies, broken logic, or "
            f"supply-chain payloads."
        ),
        recommendation=RULE.recommendation, passed=False,
        locations=locations,
    )
