"""GHA-123. Agentic-CLI output lands without human review.

A job runs an agentic coding CLI (claude / gemini / cursor-agent / aider
/ openhands / goose / ``q chat``) that edits the tree, AND the same job
then commits, pushes, or auto-merges the result with no human in the
loop: ``stefanzweifel/git-auto-commit-action``, ``ad-m/github-push-action``,
``peter-evans/enable-pull-request-automerge``, or ``gh pr merge`` with an
auto / forced-merge flag. The combination means AI-authored changes reach
a branch (or merge) without a review gate. If the agent's prompt is at
all influenced by untrusted input (a PR body, an issue comment, a fetched
page) that is prompt-injection straight to committed code, and even
without injection it removes the human review CICD-SEC-1 assumes. This is
the flow-control leg of the AI/LLM-pipeline pack (GHA-119..122).
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import find_run_command, iter_jobs, iter_steps, step_location
from ._helpers import AGENTIC_CLI_RE

RULE = Rule(
    id="GHA-123",
    title="Agentic CLI output lands without human review",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1",),
    cwe=("CWE-94", "CWE-693"),
    recommendation=(
        "Don't let an agentic CLI's output reach a branch or a merge "
        "without a human review gate. Have the agent open a normal pull "
        "request (no auto-merge) so a person reviews the diff before it "
        "lands; drop ``peter-evans/enable-pull-request-automerge`` and "
        "``gh pr merge --auto`` from the agent's job, and don't pair the "
        "agent with ``git-auto-commit-action`` / ``github-push-action`` "
        "that push straight to a branch. If the agent's prompt can be "
        "influenced by untrusted input (a PR body, an issue comment, a "
        "fetched page), treat the committed result as attacker-"
        "controlled."
    ),
    docs_note=(
        "Fires when one job both invokes an agentic CLI (``claude`` / "
        "``gemini`` / ``cursor-agent`` / ``aider`` / ``openhands`` / "
        "``goose`` / ``q chat``) and, in the same job, lands the result "
        "with no review gate. The landing step is one of: ``uses: "
        "stefanzweifel/git-auto-commit-action``, ``uses: "
        "ad-m/github-push-action``, ``uses: "
        "peter-evans/enable-pull-request-automerge``, or a ``run:`` step "
        "with ``gh pr merge`` plus ``--auto`` / ``--admin`` / ``--merge`` "
        "/ ``--squash`` / ``--rebase``.\n\n"
        "Does NOT fire when the agent only opens a pull request for "
        "review (a bare ``peter-evans/create-pull-request`` with no "
        "auto-merge), nor on an auto-commit / auto-merge job that does "
        "not run an agent (ordinary formatting / generated-file bots). "
        "The agent-plus-auto-land coupling is the signal."
    ),
    known_fp=(
        "A job that runs an agent for a read-only task (triage, labeling) "
        "but also auto-commits an unrelated generated file would match by "
        "co-location. Split the agent and the auto-commit into separate "
        "jobs, or suppress on the job with a rationale noting the agent "
        "does not write the committed paths.",
    ),
)

# Composite actions that push generated changes straight to a branch, or
# enable auto-merge, with no review gate.
_AUTOLAND_USES = (
    "stefanzweifel/git-auto-commit-action",
    "ad-m/github-push-action",
    "peter-evans/enable-pull-request-automerge",
)

# ``gh pr merge`` with an auto / forced-merge flag (merges with no human
# approval step).
_GH_AUTOMERGE_RE = re.compile(
    r"\bgh\s+pr\s+merge\b[^\n]*--(?:auto|admin|merge|squash|rebase)\b",
    re.IGNORECASE,
)


def _step_autolands(step: dict[str, Any]) -> str | None:
    """Return a label for the no-review landing in *step*, or ``None``."""
    uses = step.get("uses")
    if isinstance(uses, str):
        head = uses.split("@", 1)[0].lower()
        for action in _AUTOLAND_USES:
            if head == action:
                return f"uses: {action}"
    run = step.get("run")
    if isinstance(run, str) and _GH_AUTOMERGE_RE.search(run):
        return "gh pr merge (auto / forced)"
    return None


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    anchor_jobs: dict[str, None] = {}
    for job_id, job in iter_jobs(doc):
        agent: str | None = None
        autoland: str | None = None
        autoland_step: dict[str, Any] | None = None
        for step in iter_steps(job):
            run = step.get("run")
            if isinstance(run, str) and agent is None:
                # Scan real command chunks so an agent name that appears
                # only in a comment or an ``echo`` string isn't read as an
                # invocation.
                m = find_run_command(run, AGENTIC_CLI_RE)
                if m:
                    agent = m.group(0).lower()
            if autoland is None:
                label = _step_autolands(step)
                if label is not None:
                    autoland, autoland_step = label, step
        if agent is not None and autoland is not None:
            offenders.append(f"{job_id}: {agent} + {autoland}")
            locations.append(step_location(path, autoland_step or {}))
            anchor_jobs[job_id] = None
    passed = not offenders
    desc = (
        "No job both runs an agentic CLI and lands its output without a "
        "review gate."
        if passed else
        f"{len(offenders)} job(s) run an agentic CLI and then commit, "
        f"push, or auto-merge the result with no human review: "
        f"{', '.join(offenders[:5])}{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
        job_anchors=tuple(anchor_jobs),
    )
