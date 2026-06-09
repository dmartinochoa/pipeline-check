"""ADO-038. Agentic-CLI output lands without human review.

An Azure Pipelines job runs an agentic coding CLI (claude / gemini /
cursor-agent / aider / openhands / goose / ``q chat``) that edits the tree,
AND the same job then lands the result with no human in the loop: a
``git push`` straight to a branch, or an ``az repos pr`` set to
``--auto-complete`` (Azure Repos merges the PR automatically once policies
pass). The combination means AI-authored changes reach a branch (or a
merge) without a review gate. If the agent's prompt is at all influenced by
untrusted input (a PR commit message, a fetched page) that is
prompt-injection straight to committed code (see ADO-035), and even without
injection it removes the human review CICD-SEC-1 assumes.

The Azure DevOps analog of GHA-123 / GL-049, completing the flow-control
leg across the script-based CI providers. Coupling is per job (across its
steps), since the steps of an Azure job share one checkout / workspace; the
agentic-CLI catalog is the shared ``_primitives/agentic_cli`` helper, and
the landing idioms (``git push`` / ``az repos pr --auto-complete``, no
``uses:`` actions here) are its own.
"""
from __future__ import annotations

import re
from typing import Any

from ..._primitives.agentic_cli import invokes_agentic_cli
from ..._yaml_lines import line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="ADO-038",
    title="Agentic CLI output lands without human review",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1",),
    esf=("ESF-C-APPROVAL",),
    cwe=("CWE-94", "CWE-693"),
    recommendation=(
        "Don't let an agentic CLI's output reach a branch or a merge "
        "without a human review gate. Have the agent open a normal pull "
        "request (``az repos pr create`` with no ``--auto-complete``) so a "
        "person reviews the diff before it lands; drop ``--auto-complete`` "
        "from the agent's job, and don't pair the agent with a ``git push`` "
        "straight to a branch. If the agent's prompt can be influenced by "
        "untrusted input (a PR commit message, a fetched page), treat the "
        "committed result as attacker-controlled."
    ),
    docs_note=(
        "Fires when one job both invokes an agentic CLI (``claude`` / "
        "``gemini`` / ``cursor-agent`` / ``aider`` / ``openhands`` / "
        "``goose`` / ``q chat``) in a step body (``script`` / ``bash`` / "
        "``pwsh`` / ``powershell`` or a task-based step's ``inputs.script``) "
        "and, in the same job, lands the result with no review gate. The "
        "landing command is one of: an ``az repos pr create`` / ``update`` "
        "carrying ``--auto-complete`` (Azure Repos merges the PR once "
        "policies pass), or a plain ``git push`` (committing straight to a "
        "branch). Coupling is per job because the steps of one Azure job "
        "share a checkout.\n\n"
        "Does NOT fire when the agent only opens a pull request for review "
        "(``az repos pr create`` with no ``--auto-complete``), nor on a "
        "push / auto-complete job that does not run an agent (ordinary "
        "formatting / generated-file bots). The agent-plus-auto-land "
        "coupling is the signal. A ``git push --dry-run`` is ignored."
    ),
    known_fp=(
        "A job that runs an agent for a read-only task (triage, labeling) "
        "but also pushes an unrelated generated file would match by "
        "co-location. Split the agent and the push into separate jobs, or "
        "suppress on the job with a rationale noting the agent does not "
        "write the pushed paths.",
    ),
)

# ``az repos pr create / update`` set to auto-complete (Azure Repos merges
# the PR automatically once branch policies pass, with no review step).
_AZ_AUTOCOMPLETE_RE = re.compile(
    r"\baz\s+repos\s+pr\s+(?:create|update)\b[^\n]*--auto-complete",
    re.IGNORECASE,
)

# A plain ``git push`` (committing straight to a branch); ``--dry-run`` is
# ignored.
_GIT_PUSH_RE = re.compile(r"\bgit\s+push\b", re.IGNORECASE)


def _step_bodies(step: dict[str, Any]) -> list[str]:
    bodies = [
        step[key] for key in ("script", "bash", "pwsh", "powershell")
        if isinstance(step.get(key), str)
    ]
    inputs = step.get("inputs")
    if isinstance(inputs, dict) and isinstance(inputs.get("script"), str):
        bodies.append(inputs["script"])
    return bodies


def _body_autolands(body: str) -> str | None:
    """Return a label for the no-review landing in *body*, or ``None``."""
    if _AZ_AUTOCOMPLETE_RE.search(body):
        return "az repos pr --auto-complete"
    for line in body.splitlines():
        if _GIT_PUSH_RE.search(line) and "--dry-run" not in line:
            return "git push (commits to a branch)"
    return None


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    seen_step_lines: set[int] = set()
    for job_loc, job in iter_jobs(doc):
        agent: str | None = None
        autoland: str | None = None
        autoland_step: dict[str, Any] | None = None
        for _step_loc, step in iter_steps(job):
            for body in _step_bodies(step):
                if agent is None:
                    agent = invokes_agentic_cli(body)
                if autoland is None:
                    label = _body_autolands(body)
                    if label is not None:
                        autoland, autoland_step = label, step
        if agent is not None and autoland is not None:
            offenders.append(f"{job_loc}: {agent} + {autoland}")
            line = line_of(autoland_step) if autoland_step is not None else None
            if line is not None and line not in seen_step_lines:
                seen_step_lines.add(line)
                locations.append(
                    Location(path=path, start_line=line, end_line=line)
                )
    passed = not offenders
    desc = (
        "No job both runs an agentic CLI and lands its output without a "
        "review gate."
        if passed else
        f"{len(offenders)} job(s) run an agentic CLI and then push or "
        f"auto-complete the result with no human review: "
        f"{', '.join(offenders[:5])}{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
