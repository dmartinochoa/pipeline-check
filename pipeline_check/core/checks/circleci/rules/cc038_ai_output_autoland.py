"""CC-038. Agentic-CLI output lands without human review.

A CircleCI job runs an agentic coding CLI (claude / gemini / cursor-agent
/ aider / openhands / goose / ``q chat``) in a ``run:`` command that edits
the tree, AND the same job then lands the result with no human in the
loop: a ``git push`` straight to a branch. The combination means
AI-authored changes reach a branch without a review gate. If the agent's
prompt is at all influenced by untrusted input (a PR title / branch, a
pipeline parameter) that is prompt-injection straight to committed code
(see CC-037), and even without injection it removes the human review
CICD-SEC-1 assumes.

The CircleCI analog of GHA-123 / GL-049 / BB-039 / ADO-038 / JF-038, and
the flow-control leg of the CircleCI AI pack alongside CC-037 (prompt
injection). Coupling is *per job*: a CircleCI job has its own executor and
checkout, so the run steps of one job share a workspace (an agent edit and
a ``git push`` in the same job are the same execution), but separate jobs
do not. The agentic-CLI catalog is the shared ``_primitives/agentic_cli``
helper; the landing idiom (``git push``) is its own.
"""
from __future__ import annotations

import re
from typing import Any

from ..._primitives.agentic_cli import invokes_agentic_cli
from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_run_commands

RULE = Rule(
    id="CC-038",
    title="Agentic CLI output lands without human review",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1",),
    esf=("ESF-C-APPROVAL",),
    cwe=("CWE-94", "CWE-693"),
    recommendation=(
        "Don't let an agentic CLI's output reach a branch without a human "
        "review gate. Have the agent open a normal pull request (no "
        "auto-merge) so a person reviews the diff before it lands, and "
        "don't pair the agent with a ``git push`` straight to a branch in "
        "the same job. If the agent's prompt can be influenced by untrusted "
        "input (a PR title / branch, a pipeline parameter), treat the "
        "committed result as attacker-controlled."
    ),
    docs_note=(
        "Fires when one CircleCI job both invokes an agentic CLI (``claude`` "
        "/ ``gemini`` / ``cursor-agent`` / ``aider`` / ``openhands`` / "
        "``goose`` / ``q chat``) in a ``run:`` command and, in the same "
        "job, lands the result with a ``git push`` (committing straight to "
        "a branch). Coupling is per-job because a CircleCI job has its own "
        "executor / checkout; the run steps of one job share a workspace, "
        "separate jobs do not.\n\n"
        "Does NOT fire when the agent only opens a pull request for review, "
        "nor on a push step that does not run an agent (ordinary formatting "
        "/ generated-file jobs), nor when the agent and the push are in "
        "different jobs. A ``git push --dry-run`` is ignored."
    ),
)

# A plain ``git push`` (committing straight to a branch); ``--dry-run`` is
# ignored.
_GIT_PUSH_RE = re.compile(r"\bgit\s+push\b", re.IGNORECASE)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for job_id, job in iter_jobs(doc):
        agent: str | None = None
        pushes = False
        for cmd in iter_run_commands(job):
            if agent is None:
                agent = invokes_agentic_cli(cmd)
            if not pushes and _GIT_PUSH_RE.search(cmd) and "--dry-run" not in cmd:
                pushes = True
        if agent is not None and pushes:
            offenders.append(f"{job_id} ({agent})")
            line = _line_of(job)
            locations.append(Location(
                path=path, start_line=line, end_line=line,
            ))
    passed = not offenders
    desc = (
        "No job both runs an agentic CLI and pushes its output without a "
        "review gate."
        if passed else
        f"{len(offenders)} job(s) run an agentic CLI and then push the "
        f"result straight to a branch (git push) with no human review: "
        f"{', '.join(offenders)}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
