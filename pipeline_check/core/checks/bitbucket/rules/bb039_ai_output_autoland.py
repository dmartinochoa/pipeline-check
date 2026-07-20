"""BB-039. Agentic-CLI output lands without human review.

A Bitbucket Pipelines ``script:`` step runs an agentic coding CLI (claude /
gemini / cursor-agent / aider / openhands / goose / ``q chat``) that edits
the tree, AND the same step then lands the result with no human in the
loop: a ``git push`` straight to a branch. The combination means
AI-authored changes reach a branch without a review gate. If the agent's
prompt is at all influenced by untrusted input (a PR title / description, a
fetched page) that is prompt-injection straight to committed code (see
BB-036), and even without injection it removes the human review CICD-SEC-1
assumes.

The Bitbucket analog of GHA-123 / GL-049, and the flow-control leg of the
Bitbucket AI/model pack (BB-035..038). Coupling is scoped to a single step,
since each Bitbucket step runs in its own container with a fresh clone; the
agentic-CLI catalog is the shared ``_primitives/agentic_cli`` helper, and
the landing idiom (``git push``, no ``uses:`` actions here) is its own.
"""
from __future__ import annotations

import re
from typing import Any

from ..._primitives.agentic_cli import invokes_agentic_cli
from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_steps, step_scripts_all

RULE = Rule(
    id="BB-039",
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
        "the same step. If the agent's prompt can be influenced by "
        "untrusted input (a PR title / description, a fetched page), treat "
        "the committed result as attacker-controlled."
    ),
    docs_note=(
        "Fires when one ``script:`` step both invokes an agentic CLI "
        "(``claude`` / ``gemini`` / ``cursor-agent`` / ``aider`` / "
        "``openhands`` / ``goose`` / ``q chat``) and, in the same step, "
        "lands the result with a ``git push`` (the Bitbucket idiom for "
        "committing straight to a branch, since there are no ``uses:`` "
        "actions). Coupling is per step because each Bitbucket step runs "
        "in its own container with a fresh clone.\n\n"
        "Does NOT fire when the agent only opens a pull request for review, "
        "nor on a push step that does not run an agent (ordinary formatting "
        "/ generated-file bots). The agent-plus-push coupling is the "
        "signal. A ``git push --dry-run`` is ignored."
    ),
    known_fp=(
        "A step that runs an agent for a read-only task (triage, labeling) "
        "but also pushes an unrelated generated file would match by "
        "co-location. Split the agent and the push into separate steps, or "
        "suppress on the step with a rationale noting the agent does not "
        "write the pushed paths.",
    ),
)

# A plain ``git push`` (the Bitbucket idiom for committing straight to a
# branch); ``--dry-run`` is ignored.
_GIT_PUSH_RE = re.compile(r"\bgit\s+push\b", re.IGNORECASE)


def _line_autolands(line: str) -> str | None:
    """Return a label for the no-review landing in *line*, or ``None``."""
    if _GIT_PUSH_RE.search(line) and "--dry-run" not in line:
        return "git push (commits to a branch)"
    return None


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for loc, step in iter_steps(doc):
        agent: str | None = None
        autoland: str | None = None
        for line in step_scripts_all(step):
            if agent is None:
                agent = invokes_agentic_cli(line)
            if autoland is None:
                autoland = _line_autolands(line)
        if agent is not None and autoland is not None:
            offenders.append(f"{loc}: {agent} + {autoland}")
            step_line = _line_of(step) if isinstance(step, dict) else None
            locations.append(
                Location(path=path, start_line=step_line, end_line=step_line)
            )
    passed = not offenders
    desc = (
        "No step both runs an agentic CLI and pushes its output without a "
        "review gate."
        if passed else
        f"{len(offenders)} step(s) run an agentic CLI and then push the "
        f"result straight to a branch with no human review: "
        f"{', '.join(offenders[:5])}{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
