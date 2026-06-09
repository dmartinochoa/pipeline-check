"""JF-038. Agentic-CLI output lands without human review.

A Jenkinsfile runs an agentic coding CLI (claude / gemini / cursor-agent /
aider / openhands / goose / ``q chat``) in a ``sh`` / ``bat`` /
``powershell`` step that edits the tree, AND the same pipeline then lands
the result with no human in the loop: a ``git push`` straight to a branch.
The combination means AI-authored changes reach a branch without a review
gate. If the agent's prompt is at all influenced by untrusted input (a PR
title / branch, a build parameter, a fetched page) that is prompt-injection
straight to committed code (see JF-037), and even without injection it
removes the human review CICD-SEC-1 assumes.

The Jenkins analog of GHA-123 / GL-049 / BB-039 / ADO-038, and the
flow-control leg of the Jenkins AI pack alongside JF-037 (prompt injection).
Coupling is pipeline-level (not per-stage): the stages of one Jenkins
pipeline share a single checkout / workspace, so an agent in one stage and
a ``git push`` in another are still the same execution. The agentic-CLI
catalog is the shared ``_primitives/agentic_cli`` helper; the landing idiom
(``git push``, no ``uses:`` actions here) is its own.
"""
from __future__ import annotations

import re

from ..._primitives.agentic_cli import invokes_agentic_cli
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import Jenkinsfile
from ._helpers import SHELL_STEP_RE

RULE = Rule(
    id="JF-038",
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
        "the same pipeline. If the agent's prompt can be influenced by "
        "untrusted input (a PR title / branch, a build parameter), treat "
        "the committed result as attacker-controlled."
    ),
    docs_note=(
        "Fires when one Jenkinsfile both invokes an agentic CLI (``claude`` "
        "/ ``gemini`` / ``cursor-agent`` / ``aider`` / ``openhands`` / "
        "``goose`` / ``q chat``) in a ``sh`` / ``bat`` / ``powershell`` "
        "step and, in the same pipeline, lands the result with a "
        "``git push`` (the Jenkins idiom for committing straight to a "
        "branch, since there are no ``uses:`` actions). Coupling is "
        "pipeline-level because the stages of one pipeline share a "
        "checkout.\n\n"
        "Does NOT fire when the agent only opens a pull request for review, "
        "nor on a push step that does not run an agent (ordinary formatting "
        "/ generated-file jobs). The agent-plus-push coupling is the "
        "signal. A ``git push --dry-run`` is ignored."
    ),
)

# A plain ``git push`` (the Jenkins idiom for committing straight to a
# branch); ``--dry-run`` is ignored.
_GIT_PUSH_RE = re.compile(r"\bgit\s+push\b", re.IGNORECASE)


def check(jf: Jenkinsfile) -> Finding:
    text = jf.text_no_comments
    agent: str | None = None
    push_line: int | None = None
    for m in SHELL_STEP_RE.finditer(text):
        body = (
            m.group("triple_d") or m.group("triple_s")
            or m.group("dq") or m.group("sq") or ""
        )
        if agent is None:
            agent = invokes_agentic_cli(body)
        if push_line is None and _GIT_PUSH_RE.search(body) and "--dry-run" not in body:
            push_line = text[: m.start()].count("\n") + 1
    passed = not (agent is not None and push_line is not None)
    locations: list[Location] = []
    if not passed and push_line is not None:
        locations.append(Location(
            path=jf.path, start_line=push_line, end_line=push_line,
        ))
    desc = (
        "No pipeline both runs an agentic CLI and pushes its output without "
        "a review gate."
        if passed else
        f"The pipeline runs an agentic CLI ({agent}) and then pushes the "
        f"result straight to a branch (git push at line {push_line}) with "
        f"no human review."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
