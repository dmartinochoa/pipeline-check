"""HARNESS-009. Agentic-CLI output lands without human review."""
from __future__ import annotations

import re

from ..._primitives.agentic_cli import invokes_agentic_cli
from ...base import Finding, Severity
from ...rule import Rule
from ..base import HarnessPipeline, iter_steps, step_command_text

RULE = Rule(
    id="HARNESS-009",
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
        "untrusted input (a PR title / branch, a ``<+trigger.*>`` value), "
        "treat the committed result as attacker-controlled (HARNESS-008)."
    ),
    docs_note=(
        "Fires when one pipeline both invokes an agentic CLI (``claude`` / "
        "``gemini`` / ``cursor-agent`` / ``aider`` / ``openhands`` / "
        "``goose`` / ``q chat``) in a step ``command`` and, in the same "
        "pipeline, lands the result with a ``git push`` (the Harness idiom "
        "for committing straight to a branch). Coupling is pipeline-level "
        "because the stages of one Harness pipeline share the cloned "
        "codebase. Does NOT fire when the agent only opens a pull request "
        "for review, nor on a push step that runs no agent. A "
        "``git push --dry-run`` is ignored. The Harness analog of GHA-123 / "
        "GL-049 / BB-039 / ADO-038 / JF-038; with HARNESS-008 it composes "
        "the AC-040 injection -> autoland chain."
    ),
    exploit_example=(
        "# Vulnerable: an agent edits the tree and the same pipeline pushes\n"
        "# the result straight to a branch with no human reviewing the diff.\n"
        "- step:\n"
        "    type: Run\n"
        "    identifier: edit\n"
        "    spec:\n"
        "      image: node@sha256:...\n"
        "      command: |\n"
        "        aider --yes --message 'apply the fix'\n"
        "        git add -A && git commit -m auto && git push origin HEAD\n"
        "\n"
        "# Safe: the agent opens a pull request for human review instead of\n"
        "# pushing straight to a branch.\n"
    ),
)

# A plain ``git push`` (commit straight to a branch); ``--dry-run`` ignored.
_GIT_PUSH_RE = re.compile(r"\bgit\s+push\b", re.IGNORECASE)


def check(pipeline: HarnessPipeline) -> Finding:
    agent: str | None = None
    pushes = False
    for _stage_id, step in iter_steps(pipeline):
        text = step_command_text(step)
        if not text:
            continue
        if agent is None:
            agent = invokes_agentic_cli(text)
        if not pushes and _GIT_PUSH_RE.search(text) and "--dry-run" not in text:
            pushes = True
    passed = not (agent is not None and pushes)
    desc = (
        "No pipeline both runs an agentic CLI and pushes its output without "
        "a review gate."
        if passed else
        f"The pipeline runs an agentic CLI ({agent}) and then pushes the "
        f"result straight to a branch (git push) with no human review. "
        f"AI-authored changes reach a branch with no diff review."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
