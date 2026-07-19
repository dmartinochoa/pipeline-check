"""GL-049. Agentic-CLI output lands without human review.

A GitLab job runs an agentic coding CLI (claude / gemini / cursor-agent /
aider / openhands / goose / ``q chat``) that edits the tree, AND the same
job then lands the result with no human in the loop: a raw ``git push`` to
a branch, a ``git push`` with the ``merge_request.merge_when_pipeline_
succeeds`` push option, or ``glab mr merge`` with an auto / non-interactive
flag. The combination means AI-authored changes reach a branch (or a merge)
without a review gate. If the agent's prompt is at all influenced by
untrusted input (an MR title / description, a fetched page) that is
prompt-injection straight to committed code (see GL-048), and even without
injection it removes the human review CICD-SEC-1 assumes.

The GitLab analog of GHA-123, and the flow-control leg of the GitLab
AI/model pack (GL-045..048). The landing idioms are GitLab-specific
(``uses:`` actions don't exist here), so the detection is its own; the
agentic-CLI catalog is the shared ``_primitives/agentic_cli`` helper.
"""
from __future__ import annotations

import re
from typing import Any

from ..._primitives.agentic_cli import invokes_agentic_cli
from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, job_scripts

RULE = Rule(
    id="GL-049",
    title="Agentic CLI output lands without human review",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1",),
    esf=("ESF-C-APPROVAL",),
    cwe=("CWE-94", "CWE-693"),
    recommendation=(
        "Don't let an agentic CLI's output reach a branch or a merge "
        "without a human review gate. Have the agent open a normal merge "
        "request (``glab mr create`` with no auto-merge) so a person "
        "reviews the diff before it lands; drop ``glab mr merge "
        "--auto-merge`` / ``--yes`` and the ``merge_request.merge_when_"
        "pipeline_succeeds`` push option from the agent's job, and don't "
        "pair the agent with a ``git push`` straight to a protected branch. "
        "If the agent's prompt can be influenced by untrusted input (an MR "
        "title / description, a fetched page), treat the committed result "
        "as attacker-controlled."
    ),
    docs_note=(
        "Fires when one job both invokes an agentic CLI (``claude`` / "
        "``gemini`` / ``cursor-agent`` / ``aider`` / ``openhands`` / "
        "``goose`` / ``q chat``) and, in the same job, lands the result "
        "with no review gate. The landing command is one of: a ``glab mr "
        "merge`` with an auto / non-interactive flag (``--auto-merge`` / "
        "``--yes`` / ``-y`` / ``--when-pipeline-succeeds``), a ``git push`` "
        "carrying the ``merge_request.merge_when_pipeline_succeeds`` push "
        "option, or a plain ``git push`` (the GitLab idiom for committing "
        "straight to a branch).\n\n"
        "Does NOT fire when the agent only opens a merge request for review "
        "(``glab mr create`` with no merge), nor on a push / auto-merge job "
        "that does not run an agent (ordinary formatting / generated-file "
        "bots). The agent-plus-auto-land coupling is the signal. A "
        "``git push --dry-run`` is ignored."
    ),
    known_fp=(
        "A job that runs an agent for a read-only task (triage, labeling) "
        "but also pushes an unrelated generated file would match by "
        "co-location. Split the agent and the push into separate jobs, or "
        "suppress on the job with a rationale noting the agent does not "
        "write the pushed paths.",
    ),
)

# ``glab mr merge`` with an auto / non-interactive flag (merges with no
# human approval step).
_GLAB_MERGE_RE = re.compile(
    r"\bglab\s+mr\s+merge\b[^\n]*"
    r"(?:--auto-merge|--when-pipeline-succeeds|--merge-when-pipeline-succeeds"
    r"|--yes\b|\s-y\b)",
    re.IGNORECASE,
)

# ``git push`` carrying the auto-merge push option.
_PUSH_AUTOMERGE_RE = re.compile(
    r"\bgit\s+push\b[^\n]*merge_request\.merge_when_pipeline_succeeds",
    re.IGNORECASE,
)

# A plain ``git push`` (the GitLab idiom for committing straight to a branch).
_GIT_PUSH_RE = re.compile(r"\bgit\s+push\b", re.IGNORECASE)

# Opening a merge request routes the change through human review, so a
# plain ``git push`` that feeds a ``glab mr create`` is not an auto-land.
_GLAB_MR_CREATE_RE = re.compile(r"\bglab\s+mr\s+create\b", re.IGNORECASE)

_PLAIN_PUSH_LABEL = "git push (commits to a branch)"


def _line_autolands(line: str) -> str | None:
    """Return a label for the no-review landing in *line*, or ``None``."""
    if _GLAB_MERGE_RE.search(line):
        return "glab mr merge (auto / non-interactive)"
    if _PUSH_AUTOMERGE_RE.search(line):
        return "git push -o merge_request.merge_when_pipeline_succeeds"
    if _GIT_PUSH_RE.search(line) and "--dry-run" not in line:
        return _PLAIN_PUSH_LABEL
    return None


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    anchor_jobs: dict[str, None] = {}
    for job_id, job in iter_jobs(doc):
        agent: str | None = None
        autoland: str | None = None
        opens_mr = False
        for line in job_scripts(job):
            if agent is None:
                agent = invokes_agentic_cli(line)
            if autoland is None:
                autoland = _line_autolands(line)
            if _GLAB_MR_CREATE_RE.search(line):
                opens_mr = True
        # A plain ``git push`` that feeds an ``glab mr create`` opens the
        # change for human review — the recommended flow — so it is not an
        # auto-land. The explicit auto-merge shapes still fire.
        if autoland == _PLAIN_PUSH_LABEL and opens_mr:
            autoland = None
        if agent is not None and autoland is not None:
            offenders.append(f"{job_id}: {agent} + {autoland}")
            line_no = _line_of(job)
            locations.append(
                Location(path=path, start_line=line_no, end_line=line_no)
            )
            anchor_jobs[job_id] = None
    passed = not offenders
    desc = (
        "No job both runs an agentic CLI and lands its output without a "
        "review gate."
        if passed else
        f"{len(offenders)} job(s) run an agentic CLI and then push or "
        f"auto-merge the result with no human review: "
        f"{', '.join(offenders[:5])}{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
        job_anchors=tuple(anchor_jobs),
    )
