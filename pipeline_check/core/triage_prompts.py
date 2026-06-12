"""Prompt template for local-LLM finding triage.

Kept in its own module (separate from the ``triage`` client) so the exact
text sent to a model is reviewable in one place and easy to tune without
touching the transport / parsing logic.

The prompt is deliberately closed-form: it states the finding, shows the
surrounding pipeline snippet, and asks for a single JSON object with one
of three labels plus a one-sentence rationale. The model is told the
verdict is advisory and must not invent severity.
"""
from __future__ import annotations

from .checks.base import Finding

#: The three advisory labels the model must choose from. Kept here next to
#: the prompt so the wording the model sees and the wording the parser
#: accepts can't drift apart.
TRIAGE_LABELS = ("confirmed", "needs_review", "likely_fp")

_SYSTEM = (
    "You are a CI/CD security triage assistant. A static scanner has "
    "flagged a finding in a pipeline definition. Using ONLY the finding "
    "details and the surrounding pipeline snippet provided, judge whether "
    "the issue is actually exploitable in this repository's context.\n\n"
    "Reply with exactly one JSON object and nothing else:\n"
    '  {"label": "confirmed" | "needs_review" | "likely_fp", '
    '"rationale": "<one short sentence>"}\n\n'
    "Use \"confirmed\" only when the snippet shows the issue is concretely "
    "reachable / exploitable; \"likely_fp\" when the surrounding context "
    "clearly neutralizes it; \"needs_review\" when you cannot tell from the "
    "snippet alone. Your verdict is advisory and never changes the "
    "scanner's severity."
)


def build_prompt(finding: Finding, snippet: str) -> str:
    """Return the full triage prompt for *finding* and its *snippet*.

    *snippet* is the surrounding pipeline text (typically a few lines
    around the finding's location); it may be empty when no source
    context could be extracted, in which case the model is told so.
    """
    sev = finding.severity.value if finding.severity is not None else "UNKNOWN"
    snippet_block = snippet.strip() or "(no source snippet available)"
    return (
        f"{_SYSTEM}\n\n"
        f"Finding: {finding.check_id} [{sev}] {finding.title}\n"
        f"Resource: {finding.resource}\n"
        f"Description: {finding.description}\n\n"
        f"Pipeline snippet:\n"
        f"```\n{snippet_block}\n```\n"
    )
