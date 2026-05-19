"""GHA-013, issue_comment trigger must guard on author association."""
from __future__ import annotations

import re
from typing import Any

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, workflow_triggers

RULE = Rule(
    id="GHA-013",
    title="issue_comment trigger without author guard",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-78",),
    recommendation=(
        "Add an `if:` condition that checks "
        "`github.event.comment.author_association` (e.g. "
        "`contains('OWNER MEMBER COLLABORATOR', ...)`), "
        "`github.event.sender.login`, or `github.actor` against an "
        "allowlist. Without a guard, any GitHub user can trigger the "
        "workflow by posting a comment."
    ),
    docs_note=(
        "`on: issue_comment` (and `discussion_comment`) fires for "
        "every comment on every issue or discussion in the repository. "
        "On public repos this means any GitHub user can trigger "
        "workflow execution. If the workflow runs commands, deploys, "
        "or accesses secrets, the attacker controls timing and can "
        "inject payloads through the comment body."
    ),
    known_fp=(
        "Guard detection runs against the whole workflow as text "
        "rather than against parsed ``if:`` expressions, so a "
        "guard token appearing in an unrelated context (a "
        "comment, a step name, a description field) reads as "
        "satisfying the rule. Conversely, guards expressed via "
        "alternative author-association idioms the regex doesn't "
        "recognize (``github.event.issue.user.login``, an org-"
        "membership API check inside a script) leave the rule "
        "firing even though the workflow is safely gated. "
        "Suppress per-workflow via ``--ignore-file`` once you've "
        "verified the gate logic; tighten the guard expression "
        "to use the recognized tokens if possible.",
    ),
    exploit_example=(
        "# Vulnerable: any GitHub user posts a comment ``/deploy``\n"
        "# (or just any comment, since the if: doesn't gate on author)\n"
        "# and the workflow runs with write-scope GITHUB_TOKEN.\n"
        "on:\n"
        "  issue_comment:\n"
        "    types: [created]\n"
        "jobs:\n"
        "  ship:\n"
        "    if: contains(github.event.comment.body, '/deploy')\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: ./scripts/deploy\n"
        "\n"
        "# Safe: the if: gates on author association first; only\n"
        "# OWNER / MEMBER / COLLABORATOR commenters can trigger.\n"
        "on:\n"
        "  issue_comment:\n"
        "    types: [created]\n"
        "jobs:\n"
        "  ship:\n"
        "    if: >\n"
        "      contains(github.event.comment.body, '/deploy') &&\n"
        "      contains('OWNER MEMBER COLLABORATOR',\n"
        "               github.event.comment.author_association)\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: ./scripts/deploy"
    ),
)

# Guards that restrict comment-triggered execution to trusted actors.
_AUTHOR_GUARD_RE = re.compile(
    r"github\.event\.(?:comment\.author_association|sender\.login)"
    r"|github\.actor",
)

_COMMENT_TRIGGERS = frozenset({
    "issue_comment",
    "discussion_comment",
})


def check(path: str, doc: dict[str, Any]) -> Finding:
    triggers = set(workflow_triggers(doc))
    if not triggers & _COMMENT_TRIGGERS:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Workflow is not triggered by issue_comment.",
            recommendation="No action required.", passed=True,
        )
    # Look for author-association or actor guards in job/workflow if: conditions.
    guarded = False
    # Check workflow-level if: (uncommon but valid).
    # Scan entire doc as text for the guard patterns. They must appear
    # in an `if:` expression somewhere to be effective.
    from ...base import blob_lower
    blob = blob_lower(doc)
    if _AUTHOR_GUARD_RE.search(blob):
        guarded = True
    passed = guarded
    active = sorted(triggers & _COMMENT_TRIGGERS)
    desc = (
        f"Comment-triggered workflow ({', '.join(active)}) gates "
        f"execution on author association or actor identity."
        if passed else
        f"Workflow triggers on {', '.join(active)} without checking "
        f"`github.event.comment.author_association`, "
        f"`github.event.sender.login`, or `github.actor`. Any GitHub "
        f"user can post a comment and trigger this workflow."
    )
    locations: list[Location] = []
    if not passed:
        # Anchor on the workflow's ``on:`` block, that's where the
        # missing guard lives. The loader's str-key shim normalises
        # the YAML 1.1 ``on`` -> ``True`` quirk, so a plain ``"on"``
        # lookup is sufficient. Falls back to the doc's own line
        # when ``on:`` somehow isn't a dict.
        on_block = doc.get("on")
        anchor: Any = on_block if isinstance(on_block, dict) else doc
        line = _line_of(anchor)
        locations.append(Location(path=path, start_line=line, end_line=line))
    # ``issue_comment`` is a workflow-level trigger: any unguarded
    # comment fires every job in the file. AC-029 intersects this
    # with credential / integrity legs that DO anchor per-job, so
    # fan the workflow-level anchor out to every job here so
    # reachability lands on any one of them.
    anchor_jobs = (
        tuple(job_id for job_id, _ in iter_jobs(doc))
        if not passed else ()
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
        job_anchors=anchor_jobs,
    )
