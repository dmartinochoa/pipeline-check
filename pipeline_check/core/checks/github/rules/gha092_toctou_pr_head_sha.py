"""GHA-092. PR head read LIVE then re-fetched: contributor force-push race.

Inspired by zizmor proposal #935. A workflow that resolves the PR head
with a **live** read (``gh pr view``/``gh api .../pulls/<n>``, or
``git rev-parse HEAD`` after a mutable-ref checkout) and then runs
``actions/checkout`` with ``ref: ${{ github.event.pull_request.head.sha
}}`` in a later step is racing the contributor: the live read and the
pinned re-fetch resolve independently, so a force-push between them
desyncs the gate decision from what actually gets built.

Crucially, ``${{ github.event.pull_request.head.sha }}`` is the
*immutable* webhook payload. A workflow that reads it for the gate AND
checks it out is doing two reads of the **same constant** — there is no
race, and pipeline-check stays silent. This rule fires only when one
side is a genuinely live read that a force-push can move.

Detection: per-job step-order traversal. Mark the job once a step does a
live PR-head read. On any subsequent ``actions/checkout`` with
``ref: ${{ github.event.pull_request.head.sha }}``, fire.

Pairs with GHA-045 (caller-controlled ref into checkout) and GHA-046
(manual PR-head fetch).
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location

RULE = Rule(
    id="GHA-092",
    title="PR head read live then re-fetched (force-push race)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1", "CICD-SEC-7"),
    esf=("ESF-D-CODE-REVIEW",),
    cwe=("CWE-367", "CWE-362"),
    recommendation=(
        "Read the PR head once and reuse the captured value for both "
        "the gate and the checkout. Snapshot the immutable payload SHA "
        "(``echo \"sha=${{ github.event.pull_request.head.sha }}\" >> "
        "\"$GITHUB_OUTPUT\"``) and drive both the gate decision and "
        "``actions/checkout`` (``ref: ${{ steps.snap.outputs.sha }}``) "
        "from that single atom, so a force-push can't desync them. "
        "Don't pair a live re-read (``gh pr view`` / ``gh api "
        ".../pulls/<n>`` / ``git rev-parse HEAD`` after a mutable "
        "checkout) with a second, independent read: that is the race. "
        "Pinning both sides to ``github.event.*.head.sha`` is already "
        "safe (the payload is a trigger-time constant)."
    ),
    docs_note=(
        "Within a single job, step-order traversal looks for:\n\n"
        "1. A **live read** of the PR head, a ``run:`` body invoking "
        "``gh pr view`` / ``gh api .../pulls/<n>`` (both fetch the "
        "*current* head), or ``git rev-parse HEAD`` after a mutable-ref "
        "checkout (a checkout with no ``ref:``, or one whose ``ref`` is "
        "anything other than the pinned ``head.sha``). Each of these "
        "can resolve to a commit a contributor force-pushed after the "
        "trigger.\n"
        "2. A **fetch** step that follows it, an ``actions/checkout`` "
        "whose ``with.ref:`` is ``${{ github.event.pull_request.head."
        "sha }}``.\n\n"
        "The fire condition is the *order*, live-read-then-fetch. "
        "A workflow that reads ``github.event.*.head.sha`` (in a "
        "``run:`` / ``env:`` interpolation or a checkout ``ref``) and "
        "also checks it out is reading the same immutable payload "
        "constant twice, no race, and stays silent. Cross-job state "
        "isn't covered because GitHub Actions doesn't share a "
        "filesystem between jobs by default."
    ),
    known_fp=(
        "If the workflow genuinely wants to track HEAD-of-PR over time "
        "(e.g., a long-running review session that picks up additional "
        "commits between gate and merge), the live-read shape isn't the "
        "bug, the design is. Suppress per-step with a rationale that "
        "explains the contract; pair with a branch-protection rule on "
        "the contributor side that blocks force-pushes to PR branches "
        "so the race window stays closed in practice.",
    ),
    incident_refs=(
        "GitHub Security Lab \"checkout-after-rev-parse\" research "
        "(2024) and zizmor proposal #935: red-team demonstrations of "
        "contributor force-pushes landing un-reviewed code between a "
        "workflow's live read of the PR head and a later checkout.",
    ),
    exploit_example=(
        "# Vulnerable: the gate reads the CURRENT head live (gh pr\n"
        "# view), then a later checkout pins to the payload SHA. The\n"
        "# two reads resolve independently, so a force-push after the\n"
        "# gate lets the gate approve one commit while a different one\n"
        "# is what the run examined.\n"
        "jobs:\n"
        "  gate-and-build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - id: gate\n"
        "        env:\n"
        "          PR: ${{ github.event.number }}\n"
        "        run: |\n"
        "          LIVE=$(gh pr view \"$PR\" --json headRefOid -q .headRefOid)\n"
        "          ./review-gate.sh \"$LIVE\"\n"
        "      - uses: actions/checkout@<sha>\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        "\n"
        "# Safe: snapshot the immutable payload SHA once and use the\n"
        "# captured value for both the gate and the fetch, so there is\n"
        "# only ever one read.\n"
        "jobs:\n"
        "  gate-and-build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - id: snap\n"
        "        run: echo \"sha=${{ github.event.pull_request.head.sha }}\" >> \"$GITHUB_OUTPUT\"\n"
        "      - run: ./review-gate.sh ${{ steps.snap.outputs.sha }}\n"
        "      - uses: actions/checkout@<sha>\n"
        "        with:\n"
        "          ref: ${{ steps.snap.outputs.sha }}"
    ),
)


#: ``${{ github.event.pull_request.head.sha }}`` (and the
#: ``pull_request_target`` variant, same value, more dangerous trigger
#: context). Whitespace inside ``${{ ... }}`` is permitted by
#: GitHub-Actions; collapse with ``\s*``.
_PR_HEAD_SHA_RE = re.compile(
    r"\$\{\{\s*github\.event\.pull_request(?:_target)?\.head\.sha\s*\}\}",
)

#: A genuinely LIVE read of the current PR head: ``gh pr view`` and
#: ``gh api .../pulls/<n>`` both fetch the head as it is *now*, which a
#: contributor can force-push after the trigger, unlike the immutable
#: ``github.event.*.head.sha`` payload.
_LIVE_PR_HEAD_READ_RE = re.compile(
    r"\bgh\s+pr\s+view\b|\bgh\s+api\b[^\n]*\bpulls/",
    re.IGNORECASE,
)

#: ``git rev-parse HEAD`` (with or without ``--verify``). Anchored on
#: word boundaries so ``git rev-parse refs/heads/main`` doesn't match.
#: Only a live read when it follows a *mutable* checkout (see below).
_GIT_REV_PARSE_HEAD_RE = re.compile(r"\bgit\s+rev-parse\s+HEAD\b")


def _step_is_checkout(step: dict[str, Any]) -> bool:
    """True when *step* invokes ``actions/checkout`` (any ref)."""
    uses = step.get("uses")
    return isinstance(uses, str) and uses.lower().startswith(
        "actions/checkout@",
    )


def _step_checkout_pr_head_sha(step: dict[str, Any]) -> bool:
    """True when *step* is ``actions/checkout`` with ``ref:`` containing
    ``github.event.pull_request.head.sha``."""
    if not _step_is_checkout(step):
        return False
    with_block = step.get("with")
    if not isinstance(with_block, dict):
        return False
    ref = with_block.get("ref")
    if not isinstance(ref, str):
        return False
    return bool(_PR_HEAD_SHA_RE.search(ref))


def _step_live_capture(step: dict[str, Any], saw_mutable_checkout: bool) -> bool:
    """True when *step* performs a live read of the PR head.

    ``gh pr view`` / ``gh api .../pulls/<n>`` are always live. ``git
    rev-parse HEAD`` is a live read only after a *mutable* checkout has
    put HEAD at a force-pushable ref; ``saw_mutable_checkout`` carries
    that signal.
    """
    run = step.get("run")
    if not isinstance(run, str):
        return False
    if _LIVE_PR_HEAD_READ_RE.search(run):
        return True
    if saw_mutable_checkout and _GIT_REV_PARSE_HEAD_RE.search(run):
        return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for job_id, job in iter_jobs(doc):
        captured_live = False
        saw_mutable_checkout = False
        for idx, step in enumerate(iter_steps(job)):
            # Fetch side: a pinned-payload checkout after a live read is
            # the race. Checked before the capture/mutable updates so a
            # checkout can't count as its own predecessor.
            if captured_live and _step_checkout_pr_head_sha(step):
                name = step.get("name") or step.get("id") or f"steps[{idx}]"
                offenders.append(f"{job_id}.{name}")
                locations.append(step_location(path, step))
                continue
            if _step_live_capture(step, saw_mutable_checkout):
                captured_live = True
            if _step_is_checkout(step) and not _step_checkout_pr_head_sha(step):
                # A checkout pinned to the immutable payload SHA leaves a
                # fixed tree; any other ref (default / branch / head.ref)
                # is mutable, so a subsequent ``git rev-parse HEAD`` is a
                # live read.
                saw_mutable_checkout = True
    passed = not offenders
    desc = (
        "No step re-fetches the pinned PR head SHA after a prior live "
        "read of the PR head."
        if passed else
        f"{len(offenders)} actions/checkout step(s) re-fetch the pinned "
        f"PR head SHA after a previous step read the head live: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A contributor force-push "
        f"between the live read and the fetch lets the gate decision "
        f"and the built code disagree."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
