"""GHA-092. PR head SHA captured then re-fetched: contributor force-push race.

Inspired by zizmor proposal #935. A workflow that resolves the PR
head once (``HEAD_SHA=${{ github.event.pull_request.head.sha }}``,
or ``git rev-parse HEAD`` after a prior checkout) and then runs
``actions/checkout`` with ``ref: ${{ github.event.pull_request.head.
sha }}`` in a later step is racing the contributor.

The PR head can be force-pushed between the two reads. The first
read is the snapshot the review / label / approver gate sees; the
second is what actually gets fetched and built. The two can
disagree on adversarial timing, and the workflow ends up running
code that bypassed its own gate.

Detection: per-job step-order traversal. Mark the job once any step
"captures" the PR head SHA (a ``run:`` body interpolating
``github.event.pull_request.head.sha``, an ``env:`` binding of that
expression, or a ``run:`` containing ``git rev-parse HEAD``). On any
subsequent step that calls ``actions/checkout`` with ``ref:``
containing ``github.event.pull_request.head.sha``, fire.

Pairs with GHA-045 (caller-controlled ref into checkout) and
GHA-046 (manual PR-head fetch).
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location

RULE = Rule(
    id="GHA-092",
    title="PR head SHA captured then re-fetched (force-push race)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1", "CICD-SEC-7"),
    esf=("ESF-D-CODE-REVIEW",),
    cwe=("CWE-367", "CWE-362"),
    recommendation=(
        "Read the PR head SHA once and reuse the captured value for "
        "the actual checkout. ``actions/checkout`` accepts a ``ref:`` "
        "the workflow already resolved (``ref: ${{ steps.snap."
        "outputs.sha }}`` after a ``steps.snap`` that captures the "
        "SHA from the event payload), so the same atom drives both "
        "the gate decision and the fetch. If a re-read is genuinely "
        "needed (you want the latest commit, accepting the race), "
        "drop the gate logic that depends on the earlier snapshot, "
        "the two are not the same primitive."
    ),
    docs_note=(
        "Within a single job, step-order traversal looks for:\n\n"
        "1. A **capture** step, any step that reads "
        "``github.event.pull_request.head.sha`` (either as a "
        "``${{ }}`` interpolation in a ``run:`` body, in a step or "
        "job ``env:`` block, or via a ``run:`` body containing "
        "``git rev-parse HEAD`` after an earlier checkout).\n"
        "2. A **fetch** step that follows it, an "
        "``actions/checkout`` whose ``with.ref:`` contains the same "
        "``${{ github.event.pull_request.head.sha }}`` expression.\n\n"
        "The fire condition is the *order*, capture-then-fetch with "
        "no intervening lock on the ref. Workflows that do the "
        "fetch FIRST (and only read the SHA after) are not "
        "TOCTOU-shaped because there's only one read; pipeline-"
        "check stays silent. Cross-job state isn't covered because "
        "GitHub-Actions doesn't share a filesystem between jobs by "
        "default; ``needs:`` data passing via ``outputs:`` is a "
        "separate shape (TAINT-002 territory)."
    ),
    known_fp=(
        "If the workflow genuinely wants to track HEAD-of-PR over "
        "time (e.g., a long-running review session that picks up "
        "additional commits between gate and merge), the TOCTOU "
        "shape isn't the bug, the design is. Suppress per-step "
        "with a rationale that explains the contract; pair with a "
        "branch-protection rule on the contributor side that "
        "blocks force-pushes to PR branches so the race window "
        "stays closed in practice.",
    ),
    incident_refs=(
        "GitHub Security Lab \"checkout-after-rev-parse\" research "
        "(2024) and zizmor proposal #935: red-team demonstrations "
        "of contributor force-pushes landing un-reviewed code "
        "between a workflow's two reads of the PR head SHA. The "
        "attack works against PR-review gates, labeler gates, and "
        "any approval-by-SHA workflow that uses the snapshot value "
        "for the decision and a live re-read for the build.",
    ),
    exploit_example=(
        "# Vulnerable: two reads of the PR head, with a gate in\n"
        "# between. A contributor force-push between the snapshot\n"
        "# and the second checkout lets unreviewed code run with\n"
        "# the gate's stamp of approval.\n"
        "jobs:\n"
        "  review-and-build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - id: snap\n"
        "        run: echo \"sha=${{ github.event.pull_request.head.sha }}\" >> \"$GITHUB_OUTPUT\"\n"
        "      - run: ./review-gate.sh ${{ steps.snap.outputs.sha }}\n"
        "      - uses: actions/checkout@<sha>\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        "\n"
        "# Safe: capture once, use the captured value for both the\n"
        "# gate and the fetch. ``checkout`` accepts the resolved\n"
        "# SHA as a ``ref:`` directly.\n"
        "jobs:\n"
        "  review-and-build:\n"
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
#: ``pull_request_target`` variant, same value, more dangerous
#: trigger context). Whitespace inside ``${{ ... }}`` is permitted
#: by GitHub-Actions; collapse with ``\s*``.
_PR_HEAD_SHA_RE = re.compile(
    r"\$\{\{\s*github\.event\.pull_request(?:_target)?\.head\.sha\s*\}\}",
)

#: ``git rev-parse HEAD`` (with or without ``--verify``, with or
#: without the trailing newline). Anchored on word boundaries so
#: ``git rev-parse refs/heads/main`` doesn't match.
_GIT_REV_PARSE_HEAD_RE = re.compile(r"\bgit\s+rev-parse\s+HEAD\b")


def _step_captures_pr_head(
    step: dict[str, Any],
    workflow_env_captures: bool,
    job_env_captures: bool,
    saw_checkout: bool,
) -> bool:
    """True when *step* captures the PR head SHA (any of the shapes).

    ``workflow_env_captures`` / ``job_env_captures`` propagate the
    "the env block at a higher scope already binds the SHA" signal
    so any step that touches env names defined at that scope counts
    as a capture by transitive reference. ``saw_checkout`` gates the
    ``git rev-parse HEAD`` shape, that read is only meaningful after a
    prior checkout has set HEAD to the PR ref; firing on it absent a
    checkout produces false positives on workflows that just probe
    runner SHAs unrelated to the PR.
    """
    if workflow_env_captures or job_env_captures:
        # Higher-scope env binds it; this step inherits. Treating
        # all subsequent steps as past-capture is the conservative
        # call.
        return True
    env_block = step.get("env")
    if isinstance(env_block, dict):
        for value in env_block.values():
            if isinstance(value, str) and _PR_HEAD_SHA_RE.search(value):
                return True
    run = step.get("run")
    if isinstance(run, str):
        if _PR_HEAD_SHA_RE.search(run):
            return True
        if saw_checkout and _GIT_REV_PARSE_HEAD_RE.search(run):
            return True
    return False


def _step_is_checkout(step: dict[str, Any]) -> bool:
    """True when *step* invokes ``actions/checkout`` (any ref)."""
    uses = step.get("uses")
    return isinstance(uses, str) and uses.lower().startswith(
        "actions/checkout@",
    )


def _step_checkout_pr_head_sha(step: dict[str, Any]) -> bool:
    """True when *step* is ``actions/checkout`` with
    ``ref:`` containing ``github.event.pull_request.head.sha``."""
    uses = step.get("uses")
    if not isinstance(uses, str):
        return False
    if not uses.lower().startswith("actions/checkout@"):
        return False
    with_block = step.get("with")
    if not isinstance(with_block, dict):
        return False
    ref = with_block.get("ref")
    if not isinstance(ref, str):
        return False
    return bool(_PR_HEAD_SHA_RE.search(ref))


def _env_binds_pr_head(env_block: Any) -> bool:
    """True when an ``env:`` block (any scope) maps a name to the
    PR head SHA expression."""
    if not isinstance(env_block, dict):
        return False
    for value in env_block.values():
        if isinstance(value, str) and _PR_HEAD_SHA_RE.search(value):
            return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    workflow_env_captures = _env_binds_pr_head(doc.get("env"))
    offenders: list[str] = []
    locations: list[Location] = []
    for job_id, job in iter_jobs(doc):
        job_env_captures = _env_binds_pr_head(job.get("env"))
        captured_so_far = False
        saw_checkout = False
        for idx, step in enumerate(iter_steps(job)):
            # Update capture state BEFORE the fetch check so a step
            # that both captures and fetches in the same body (the
            # canonical "checkout with ref interpolating sha" + body
            # that also reads sha) doesn't false-fire on its own
            # first-and-only read.
            if _step_checkout_pr_head_sha(step) and captured_so_far:
                name = step.get("name") or step.get("id") or f"steps[{idx}]"
                offenders.append(f"{job_id}.{name}")
                locations.append(step_location(path, step))
                saw_checkout = True
                continue
            if _step_captures_pr_head(
                step,
                workflow_env_captures,
                job_env_captures,
                saw_checkout,
            ):
                captured_so_far = True
            if _step_is_checkout(step):
                saw_checkout = True
    passed = not offenders
    desc = (
        "No step re-fetches the PR head SHA after a prior step "
        "captured it."
        if passed else
        f"{len(offenders)} actions/checkout step(s) re-read the PR "
        f"head SHA after a previous step captured the same value: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A contributor force-"
        f"push between the two reads lets unreviewed code land with "
        f"the gate's stamp of approval."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
