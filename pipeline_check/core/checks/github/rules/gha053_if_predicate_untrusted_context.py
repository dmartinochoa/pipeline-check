"""GHA-053. ``if:`` predicate evaluates attacker-controllable context."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="GHA-053",
    title="if: predicate evaluates attacker-controllable context as expression",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-CODE-INTEGRITY",),
    cwe=("CWE-94", "CWE-1336"),
    recommendation=(
        "Compare against safe context keys (``github.ref``, "
        "``github.actor``, ``github.repository``) and check the "
        "untrusted input via a step output rather than a direct "
        "``if:`` reference. Concretely: read the attacker-"
        "controllable field into a step output first, then use "
        "``if: steps.gate.outputs.is_release == 'true'`` rather "
        "than ``if: contains(github.event.head_commit.message, "
        "'[release]')``. The shape difference is subtle but "
        "decisive: GitHub passes the ``if:`` string through its "
        "expression evaluator, which means certain payloads in "
        "the untrusted value (single-quote injection, nested "
        "``${{ }}``) execute as expression syntax rather than "
        "matching as a literal. Routing through a step output "
        "forces the value to land in a shell variable first, "
        "where the runner's normal quoting protects it.\n\n"
        "Documented attack: a PR title of ``${{ secrets.X }}`` "
        "inside an ``if: contains(github.event.pull_request."
        "title, ...)`` predicate evaluates the ``secrets.X`` "
        "reference instead of comparing it as a literal, "
        "exfiltrating the secret into the workflow's "
        "conditional decision and from there into logs."
    ),
    docs_note=(
        "Scans every job-level and step-level ``if:`` for "
        "references to attacker-controllable expression "
        "contexts: ``github.event.head_commit.message``, "
        "``github.event.pull_request.title``, ``...body``, "
        "``...head.ref``, ``github.head_ref`` (the top-level "
        "shorthand for the same PR source-branch name), "
        "``github.event.issue.title`` / "
        "``...body``, ``github.event.comment.body``, "
        "``github.event.review_comment.body``, "
        "``github.event.review.body``.\n\n"
        "Safe contexts (``github.ref``, ``github.ref_name``, "
        "``github.actor``, ``github.repository``, "
        "``github.event_name``) are not flagged — those are "
        "set by GitHub, not by the actor. ``inputs.*`` "
        "references are also safe by convention; the trigger "
        "channel that supplies them is a separate trust "
        "boundary the workflow author controls.\n\n"
        "Complements GHA-002 (``run:`` body interpolating "
        "untrusted context — same source set, shell sink) and "
        "GHA-052 (cache key derived from untrusted context — "
        "same source set, cache sink). GHA-053 closes the "
        "third sink: the expression evaluator itself."
    ),
    known_fp=(
        "A workflow that legitimately gates on the existence "
        "of certain text in the commit message (release "
        "automation) and is invoked only via "
        "``workflow_dispatch`` from a trusted actor isn't "
        "exposed to the attack. The right pattern is still to "
        "route through a step output for clarity; suppress on "
        "the specific job/step when the trigger channel itself "
        "enforces the trust boundary.",
    ),
    exploit_example=(
        "# Vulnerable: ``if: ${{ contains(github.event.issue.title,\n"
        "# 'deploy') }}`` evaluates an attacker-controllable string\n"
        "# in the expression language. The expression engine\n"
        "# parses certain inputs (``${{ ... }}`` nested) before\n"
        "# the contains() check, so a crafted title can corrupt\n"
        "# the predicate's evaluation.\n"
        "on:\n"
        "  issue_comment:\n"
        "    types: [created]\n"
        "jobs:\n"
        "  ondemand-deploy:\n"
        "    if: ${{ contains(github.event.comment.body, '/deploy') }}\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions: { contents: write }\n"
        "    steps:\n"
        "      - run: ./deploy.sh\n"
        "\n"
        "# Safe: route the untrusted value through an intermediate\n"
        "# step that pulls the value into an env var, then evaluate\n"
        "# the predicate against a guaranteed-safe shape (issue\n"
        "# author is a maintainer, label exists, etc.) computed\n"
        "# from authenticated sources.\n"
        "on:\n"
        "  issue_comment:\n"
        "    types: [created]\n"
        "jobs:\n"
        "  ondemand-deploy:\n"
        "    if: |\n"
        "      github.event.comment.author_association == 'OWNER' &&\n"
        "      startsWith(github.event.comment.body, '/deploy')\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions: { contents: write }\n"
        "    steps:\n"
        "      - run: ./deploy.sh"
    ),
)


_UNTRUSTED_CONTEXTS: tuple[str, ...] = (
    "github.event.head_commit.message",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    # ``github.head_ref`` is the top-level shorthand for the PR's
    # source-branch name on ``pull_request`` events. The branch name
    # is fully attacker-controlled (a fork can name its branch
    # anything, including ``${{ secrets.X }}``); same risk shape as
    # ``github.event.pull_request.head.ref``, more common in the wild.
    "github.head_ref",
    # PR metadata that any contributor with ``triage`` (or that any
    # first-time contributor under certain repo configurations) can
    # set. Gating an ``if:`` on ``contains(github.event.pull_request.
    # labels.*.name, 'safe-to-test')`` was the canonical 2024
    # supply-chain foot-gun. The milestone fields and the
    # requested-reviewers list have the same shape: visible in YAML,
    # settable by a low-privilege actor. Substring-match against
    # the parent path catches every spelling of the nested access.
    "github.event.pull_request.labels",
    "github.event.pull_request.milestone.title",
    "github.event.pull_request.milestone.description",
    "github.event.pull_request.requested_reviewers",
    "github.event.pull_request.assignees",
)


_UNTRUSTED_BOUNDARY_RE = {
    token: re.compile(re.escape(token) + r"(?![A-Za-z0-9_])")
    for token in _UNTRUSTED_CONTEXTS
}


def _matches_untrusted(value: Any) -> list[str]:
    if not isinstance(value, str):
        return []
    return [token for token, pat in _UNTRUSTED_BOUNDARY_RE.items() if pat.search(value)]


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        # Job-level ``if:`` is evaluated to decide whether the job
        # runs at all; same expression evaluator as step-level.
        job_if = job.get("if")
        hits = _matches_untrusted(job_if)
        if hits:
            offenders.append(
                f"jobs.{job_id}.if: {', '.join(hits[:2])}"
            )
        for idx, step in enumerate(iter_steps(job)):
            step_if = step.get("if")
            step_hits = _matches_untrusted(step_if)
            if not step_hits:
                continue
            step_label = step.get("name") or step.get("id") or f"steps[{idx}]"
            offenders.append(
                f"jobs.{job_id}.{step_label}.if: "
                f"{', '.join(step_hits[:2])}"
            )
    passed = not offenders
    desc = (
        "No ``if:`` predicate evaluates attacker-controllable "
        "context as an expression."
        if passed else
        f"{len(offenders)} ``if:`` predicate(s) reference "
        f"untrusted context directly: {', '.join(offenders[:3])}"
        f"{'…' if len(offenders) > 3 else ''}. A crafted "
        f"payload in that context (e.g., a PR title containing "
        f"``${{{{ secrets.X }}}}``) is parsed by the expression "
        f"evaluator, not compared as a literal."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
