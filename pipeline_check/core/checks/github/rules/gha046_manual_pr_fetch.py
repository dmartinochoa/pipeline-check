"""GHA-046, manual PR-head fetch inside an untrusted-trigger workflow.

GHA-002 catches the ``actions/checkout`` form of PR-head checkout
under ``pull_request_target``. This rule catches the same threat
when authors bypass ``actions/checkout`` and pull the PR head with
shell commands:

  * ``gh pr checkout <N>``
  * ``git fetch origin pull/<N>/head[:<local>]``
  * ``git fetch origin refs/pull/<N>/{head,merge}``
  * ``git checkout ${{ github.event.pull_request.head.sha }}``
  * ``git checkout FETCH_HEAD`` after one of the fetches above

The fetches resolve PR-controlled bytes; once the workflow then
runs anything against that tree, the attacker's commit executes
in a privileged context.
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, workflow_triggers
from ._helpers import UNTRUSTED_TRIGGERS

RULE = Rule(
    id="GHA-046",
    title="Manual PR-head fetch on untrusted-trigger workflow",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-829",),
    recommendation=(
        "Don't materialize the PR head in a ``pull_request_target`` "
        "or ``workflow_run`` job. If you need to inspect PR content, "
        "split the workflow: a privileged half (with secrets) that "
        "uses metadata only (PR number, base ref, label) and an "
        "unprivileged ``pull_request`` half that builds the code with "
        "no secrets in scope."
    ),
    docs_note=(
        "GHA-002 catches ``actions/checkout`` with "
        "``ref: ${{ github.event.pull_request.head.sha }}``. The "
        "same primitive shows up as ``gh pr checkout``, "
        "``git fetch origin pull/<N>/head``, and ``git checkout`` "
        "of an attacker-controlled SHA expression inside a "
        "``run:`` block. They all land the same bytes in the "
        "workspace with the same privileged context active, so "
        "they get the same severity."
    ),
    incident_refs=(
        "GitHub Security Lab: "
        "[Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/) "
        "(2020) listed manual ``git fetch pull/<N>/head`` as one of "
        "the equivalent ways teams shoot themselves in the foot. "
        "Auditors checking only ``actions/checkout`` miss the "
        "shell-level variants entirely.",
    ),
    exploit_example=(
        "# Vulnerable: pull_request_target + gh pr checkout.\n"
        "name: triage\n"
        "on:\n"
        "  pull_request_target:\n"
        "    types: [opened, synchronize]\n"
        "jobs:\n"
        "  test-pr:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>     # base, looks safe\n"
        "      - run: gh pr checkout ${{ github.event.number }}\n"
        "        env:\n"
        "          GH_TOKEN: ${{ github.token }}\n"
        "      - run: make test           # now runs PR Makefile\n"
        "\n"
        "# Attack: same as GHA-002. The PR ships a Makefile that\n"
        "# exfils $GITHUB_TOKEN and every ${{ secrets.* }} the\n"
        "# pull_request_target context exposes. GHA-002's pattern\n"
        "# match never fires because ``actions/checkout`` looks\n"
        "# innocent, the PR content lands via the shell instead.\n"
        "\n"
        "# Safe: don't materialize PR content with secrets active.\n"
        "# Move the build to a pull_request workflow:\n"
        "name: build\n"
        "on: { pull_request: {} }\n"
        "jobs:\n"
        "  test-pr:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>     # PR head, no secrets\n"
        "      - run: make test"
    ),
)


# Pattern catalog. Each entry is a regex anchored at the start of
# a line (after optional whitespace) to avoid matching mentions
# inside comments / strings.
_FETCH_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("gh pr checkout",
     re.compile(r"^\s*(?:sudo\s+)?gh\s+pr\s+checkout\b")),
    ("git fetch pull/<N>",
     # ``git fetch origin pull/123/head``, ``git fetch origin
     # refs/pull/123/head:pr-123``. Matches any remote name (not just
     # ``origin``) and either ``pull/`` or ``refs/pull/``.
     re.compile(
         r"^\s*(?:sudo\s+)?git\s+fetch\s+\S+\s+"
         r"(?:refs/)?pull/\d+/(?:head|merge)"
     )),
    ("git checkout PR-head expr",
     # ``git checkout ${{ github.event.pull_request.head.sha }}``,
     # ``.head.ref``, ``.head.label``. The expression form is the
     # tell that an attacker-controlled value lands at the
     # checkout boundary.
     re.compile(
         r"^\s*(?:sudo\s+)?git\s+(?:checkout|switch|reset(?:\s+--hard)?)"
         r"\s+(?:\S+\s+)*\$\{\{\s*"
         r"(?:github\.event\.pull_request\.head\.(?:sha|ref|label)"
         r"|github\.head_ref"
         r"|github\.event\.workflow_run\.head_(?:sha|branch))"
         r"\s*\}\}"
     )),
    ("git checkout FETCH_HEAD",
     # Only counts when paired with a pull/<N> fetch elsewhere in
     # the same run block. Detected by the secondary scan below.
     re.compile(r"^\s*(?:sudo\s+)?git\s+(?:checkout|switch)\s+FETCH_HEAD\b")),
)

_PULL_FETCH_RE = re.compile(
    r"git\s+fetch\s+\S+\s+(?:refs/)?pull/\d+/(?:head|merge)"
)


def _scan_run(run_body: str) -> str | None:
    """Return the first matching pattern label for *run_body*, or
    ``None`` if nothing fires.

    The ``FETCH_HEAD`` checkout is only counted when the same
    block contains a ``pull/<N>`` fetch. By itself, ``git checkout
    FETCH_HEAD`` is ambiguous: it follows a ``git fetch`` of
    *something*, which may have been the base ref.
    """
    has_pull_fetch = bool(_PULL_FETCH_RE.search(run_body))
    for line in run_body.splitlines():
        for label, pat in _FETCH_PATTERNS:
            if not pat.search(line):
                continue
            if label == "git checkout FETCH_HEAD" and not has_pull_fetch:
                continue
            return label
    return None


def check(path: str, doc: dict[str, Any]) -> Finding:
    triggers = set(workflow_triggers(doc))
    matching = triggers & UNTRUSTED_TRIGGERS
    if not matching:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Workflow has no untrusted trigger.",
            recommendation="No action required.", passed=True,
        )
    offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            hit = _scan_run(run)
            if hit is not None:
                offenders.append(f"{job_id}[{idx}]: {hit}")
    passed = not offenders
    desc = (
        f"No manual PR-head fetch detected under untrusted trigger(s) "
        f"{sorted(matching)}."
        if passed else
        f"Workflow with untrusted trigger ({', '.join(sorted(matching))}) "
        f"materializes PR-head content via shell commands: "
        f"{', '.join(offenders[:5])}{'…' if len(offenders) > 5 else ''}. "
        f"This bypasses ``actions/checkout`` detection but lands the "
        f"same attacker-controlled bytes with the same privileged "
        f"context active."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
