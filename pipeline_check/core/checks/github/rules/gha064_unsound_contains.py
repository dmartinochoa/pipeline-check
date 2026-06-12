"""GHA-064. ``contains()`` called with a comma-delimited string operand.

zizmor's ``unsound-contains`` audit. The shape:

    if: contains('main, develop', github.ref_name)

reads like a list membership check ("is ``github.ref_name`` one of
``main`` or ``develop``?"). It isn't. ``contains()`` invoked with a
string left operand is a *substring* match, so the predicate is
true for ``ref_name == 'mai'``, ``'develop'``, ``'releaseintegrate
main, develop'``, and many other strings the author didn't intend.

The fix is to pass an array literal instead:

    if: contains(fromJSON('["main", "develop"]'), github.ref_name)

or fan out the predicate explicitly:

    if: github.ref_name == 'main' || github.ref_name == 'develop'
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="GHA-064",
    title="``contains()`` invoked with comma-delimited string operand",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1", "CICD-SEC-4"),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-697",),  # Incorrect Comparison
    recommendation=(
        "Replace the string left operand with an explicit array. "
        "``contains(fromJSON('[\"main\", \"develop\"]'), "
        "github.ref_name)`` is the canonical fix. For very short "
        "lists, fan out: ``github.ref_name == 'main' || "
        "github.ref_name == 'develop'``. Avoid relying on the "
        "string form being substring-matched, both because it's "
        "rarely the intent and because a substring match across an "
        "attacker-controlled context (``github.head_ref`` etc.) is "
        "itself a foot-gun (see GHA-053)."
    ),
    docs_note=(
        "Fires when an ``if:`` expression invokes "
        "``contains(<string-literal>, <expr>)`` where the string "
        "literal contains a comma. The comma is the author's "
        "tell, they meant the literal to be a list. Substring "
        "matches on a no-comma literal (``contains('refs/heads/"
        "release', github.ref)``) are not flagged, they're often "
        "intentional prefix / suffix checks. Both single and "
        "double quote styles are detected.\n\n"
        "Argument-order matters: ``contains(<haystack>, "
        "<needle>)``. Only the left operand (haystack) is "
        "checked; the right operand can be any expression."
    ),
    known_fp=(
        "A literal that happens to contain a comma but is "
        "genuinely meant as a single search string (a free-form "
        "PR title fragment, e.g. ``contains('feat:, fix:', "
        "github.event.pull_request.title)``). These are rare; "
        "almost every comma-in-literal is a list-confusion bug. "
        "Suppress per-step via ignore-file when audited.",
    ),
    incident_refs=(
        "zizmor v1.25.2 ``unsound-contains`` audit: "
        "https://docs.zizmor.sh/audits/#unsound-contains",
    ),
    exploit_example=(
        "# Vulnerable: looks like \"branch is one of main / develop /\n"
        "# release\" but ``contains()`` on the string\n"
        "# ``'main, develop, release'`` matches every branch whose\n"
        "# name is a substring of that string. ``mai``, ``ele``,\n"
        "# ``main, devel`` all pass; so does any branch whose\n"
        "# name is part of a longer string the maintainer pushed.\n"
        "on: push\n"
        "jobs:\n"
        "  deploy:\n"
        "    if: contains('main, develop, release', github.ref_name)\n"
        "    runs-on: ubuntu-latest\n"
        "    environment: production\n"
        "    steps:\n"
        "      - run: ./deploy.sh\n"
        "\n"
        "# Safe: ``fromJSON`` materializes a real array, so\n"
        "# ``contains`` does a proper list-membership check.\n"
        "on: push\n"
        "jobs:\n"
        "  deploy:\n"
        "    if: contains(fromJSON('[\"main\", \"develop\", "
        "\"release\"]'), github.ref_name)\n"
        "    runs-on: ubuntu-latest\n"
        "    environment: production\n"
        "    steps:\n"
        "      - run: ./deploy.sh"
    ),
)


#: ``contains('<haystack-with-comma>', <expr>)``. Both quote styles.
#: The haystack must literally contain a comma to fire; comma-free
#: substring searches are not the bug shape.
#: The first segment excludes the comma (``[^'",]*``) so it stops at the
#: first comma instead of backtracking across every comma position. That
#: keeps the match linear (a split-greedy ``[^'"]*,[^'"]*`` is quadratic on
#: a long comma-run with no closing quote) while preserving the semantics:
#: the quoted operand still must contain a comma to fire.
_UNSOUND_CONTAINS_RE = re.compile(
    r"""\bcontains\s*\(
        \s*
        (?P<quote>['"])
        (?P<haystack>[^'",]*,[^'"]*)
        (?P=quote)
        \s*,
    """,
    re.VERBOSE,
)


def _scan_expression(expr: str) -> list[str]:
    """Return offender labels for *expr* (one per unsound contains)."""
    if not isinstance(expr, str) or not expr:
        return []
    out: list[str] = []
    for m in _UNSOUND_CONTAINS_RE.finditer(expr):
        haystack = m.group("haystack")
        snip = haystack if len(haystack) <= 40 else haystack[:37] + "..."
        out.append(f"``contains('{snip}', ...)``")
    return out


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        job_if = job.get("if")
        for label in _scan_expression(job_if if isinstance(job_if, str) else ""):
            offenders.append(f"jobs.{job_id}.if: {label}")
        for idx, step in enumerate(iter_steps(job)):
            step_if = step.get("if")
            for label in _scan_expression(
                step_if if isinstance(step_if, str) else "",
            ):
                offenders.append(f"jobs.{job_id}.steps[{idx}].if: {label}")
    passed = not offenders
    desc = (
        "No ``contains()`` call with a comma-delimited string operand."
        if passed else
        f"{len(offenders)} ``contains()`` call(s) use a comma-"
        f"delimited string operand that's matched as a substring, "
        f"not a list: {'; '.join(offenders[:3])}"
        f"{'...' if len(offenders) > 3 else ''}. Wrap the list in "
        f"``fromJSON('[...]')`` for a real array membership check."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
