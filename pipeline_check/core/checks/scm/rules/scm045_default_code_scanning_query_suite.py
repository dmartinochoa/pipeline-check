"""SCM-045. GitHub default code scanning uses the limited query suite.

Default code scanning supports two CodeQL query suites: ``default``
(the standard pack) and ``extended`` (default plus the
``security-and-quality`` pack — maintainability + reliability queries
that frequently surface taint paths the standard suite misses).
SCM-003 fires when default scanning is off entirely; this rule
catches the next-most-common posture gap: the gate exists but is
shallower than achievable in one click.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    SCMRepoSnapshot,
    archived_state_label,
    repo_resource,
)

RULE = Rule(
    id="SCM-045",
    title="Default code scanning uses the limited query suite",
    severity=Severity.LOW,
    owasp=("CICD-SEC-10",),
    esf=("ESF-V-VULN-MGMT",),
    cwe=("CWE-1059",),
    recommendation=(
        "In ``Settings → Code security → Code scanning → Default "
        "setup``, switch ``Query suite`` from ``Default`` to "
        "``Extended``. The extended suite adds CodeQL's "
        "``security-and-quality`` pack, which catches "
        "maintainability and reliability issues that often "
        "co-occur with security findings (e.g. dead-code paths "
        "that hide an unauthenticated branch). Teams that ship a "
        "hand-authored CodeQL workflow can pin ``queries: "
        "security-extended`` in ``.github/codeql/codeql-config.yml`` "
        "for the same effect."
    ),
    docs_note=(
        "Reads ``query_suite`` from the default code-scanning setup "
        "endpoint. Fires only when ``state == configured`` AND "
        "``query_suite == default``. Passes silently when scanning "
        "is off (SCM-003 owns that case) or when the suite is "
        "already ``extended``."
    ),
    known_fp=(
        "Teams that route code-scanning via a hand-authored CodeQL "
        "workflow rather than default setup will see SCM-045 pass "
        "by virtue of ``state != configured``; verify the workflow "
        "pins the extended suite. Some repos intentionally keep "
        "the default suite to bound CI minutes; suppress per repo "
        "with a rationale.",
    ),
)


def check(snapshot: SCMRepoSnapshot) -> Finding:
    if label := archived_state_label(snapshot):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                f"Repo is {label}; GitHub auto-disables code "
                f"scanning on {label} repos. Skipped."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    setup = snapshot.code_scanning_default_setup
    if not isinstance(setup, dict):
        # SCM-003 owns the "no default setup" case; pass silently
        # to avoid double-counting a single root cause.
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "Default code scanning setup is unavailable; "
                "SCM-003 owns the no-scanning case."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    if setup.get("state") != "configured":
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "Default code scanning is not configured; SCM-003 "
                "owns that case."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    suite = setup.get("query_suite")
    suite_label = suite if isinstance(suite, str) else "unset"
    passed = suite_label != "default"
    desc = (
        f"Default code scanning runs the ``{suite_label}`` query "
        f"suite (≥extended)."
        if passed else
        "Default code scanning is configured with the ``default`` "
        "query suite. The extended suite adds the "
        "``security-and-quality`` pack, which surfaces taint paths "
        "and dead-branch issues the standard pack frequently misses."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
