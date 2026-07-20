"""SCM-046. GitHub default code scanning has no periodic scan schedule.

A ``configured`` default-setup already scans on push to the default
branch and on pull requests targeting it, so code that keeps landing
is covered. What a missing ``schedule`` costs is the *periodic*
re-scan: a branch (or the default branch during a quiet period) that
receives no pushes won't be re-analyzed as CodeQL's queries improve,
so a newly-detectable issue in already-merged code can sit unflagged
until the next push. That's a real but narrow coverage gap, hence
LOW, not the "no scans run at all" claim this rule used to make.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    SCMRepoSnapshot,
    archived_state_label,
    repo_resource,
)

RULE = Rule(
    id="SCM-046",
    title="Default code scanning has no periodic scan schedule",
    severity=Severity.LOW,
    owasp=("CICD-SEC-10",),
    esf=("ESF-V-VULN-MGMT",),
    cwe=("CWE-1059",),
    recommendation=(
        "Set ``schedule`` to ``weekly`` on the default code-scanning "
        "setup (``Settings → Code security → Code scanning → Default "
        "setup → Edit configuration``). Push and pull-request scans "
        "already run without it, so this only adds the periodic "
        "re-scan that catches newly-detectable issues in code that "
        "isn't currently being pushed (stale branches, a quiet "
        "default branch). It does not gate merges; SCM-003 covers "
        "whether scanning exists at all."
    ),
    docs_note=(
        "Reads ``schedule`` from the default code-scanning setup "
        "endpoint. Fires (LOW) when ``state == configured`` AND "
        "schedule is ``None`` / ``\"none\"`` / missing, flagging the "
        "missing *periodic* re-scan. Push/PR scans still run, so this "
        "is a stale-branch coverage gap, not an absence of scanning. "
        "Passes silently when scanning is off entirely (SCM-003) or "
        "when a schedule is set."
    ),
    known_fp=(
        "Repos that route scanning via a hand-authored workflow "
        "(which carries its own schedule) may keep default setup "
        "configured but unscheduled intentionally. Suppress per repo "
        "with a rationale that names the workflow file.",
    ),
)


def _schedule_value(setup: dict[str, Any]) -> Any:
    """Read schedule from either the top-level field or the nested
    ``schedule`` block (the API has changed shape between versions)."""
    schedule = setup.get("schedule")
    if isinstance(schedule, dict):
        return schedule.get("frequency")
    return schedule


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
    schedule = _schedule_value(setup)
    has_schedule = isinstance(schedule, str) and schedule.lower() not in (
        "", "none",
    )
    passed = has_schedule
    desc = (
        f"Default code scanning runs on a ``{schedule}`` schedule."
        if passed else
        "Default code scanning is configured with no periodic "
        "``schedule``. Push and pull-request scans still run, but "
        "code that isn't being pushed (stale branches, a quiet "
        "default branch) won't be re-analyzed as CodeQL's queries "
        "improve. Set ``schedule: weekly`` to close the re-scan gap."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
