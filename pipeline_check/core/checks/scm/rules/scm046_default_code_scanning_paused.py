"""SCM-046. GitHub default code scanning is configured but not running.

Default code scanning's ``state == "configured"`` only means the
setup record exists. The scan actually runs when either a
``schedule`` is set (``weekly`` / ``daily``) or a triggering event
(``push`` / ``pull_request``) is enabled. A configured-but-unscheduled
setup is the silent-pass shape SCM-003 misses: the SAST gate appears
to exist when audited via the API, but no scans run.
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
    title="Default code scanning is configured but paused",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    esf=("ESF-V-VULN-MGMT",),
    cwe=("CWE-1059",),
    recommendation=(
        "Set ``schedule`` to ``weekly`` (or ``daily`` if CI minutes "
        "allow) on the default code-scanning setup, and confirm "
        "``On push`` + ``On pull request`` triggers are enabled in "
        "``Settings → Code security → Code scanning → Default "
        "setup → Edit configuration``. Without a schedule or event "
        "trigger, the setup record exists but no scan output ever "
        "lands; the Code Scanning UI stays empty and SCM-003 "
        "passes because ``state == configured``."
    ),
    docs_note=(
        "Reads ``schedule`` from the default code-scanning setup "
        "endpoint. Fires when ``state == configured`` AND schedule "
        "is ``None`` / ``\"none\"`` / missing. Passes silently when "
        "scanning is off entirely (SCM-003) or when a schedule is "
        "set."
    ),
    known_fp=(
        "Repos that route scanning via a hand-authored workflow "
        "may keep default setup configured but unscheduled "
        "intentionally. Suppress per repo with a rationale that "
        "names the workflow file.",
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
        "Default code scanning is configured but no schedule is "
        "set. ``state == configured`` passes SCM-003's check, but "
        "no scan output ever lands in the Code Scanning UI without "
        "a schedule or event trigger."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
