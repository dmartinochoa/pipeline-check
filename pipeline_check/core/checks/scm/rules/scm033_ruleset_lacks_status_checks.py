"""SCM-033. Active ruleset doesn't require status checks."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    SCMRepoSnapshot,
    archived_state_label,
    github_only_skip,
    repo_resource,
)

RULE = Rule(
    id="SCM-033",
    title="Active ruleset doesn't require status checks",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1", "CICD-SEC-4"),
    esf=("ESF-S-CHANGE-CONTROL", "ESF-D-CI-COVERAGE"),
    cwe=("CWE-693",),
    recommendation=(
        "Add a ``required_status_checks`` rule to every active "
        "ruleset and populate ``parameters.required_status_"
        "checks`` with the names of the contexts that must pass "
        "(Settings → Rules → <ruleset> → Add rule → Require "
        "status checks to pass before merging → pick the "
        "specific check runs). Without it, the ruleset is "
        "enforced but pushes / merges land without any of your "
        "tests, lint, security scans, or build verification "
        "actually being green — the ruleset documents that "
        "checks *exist* without requiring them to *pass*. The "
        "ruleset analog of SCM-008 (legacy branch-protection "
        "required checks).\n\n"
        "An empty contexts list (``required_status_checks: []``) "
        "is the same as no rule — it documents the gate without "
        "filling it. Pick at least one canonical job name (the "
        "primary build) and add the rest of your CI matrix over "
        "time."
    ),
    docs_note=(
        "For every active ruleset, walks the merged ``rules`` "
        "array looking for an entry with ``type: "
        "\"required_status_checks\"`` whose "
        "``parameters.required_status_checks`` lists at least "
        "one context. Empty lists are treated as no rule. "
        "Non-active rulesets are SCM-029's surface; rulesets "
        "with unavailable detail are surfaced explicitly. Passes "
        "silently when no rulesets are configured (legacy "
        "branch-protection SCM-008 covers the gap)."
    ),
    known_fp=(
        "Some rulesets are deliberately scoped to non-CI "
        "concerns (commit-message format, tag-name pattern); "
        "those should be paired with a separate ruleset that "
        "enforces status checks on the same refs. Suppress with "
        "a rationale that names the parallel ruleset.",
    ),
)


def _has_status_checks_rule(rules: Any) -> bool:
    if not isinstance(rules, list):
        return False
    for entry in rules:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") != "required_status_checks":
            continue
        params = entry.get("parameters")
        if not isinstance(params, dict):
            # Bare ``required_status_checks`` with no params is
            # malformed; treat as not-satisfied.
            continue
        contexts = params.get("required_status_checks")
        if isinstance(contexts, list) and contexts:
            return True
    return False


def check(snapshot: SCMRepoSnapshot) -> Finding:
    skip = github_only_skip(snapshot)
    if skip is not None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=skip,
            recommendation=RULE.recommendation, passed=True,
        )
    if label := archived_state_label(snapshot):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=f"Repo is {label}; ruleset status-checks check skipped.",
            recommendation=RULE.recommendation, passed=True,
        )
    rulesets = snapshot.rulesets
    if rulesets is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "repos/rulesets endpoint unavailable (token "
                "likely lacks ``admin`` scope on the repo)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    if not rulesets:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "No repository rulesets configured; legacy "
                "branch-protection (SCM-008) carries the gate."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    unavailable: list[str] = []
    for rs in rulesets:
        if rs.get("enforcement") != "active":
            continue
        name = rs.get("name")
        rs_id = rs.get("id")
        rs_label = name if isinstance(name, str) and name else (
            f"ruleset:{rs_id}" if isinstance(rs_id, int) else "(unnamed)"
        )
        if rs.get("_detail_unavailable") is True:
            unavailable.append(rs_label)
            continue
        if _has_status_checks_rule(rs.get("rules")):
            continue
        offenders.append(rs_label)
    passed = not offenders
    if passed and unavailable:
        desc = (
            f"Ruleset detail unavailable for {len(unavailable)} "
            f"active ruleset(s): {', '.join(unavailable[:3])}"
            f"{'…' if len(unavailable) > 3 else ''}. Status-checks "
            "posture not fully evaluated."
        )
    elif passed:
        desc = (
            "Every active ruleset requires at least one status "
            "check to pass."
        )
    else:
        desc = (
            f"{len(offenders)} active ruleset(s) don't require "
            f"status checks: {', '.join(offenders[:3])}"
            f"{'…' if len(offenders) > 3 else ''}. Merges land "
            "without any CI gate."
        )
        if unavailable:
            desc += (
                f" Additionally, {len(unavailable)} ruleset(s) had "
                "detail-endpoint errors and were not evaluated."
            )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
