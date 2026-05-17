"""SCM-034. Active ruleset doesn't block force-push."""
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
    id="SCM-034",
    title="Active ruleset doesn't block force-push",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-471",),
    recommendation=(
        "Add a ``non_fast_forward`` rule to every active ruleset "
        "(Settings → Rules → <ruleset> → Add rule → Block force "
        "pushes). Without it, a force-push rewrites history on "
        "the target branch — commits that previously appeared "
        "in the audit trail disappear from the surface log, and "
        "anyone with push access can erase evidence of an "
        "earlier action. The ruleset analog of SCM-007 (legacy "
        "branch-protection force-push denial). Pair with SCM-006 "
        "(signed commits) so even a rewrite leaves verifiable "
        "signatures on the surviving commits."
    ),
    docs_note=(
        "For every active ruleset, looks for an entry in the "
        "merged ``rules`` array with ``type: \"non_fast_forward\"``. "
        "Presence of the rule means force-pushes are blocked on "
        "the refs the ruleset targets. Passes silently when no "
        "rulesets are configured (legacy SCM-007 covers the "
        "gap)."
    ),
    known_fp=(
        "Release-engineering rulesets sometimes deliberately "
        "allow force-push on a specific tag-pattern target (e.g. "
        "moving release tags). Suppress on the specific ruleset "
        "id with a rationale that names the target pattern.",
    ),
)


def _blocks_force_push(rules: Any) -> bool:
    if not isinstance(rules, list):
        return False
    return any(
        isinstance(entry, dict) and entry.get("type") == "non_fast_forward"
        for entry in rules
    )


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
            description=f"Repo is {label}; ruleset force-push check skipped.",
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
                "branch-protection (SCM-007) carries the gate."
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
        if _blocks_force_push(rs.get("rules")):
            continue
        offenders.append(rs_label)
    passed = not offenders
    if passed and unavailable:
        desc = (
            f"Ruleset detail unavailable for {len(unavailable)} "
            f"active ruleset(s): {', '.join(unavailable[:3])}"
            f"{'…' if len(unavailable) > 3 else ''}. Force-push "
            "posture not fully evaluated."
        )
    elif passed:
        desc = "Every active ruleset blocks force-push."
    else:
        desc = (
            f"{len(offenders)} active ruleset(s) don't block "
            f"force-push: {', '.join(offenders[:3])}"
            f"{'…' if len(offenders) > 3 else ''}. History can "
            "be rewritten, erasing prior commits from the surface "
            "log."
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
