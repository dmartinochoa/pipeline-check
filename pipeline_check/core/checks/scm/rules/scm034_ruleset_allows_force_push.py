"""SCM-034. Active ruleset doesn't block force-push."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    SCMRepoSnapshot,
    active_rulesets_targeting_default,
    archived_state_label,
    default_branch_name,
    github_only_skip,
    repo_resource,
    ruleset_label,
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
    targeting, unavailable_rs, scoped_away = (
        active_rulesets_targeting_default(snapshot)
    )
    if not targeting and scoped_away:
        labels = [ruleset_label(rs) for rs in scoped_away]
        default = default_branch_name(snapshot)
        desc = (
            f"{len(scoped_away)} active ruleset(s) configured "
            f"but none target the default branch "
            f"(refs/heads/{default}): "
            f"{', '.join(labels[:3])}"
            f"{'…' if len(labels) > 3 else ''}. The force-"
            f"push denial isn't applied to the default "
            f"branch at the ruleset layer; SCM-007 covers "
            f"the legacy branch-protection carry."
        )
        if unavailable_rs:
            desc += (
                f" Additionally, {len(unavailable_rs)} active "
                "ruleset(s) had detail-endpoint errors and were "
                "not evaluated."
            )
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=desc,
            recommendation=RULE.recommendation, passed=False,
        )
    if not targeting and not unavailable_rs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "No active rulesets target the default branch; "
                "legacy branch-protection (SCM-007) carries the "
                "force-push denial."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    # GitHub aggregates rules across every ruleset targeting a ref, so
    # the gate is satisfied when ANY targeting ruleset carries it. Fire
    # only when none does (the whole targeting set then lists as the
    # offenders: no ruleset on the default branch carries the gate).
    covered = any(_blocks_force_push(rs.get("rules")) for rs in targeting)
    offenders: list[str] = (
        [] if covered else [ruleset_label(rs) for rs in targeting]
    )
    unavailable = [ruleset_label(rs) for rs in unavailable_rs]
    passed = not offenders
    if passed and unavailable:
        desc = (
            f"Ruleset detail unavailable for {len(unavailable)} "
            f"active ruleset(s): {', '.join(unavailable[:3])}"
            f"{'…' if len(unavailable) > 3 else ''}. Force-push "
            "posture not fully evaluated."
        )
    elif passed:
        desc = (
            "Every active ruleset targeting the default branch "
            "blocks force-push."
        )
    else:
        desc = (
            f"{len(offenders)} active ruleset(s) targeting the "
            f"default branch don't block force-push: "
            f"{', '.join(offenders[:3])}"
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
