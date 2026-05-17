"""SCM-037. Active ruleset PR rule doesn't dismiss stale reviews."""
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
    id="SCM-037",
    title="Active ruleset's pull_request rule doesn't dismiss stale reviews",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1", "CICD-SEC-4"),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-863",),
    recommendation=(
        "On every active ruleset's ``pull_request`` rule, set "
        "``parameters.dismiss_stale_reviews_on_push: true`` "
        "(Settings → Rules → <ruleset> → Require a pull request "
        "before merging → Dismiss stale pull request approvals "
        "when new commits are pushed). Without it, an attacker "
        "can land an approving review on a benign early version "
        "of the PR, then force-push (if not blocked by SCM-034) "
        "or otherwise update the head with malicious commits, "
        "and the original approval still counts toward the "
        "required-review gate.\n\n"
        "The ruleset analog of SCM-012 (legacy branch-protection "
        "stale-review dismissal). Pair with SCM-032 (PR-review "
        "presence) — without dismissal, the review-count gate "
        "documents intent rather than reality once the PR has "
        "diverged from the approved state."
    ),
    docs_note=(
        "For every active ruleset with a ``pull_request`` rule, "
        "checks ``parameters.dismiss_stale_reviews_on_push`` is "
        "``true``. Skips rulesets that don't have a "
        "``pull_request`` rule at all — SCM-032 owns that "
        "surface. Passes silently when no rulesets are "
        "configured (legacy SCM-012 covers the gap)."
    ),
    known_fp=(
        "Some workflows use ephemeral review-bot accounts that "
        "auto-re-approve after push; dismissing on push then "
        "re-issuing the approval is the documented pattern. The "
        "rule still fires (the dismissal happens) and the re-"
        "approval lands separately. If your team operates a "
        "different review-velocity flow, suppress with a "
        "rationale that names the re-approval channel.",
    ),
)


def _dismisses_stale_reviews(rules: Any) -> bool | None:
    """Return True / False if a ``pull_request`` rule with explicit
    ``dismiss_stale_reviews_on_push`` exists, ``None`` when no
    ``pull_request`` rule is present (SCM-032's surface).
    """
    if not isinstance(rules, list):
        return None
    found_pr_rule = False
    for entry in rules:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") != "pull_request":
            continue
        found_pr_rule = True
        params = entry.get("parameters")
        if not isinstance(params, dict):
            # ``pull_request`` with no params block: GitHub's
            # default for ``dismiss_stale_reviews_on_push`` is
            # false. Treat as not-satisfied.
            continue
        if params.get("dismiss_stale_reviews_on_push") is True:
            return True
    return False if found_pr_rule else None


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
            description=f"Repo is {label}; ruleset stale-review check skipped.",
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
                "branch-protection (SCM-012) carries the gate."
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
            f"{'…' if len(labels) > 3 else ''}. The stale-"
            f"review dismissal gate isn't applied to the "
            f"default branch at the ruleset layer; SCM-012 "
            f"covers the legacy branch-protection carry."
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
                "legacy branch-protection (SCM-012) carries the "
                "stale-review dismissal gate."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    for rs in targeting:
        result = _dismisses_stale_reviews(rs.get("rules"))
        if result is None:
            # No ``pull_request`` rule on this ruleset — SCM-032
            # surface. Skip; we only flag the gap when the rule
            # exists and is misconfigured.
            continue
        if result:
            continue
        offenders.append(ruleset_label(rs))
    unavailable = [ruleset_label(rs) for rs in unavailable_rs]
    passed = not offenders
    if passed and unavailable:
        desc = (
            f"Ruleset detail unavailable for {len(unavailable)} "
            f"active ruleset(s): {', '.join(unavailable[:3])}"
            f"{'…' if len(unavailable) > 3 else ''}. Stale-review "
            "dismissal posture not fully evaluated."
        )
    elif passed:
        desc = (
            "Every active ruleset (targeting the default branch) "
            "with a ``pull_request`` rule dismisses stale reviews "
            "on new commits."
        )
    else:
        desc = (
            f"{len(offenders)} active ruleset(s) targeting the "
            f"default branch don't dismiss stale reviews on push: "
            f"{', '.join(offenders[:3])}"
            f"{'…' if len(offenders) > 3 else ''}. An approved "
            "early version of a PR continues to count after the "
            "head changes."
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
