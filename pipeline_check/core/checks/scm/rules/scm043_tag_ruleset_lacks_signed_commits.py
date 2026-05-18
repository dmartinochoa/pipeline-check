"""SCM-043. Tag-targeted ruleset doesn't require signed commits.

SCM-006 / SCM-036 cover signed-commit enforcement on the default
branch. Release tags are a separate surface: a maintainer can push
a forged tag (``git tag v9.9.9 && git push --tags``) without ever
landing a commit on the protected branch. If the repo has a tag
ruleset but it doesn't enforce ``required_signatures``, the tag
object lands unsigned even when branch-side signing is required.

This is distinct from SCM-009 (branch-deletion) and SCM-035
(ruleset-allows-deletion): those cover the tag-rewrite surface,
this one covers tag-creation-without-signing.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    SCMRepoSnapshot,
    archived_state_label,
    github_only_skip,
    repo_resource,
    ruleset_label,
)

RULE = Rule(
    id="SCM-043",
    title="Tag-targeted ruleset doesn't require signed commits",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1", "CICD-SEC-9"),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-345",),
    recommendation=(
        "Add a ``required_signatures`` rule to every active "
        "ruleset whose ``target == tag`` (Settings → Rules → "
        "<ruleset> → Add rule → Require signed commits). Tag "
        "objects under a release-like glob (``refs/tags/v*`` or "
        "``refs/tags/**``) are downstream consumers' lookup keys; "
        "an unsigned tag means a stolen PAT can stamp a release "
        "with arbitrary author metadata while the branch-side "
        "signing requirement (SCM-006 / SCM-036) passes."
    ),
    docs_note=(
        "Iterates active rulesets where ``target == \"tag\"`` and "
        "fires when none enforce ``required_signatures`` on the "
        "tag refs they cover. Passes silently when no tag-"
        "targeted rulesets exist at all (a separate gap: there's "
        "no tag protection to evaluate)."
    ),
    known_fp=(
        "Repos that sign tags via a release workflow rather than "
        "the ruleset gate (e.g. ``cosign sign`` on the release "
        "artifact) get equivalent provenance. Suppress per repo "
        "with a rationale that names the workflow.",
    ),
)


def _is_active(rs: dict[str, Any]) -> bool:
    return rs.get("enforcement") == "active"


def _is_tag_target(rs: dict[str, Any]) -> bool:
    return rs.get("target") == "tag"


def _requires_signed_commits(rs: dict[str, Any]) -> bool:
    rules = rs.get("rules")
    if not isinstance(rules, list):
        return False
    return any(
        isinstance(entry, dict)
        and entry.get("type") == "required_signatures"
        for entry in rules
    )


def check(snapshot: SCMRepoSnapshot) -> Finding:
    if skip := github_only_skip(snapshot):
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
            description=f"Repo is {label}; tag-signing check skipped.",
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
    tag_rulesets = [
        rs for rs in rulesets
        if isinstance(rs, dict) and _is_active(rs) and _is_tag_target(rs)
    ]
    if not tag_rulesets:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "No active tag-targeted rulesets configured; "
                "tag-signing posture not evaluated here."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    unavailable: list[str] = []
    offenders: list[str] = []
    for rs in tag_rulesets:
        if rs.get("_detail_unavailable") is True:
            unavailable.append(ruleset_label(rs))
            continue
        if _requires_signed_commits(rs):
            continue
        offenders.append(ruleset_label(rs))
    passed = not offenders
    if passed and unavailable:
        desc = (
            f"Tag-targeted ruleset detail unavailable for "
            f"{len(unavailable)} active ruleset(s): "
            f"{', '.join(unavailable[:3])}"
            f"{'…' if len(unavailable) > 3 else ''}. Tag-signing "
            "posture not fully evaluated."
        )
    elif passed:
        desc = (
            f"All {len(tag_rulesets)} active tag-targeted "
            f"ruleset(s) require signed commits."
        )
    else:
        desc = (
            f"{len(offenders)} of {len(tag_rulesets)} active "
            f"tag-targeted ruleset(s) don't require signed "
            f"commits: {', '.join(offenders[:3])}"
            f"{'…' if len(offenders) > 3 else ''}. A stolen PAT "
            "can stamp release tags with arbitrary author "
            "metadata while branch-side signing (SCM-006 / "
            "SCM-036) passes."
        )
        if unavailable:
            desc += (
                f" Additionally, {len(unavailable)} ruleset(s) "
                "had detail-endpoint errors and were not "
                "evaluated."
            )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
