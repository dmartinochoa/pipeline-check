"""SCM-038. Active ruleset doesn't require linear history."""
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
    id="SCM-038",
    title="Active ruleset doesn't require linear history",
    severity=Severity.LOW,
    owasp=("CICD-SEC-1",),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-693",),
    recommendation=(
        "Add a ``required_linear_history`` rule to every active "
        "ruleset (Settings → Rules → <ruleset> → Add rule → "
        "Require linear history). Without it, merges into the "
        "targeted refs can introduce merge commits, which "
        "produce a branching history where two ancestors share "
        "authorship of the merge result. Linear history forces "
        "rebase- or squash-style integration so every commit on "
        "the trunk has a single parent and a single attributable "
        "author. This pairs with SCM-036 (signed commits) to give "
        "post-incident forensics a clean answer to *who wrote this "
        "code and when*: each commit on main has one signature, "
        "one author, one parent, one timestamp.\n\n"
        "Merge commits aren't a direct attacker primitive — "
        "force-push (SCM-034) is the history-rewrite surface — "
        "but they obscure git-bisect and complicate "
        "``git log --first-parent`` triage during an incident, "
        "and they hide which specific commits landed when a "
        "long-lived feature branch is merged."
    ),
    docs_note=(
        "For every active ruleset, looks for an entry in the "
        "merged ``rules`` array with ``type: \"required_linear_history\"``. "
        "Presence means merge commits to the targeted refs are "
        "rejected (only fast-forward / rebase / squash integration "
        "is allowed). Passes silently when no rulesets are "
        "configured — linear history has no legacy "
        "branch-protection analog, so absence of rulesets means "
        "the gate simply doesn't exist (not that it's enforced "
        "elsewhere)."
    ),
    known_fp=(
        "Teams that prefer merge commits as a deliberate policy "
        "(e.g. to preserve the shape of long-lived feature "
        "branches in the history) legitimately ship without this "
        "rule. Suppress with a rationale that names the "
        "merge-strategy policy. The rule is a hygiene / "
        "auditability control, not a hard security gate.",
    ),
)


def _requires_linear_history(rules: Any) -> bool:
    if not isinstance(rules, list):
        return False
    return any(
        isinstance(entry, dict)
        and entry.get("type") == "required_linear_history"
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
            description=f"Repo is {label}; ruleset linear-history check skipped.",
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
                "No repository rulesets configured; linear-history "
                "enforcement has no legacy branch-protection "
                "analog and is not separately evaluated."
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
        if _requires_linear_history(rs.get("rules")):
            continue
        offenders.append(rs_label)
    passed = not offenders
    if passed and unavailable:
        desc = (
            f"Ruleset detail unavailable for {len(unavailable)} "
            f"active ruleset(s): {', '.join(unavailable[:3])}"
            f"{'…' if len(unavailable) > 3 else ''}. Linear-history "
            "posture not fully evaluated."
        )
    elif passed:
        desc = "Every active ruleset requires linear history."
    else:
        desc = (
            f"{len(offenders)} active ruleset(s) don't require "
            f"linear history: {', '.join(offenders[:3])}"
            f"{'…' if len(offenders) > 3 else ''}. Merge commits "
            "are permitted on the targeted refs, muddying "
            "``git log --first-parent`` triage and git-bisect."
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
