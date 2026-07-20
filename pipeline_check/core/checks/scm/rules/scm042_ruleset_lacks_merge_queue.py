"""SCM-042. Active ruleset doesn't require merge queue."""
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
    id="SCM-042",
    title="Active ruleset doesn't require merge queue",
    severity=Severity.LOW,
    owasp=("CICD-SEC-1", "CICD-SEC-4"),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-362",),
    recommendation=(
        "Add a ``merge_queue`` rule to every active ruleset that "
        "covers a high-throughput trunk (Settings → Rules → "
        "<ruleset> → Add rule → Require merge queue). Without "
        "it, two PRs that each pass ``required_status_checks`` "
        "(SCM-033) independently can both merge into the same "
        "trunk and produce a state where the combined diff "
        "wasn't actually validated — a class of integration "
        "regressions that CI on the individual PRs can't catch. "
        "The merge queue serializes merges and re-runs the "
        "configured checks against the queue's post-merge "
        "candidate commit before the merge lands, so the trunk "
        "always reflects a tested state.\n\n"
        "Pair with SCM-033 (required status checks). SCM-033 "
        "ensures CI passes BEFORE merge; SCM-042's merge queue "
        "ensures CI passes AFTER merge in queue order. The two "
        "gates address different failure modes — the queue "
        "closes the merge-race surface that per-PR CI can't see."
    ),
    docs_note=(
        "For every active ruleset, looks for an entry in the "
        "merged ``rules`` array with ``type: \"merge_queue\"``. "
        "Presence means merges to the targeted refs must enter "
        "the queue. Passes silently when no rulesets are "
        "configured — merge queue has no legacy branch-"
        "protection analog (the feature is ruleset-only)."
    ),
    known_fp=(
        "Low-throughput repos (one or two PRs landing per day) "
        "don't typically hit the merge-race shape this rule "
        "addresses; the operational cost of a merge queue can "
        "outweigh the benefit. Suppress with a rationale that "
        "names the merge-velocity profile. The rule fires LOW "
        "because most teams' CI integrity comes from "
        "status-checks (SCM-033); merge_queue is the additional "
        "concurrency-hardening control.",
    ),
)


def _requires_merge_queue(rules: Any) -> bool:
    if not isinstance(rules, list):
        return False
    return any(
        isinstance(entry, dict) and entry.get("type") == "merge_queue"
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
            description=f"Repo is {label}; ruleset merge-queue check skipped.",
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
                "No repository rulesets configured; merge-queue "
                "enforcement has no legacy branch-protection "
                "analog and is not separately evaluated."
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
            f"{'…' if len(labels) > 3 else ''}. Merge-queue "
            f"enforcement has no legacy branch-protection "
            f"analog, so the default branch has no merge-race "
            f"protection."
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
                "merge-queue enforcement has no legacy branch-"
                "protection analog and is not separately "
                "evaluated."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    # GitHub aggregates rules across every ruleset targeting a ref, so
    # the gate is satisfied when ANY targeting ruleset carries it. Fire
    # only when none does (the whole targeting set then lists as the
    # offenders: no ruleset on the default branch carries the gate).
    covered = any(_requires_merge_queue(rs.get("rules")) for rs in targeting)
    offenders: list[str] = (
        [] if covered else [ruleset_label(rs) for rs in targeting]
    )
    unavailable = [ruleset_label(rs) for rs in unavailable_rs]
    passed = not offenders
    if passed and unavailable:
        desc = (
            f"Ruleset detail unavailable for {len(unavailable)} "
            f"active ruleset(s): {', '.join(unavailable[:3])}"
            f"{'…' if len(unavailable) > 3 else ''}. Merge-queue "
            "posture not fully evaluated."
        )
    elif passed:
        desc = (
            "Every active ruleset targeting the default branch "
            "requires merges to enter the merge queue."
        )
    else:
        desc = (
            f"{len(offenders)} active ruleset(s) targeting the "
            f"default branch don't require the merge queue: "
            f"{', '.join(offenders[:3])}"
            f"{'…' if len(offenders) > 3 else ''}. Two PRs that "
            "individually pass CI can both merge and produce a "
            "trunk state where the combined diff wasn't validated."
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
