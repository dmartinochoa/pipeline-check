"""SCM-035. Active ruleset doesn't block branch deletion."""
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
    id="SCM-035",
    title="Active ruleset doesn't block branch deletion",
    severity=Severity.LOW,
    owasp=("CICD-SEC-1",),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-471",),
    recommendation=(
        "Add a ``deletion`` rule to every active ruleset "
        "(Settings → Rules → <ruleset> → Add rule → Restrict "
        "deletions). Without it, anyone with push access to a "
        "ref the ruleset targets can delete that ref. The "
        "ruleset analog of SCM-009 (legacy branch-protection "
        "branch deletion denial). Mostly a hygiene control — "
        "deleted commits are recoverable from the reflog "
        "until garbage collection — but loss of the default-"
        "branch ref is a real operational disruption."
    ),
    docs_note=(
        "For every active ruleset, looks for an entry in the "
        "merged ``rules`` array with ``type: \"deletion\"``. "
        "Presence of the rule means deletion is blocked. Passes "
        "silently when no rulesets are configured (legacy "
        "SCM-009 covers the gap)."
    ),
    known_fp=(
        "Rulesets that target ephemeral preview / feature "
        "branches legitimately allow deletion. Suppress on the "
        "specific ruleset id with a rationale that names the "
        "target pattern.",
    ),
)


def _blocks_deletion(rules: Any) -> bool:
    if not isinstance(rules, list):
        return False
    return any(
        isinstance(entry, dict) and entry.get("type") == "deletion"
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
            description=f"Repo is {label}; ruleset deletion check skipped.",
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
                "branch-protection (SCM-009) carries the gate."
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
        if _blocks_deletion(rs.get("rules")):
            continue
        offenders.append(rs_label)
    passed = not offenders
    if passed and unavailable:
        desc = (
            f"Ruleset detail unavailable for {len(unavailable)} "
            f"active ruleset(s): {', '.join(unavailable[:3])}"
            f"{'…' if len(unavailable) > 3 else ''}. Deletion "
            "posture not fully evaluated."
        )
    elif passed:
        desc = "Every active ruleset blocks branch deletion."
    else:
        desc = (
            f"{len(offenders)} active ruleset(s) don't block "
            f"deletion: {', '.join(offenders[:3])}"
            f"{'…' if len(offenders) > 3 else ''}. Targeted refs "
            "can be deleted by anyone with push access."
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
