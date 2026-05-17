"""SCM-036. Active ruleset doesn't require signed commits."""
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
    id="SCM-036",
    title="Active ruleset doesn't require signed commits",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1", "CICD-SEC-9"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-345",),
    recommendation=(
        "Add a ``required_signatures`` rule to every active "
        "ruleset (Settings → Rules → <ruleset> → Add rule → "
        "Require signed commits). Without it, a compromised "
        "contributor account (or a stolen PAT) can push commits "
        "that appear to originate from any author the attacker "
        "names in the commit metadata. The signature requirement "
        "ties each commit to a key the contributor controls "
        "(SSH / GPG / sigstore via gitsign), so post-incident "
        "the audit log shows which commits were signed by the "
        "key vs forged. The ruleset analog of SCM-006 (legacy "
        "branch-protection signed-commit enforcement)."
    ),
    docs_note=(
        "For every active ruleset, looks for an entry in the "
        "merged ``rules`` array with ``type: \"required_signatures\"``. "
        "Presence means commits to the targeted refs must carry "
        "a valid signature. Passes silently when no rulesets are "
        "configured (legacy SCM-006 covers the gap)."
    ),
    known_fp=(
        "Teams that haven't yet rolled out signing keys for all "
        "contributors sometimes ship without signature enforcement "
        "to avoid blocking ordinary PRs. The right pattern is a "
        "phased rollout (configure the rule in ``evaluate`` mode "
        "first, then flip to ``active`` once contributors have "
        "their keys). Suppress with a rationale that names the "
        "rollout date.",
    ),
)


def _requires_signed_commits(rules: Any) -> bool:
    if not isinstance(rules, list):
        return False
    return any(
        isinstance(entry, dict) and entry.get("type") == "required_signatures"
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
            description=f"Repo is {label}; ruleset signed-commit check skipped.",
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
                "branch-protection (SCM-006) carries the gate."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    targeting, unavailable_rs, scoped_away = (
        active_rulesets_targeting_default(snapshot)
    )
    if not targeting and not unavailable_rs and scoped_away:
        labels = [ruleset_label(rs) for rs in scoped_away]
        default = default_branch_name(snapshot)
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                f"{len(scoped_away)} active ruleset(s) configured "
                f"but none target the default branch "
                f"(refs/heads/{default}): "
                f"{', '.join(labels[:3])}"
                f"{'…' if len(labels) > 3 else ''}. The signed-"
                f"commit gate isn't applied to the default "
                f"branch at the ruleset layer; SCM-006 covers "
                f"the legacy branch-protection carry."
            ),
            recommendation=RULE.recommendation, passed=False,
        )
    if not targeting and not unavailable_rs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "No active rulesets target the default branch; "
                "legacy branch-protection (SCM-006) carries the "
                "signed-commit gate."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    for rs in targeting:
        if _requires_signed_commits(rs.get("rules")):
            continue
        offenders.append(ruleset_label(rs))
    unavailable = [ruleset_label(rs) for rs in unavailable_rs]
    passed = not offenders
    if passed and unavailable:
        desc = (
            f"Ruleset detail unavailable for {len(unavailable)} "
            f"active ruleset(s): {', '.join(unavailable[:3])}"
            f"{'…' if len(unavailable) > 3 else ''}. Signed-commit "
            "posture not fully evaluated."
        )
    elif passed:
        desc = (
            "Every active ruleset targeting the default branch "
            "requires signed commits."
        )
    else:
        desc = (
            f"{len(offenders)} active ruleset(s) targeting the "
            f"default branch don't require signed commits: "
            f"{', '.join(offenders[:3])}"
            f"{'…' if len(offenders) > 3 else ''}. Commits with "
            "arbitrary author metadata land without a verifiable "
            "tie to a contributor key."
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
