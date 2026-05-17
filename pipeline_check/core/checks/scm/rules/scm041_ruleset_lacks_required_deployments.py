"""SCM-041. Active ruleset doesn't gate on a deployment environment."""
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
    id="SCM-041",
    title="Active ruleset doesn't gate on a deployment environment",
    severity=Severity.LOW,
    owasp=("CICD-SEC-1", "CICD-SEC-4"),
    esf=("ESF-S-CHANGE-CONTROL", "ESF-C-APPROVAL"),
    cwe=("CWE-693",),
    recommendation=(
        "Add a ``required_deployments`` rule to every active "
        "ruleset (Settings → Rules → <ruleset> → Add rule → "
        "Require deployments to succeed before merging) and "
        "pin at least one environment (typically the staging "
        "environment that a CI pipeline deploys the PR's "
        "commit to). Pairs with SCM-023 (env reviewers) and "
        "SCM-024 (env branch policy): SCM-023/024 ensure the "
        "environment itself is gated; SCM-041 makes a "
        "successful deployment to that environment a "
        "merge prerequisite. Without it, a PR can merge into "
        "the default branch without a smoke-test deployment "
        "having run, even when the environment is rigorously "
        "configured. The ruleset analog of legacy branch "
        "protection's ``required_deployments`` checkbox.\n\n"
        "An empty environments list "
        "(``required_deployment_environments: []``) "
        "documents the gate without filling it and is treated "
        "as no rule. Pick at least one environment name "
        "(typically ``staging`` or ``preview``) so the rule "
        "actually gates."
    ),
    docs_note=(
        "For every active ruleset, walks the merged ``rules`` "
        "array looking for an entry with ``type: "
        "\"required_deployments\"`` whose "
        "``parameters.required_deployment_environments`` "
        "lists at least one environment. Empty lists are "
        "treated as no rule. Passes silently when no rulesets "
        "are configured — required-deployments enforcement "
        "has no legacy branch-protection analog in this "
        "scanner's coverage and is not separately evaluated."
    ),
    known_fp=(
        "Repos that don't have GitHub deployment environments "
        "configured (or that gate via status-checks SCM-033 "
        "pointed at a deploy job's reported context) "
        "legitimately ship without this rule. Suppress with a "
        "rationale that names the compensating control. The "
        "rule fires LOW because most teams' deployment gating "
        "comes from the environment configuration itself "
        "(SCM-023, SCM-024); SCM-041 is the merge-side "
        "complement that closes the gap when an environment "
        "exists but isn't named in any ruleset.",
    ),
)


def _has_required_deployments_rule(rules: Any) -> bool:
    if not isinstance(rules, list):
        return False
    for entry in rules:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") != "required_deployments":
            continue
        params = entry.get("parameters")
        if not isinstance(params, dict):
            # Bare ``required_deployments`` with no params is
            # malformed; treat as not-satisfied.
            continue
        envs = params.get("required_deployment_environments")
        if isinstance(envs, list) and envs:
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
            description=f"Repo is {label}; ruleset deployment-gate check skipped.",
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
                "No repository rulesets configured; required-"
                "deployments enforcement has no legacy branch-"
                "protection analog and is not separately "
                "evaluated."
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
            f"{'…' if len(labels) > 3 else ''}. Required-"
            f"deployments enforcement has no legacy branch-"
            f"protection analog, so the default branch has "
            f"no merge-gate on deployment success."
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
                "required-deployments enforcement has no legacy "
                "branch-protection analog and is not separately "
                "evaluated."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    for rs in targeting:
        if _has_required_deployments_rule(rs.get("rules")):
            continue
        offenders.append(ruleset_label(rs))
    unavailable = [ruleset_label(rs) for rs in unavailable_rs]
    passed = not offenders
    if passed and unavailable:
        desc = (
            f"Ruleset detail unavailable for {len(unavailable)} "
            f"active ruleset(s): {', '.join(unavailable[:3])}"
            f"{'…' if len(unavailable) > 3 else ''}. Required-"
            "deployments posture not fully evaluated."
        )
    elif passed:
        desc = (
            "Every active ruleset targeting the default branch "
            "gates on at least one deployment environment."
        )
    else:
        desc = (
            f"{len(offenders)} active ruleset(s) targeting the "
            f"default branch don't gate on a deployment "
            f"environment: {', '.join(offenders[:3])}"
            f"{'…' if len(offenders) > 3 else ''}. A PR can "
            "merge into the default branch without a smoke-"
            "test deployment having run, even when the "
            "environment is rigorously configured (SCM-023 / "
            "SCM-024)."
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
