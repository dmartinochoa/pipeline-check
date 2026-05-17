"""SCM-024. Deployment environment can deploy from any branch."""
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
    id="SCM-024",
    title="Deployment environment can deploy from any branch",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1", "CICD-SEC-4"),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-862", "CWE-913"),
    recommendation=(
        "Configure a deployment-branch policy on every "
        "environment (Settings → Environments → <name> → "
        "``Deployment branches and tags``). Pick "
        "``Protected branches only`` for production-like "
        "environments so a workflow run on a feature branch "
        "cannot push to production. The combination ``required "
        "reviewers`` (SCM-023) + ``deployment branch policy`` "
        "(SCM-024) is the deploy-gate the rest of the rule pack "
        "(GHA-050 publish-without-OIDC, SCM-001 branch "
        "protection) assumes is in place; without SCM-024, a "
        "workflow on any branch can target the production "
        "environment and reviewers approve a stale or wrong-"
        "branch deployment without realizing."
    ),
    docs_note=(
        "Reads each environment's ``deployment_branch_policy`` "
        "field. ``null`` means any branch can deploy and fails; "
        "``{\"protected_branches\": true}`` or ``{\"custom_branch_"
        "policies\": true}`` (with at least one configured "
        "policy) passes. Passes silently when no environments "
        "are configured. Pairs with SCM-023 (required reviewers "
        "on the same environments); both knobs together close "
        "the deploy-gate loop."
    ),
    known_fp=(
        "Test / preview environments often accept any branch "
        "by design (the whole point is to validate feature "
        "branches before merging). Suppress on those specific "
        "environment names; treat the rule as production-"
        "scoped.",
    ),
)


def _environments_list(snapshot: SCMRepoSnapshot) -> list[dict[str, Any]]:
    raw = snapshot.environments
    if not isinstance(raw, dict):
        return []
    envs = raw.get("environments")
    if not isinstance(envs, list):
        return []
    return [e for e in envs if isinstance(e, dict)]


def _has_branch_policy(env: dict[str, Any]) -> bool:
    """True when *env* configures a deployment-branch policy at all."""
    policy = env.get("deployment_branch_policy")
    if not isinstance(policy, dict):
        return False
    # GitHub returns either ``protected_branches: true`` (use the
    # repo's protected-branches list as the allow-set) or
    # ``custom_branch_policies: true`` (user-defined branch / tag
    # name patterns; the actual patterns are fetched separately).
    # Either flag set to True is a configured policy.
    return bool(
        policy.get("protected_branches")
        or policy.get("custom_branch_policies")
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
            description=(
                f"Repo is {label}; environment-branch-policy check "
                f"skipped."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    if not isinstance(snapshot.environments, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "environments endpoint unavailable (token likely "
                "lacks ``admin`` scope on the repo)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    envs = _environments_list(snapshot)
    if not envs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "No deployment environments configured; nothing "
                "to evaluate."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    for env in envs:
        name = env.get("name")
        if not isinstance(name, str):
            continue
        if not _has_branch_policy(env):
            offenders.append(name)
    passed = not offenders
    desc = (
        "Every deployment environment configures a branch / "
        "tag policy."
        if passed else
        f"{len(offenders)} environment(s) accept deployments "
        f"from any branch: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A workflow run "
        f"from a feature branch can target these environments "
        f"directly."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
