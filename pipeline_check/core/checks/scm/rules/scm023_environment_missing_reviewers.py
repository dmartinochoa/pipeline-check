"""SCM-023. Deployment environment has no required-reviewer protection."""
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
    id="SCM-023",
    title="Deployment environment lacks required-reviewer protection",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1", "CICD-SEC-5"),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-269", "CWE-862"),
    recommendation=(
        "Configure required reviewers on every deployment "
        "environment (Settings → Environments → <name> → "
        "``Required reviewers``). Pick a team or set of users "
        "who must approve each deployment job that targets the "
        "environment. Without a required-reviewer protection "
        "rule, any workflow run with the right environment "
        "name in its ``jobs.<id>.environment:`` block can "
        "deploy without human gate — the exact primitive GHA-"
        "050 (publish without OIDC + environment) catches at "
        "the workflow layer. SCM-023 is the org-level "
        "complement: a workflow that *declares* an environment "
        "still needs the environment itself to enforce the "
        "gate."
    ),
    docs_note=(
        "Walks ``GET /repos/{owner}/{repo}/environments`` and "
        "flags every environment whose ``protection_rules`` list "
        "doesn't include a rule with ``type == \"required_"
        "reviewers\"``. Passes silently when no environments are "
        "configured (``total_count: 0``) — there's nothing to "
        "evaluate. Pairs with GHA-050 (the workflow-layer rule "
        "that checks ``jobs.<id>.environment:`` is declared) "
        "and SCM-024 (deployment-branch-policy on the same "
        "environments)."
    ),
    known_fp=(
        "Non-production environments (``preview``, ``staging-"
        "ephemeral``) that legitimately auto-deploy without "
        "human gate are flagged by this rule, since GitHub "
        "doesn't distinguish environment severity. Suppress on "
        "those specific environment names with a rationale "
        "rather than disabling the rule for the whole repo.",
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


def _has_required_reviewers(env: dict[str, Any]) -> bool:
    rules = env.get("protection_rules")
    if not isinstance(rules, list):
        return False
    for rule in rules:
        if isinstance(rule, dict) and rule.get("type") == "required_reviewers":
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
            description=(
                f"Repo is {label}; environment-reviewer check skipped."
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
        if not _has_required_reviewers(env):
            offenders.append(name)
    passed = not offenders
    desc = (
        "Every deployment environment has a required-reviewer "
        "protection rule."
        if passed else
        f"{len(offenders)} environment(s) lack a required-reviewer "
        f"rule: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Any workflow that "
        f"targets one of these environments deploys without a "
        f"human gate."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
