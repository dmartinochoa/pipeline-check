"""SCM-028. Private repo allows forking (fork-PR secret-leak surface)."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    SCMRepoSnapshot,
    archived_state_label,
    github_only_skip,
    repo_resource,
)

RULE = Rule(
    id="SCM-028",
    title="Private repo allows forking",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-D-ACCESS-CONTROL",),
    cwe=("CWE-200", "CWE-538"),
    recommendation=(
        "In repo Settings → General → Features, uncheck "
        "``Allow forking``. The setting only opens the trapdoor "
        "if you actually use ``pull_request_target`` or trigger "
        "workflows on fork PRs, but every private-repo fork "
        "carries the code into the forker's personal namespace "
        "(which has its own visibility surface — public profile, "
        "weaker 2FA enforcement, separate token scope). Even "
        "without the Actions-secret leak surface, allowing forks "
        "of a private repo means a compromised user account that "
        "had access at any point can preserve a copy of the "
        "intellectual property indefinitely.\n\n"
        "If forks are genuinely needed for the development "
        "workflow, enforce ``Allow forking`` at the org level "
        "and pair it with GHA-046 (block manual PR-head fetches "
        "on untrusted-trigger workflows) and GHA-027 (no "
        "``pull_request_target`` on untrusted input) so the "
        "secret-leak surface stays closed at the workflow layer."
    ),
    docs_note=(
        "Reads ``private`` and ``allow_forking`` from the repo "
        "metadata. Fires when both are ``true``. Public repos "
        "(``private: false``) pass — forking a public repo is "
        "expected. Repos that explicitly disable forking "
        "(``allow_forking: false``) pass regardless of "
        "visibility. The fork-vs-Actions-secret-leak interaction "
        "is the operational risk: a fork PR using "
        "``pull_request_target`` runs with the *base* repo's "
        "secrets, so a fork carries both the code and a path to "
        "the secrets if the workflow surface is permissive. "
        "Pairs with GHA-027 (``pull_request_target`` on "
        "untrusted input) and GHA-046 (manual PR-head fetches on "
        "untrusted triggers) at the workflow layer; SCM-028 is "
        "the org-policy gate."
    ),
    known_fp=(
        "Org-wide development workflows that require contributors "
        "to fork-and-PR within the company (rather than push to "
        "branches in the original repo) legitimately rely on "
        "``allow_forking: true`` for private repos. The right "
        "compensating control is the workflow-side hardening: "
        "GHA-027 / GHA-046 / SCM-021 (Actions self-approval off) "
        "together keep the secret-leak surface closed even when "
        "forks are allowed. Suppress with a rationale that "
        "names the contribution workflow.",
    ),
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
                f"Repo is {label}; fork-policy check skipped."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    meta = snapshot.repo_meta
    if not isinstance(meta, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "repo metadata unavailable; fork-policy check "
                "skipped."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    if meta.get("private") is not True:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "Repo is public; forking is expected behavior, "
                "not a leak surface."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    if meta.get("allow_forking") is not True:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "Private repo disables forking."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot),
        description=(
            "Private repo allows forking. A fork inherits the "
            "code into the forker's namespace; if any workflow "
            "uses ``pull_request_target`` (GHA-027) or runs on "
            "fork PRs (GHA-046), Actions secrets reach the fork "
            "execution context."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
