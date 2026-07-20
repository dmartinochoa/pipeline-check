"""SCM-054. Bitbucket private repo allows public forks."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    SCMRepoSnapshot,
    bitbucket_only_skip,
    repo_resource,
)

RULE = Rule(
    id="SCM-054",
    title="Bitbucket private repo allows public forks",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1", "CICD-SEC-6"),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-200", "CWE-732"),
    recommendation=(
        "On the repo Settings -> Repository details panel, set "
        "``Forking`` to either ``Disabled`` or ``Restrict to "
        "private forks``. The API field is ``fork_policy`` with "
        "three values: ``allow_forks`` (permissive, the failure "
        "case this rule catches), ``no_public_forks`` (forks "
        "allowed but they inherit the parent's private "
        "visibility), and ``no_forks`` (forks blocked entirely). "
        "On a private repo, ``allow_forks`` means any workspace "
        "member can fork the repo into a public personal "
        "workspace, which silently makes the source visible to "
        "the entire internet. The fork retains the parent's commit "
        "history including any secrets the source repo's "
        "secret-scanning policy hasn't yet rotated."
    ),
    docs_note=(
        "Reads ``repo_meta._bitbucket_repo.fork_policy`` and fires "
        "when the repo is private (``is_private: true``) and "
        "``fork_policy`` is ``allow_forks`` (the permissive "
        "value). Public repos are not flagged: a public source "
        "repo is already visible, so a public fork doesn't "
        "increase the disclosure surface. The Bitbucket Cloud "
        "API exposes ``fork_policy`` directly on the repo "
        "object, so no extra fetch is needed beyond what the "
        "hydrator already issues."
    ),
    known_fp=(
        "Repos that are explicitly meant as upstream templates "
        "for community contribution may have been set to "
        "``allow_forks`` on purpose. The right pattern in that "
        "case is to either make the source public (so "
        "``allow_forks`` is a no-op for confidentiality) or "
        "switch to ``no_public_forks`` (still allows community "
        "forks but keeps them inside the workspace's privacy "
        "boundary). Suppress per-repo for known-public templates.",
    ),
    incident_refs=(
        "Bitbucket workspace policy gap that surfaces in audits "
        "of multi-tenant SaaS engineering orgs: a private "
        "monorepo with ``allow_forks`` lets a contractor fork "
        "the entire commit history into their personal "
        "workspace, where the source plus full git log is now "
        "visible to anyone with the fork URL. Detection requires "
        "auditing fork lists per-repo, which most orgs never "
        "do.",
    ),
    exploit_example=(
        "# Vulnerable: a private monorepo has fork_policy:\n"
        "# allow_forks.\n"
        "GET /2.0/repositories/myworkspace/payments-monorepo\n"
        "{\n"
        "  \"is_private\": true,\n"
        "  \"fork_policy\": \"allow_forks\",\n"
        "  ...\n"
        "}\n"
        "\n"
        "# Attack: a workspace member with read access opens the\n"
        "# repo in the web UI, hits Fork, picks their personal\n"
        "# workspace as the destination. The fork lands at\n"
        "# bitbucket.org/<user>/payments-monorepo with the full\n"
        "# commit history and any leaked secrets the source\n"
        "# hasn't rotated. The fork URL is searchable; the\n"
        "# audit log entry for the fork rarely gets reviewed.\n"
        "\n"
        "# Safe: set ``fork_policy`` to ``no_forks`` (block\n"
        "# entirely) or ``no_public_forks`` (forks stay inside\n"
        "# the workspace's private boundary)."
    ),
)


def check(snapshot: SCMRepoSnapshot) -> Finding:
    if skip := bitbucket_only_skip(snapshot):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=skip,
            recommendation=RULE.recommendation, passed=True,
        )
    meta = snapshot.repo_meta if isinstance(snapshot.repo_meta, dict) else {}
    repo: Any = meta.get("_bitbucket_repo")
    if not isinstance(repo, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description="Bitbucket repo metadata unavailable.",
            recommendation=RULE.recommendation, passed=True,
        )
    is_private = bool(repo.get("is_private"))
    if not is_private:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "Repo is public; fork-policy enforcement is not "
                "load-bearing for confidentiality on a public "
                "source."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    policy = repo.get("fork_policy")
    if not isinstance(policy, str):
        # The payload carries no ``fork_policy`` (older API / a token
        # without full repository read scope). Don't assert a permissive
        # policy that was never observed; pass with an unavailable note,
        # matching how the rest of the pack degrades on missing data.
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "Bitbucket ``fork_policy`` is absent from the repo "
                "payload; fork posture could not be read. Not "
                "asserting a permissive policy on missing data."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    passed = policy in ("no_forks", "no_public_forks")
    desc = (
        f"Private repo restricts forks (``fork_policy: {policy}``)."
        if passed else
        f"Private repo allows public forks (``fork_policy: {policy}``). "
        f"Any workspace member can fork the repo into a personal "
        f"public workspace, exposing source plus full git history "
        f"to the public internet."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
