"""ORG-009. An org self-hosted runner group is available to public repos."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMOrgContext, org_resource


def _public_runner_groups(body: dict[str, Any]) -> list[str]:
    """Names of runner groups with ``allows_public_repositories`` true."""
    groups = body.get("runner_groups")
    if not isinstance(groups, list):
        return []
    names: list[str] = []
    for entry in groups:
        if not isinstance(entry, dict):
            continue
        if entry.get("allows_public_repositories") is True:
            name = entry.get("name")
            names.append(name if isinstance(name, str) and name else "<unnamed>")
    return names


RULE = Rule(
    id="ORG-009",
    title="Organization self-hosted runner group is available to public repositories",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4", "CICD-SEC-7"),
    cwe=("CWE-668",),
    recommendation=(
        "Turn off ``Allow public repositories`` on the runner group (Org "
        "Settings -> Actions -> Runner groups -> edit the group). When it is "
        "on, a workflow in any public repository, including a pull request "
        "from a fork, can run jobs on the org's self-hosted runners. Fork "
        "code then executes on persistent infrastructure you operate: it can "
        "read other jobs' files, steal cached credentials, pivot into the "
        "network, or leave a backdoor on the host. GitHub's own hardening "
        "guidance is that self-hosted runners should never be available to "
        "public repositories. Use ephemeral, isolated runners for public "
        "repos, or keep the runner group scoped to trusted private repos."
    ),
    docs_note=(
        "Reads ``GET /orgs/{org}/actions/runner-groups`` and fires when any "
        "group has ``allows_public_repositories: true``. Group names are "
        "listed so the operator can find them. The org-governance analog of "
        "GHA-105 (a self-hosted runner reachable from an untrusted PR "
        "trigger) and GLRUN-005 (a fork pipeline on a self-managed runner). "
        "Needs a token with the ``admin:org`` / ``manage_runners:org`` scope; "
        "when the endpoint is unavailable (no scope, or the org has no runner "
        "groups) the rule passes with a note."
    ),
)


def check(ctx: SCMOrgContext) -> Finding:
    body = ctx.actions_runner_groups
    if not isinstance(body, dict):
        return RULE.pass_finding(
            org_resource(ctx),
            "The organization's Actions runner groups were not available "
            "(needs a token with the ``admin:org`` / ``manage_runners:org`` "
            "scope, or the org has no runner groups); not evaluated.",
        )
    names = _public_runner_groups(body)
    if not names:
        return RULE.pass_finding(
            org_resource(ctx),
            f"Organization ``{ctx.org}`` has no self-hosted runner group "
            "available to public repositories.",
        )
    sample = ", ".join(names[:5])
    if len(names) > 5:
        sample += f", ... (+{len(names) - 5} more)"
    return RULE.fail_finding(
        org_resource(ctx),
        f"Organization ``{ctx.org}`` has {len(names)} self-hosted runner "
        f"group(s) available to public repositories: {sample}. A fork pull "
        "request can run code on infrastructure you operate; scope these "
        "groups to trusted private repos.",
    )
