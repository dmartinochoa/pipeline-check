"""ORG-006. An org Actions secret is readable by every repository."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMOrgContext, org_resource


def _all_repo_secret_names(body: dict[str, Any]) -> list[str]:
    """Names of org secrets whose ``visibility`` is ``all``."""
    secrets = body.get("secrets")
    if not isinstance(secrets, list):
        return []
    names: list[str] = []
    for entry in secrets:
        if not isinstance(entry, dict):
            continue
        if entry.get("visibility") == "all":
            name = entry.get("name")
            if isinstance(name, str) and name:
                names.append(name)
    return names


RULE = Rule(
    id="ORG-006",
    title="Organization Actions secret is exposed to every repository",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-522",),
    recommendation=(
        "Scope each org-level Actions secret to selected repositories "
        "(Org Settings -> Secrets and variables -> Actions -> edit the "
        "secret -> ``Repository access: Selected repositories``) instead of "
        "``All repositories``. An all-repos secret is readable by every "
        "workflow in every current and future repo, including low-trust "
        "ones, so one script injection or compromised action in any repo "
        "exfiltrates it. Grant the secret only to the repos that build the "
        "system that needs it."
    ),
    docs_note=(
        "Reads ``GET /orgs/{org}/actions/secrets`` and fires when any secret "
        "has ``visibility: all``. ``selected`` and ``private`` pass. The "
        "endpoint returns secret names and visibility only, never values; "
        "names are listed so the operator can find them. Needs a token with "
        "the ``admin:org`` (or secrets) scope; when unavailable the rule "
        "passes with a note. The repo-level analog is SCM-048 (org "
        "codespace secret scoped to all repos)."
    ),
)


def check(ctx: SCMOrgContext) -> Finding:
    body = ctx.actions_secrets
    if not isinstance(body, dict):
        return RULE.pass_finding(
            org_resource(ctx),
            "The organization's Actions secrets were not available (needs a "
            "token with the ``admin:org`` / secrets scope); not evaluated.",
        )
    names = _all_repo_secret_names(body)
    if not names:
        return RULE.pass_finding(
            org_resource(ctx),
            f"Organization ``{ctx.org}`` has no Actions secret scoped to "
            "all repositories.",
        )
    sample = ", ".join(names[:5])
    if len(names) > 5:
        sample += f", ... (+{len(names) - 5} more)"
    return RULE.fail_finding(
        org_resource(ctx),
        f"Organization ``{ctx.org}`` has {len(names)} Actions secret(s) "
        f"readable by every repository: {sample}. Any workflow in any repo "
        "(including low-trust ones) can read them; scope each to selected "
        "repositories.",
    )
