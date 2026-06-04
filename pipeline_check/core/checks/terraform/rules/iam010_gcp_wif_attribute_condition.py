"""IAM-010 (Terraform). GCP workload identity provider lacks a repo constraint."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext

# OIDC issuers where the federating principal is a CI repository, so the
# ``attribute_condition`` is expected to constrain WHICH repo can federate.
_CI_ISSUERS = ("token.actions.githubusercontent.com", "gitlab.com")

# Tokens that show an ``attribute_condition`` constrains the source repo.
_REPO_TOKENS = ("repository", "repo:", "sub")

RULE = Rule(
    id="IAM-010",
    title="GCP workload identity provider has no repository attribute condition",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-287", "CWE-1390"),
    recommendation=(
        "Set ``attribute_condition`` on every "
        "``google_iam_workload_identity_pool_provider`` with an ``oidc`` "
        "block, and make it constrain the source repository, e.g. "
        "``assertion.repository_owner == 'myorg'`` or "
        "``assertion.repository == 'myorg/myrepo'``. Without a condition "
        "that pins the repo, any identity the issuer mints (any GitHub "
        "repo on the planet, for the GitHub issuer) can exchange its "
        "token for a Google access token scoped to whatever the pool "
        "grants. Restrict ``allowed_audiences`` as well."
    ),
    docs_note=(
        "Fires on a ``google_iam_workload_identity_pool_provider`` with "
        "an ``oidc`` block that either has no ``attribute_condition`` at "
        "all (any token from the issuer federates), or - for the GitHub / "
        "GitLab CI issuers - has a condition that never references the "
        "repository (``repository`` / ``repo:`` / ``sub``), so it does "
        "not constrain which repo can assume the identity. GHA-062 audits "
        "the same surface from a GitHub workflow's sibling files; this "
        "reads the Terraform resource directly."
    ),
    exploit_example=(
        "# Vulnerable: an OIDC provider with no attribute_condition.\n"
        "# Google trusts every GitHub Actions token, so any repo can\n"
        "# federate into this pool.\n"
        'resource "google_iam_workload_identity_pool_provider" "gh" {\n'
        '  workload_identity_pool_id          = google_iam_workload_identity_pool.p.id\n'
        '  workload_identity_pool_provider_id = "github"\n'
        "  attribute_mapping = {\n"
        '    "google.subject"       = "assertion.sub"\n'
        '    "attribute.repository" = "assertion.repository"\n'
        "  }\n"
        "  oidc {\n"
        '    issuer_uri = "https://token.actions.githubusercontent.com"\n'
        "  }\n"
        "}\n"
        "\n"
        "# Safe: constrain the source repo (and audience).\n"
        '  attribute_condition = "assertion.repository_owner == \'myorg\'"'
    ),
)


def _first_block(value: object) -> dict[str, Any]:
    """A Terraform nested block is a one-element list in plan / HCL JSON."""
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return value[0]
    if isinstance(value, dict):
        return value
    return {}


def check(ctx: TerraformContext) -> list[Finding]:
    out: list[Finding] = []
    for prov in ctx.resources("google_iam_workload_identity_pool_provider"):
        oidc = _first_block(prov.values.get("oidc"))
        issuer = oidc.get("issuer_uri")
        if not isinstance(issuer, str) or not issuer:
            # No OIDC block (an aws / saml provider) - out of scope.
            continue
        cond = prov.values.get("attribute_condition")
        cond_text = cond.lower() if isinstance(cond, str) else ""
        is_ci_issuer = any(host in issuer for host in _CI_ISSUERS)

        if not cond_text.strip():
            reason = "no attribute_condition: any token from the issuer can federate"
            failed = True
        elif is_ci_issuer and not any(tok in cond_text for tok in _REPO_TOKENS):
            reason = "attribute_condition does not constrain the source repository"
            failed = True
        else:
            reason = ""
            failed = False

        out.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=prov.address,
            description=(
                f"Workload identity provider trusting `{issuer}` {reason}."
                if failed else
                "Workload identity provider constrains the federating repository."
            ),
            recommendation=RULE.recommendation, passed=not failed,
        ))
    return out
