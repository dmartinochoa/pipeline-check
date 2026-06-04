"""IAM-009 (Terraform). Azure federated credential trusts a broad subject."""
from __future__ import annotations

from ..._iam_policy import github_repo_sub_too_broad
from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext

# The GitHub Actions OIDC issuer. Azure federated identity credentials
# that trust it carry a GitHub ``repo:<org>/<repo>:<context>`` subject,
# the same claim shape AWS pins via ``...:sub``.
_GITHUB_ISSUER = "token.actions.githubusercontent.com"

RULE = Rule(
    id="IAM-009",
    title="Azure federated identity credential trusts a broad GitHub subject",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-287", "CWE-1390"),
    recommendation=(
        "Pin ``azurerm_federated_identity_credential.subject`` to one "
        "repository AND a specific ref or environment, e.g. "
        "``repo:myorg/myrepo:ref:refs/heads/main`` or "
        "``repo:myorg/myrepo:environment:production``. An org wildcard "
        "(``repo:myorg/*``), a ref wildcard (``repo:myorg/myrepo:*``), or "
        "the ``pull_request`` context lets an untrusted workflow run "
        "(including a fork pull request) exchange its GitHub token for "
        "your Azure identity. Use one federated credential per "
        "repo+environment rather than a wildcarded subject."
    ),
    docs_note=(
        "Fires on an ``azurerm_federated_identity_credential`` whose "
        "``issuer`` is the GitHub Actions OIDC issuer and whose "
        "``subject`` wildcards the org/repo segment, wildcards the ref "
        "segment, or uses the ``pull_request`` context. Azure's Workload "
        "Identity Federation is the Azure analogue of the AWS OIDC trust "
        "IAM-008 audits; no other rule reads "
        "``azurerm_federated_identity_credential``. A subject pinned to a "
        "specific repo and ref/environment passes."
    ),
    exploit_example=(
        "# Vulnerable: the federated credential trusts any pull request\n"
        "# in the repo, so a fork PR (via a pull_request_target-style\n"
        "# workflow) mints a token Azure accepts.\n"
        'resource "azurerm_federated_identity_credential" "gh" {\n'
        '  name                = "github"\n'
        '  resource_group_name = azurerm_resource_group.rg.name\n'
        '  parent_id           = azurerm_user_assigned_identity.ci.id\n'
        '  audience            = ["api://AzureADTokenExchange"]\n'
        '  issuer              = "https://token.actions.githubusercontent.com"\n'
        '  subject             = "repo:myorg/myrepo:pull_request"\n'
        "}\n"
        "\n"
        "# Safe: pin the subject to a specific repo + ref (or\n"
        "# environment); use a second credential for other refs.\n"
        '  subject = "repo:myorg/myrepo:ref:refs/heads/main"'
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    out: list[Finding] = []
    for cred in ctx.resources("azurerm_federated_identity_credential"):
        issuer = cred.values.get("issuer")
        if not (isinstance(issuer, str) and _GITHUB_ISSUER in issuer):
            continue
        subject = cred.values.get("subject")
        broad = isinstance(subject, str) and github_repo_sub_too_broad(subject)
        out.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=cred.address,
            description=(
                f"Federated credential subject `{subject}` trusts a broad "
                "set of GitHub workflows (org / ref wildcard or "
                "pull_request); a fork PR can mint a token Azure accepts."
                if broad else
                "Federated credential subject pins a specific repo and ref."
            ),
            recommendation=RULE.recommendation, passed=not broad,
        ))
    return out
