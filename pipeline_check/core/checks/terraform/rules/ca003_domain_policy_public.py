"""CA-003 (Terraform). CodeArtifact domain policy allows wildcard."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..services import _codeartifact

RULE = Rule(
    id="CA-003",
    title="CodeArtifact domain policy allows cross-account wildcard",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-8",),
    cwe=("CWE-732",),
    recommendation=(
        "Remove ``Principal: \"*\"`` (or ``Principal.AWS = \"*\"``) "
        "from every ``Allow`` statement in "
        "``aws_codeartifact_domain_permissions_policy``. Name the "
        "specific accounts and add an ``aws:PrincipalOrgID`` "
        "condition."
    ),
    docs_note=(
        "Parses "
        "``aws_codeartifact_domain_permissions_policy.policy_document``. "
        "Fires on any ``Allow`` statement that names a wildcard "
        "principal — wildcard at the domain level grants the bearer "
        "access to every repo in the domain."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [f for f in _codeartifact(ctx) if f.check_id == "CA-003"]
