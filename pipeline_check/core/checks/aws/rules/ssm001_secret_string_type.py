"""SSM-001. SSM parameter with secret-like name stored as String (not SecureString)."""
from __future__ import annotations

from ..._patterns import SECRET_NAME_RE
from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="SSM-001",
    title="SSM Parameter with secret-like name is not a SecureString",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-312",),
    recommendation=(
        "Recreate the parameter with ``Type=SecureString`` and migrate "
        "consumers to the new name if needed. Plain ``String`` parameters "
        "are visible via ``ssm:GetParameter`` without any KMS authorization."
    ),
    docs_note=(
        "An SSM ``String`` parameter is plaintext at rest and at "
        "API; ``ssm:GetParameter`` without any KMS Decrypt authority "
        "returns the value. ``SecureString`` adds KMS-encryption + "
        "the ``WithDecryption=true`` flag (which forces an explicit "
        "KMS authorization step). Secret-named parameters (``TOKEN``, "
        "``PASSWORD``, ``KEY``) are almost always intended to be "
        "SecureString and rarely should not be."
    ),
    exploit_example=(
        "# Vulnerable: secret-named parameter stored as plain ``String``.\n"
        "$ aws ssm put-parameter \\\n"
        "    --name /prod/api/GITHUB_TOKEN \\\n"
        "    --value ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA \\\n"
        "    --type String\n"
        "\n"
        "# Attack: any principal with the minimal ``ssm:GetParameter``\n"
        "# permission reads the cleartext, no KMS authorization needed:\n"
        "#\n"
        "#   aws ssm get-parameter --name /prod/api/GITHUB_TOKEN\n"
        "#   # Returns the plaintext, even for principals with\n"
        "#   # ``kms:Decrypt`` explicitly denied account-wide.\n"
        "#\n"
        "# CloudTrail records the GetParameter call but not the value;\n"
        "# defenders see the access only by name + principal, not what\n"
        "# was read.\n"
        "\n"
        "# Safe: SecureString forces a separate KMS authorization step.\n"
        "$ aws ssm put-parameter \\\n"
        "    --name /prod/api/GITHUB_TOKEN \\\n"
        "    --value ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA \\\n"
        "    --type SecureString \\\n"
        "    --key-id alias/prod-secrets\n"
        "\n"
        "# Now readers need BOTH ``ssm:GetParameter`` AND ``kms:Decrypt``\n"
        "# on the named CMK, and the call only returns plaintext when\n"
        "# ``WithDecryption=true`` is set (an explicit, auditable opt-in)."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for param in catalog.ssm_parameters():
        name = param.get("Name", "<unnamed>")
        ptype = param.get("Type", "")
        if ptype == "SecureString":
            continue
        if not SECRET_NAME_RE.search(name):
            continue
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name,
            description=(
                f"Parameter '{name}' has a secret-like name but is stored "
                f"as {ptype or 'String'}, not SecureString."
            ),
            recommendation=RULE.recommendation, passed=False,
        ))
    return findings
