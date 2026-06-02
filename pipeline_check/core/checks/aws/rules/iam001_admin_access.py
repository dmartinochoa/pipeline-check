"""IAM-001. CI/CD service role has AdministratorAccess attached."""
from __future__ import annotations

from ..._iam_policy import _ADMIN_POLICY_SUFFIX, ADMIN_POLICY_ARN
from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="IAM-001",
    title="CI/CD role has AdministratorAccess policy attached",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-269",),
    recommendation=(
        "Replace AdministratorAccess with least-privilege policies."
    ),
    docs_note=(
        "A CI/CD service role with ``AdministratorAccess`` attached "
        "turns any pipeline compromise into account compromise. The "
        "classic anti-pattern: the role started narrow, the "
        "pipeline grew, someone attached AdministratorAccess to "
        "unblock a deploy, and it never came off."
    ),
    exploit_example=(
        "# Vulnerable: CodeBuild service role with AdministratorAccess.\n"
        "# (Terraform shown for clarity; the actual finding comes from\n"
        "# live ListAttachedRolePolicies on the role.)\n"
        "resource \"aws_iam_role\" \"codebuild\" {\n"
        "  name               = \"codebuild-deploy\"\n"
        "  assume_role_policy = data.aws_iam_policy_document.cb_trust.json\n"
        "}\n"
        "resource \"aws_iam_role_policy_attachment\" \"admin\" {\n"
        "  role       = aws_iam_role.codebuild.name\n"
        "  policy_arn = \"arn:aws:iam::aws:policy/AdministratorAccess\"\n"
        "}\n"
        "\n"
        "# Attack: any compromise of the build (poisoned dependency,\n"
        "# leaked buildspec edit, malicious PR merged to the branch\n"
        "# CodeBuild trusts) runs as a principal with full account\n"
        "# permissions. From a build shell:\n"
        "#\n"
        "#   aws iam create-user --user-name persistence\n"
        "#   aws iam attach-user-policy --user-name persistence \\\n"
        "#     --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n"
        "#   aws iam create-access-key --user-name persistence\n"
        "#\n"
        "# Game over: out-of-band admin, no IP gate, survives every\n"
        "# subsequent rotation of the CodeBuild role itself.\n"
        "\n"
        "# Safe: scope the role to the resources the pipeline actually\n"
        "# touches. ``AdministratorAccess`` is never the right answer\n"
        "# for an automation principal.\n"
        "resource \"aws_iam_role_policy\" \"codebuild_least_priv\" {\n"
        "  role   = aws_iam_role.codebuild.id\n"
        "  policy = data.aws_iam_policy_document.deploy_specific.json\n"
        "}"
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for role in catalog.cicd_roles():
        role_name = role.get("RoleName", "<unnamed>")
        arns, error = catalog.iam_role_attached_arns(role_name)
        if error:
            findings.append(Finding(
                check_id=RULE.id, title=RULE.title, severity=RULE.severity,
                resource=role_name,
                description=error,
                recommendation="Ensure iam:ListAttachedRolePolicies permission.",
                passed=False,
            ))
            continue
        # Match the commercial ARN exactly, but also accept GovCloud
        # (arn:aws-us-gov:) and China (arn:aws-cn:) partition forms by
        # checking the suffix that is constant across all partitions.
        has_admin = ADMIN_POLICY_ARN in arns or any(
            a.endswith(_ADMIN_POLICY_SUFFIX) for a in arns
        )
        desc = (
            f"Role '{role_name}' has AdministratorAccess attached."
            if has_admin else
            f"Role '{role_name}' does not have AdministratorAccess attached."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=role_name, description=desc,
            recommendation=RULE.recommendation, passed=not has_admin,
        ))
    return findings
