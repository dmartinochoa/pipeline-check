"""IAM-008 (Terraform). OIDC trust missing :aud / :sub pin."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..extended import _iam_oidc_check

RULE = Rule(
    id="IAM-008",
    title="OIDC-federated role trust policy missing audience or subject pin",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-287",),
    recommendation=(
        "Add ``Condition.StringEquals`` (or ``StringLike``) entries "
        "pinning both ``<host>:aud`` and ``<host>:sub`` to specific "
        "values. For GitHub Actions: pin ``aud`` to "
        "``sts.amazonaws.com`` and ``sub`` to "
        "``repo:<org>/<repo>:ref:refs/heads/main`` (or the env / "
        "branch combination the role expects)."
    ),
    docs_note=(
        "Inspects every ``aws_iam_role.assume_role_policy`` that "
        "carries an OIDC trust statement (provider URL like "
        "``token.actions.githubusercontent.com``). Fires when "
        "``Condition`` omits the audience or subject claim — without "
        "both, any repo under the IdP can assume the role."
    ),
    exploit_example=(
        "# Vulnerable: OIDC trust has no audience restriction.\n"
        "# Any token from the IdP can assume the role, even\n"
        "# tokens minted for a different application.\n"
        'resource "aws_iam_role" "github_oidc" {\n'
        "  assume_role_policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect = "Allow"\n'
        '      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }\n'
        '      Action = "sts:AssumeRoleWithWebIdentity"\n'
        "    }]\n"
        "  })\n"
        "}\n"
        "\n"
        "# Safe: add a StringEquals condition on the audience.\n"
        'resource "aws_iam_role" "github_oidc" {\n'
        "  assume_role_policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect = "Allow"\n'
        '      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }\n'
        '      Action = "sts:AssumeRoleWithWebIdentity"\n'
        '      Condition = { StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" } }\n'
        "    }]\n"
        "  })\n"
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return _iam_oidc_check(ctx)
