"""TF-001 (Terraform-only). Static aws_iam_access_key in the plan."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..phase4 import _tf001_iam_access_key

RULE = Rule(
    id="TF-001",
    title="Plan declares aws_iam_access_key (long-lived credential)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-798",),
    recommendation=(
        "Replace static keys with role-based access: an "
        "``aws_iam_role`` plus an OIDC ``aws_iam_openid_connect_provider`` "
        "for CI, or ``aws_iam_role`` for service-to-service auth. "
        "Static keys live forever in state, in backups, in every "
        "machine that ever ran ``terraform plan``."
    ),
    docs_note=(
        "Fires on every ``aws_iam_access_key`` in the plan. Terraform "
        "writes the resulting ``secret`` to state, even on remote "
        "backends, the secret is now in every state-file backup, "
        "every CI run, and anywhere ``terraform output`` ran."
    ),
    exploit_example=(
        "# Vulnerable: every ``terraform apply`` provisions a long-\n"
        "# lived access key and lands the literal\n"
        "# ``aws_iam_access_key.ci.secret`` in the state file. Remote\n"
        "# backends (S3) store the state plaintext by default; every\n"
        "# CI run that loads state reads the secret. The key only\n"
        "# goes away on ``terraform destroy``.\n"
        "resource \"aws_iam_user\" \"ci\" {\n"
        "  name = \"ci-bot\"\n"
        "}\n"
        "\n"
        "resource \"aws_iam_access_key\" \"ci\" {\n"
        "  user = aws_iam_user.ci.name\n"
        "}\n"
        "\n"
        "output \"ci_secret\" {\n"
        "  value     = aws_iam_access_key.ci.secret\n"
        "  sensitive = true   # masks console output but state stays plaintext\n"
        "}\n"
        "\n"
        "# Safe: federate via GitHub Actions OIDC so tokens last\n"
        "# minutes per workflow run, not forever. The role's trust\n"
        "# policy pins ``sub`` to one repo + ref, so the federation\n"
        "# can't be assumed by an unrelated workflow even on the\n"
        "# same account.\n"
        "resource \"aws_iam_openid_connect_provider\" \"github\" {\n"
        "  url             = \"https://token.actions.githubusercontent.com\"\n"
        "  client_id_list  = [\"sts.amazonaws.com\"]\n"
        "  thumbprint_list = [\"6938fd4d98bab03faadb97b34396831e3780aea1\"]\n"
        "}\n"
        "\n"
        "resource \"aws_iam_role\" \"ci\" {\n"
        "  name = \"ci-bot\"\n"
        "  assume_role_policy = jsonencode({\n"
        "    Statement = [{\n"
        "      Effect    = \"Allow\"\n"
        "      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }\n"
        "      Action    = \"sts:AssumeRoleWithWebIdentity\"\n"
        "      Condition = {\n"
        "        StringEquals = {\n"
        "          \"token.actions.githubusercontent.com:sub\" = \"repo:myorg/myrepo:ref:refs/heads/main\"\n"
        "          \"token.actions.githubusercontent.com:aud\" = \"sts.amazonaws.com\"\n"
        "        }\n"
        "      }\n"
        "    }]\n"
        "  })\n"
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return _tf001_iam_access_key(ctx)
