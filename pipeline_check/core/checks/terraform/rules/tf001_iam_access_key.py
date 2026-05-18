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
)


def check(ctx: TerraformContext) -> list[Finding]:
    return _tf001_iam_access_key(ctx)
