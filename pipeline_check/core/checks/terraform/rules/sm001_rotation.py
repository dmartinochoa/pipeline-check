"""SM-001 (Terraform). Secrets Manager secret has no rotation."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..extended import _secretsmanager_checks

RULE = Rule(
    id="SM-001",
    title="Secrets Manager secret has no rotation configured",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-262",),
    recommendation=(
        "Declare an ``aws_secretsmanager_secret_rotation`` that "
        "targets the secret via its ``secret_id``, with a Lambda "
        "rotation function and ``rotation_rules.automatically_after_days``. "
        "30 / 60 / 90-day cadences are the usual stops."
    ),
    docs_note=(
        "Joins ``aws_secretsmanager_secret_rotation`` to "
        "``aws_secretsmanager_secret`` by ``secret_id``. Fires when a "
        "secret has no matching rotation resource — a static secret "
        "that lives forever in any backup or snapshot taken since "
        "the leak."
    ),
    exploit_example=(
        "# Vulnerable: secret has no rotation schedule. A leaked\n"
        "# credential stays valid indefinitely.\n"
        'resource "aws_secretsmanager_secret" "db" {\n'
        '  name = "prod/db-password"\n'
        "}\n"
        "# (no aws_secretsmanager_secret_rotation)\n"
        "\n"
        "# Safe: enable automatic rotation.\n"
        'resource "aws_secretsmanager_secret_rotation" "db" {\n'
        "  secret_id           = aws_secretsmanager_secret.db.id\n"
        "  rotation_lambda_arn = aws_lambda_function.rotator.arn\n"
        "  rotation_rules {\n"
        "    automatically_after_days = 90\n"
        "  }\n"
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [f for f in _secretsmanager_checks(ctx) if f.check_id == "SM-001"]
