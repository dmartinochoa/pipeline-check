"""TF-002 (Terraform-only). Stateful resource carries plaintext secret."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..phase4 import _tf002_plan_secrets

RULE = Rule(
    id="TF-002",
    title="Stateful data-store resource carries a plaintext secret",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-312",),
    recommendation=(
        "Move the secret into Secrets Manager (or SSM Parameter "
        "Store SecureString) and reference it via "
        "``data.aws_secretsmanager_secret_version.…`` at apply time. "
        "Never literal-string a credential into a stateful resource — "
        "the value lives in state forever."
    ),
    docs_note=(
        "Walks every value of the stateful data-store resources "
        "(``aws_db_instance``, ``aws_rds_cluster``, "
        "``aws_redshift_cluster``, "
        "``aws_elasticache_replication_group``, ``aws_docdb_cluster``, "
        "``aws_neptune_cluster``, ``aws_opensearch_domain``, "
        "``aws_memorydb_cluster``). Fires when a string leaf matches a "
        "credential shape (AKIA/ASIA, ``ghp_``, JWT, …) OR when a "
        "secret-named attribute (``*password``, ``*token``, …) "
        "carries a non-placeholder literal."
    ),
    exploit_example=(
        "# Vulnerable: the password literal lands in the Terraform\n"
        "# state file on every apply. Remote S3 backends store state\n"
        "# in plaintext unless explicitly encrypted; CI runs that\n"
        "# load state print the value when ``-json`` or ``output``\n"
        "# touches it. The credential rotates only on the next\n"
        "# ``aws_db_instance`` replacement.\n"
        "resource \"aws_db_instance\" \"prod\" {\n"
        "  identifier        = \"app-prod\"\n"
        "  engine            = \"postgres\"\n"
        "  instance_class    = \"db.t3.medium\"\n"
        "  allocated_storage = 100\n"
        "  username          = \"appuser\"\n"
        "  password          = \"hunter2-prod-master-pw\"\n"
        "}\n"
        "\n"
        "# Safe: pull the password from Secrets Manager at apply time.\n"
        "# State carries the secret's ARN reference, not the value.\n"
        "# Rotation runs via Secrets Manager without a Terraform\n"
        "# state change. The data source is read-only, so the value\n"
        "# never appears in ``terraform plan`` output either.\n"
        "data \"aws_secretsmanager_secret_version\" \"db_master\" {\n"
        "  secret_id = \"prod/app/db_master\"\n"
        "}\n"
        "\n"
        "resource \"aws_db_instance\" \"prod\" {\n"
        "  identifier        = \"app-prod\"\n"
        "  engine            = \"postgres\"\n"
        "  instance_class    = \"db.t3.medium\"\n"
        "  allocated_storage = 100\n"
        "  username          = \"appuser\"\n"
        "  password          = data.aws_secretsmanager_secret_version.db_master.secret_string\n"
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return _tf002_plan_secrets(ctx)
