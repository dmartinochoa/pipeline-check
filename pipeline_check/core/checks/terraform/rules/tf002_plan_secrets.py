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
)


def check(ctx: TerraformContext) -> list[Finding]:
    return _tf002_plan_secrets(ctx)
