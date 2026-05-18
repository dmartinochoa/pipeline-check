"""CF-002 (CloudFormation-only). Stateful resource carries plaintext secret."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..phase4 import _cf002_template_secrets

RULE = Rule(
    id="CF-002",
    title="Stateful data-store resource carries a plaintext secret",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-312",),
    recommendation=(
        "Move the secret into Secrets Manager (or SSM Parameter "
        "Store SecureString) and reference it via "
        "``'{{resolve:secretsmanager:…}}'`` at deploy time. Never "
        "literal-string a credential into a stateful resource — the "
        "value lives in the template, the stack history, and any "
        "drift detection report."
    ),
    docs_note=(
        "Walks every string value of the stateful data-store "
        "resources (``AWS::RDS::DBInstance``, "
        "``AWS::RDS::DBCluster``, ``AWS::Redshift::Cluster``, "
        "``AWS::ElastiCache::ReplicationGroup``, "
        "``AWS::DocDB::DBCluster``, ``AWS::Neptune::DBCluster``, "
        "``AWS::OpenSearchService::Domain``, "
        "``AWS::MemoryDB::Cluster``). Fires when a string leaf "
        "matches a credential shape OR when a secret-named "
        "attribute (``*Password``, ``*Token``, …) carries a "
        "non-placeholder literal."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return _cf002_template_secrets(ctx)
