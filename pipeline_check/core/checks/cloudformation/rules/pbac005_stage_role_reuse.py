"""PBAC-005 (CloudFormation). Pipeline stage roles all equal pipeline role."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..phase3 import _pbac005_cp005_cp007

RULE = Rule(
    id="PBAC-005",
    title="Pipeline action roles all equal the pipeline-level role",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-5",),
    cwe=("CWE-250",),
    recommendation=(
        "Assign a least-privilege ``RoleArn`` to every "
        "``Stages[*].Actions[*]`` that needs cross-account or "
        "cross-service permissions, instead of falling back to the "
        "pipeline's top-level ``RoleArn``."
    ),
    docs_note=(
        "Compares each ``Stages[*].Actions[*].RoleArn`` against the "
        "pipeline's top-level ``RoleArn``. When all action-level "
        "values are empty or identical to the pipeline role, every "
        "stage runs with the same blast-radius."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [
        f for f in _pbac005_cp005_cp007(ctx) if f.check_id == "PBAC-005"
    ]
