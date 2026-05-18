"""CP-005 (Terraform). Production stage has no preceding approval."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..phase3 import _pbac005_cp005_cp007

RULE = Rule(
    id="CP-005",
    title="Production Deploy stage has no preceding ManualApproval",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    cwe=("CWE-862",),
    recommendation=(
        "Add a ``Manual`` approval action in the stage that precedes "
        "any stage whose name contains ``prod``, ``production``, or "
        "``live`` and contains a Deploy action. Approval surfaces the "
        "release decision as an auditable event."
    ),
    docs_note=(
        "A stricter version of CP-001 scoped to production-named "
        "stages. Walks ``stage[*].name`` for ``prod`` / ``production`` "
        "/ ``live`` substrings and requires a preceding "
        "``Approval`` action — even pipelines that pass CP-001 "
        "globally often skip the gate on the production stage."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [
        f for f in _pbac005_cp005_cp007(ctx) if f.check_id == "CP-005"
    ]
