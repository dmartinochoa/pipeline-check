"""LMB-004 (Terraform). Lambda permission grants Principal '*'."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..services import _lambda

RULE = Rule(
    id="LMB-004",
    title="Lambda resource policy grants wildcard principal",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-8",),
    cwe=("CWE-732",),
    recommendation=(
        "Drop any ``aws_lambda_permission`` with ``principal = \"*\"`` "
        "(or ``principal = \"arn:aws:iam::*:root\"``). Name the "
        "specific service principal or account that needs invoke, "
        "and scope further with ``source_account`` / ``source_arn`` "
        "conditions."
    ),
    docs_note=(
        "Inspects every ``aws_lambda_permission`` resource. Fires "
        "when ``principal`` is ``\"*\"`` or any other wildcard form. "
        "A wildcard invoker exposes the function — and whatever role "
        "it executes with — to the whole internet."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [f for f in _lambda(ctx) if f.check_id == "LMB-004"]
