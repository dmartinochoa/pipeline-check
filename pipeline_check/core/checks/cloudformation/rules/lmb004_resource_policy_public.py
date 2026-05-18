"""LMB-004 (CloudFormation). Lambda permission grants Principal '*'."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..services import _lambda

RULE = Rule(
    id="LMB-004",
    title="Lambda resource policy grants wildcard principal",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-8",),
    cwe=("CWE-732",),
    recommendation=(
        "Drop any ``AWS::Lambda::Permission`` with ``Principal: "
        "\"*\"``. Name the specific service principal or account "
        "that needs invoke, and scope further with ``SourceAccount`` "
        "/ ``SourceArn`` conditions."
    ),
    docs_note=(
        "Inspects every ``AWS::Lambda::Permission`` resource. Fires "
        "when ``Principal`` is ``\"*\"`` or any other wildcard form. "
        "A wildcard invoker exposes the function — and the role it "
        "executes with — to the whole internet."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _lambda(ctx) if f.check_id == "LMB-004"]
