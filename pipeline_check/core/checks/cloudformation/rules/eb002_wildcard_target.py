"""EB-002 (CloudFormation). EventBridge target ARN contains literal wildcard."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..phase4 import _eb002

RULE = Rule(
    id="EB-002",
    title="EventBridge rule has a wildcard target ARN",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-8",),
    cwe=("CWE-441",),
    recommendation=(
        "Pin ``AWS::Events::Rule.Targets[*].Arn`` to a specific "
        "function or queue ARN. Wildcards in target ARNs defeat the "
        "per-target audit trail and let any resource matching the "
        "pattern receive the event."
    ),
    docs_note=(
        "Reads ``AWS::Events::Rule.Properties.Targets[*].Arn``. A "
        "literal ``*`` in the ARN is the offending shape — it makes "
        "the target opaque to any reviewer tracing event flow."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return _eb002(ctx)
