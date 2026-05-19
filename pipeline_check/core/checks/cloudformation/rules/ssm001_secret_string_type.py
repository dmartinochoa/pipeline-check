"""SSM-001 (CloudFormation). SSM parameter stores a secret as String."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..services import _ssm

RULE = Rule(
    id="SSM-001",
    title="SSM parameter with secret-like name stored as String, not SecureString",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-312",),
    recommendation=(
        "Set ``Type: SecureString`` on every ``AWS::SSM::Parameter`` "
        "whose name or value looks secret-like. SecureString "
        "parameters are encrypted with KMS and audited separately "
        "from plain ``GetParameter`` access."
    ),
    docs_note=(
        "Checks ``AWS::SSM::Parameter.Properties.Name`` against the "
        "standard secret-name regex. If the name matches and ``Type`` "
        "is ``String`` (the CFN-only default — ``SecureString`` is "
        "not creatable via CFN, see AWS docs), the value is in "
        "plaintext."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _ssm(ctx) if f.check_id == "SSM-001"]
