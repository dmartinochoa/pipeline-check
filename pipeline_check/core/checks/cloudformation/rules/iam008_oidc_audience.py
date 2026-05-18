"""IAM-008 (CloudFormation). OIDC trust missing :aud / :sub pin."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..extended import _iam_oidc

RULE = Rule(
    id="IAM-008",
    title="OIDC-federated role trust policy missing audience or subject pin",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-287",),
    recommendation=(
        "Add ``Condition.StringEquals`` (or ``StringLike``) entries "
        "pinning both ``<host>:aud`` and ``<host>:sub`` to specific "
        "values. For GitHub Actions: pin ``aud`` to "
        "``sts.amazonaws.com`` and ``sub`` to "
        "``repo:<org>/<repo>:ref:refs/heads/main`` (or the env / "
        "branch combination the role expects)."
    ),
    docs_note=(
        "Inspects every ``AWS::IAM::Role.Properties."
        "AssumeRolePolicyDocument`` that carries an OIDC trust "
        "statement (provider URL like "
        "``token.actions.githubusercontent.com``). Fires when "
        "``Condition`` omits the audience or subject claim — without "
        "both, any repo under the IdP can assume the role."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return _iam_oidc(ctx)
