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
        "``Condition`` omits the audience or subject claim, or when a "
        "GitHub ``repo:`` subject wildcards the repo or ref segment "
        "(``repo:org/*``, ``repo:org/repo:*``) or trusts the "
        "``pull_request`` context. Without a specific repo + ref pin, an "
        "untrusted workflow (including a fork PR) can assume the role."
    ),
    exploit_example=(
        "# Vulnerable: OIDC-federated role trust policy missing\n"
        "# either ``:aud`` or ``:sub`` pin. Any OIDC token from\n"
        "# the named provider can assume the role.\n"
        "Resources:\n"
        "  Role:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      AssumeRolePolicyDocument:\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            Principal:\n"
        "              Federated:\n"
        "                'arn:aws:iam::123:oidc-provider/token.actions.githubusercontent.com'\n"
        "            Action: sts:AssumeRoleWithWebIdentity\n"
        "            # no Condition\n"
        "\n"
        "# Safe: pin both ``:aud`` (audience) and ``:sub`` (repo\n"
        "# + branch / environment).\n"
        "Resources:\n"
        "  Role:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      AssumeRolePolicyDocument:\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            Principal:\n"
        "              Federated:\n"
        "                'arn:aws:iam::123:oidc-provider/token.actions.githubusercontent.com'\n"
        "            Action: sts:AssumeRoleWithWebIdentity\n"
        "            Condition:\n"
        "              StringEquals:\n"
        "                'token.actions.githubusercontent.com:aud': sts.amazonaws.com\n"
        "                'token.actions.githubusercontent.com:sub':\n"
        "                  'repo:myorg/myrepo:environment:production'"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return _iam_oidc(ctx)
