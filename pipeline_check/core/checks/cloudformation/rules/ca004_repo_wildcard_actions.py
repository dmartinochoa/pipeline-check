"""CA-004 (CloudFormation). CodeArtifact repo policy grants codeartifact:*."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..services import _codeartifact

RULE = Rule(
    id="CA-004",
    title="CodeArtifact repo policy grants codeartifact:* with Resource '*'",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-269",),
    recommendation=(
        "Enumerate specific actions and resources instead of "
        "``codeartifact:*`` with ``Resource: \"*\"``."
    ),
    docs_note=(
        "Parses ``AWS::CodeArtifact::Repository."
        "Properties.PermissionsPolicyDocument``. Fires when an "
        "``Allow`` statement pairs ``codeartifact:*`` (or ``*``) "
        "with ``Resource: \"*\"``. That combination lets the "
        "principal publish, delete, and rewrite every package "
        "version in the repo."
    ),
    exploit_example=(
        "# Vulnerable: ``codeartifact:*`` on ``Resource '*'`` lets\n"
        "# the principal delete repositories, dispose package\n"
        "# versions, mark malicious versions Published, and\n"
        "# rewrite domain permissions.\n"
        "Resources:\n"
        "  RepoPolicy:\n"
        "    Type: AWS::CodeArtifact::Repository\n"
        "    Properties:\n"
        "      DomainName: myorg\n"
        "      RepositoryName: shared\n"
        "      PermissionsPolicyDocument:\n"
        "        Version: '2012-10-17'\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            Principal: { AWS: !Ref CIRole }\n"
        "            Action: 'codeartifact:*'\n"
        "            Resource: '*'\n"
        "\n"
        "# Safe: enumerate the verbs the CI workload needs and\n"
        "# scope ``Resource`` to specific repos / packages.\n"
        "Resources:\n"
        "  RepoPolicy:\n"
        "    Type: AWS::CodeArtifact::Repository\n"
        "    Properties:\n"
        "      DomainName: myorg\n"
        "      RepositoryName: shared\n"
        "      PermissionsPolicyDocument:\n"
        "        Version: '2012-10-17'\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            Principal: { AWS: !Ref CIRole }\n"
        "            Action:\n"
        "              - codeartifact:GetPackageVersionAsset\n"
        "              - codeartifact:ReadFromRepository\n"
        "            Resource:\n"
        "              - !GetAtt Repo.Arn\n"
        "              - !Sub '${Repo.Arn}/package/*'"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _codeartifact(ctx) if f.check_id == "CA-004"]
