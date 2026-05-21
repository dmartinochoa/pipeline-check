"""ECR-002 (CloudFormation). ECR repository tags are mutable."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext, as_str
from ..ecr import _ecr002_tag_mutability

RULE = Rule(
    id="ECR-002",
    title="Image tags are mutable",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-1357",),
    recommendation=(
        "Set ``ImageTagMutability: IMMUTABLE`` on every "
        "``AWS::ECR::Repository``. Immutable tags point at exactly "
        "one digest forever — an attacker can't swap ``:latest`` "
        "mid-deploy."
    ),
    docs_note=(
        "Reads ``AWS::ECR::Repository."
        "Properties.ImageTagMutability``. Default is ``MUTABLE`` — "
        "anyone with ``ecr:PutImage`` on the repo can overwrite "
        "release tags consumed by production deployments."
    ),
    exploit_example=(
        "# Vulnerable: ``ImageTagMutability: MUTABLE`` lets anyone\n"
        "# with ``ecr:PutImage`` swap the image under an existing\n"
        "# tag, silently changing what consumers pull next.\n"
        "Resources:\n"
        "  Repo:\n"
        "    Type: AWS::ECR::Repository\n"
        "    Properties:\n"
        "      RepositoryName: myapp\n"
        "      ImageTagMutability: MUTABLE\n"
        "\n"
        "# Safe: ``IMMUTABLE``. Tags can be pushed once; updates\n"
        "# require a new version tag.\n"
        "Resources:\n"
        "  Repo:\n"
        "    Type: AWS::ECR::Repository\n"
        "    Properties:\n"
        "      RepositoryName: myapp\n"
        "      ImageTagMutability: IMMUTABLE"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    findings: list[Finding] = []
    for r in ctx.resources("AWS::ECR::Repository"):
        name = as_str(r.properties.get("RepositoryName")) or r.logical_id
        findings.append(_ecr002_tag_mutability(r.properties, name))
    return findings
