"""ECR-002 (Terraform). ECR repository image tags are mutable."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..ecr import _ecr002_tag_mutability

RULE = Rule(
    id="ECR-002",
    title="Image tags are mutable",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-1357",),
    recommendation=(
        "Set ``image_tag_mutability = \"IMMUTABLE\"`` on every "
        "``aws_ecr_repository``. With immutable tags, a tag points at "
        "exactly one digest forever; an attacker can't swap "
        "``:latest`` mid-deploy."
    ),
    docs_note=(
        "Reads ``aws_ecr_repository.image_tag_mutability``. Default is "
        "``MUTABLE`` — anyone with ``ecr:PutImage`` on the repo can "
        "overwrite any existing tag, including release tags consumed "
        "by production deployments."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    findings: list[Finding] = []
    for r in ctx.resources("aws_ecr_repository"):
        name = r.values.get("name") or r.name
        findings.append(_ecr002_tag_mutability(r.values, name))
    return findings
