"""ECR-001 (Terraform). ECR repository scan_on_push disabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..ecr import _ecr001_scan_on_push

RULE = Rule(
    id="ECR-001",
    title="Image scanning on push not enabled",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    cwe=("CWE-1104",),
    recommendation=(
        "Set ``image_scanning_configuration { scan_on_push = true }`` "
        "on every ``aws_ecr_repository``. For deeper coverage, also "
        "enable Inspector v2 enhanced scanning at the registry level."
    ),
    docs_note=(
        "Reads ``aws_ecr_repository."
        "image_scanning_configuration[0].scan_on_push``. Without it, a "
        "freshly-pushed image goes straight into deployable storage "
        "with no known-CVE pass."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    findings: list[Finding] = []
    for r in ctx.resources("aws_ecr_repository"):
        name = r.values.get("name") or r.name
        findings.append(_ecr001_scan_on_push(r.values, name))
    return findings
