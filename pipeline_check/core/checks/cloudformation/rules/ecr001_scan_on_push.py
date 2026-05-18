"""ECR-001 (CloudFormation). ECR repository scan_on_push disabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext, as_str
from ..ecr import _ecr001_scan_on_push

RULE = Rule(
    id="ECR-001",
    title="Image scanning on push not enabled",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    cwe=("CWE-1104",),
    recommendation=(
        "Set ``ImageScanningConfiguration.ScanOnPush: true`` on "
        "every ``AWS::ECR::Repository``. For deeper coverage, also "
        "enable Inspector v2 enhanced scanning at the registry level."
    ),
    docs_note=(
        "Reads ``AWS::ECR::Repository."
        "Properties.ImageScanningConfiguration.ScanOnPush``. Without "
        "it, a freshly-pushed image goes straight into deployable "
        "storage with no known-CVE pass."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    findings: list[Finding] = []
    for r in ctx.resources("AWS::ECR::Repository"):
        name = as_str(r.properties.get("RepositoryName")) or r.logical_id
        findings.append(_ecr001_scan_on_push(r.properties, name))
    return findings
