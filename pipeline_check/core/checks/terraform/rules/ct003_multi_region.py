"""CT-003 (Terraform). CloudTrail trail is single-region."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..extended import _cloudtrail_checks

RULE = Rule(
    id="CT-003",
    title="CloudTrail trail is not multi-region",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Set ``is_multi_region_trail = true`` so a single trail "
        "captures activity from every region. A region-scoped trail "
        "misses anything an attacker does in another region (a "
        "classic pivot)."
    ),
    docs_note=(
        "Reads ``aws_cloudtrail.is_multi_region_trail`` for every "
        "declared trail. Multi-region is the only configuration that "
        "guarantees you'll see ``CreateAccessKey`` in ``ap-south-1`` "
        "from your ``us-east-1`` trail."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [f for f in _cloudtrail_checks(ctx) if f.check_id == "CT-003"]
