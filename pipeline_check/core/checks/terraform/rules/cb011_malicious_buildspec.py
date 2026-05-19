"""CB-011 (Terraform). CodeBuild inline buildspec carries IOCs."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..extended import _cb011

RULE = Rule(
    id="CB-011",
    title="CodeBuild buildspec contains indicators of malicious activity",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4",),
    cwe=("CWE-506",),
    recommendation=(
        "Treat any hit on this rule as a potential pipeline "
        "compromise. Identify the commit that introduced the "
        "buildspec, rotate every credential reachable by the "
        "project's service role, and move the buildspec to a "
        "repo-sourced file under branch protection (see CB-008)."
    ),
    docs_note=(
        "Runs the shared buildspec-IOC matcher against any inline "
        "``source[0].buildspec``. The matcher looks for "
        "reverse-shell payloads, miner CLIs, secret-exfil patterns, "
        "and credential-grabbing one-liners. Repo-sourced buildspecs "
        "are skipped — the text isn't visible in the plan."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [
        _cb011(r.values, r.address)
        for r in ctx.resources("aws_codebuild_project")
    ]
