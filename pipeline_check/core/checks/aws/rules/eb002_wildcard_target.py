"""EB-002. EventBridge rule has a wildcard target ARN."""
from __future__ import annotations

from ..._patterns import eventbridge_target_is_wildcard
from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="EB-002",
    title="EventBridge rule has a wildcard target ARN",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-8",),
    cwe=("CWE-441",),
    recommendation=(
        "Replace wildcard target ARNs with specific resource ARNs. "
        "EventBridge targets with ``*`` route events to any resource "
        "that matches the prefix, frequently triggering unintended "
        "Lambda invocations or SNS sends."
    ),
    docs_note=(
        "Wildcard target ARNs (e.g. "
        "``arn:aws:lambda:us-east-1:123456789012:function:*``) "
        "match every resource that fits the prefix. This is rarely "
        "intentional, usually a copy-paste from a more permissive "
        "resource ARN, and means the rule fans out to a much "
        "larger set of consumers than the author meant. A "
        "CloudWatch Logs target ARN, whose documented form ends in "
        "``:log-group:/name:*`` (the mandatory log-stream selector), "
        "is not treated as a fan-out wildcard."
    ),
    exploit_example=(
        "# Vulnerable: an EventBridge rule with a wildcard ARN\n"
        "# target. The rule fires events at\n"
        "# ``arn:aws:lambda:us-east-1:123456789012:function:*``\n"
        "# — every Lambda in the account. A buggy event source\n"
        "# (or a deliberately crafted EventBridge event) can\n"
        "# now trigger arbitrary functions with whatever\n"
        "# payload the event carries.\n"
        "import boto3\n"
        "eb = boto3.client('events')\n"
        "eb.put_targets(\n"
        "    Rule='on-codebuild-failure',\n"
        "    Targets=[{\n"
        "        'Id': '1',\n"
        "        'Arn': 'arn:aws:lambda:us-east-1:123456789012:function:*',\n"
        "    }]\n"
        ")\n"
        "\n"
        "# Safe: target a specific Lambda by full ARN. The\n"
        "# event reaches exactly the function it was meant for;\n"
        "# unrelated functions stay unbothered.\n"
        "eb.put_targets(\n"
        "    Rule='on-codebuild-failure',\n"
        "    Targets=[{\n"
        "        'Id': '1',\n"
        "        'Arn': 'arn:aws:lambda:us-east-1:123456789012:function:notify-oncall',\n"
        "    }]\n"
        ")"
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for rule_row in catalog.eventbridge_rules():
        name = rule_row.get("Name", "<unnamed>")
        for target in catalog.eventbridge_targets(name):
            arn = target.get("Arn", "") or ""
            if eventbridge_target_is_wildcard(arn):
                findings.append(Finding(
                    check_id=RULE.id, title=RULE.title, severity=RULE.severity,
                    resource=f"{name}/{target.get('Id', '?')}",
                    description=f"Target ARN contains wildcard: {arn}.",
                    recommendation=RULE.recommendation, passed=False,
                ))
    return findings
