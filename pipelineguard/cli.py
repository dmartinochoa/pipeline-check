"""CLI entry point.

Usage
-----
    pipelineguard [OPTIONS]

    pipelineguard --region eu-west-1 --output both --severity-threshold HIGH
"""

import sys

import click

from .core.checks.base import Severity
from .core.reporter import report_json, report_terminal
from .core.scanner import Scanner
from .core.scorer import score

_SEVERITY_CHOICES = [
    s.value
    for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
]


@click.command()
@click.option(
    "--region",
    default="us-east-1",
    show_default=True,
    help="AWS region to scan.",
)
@click.option(
    "--profile",
    default=None,
    help="AWS CLI named profile (defaults to the environment default).",
)
@click.option(
    "--output",
    type=click.Choice(["terminal", "json", "both"], case_sensitive=False),
    default="terminal",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--severity-threshold",
    type=click.Choice(_SEVERITY_CHOICES, case_sensitive=False),
    default="LOW",
    show_default=True,
    help="Minimum severity to display (e.g. HIGH shows only HIGH and CRITICAL).",
)
def scan(region: str, profile: str | None, output: str, severity_threshold: str) -> None:
    """PipelineGuard -- AWS CI/CD Security Posture Scanner.

    Analyses AWS-native CI/CD configurations and scores them against the
    OWASP Top 10 CI/CD Security Risks framework.
    """
    threshold = Severity(severity_threshold.upper())

    scanner = Scanner(region=region, profile=profile)

    try:
        findings = scanner.run()
    except Exception as exc:
        click.echo(f"[error] Scan failed: {exc}", err=True)
        sys.exit(2)

    score_result = score(findings)

    if output in ("terminal", "both"):
        report_terminal(findings, score_result, severity_threshold=threshold)

    if output in ("json", "both"):
        click.echo(report_json(findings, score_result))

    # Non-zero exit when the grade is D so CI pipelines can gate on the result.
    if score_result["grade"] == "D":
        sys.exit(1)
