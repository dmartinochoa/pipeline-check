"""CLI entry point.

Usage
-----
    pipeline_check [OPTIONS]

    pipeline_check --pipeline aws --region eu-west-1 --output both --severity-threshold HIGH
    pipeline_check --pipeline aws --checks CB-001 --checks CB-003
"""
import sys

import click

from .core import providers as _providers
from .core.checks.base import Severity
from .core.html_reporter import report_html
from .core.reporter import report_json, report_terminal
from .core.scanner import Scanner
from .core.scorer import score

_SEVERITY_CHOICES = [
    s.value
    for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
]

# Derived from the provider registry — no manual list to maintain.
# Registering a new provider in core/providers/__init__.py automatically
# makes it available here.
_PIPELINE_CHOICES = _providers.available()


@click.command()
@click.option(
    "--pipeline",
    type=click.Choice(_PIPELINE_CHOICES, case_sensitive=False),
    default="aws",
    show_default=True,
    help="Pipeline environment to scan.",
)
@click.option(
    "--target",
    default=None,
    metavar="NAME",
    help=(
        "Scope the scan to a specific resource (e.g. a CodePipeline pipeline name).  "
        "Omit to scan the entire region."
    ),
)
@click.option(
    "--checks",
    multiple=True,
    metavar="CHECK_ID",
    help=(
        "Run only the specified check ID(s).  Repeat to include multiple "
        "(e.g. --checks CB-001 --checks CB-003).  Omit to run all checks."
    ),
)
@click.option(
    "--region",
    default="us-east-1",
    show_default=True,
    help="Region to scan (AWS only).",
)
@click.option(
    "--profile",
    default=None,
    help="AWS CLI named profile (AWS only; defaults to the environment default).",
)
@click.option(
    "--output",
    type=click.Choice(["terminal", "json", "html", "both"], case_sensitive=False),
    default="terminal",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--output-file",
    default=None,
    metavar="PATH",
    help="Write HTML report to this file (used with --output html).",
)
@click.option(
    "--severity-threshold",
    type=click.Choice(_SEVERITY_CHOICES, case_sensitive=False),
    default="INFO",
    show_default=True,
    help="Minimum severity to display (e.g. HIGH shows only HIGH and CRITICAL).",
)
def scan(
    pipeline: str,
    target: str | None,
    checks: tuple[str, ...],
    region: str,
    profile: str | None,
    output: str,
    output_file: str | None,
    severity_threshold: str,
) -> None:
    """PipelineCheck — CI/CD Security Posture Scanner.

    Analyses CI/CD configurations and scores them against the
    OWASP Top 10 CI/CD Security Risks framework.
    """
    threshold = Severity(severity_threshold.upper())

    scanner = Scanner(pipeline=pipeline, region=region, profile=profile)

    try:
        findings = scanner.run(checks=list(checks) if checks else None, target=target)
    except Exception as exc:
        click.echo(f"[error] Scan failed: {exc}", err=True)
        sys.exit(2)

    score_result = score(findings)

    if output in ("terminal", "both"):
        # When emitting both terminal and JSON, send the human-readable report to
        # stderr so the JSON on stdout remains clean and machine-parseable.
        from rich.console import Console as _Console  # local import — only needed here
        console = _Console(stderr=(output == "both"))
        report_terminal(findings, score_result, severity_threshold=threshold, console=console)

    if output in ("json", "both"):
        click.echo(report_json(findings, score_result))

    if output == "html":
        dest = output_file or "pipeline-check-report.html"
        report_html(findings, score_result, region=region, target=target or "", output_path=dest)
        click.echo(f"HTML report written to {dest}", err=True)

    # Non-zero exit when the grade is D so CI pipelines can gate on the result.
    if score_result["grade"] == "D":
        sys.exit(1)
