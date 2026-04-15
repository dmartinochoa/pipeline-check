"""CLI entry point.

Usage
-----
    pipeline_check [OPTIONS]

Examples
--------
    # Scan a live AWS account (default provider).
    pipeline_check --pipeline aws --region eu-west-1 --output both --severity-threshold HIGH

    # Run specific checks only.
    pipeline_check --pipeline aws --checks CB-001 --checks CB-003

    # Scan a Terraform plan — no AWS credentials needed.
    pipeline_check --pipeline terraform --tf-plan plan.json

    # Scan GitHub Actions workflows on disk.
    pipeline_check --pipeline github --gha-path .github/workflows

    # Annotate findings with a single standard, or list registered standards.
    pipeline_check --standard owasp_cicd_top_10
    pipeline_check --list-standards

    # Print version and exit.
    pipeline_check --version

Exit codes
----------
    0   Grade A / B / C
    1   Grade D  (use as a CI gate)
    2   Scanner failure (e.g. AWS API error)

``--tf-plan`` and ``--gha-path`` are validated before the scanner runs:
missing flag or missing path raises a ``UsageError`` (exit code 2) with a
clear message, rather than failing deep in the provider.
"""
import os
import sys

import click

from . import __version__
from .core import providers as _providers
from .core import standards as _standards
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
@click.version_option(version=__version__, prog_name="pipeline_check")
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
    "--tf-plan",
    default=None,
    metavar="PATH",
    help=(
        "Path to the JSON output of `terraform show -json` "
        "(Terraform provider only; required when --pipeline terraform)."
    ),
)
@click.option(
    "--gha-path",
    default=None,
    metavar="PATH",
    help=(
        "Path to the GitHub Actions workflows directory, typically "
        "`.github/workflows` (required when --pipeline github)."
    ),
)
@click.option(
    "--gitlab-path",
    default=None,
    metavar="PATH",
    help=(
        "Path to a .gitlab-ci.yml file or a directory containing one "
        "(required when --pipeline gitlab)."
    ),
)
@click.option(
    "--bitbucket-path",
    default=None,
    metavar="PATH",
    help=(
        "Path to a bitbucket-pipelines.yml file or a directory containing "
        "one (required when --pipeline bitbucket)."
    ),
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
    "--standard",
    "standards",
    multiple=True,
    metavar="NAME",
    help=(
        "Annotate findings with controls from the named standard. Repeat to "
        "enable multiple (e.g. --standard owasp_cicd_top_10 --standard "
        "cis_aws_foundations). Omit to include every registered standard."
    ),
)
@click.option(
    "--list-standards",
    is_flag=True,
    help="List every registered compliance standard and exit.",
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
    tf_plan: str | None,
    gha_path: str | None,
    gitlab_path: str | None,
    bitbucket_path: str | None,
    output: str,
    output_file: str | None,
    standards: tuple[str, ...],
    list_standards: bool,
    severity_threshold: str,
) -> None:
    """PipelineCheck — CI/CD Security Posture Scanner.

    Analyses CI/CD configurations and scores them against the
    OWASP Top 10 CI/CD Security Risks framework.
    """
    if list_standards:
        for std in _standards.resolve():
            click.echo(f"{std.name}  —  {std.title} (v{std.version or 'n/a'})")
            if std.url:
                click.echo(f"    {std.url}")
        return

    pipeline_lc = pipeline.lower()
    if pipeline_lc == "terraform":
        if not tf_plan:
            raise click.UsageError(
                "--tf-plan PATH is required when --pipeline terraform."
            )
        if not os.path.isfile(tf_plan):
            raise click.UsageError(f"--tf-plan path not found: {tf_plan}")
    elif pipeline_lc == "github":
        if not gha_path:
            raise click.UsageError(
                "--gha-path PATH is required when --pipeline github."
            )
        if not os.path.isdir(gha_path):
            raise click.UsageError(f"--gha-path directory not found: {gha_path}")
    elif pipeline_lc == "gitlab":
        if not gitlab_path:
            raise click.UsageError(
                "--gitlab-path PATH is required when --pipeline gitlab."
            )
        if not os.path.exists(gitlab_path):
            raise click.UsageError(f"--gitlab-path not found: {gitlab_path}")
    elif pipeline_lc == "bitbucket":
        if not bitbucket_path:
            raise click.UsageError(
                "--bitbucket-path PATH is required when --pipeline bitbucket."
            )
        if not os.path.exists(bitbucket_path):
            raise click.UsageError(f"--bitbucket-path not found: {bitbucket_path}")

    threshold = Severity(severity_threshold.upper())

    scanner = Scanner(
        pipeline=pipeline,
        region=region,
        profile=profile,
        tf_plan=tf_plan,
        gha_path=gha_path,
        gitlab_path=gitlab_path,
        bitbucket_path=bitbucket_path,
    )

    try:
        findings = scanner.run(
            checks=list(checks) if checks else None,
            target=target,
            standards=list(standards) if standards else None,
        )
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
