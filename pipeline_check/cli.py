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

    # Scan CI YAML on disk — paths auto-detected from cwd when omitted.
    pipeline_check --pipeline github
    pipeline_check --pipeline gitlab
    pipeline_check --pipeline bitbucket

    # Annotate findings with a single standard, or list registered standards.
    pipeline_check --standard owasp_cicd_top_10
    pipeline_check --list-standards

    # Print version and exit.
    pipeline_check --version

Exit codes
----------
    0   Gate passed
    1   Gate failed (default gate: any CRITICAL finding in the effective set)
    2   Scanner failure (e.g. AWS API error)

Provider-path flags (``--tf-plan``, ``--gha-path``, ``--gitlab-path``,
``--bitbucket-path``) are validated eagerly; the latter three also
auto-detect their canonical file at cwd when omitted. Missing flag plus
missing canonical file raises a ``UsageError``.
"""
import os
import sys

import click

from . import __version__
from .core import providers as _providers
from .core import standards as _standards
from .core.checks.base import Severity
from .core import autofix as _autofix
from .core.config import load_config
from .core.gate import GateConfig, evaluate_gate, load_ignore_file
from .core.html_reporter import report_html
from .core.reporter import report_json, report_terminal
from .core.sarif_reporter import report_sarif
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


def _load_config_callback(ctx: click.Context, _param, value):
    """Eager callback — populates ``ctx.default_map`` so every other flag's
    default is pre-filled from the config file + environment.

    Precedence flows naturally from click here: ``default_map`` supplies
    defaults, CLI-provided values override them, and env/file values
    already live inside ``default_map`` with env winning over file (see
    :func:`pipeline_check.core.config.load_config`).
    """
    try:
        ctx.default_map = load_config(explicit_path=value)
    except FileNotFoundError as exc:
        raise click.UsageError(str(exc)) from exc
    return value


@click.command()
@click.version_option(version=__version__, prog_name="pipeline_check")
@click.option(
    "--config",
    default=None,
    metavar="PATH",
    is_eager=True,
    expose_value=False,
    callback=_load_config_callback,
    help=(
        "Path to a config file (TOML or YAML). Auto-discovers "
        ".pipeline-check.yml or the [tool.pipeline_check] section of "
        "pyproject.toml at cwd when not specified."
    ),
)
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
    "--azure-path",
    default=None,
    metavar="PATH",
    help=(
        "Path to an azure-pipelines.yml file or a directory containing one "
        "(required when --pipeline azure)."
    ),
)
@click.option(
    "--output",
    type=click.Choice(["terminal", "json", "html", "sarif", "both"], case_sensitive=False),
    default="terminal",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--output-file",
    default=None,
    metavar="PATH",
    help="Write HTML or SARIF report to this file (used with --output html/sarif).",
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
@click.option(
    "--fail-on",
    type=click.Choice(_SEVERITY_CHOICES, case_sensitive=False),
    default=None,
    help=(
        "Fail the CI gate if any effective finding's severity is ≥ this "
        "threshold (e.g. --fail-on HIGH fails on HIGH or CRITICAL)."
    ),
)
@click.option(
    "--min-grade",
    type=click.Choice(["A", "B", "C", "D"], case_sensitive=False),
    default=None,
    help="Fail the gate if the overall grade is worse than this (A is best).",
)
@click.option(
    "--max-failures",
    type=int,
    default=None,
    metavar="N",
    help="Fail the gate if more than N effective failing findings are present.",
)
@click.option(
    "--fail-on-check",
    "fail_on_checks",
    multiple=True,
    metavar="CHECK_ID",
    help=(
        "Fail the gate if the named check fails. Repeat for multiple "
        "(e.g. --fail-on-check IAM-001 --fail-on-check CB-002)."
    ),
)
@click.option(
    "--fix",
    is_flag=True,
    default=False,
    help=(
        "Emit a unified-diff patch to stdout for every failing finding "
        "that has a registered autofix. Does not modify files — pipe "
        "the output into `git apply` to apply. Currently supports: "
        + ", ".join(_autofix.available_fixers()) + "."
    ),
)
@click.option(
    "--diff-base",
    default=None,
    metavar="REF",
    help=(
        "Scan only workflow/pipeline files changed since this git ref "
        "(e.g. `origin/main`). Uses `git diff --name-only <ref>...HEAD`; "
        "falls back to a full scan if git is unavailable. Ignored for "
        "AWS / Terraform providers."
    ),
)
@click.option(
    "--baseline",
    default=None,
    metavar="PATH",
    help=(
        "Path to a prior --output json report. Findings already failing in "
        "the baseline are excluded from gate evaluation (but still reported)."
    ),
)
@click.option(
    "--ignore-file",
    default=None,
    metavar="PATH",
    help=(
        "Path to an ignore file (one CHECK_ID or CHECK_ID:RESOURCE per line). "
        "Defaults to .pipelinecheckignore when present in the working dir."
    ),
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
    azure_path: str | None,
    output: str,
    output_file: str | None,
    standards: tuple[str, ...],
    list_standards: bool,
    severity_threshold: str,
    fail_on: str | None,
    min_grade: str | None,
    max_failures: int | None,
    fail_on_checks: tuple[str, ...],
    fix: bool,
    diff_base: str | None,
    baseline: str | None,
    ignore_file: str | None,
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
        if not gha_path and os.path.isdir(".github/workflows"):
            gha_path = ".github/workflows"
            click.echo(f"[auto] using --gha-path {gha_path}", err=True)
        if not gha_path:
            raise click.UsageError(
                "--gha-path PATH is required when --pipeline github "
                "(no .github/workflows found in the current directory)."
            )
        if not os.path.isdir(gha_path):
            raise click.UsageError(f"--gha-path directory not found: {gha_path}")
    elif pipeline_lc == "gitlab":
        if not gitlab_path and os.path.isfile(".gitlab-ci.yml"):
            gitlab_path = ".gitlab-ci.yml"
            click.echo(f"[auto] using --gitlab-path {gitlab_path}", err=True)
        if not gitlab_path:
            raise click.UsageError(
                "--gitlab-path PATH is required when --pipeline gitlab "
                "(no .gitlab-ci.yml found in the current directory)."
            )
        if not os.path.exists(gitlab_path):
            raise click.UsageError(f"--gitlab-path not found: {gitlab_path}")
    elif pipeline_lc == "bitbucket":
        if not bitbucket_path and os.path.isfile("bitbucket-pipelines.yml"):
            bitbucket_path = "bitbucket-pipelines.yml"
            click.echo(f"[auto] using --bitbucket-path {bitbucket_path}", err=True)
        if not bitbucket_path:
            raise click.UsageError(
                "--bitbucket-path PATH is required when --pipeline bitbucket "
                "(no bitbucket-pipelines.yml found in the current directory)."
            )
        if not os.path.exists(bitbucket_path):
            raise click.UsageError(f"--bitbucket-path not found: {bitbucket_path}")
    elif pipeline_lc == "azure":
        if not azure_path and os.path.isfile("azure-pipelines.yml"):
            azure_path = "azure-pipelines.yml"
            click.echo(f"[auto] using --azure-path {azure_path}", err=True)
        if not azure_path:
            raise click.UsageError(
                "--azure-path PATH is required when --pipeline azure "
                "(no azure-pipelines.yml found in the current directory)."
            )
        if not os.path.exists(azure_path):
            raise click.UsageError(f"--azure-path not found: {azure_path}")

    if output == "html" and not output_file:
        raise click.UsageError(
            "--output-file PATH is required when --output html."
        )

    threshold = Severity(severity_threshold.upper())

    scanner = Scanner(
        pipeline=pipeline,
        region=region,
        profile=profile,
        diff_base=diff_base,
        tf_plan=tf_plan,
        gha_path=gha_path,
        gitlab_path=gitlab_path,
        bitbucket_path=bitbucket_path,
        azure_path=azure_path,
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
        report_html(findings, score_result, region=region, target=target or "", output_path=output_file)
        click.echo(f"HTML report written to {output_file}", err=True)

    if output == "sarif":
        sarif_text = report_sarif(findings, score_result, tool_version=__version__)
        if output_file:
            with open(output_file, "w", encoding="utf-8") as fh:
                fh.write(sarif_text)
            click.echo(f"SARIF report written to {output_file}", err=True)
        else:
            click.echo(sarif_text)

    if fix:
        _emit_fix_patches(findings)

    # CI gate evaluation. See pipeline_check.core.gate for the full contract.
    ignore_path = ignore_file or ".pipelinecheckignore"
    gate_config = GateConfig(
        fail_on=Severity(fail_on.upper()) if fail_on else None,
        min_grade=min_grade.upper() if min_grade else None,
        max_failures=max_failures,
        fail_on_checks={c.upper() for c in fail_on_checks},
        baseline_path=baseline,
        ignore_rules=load_ignore_file(ignore_path),
    )
    gate = evaluate_gate(findings, score_result, gate_config)

    if output != "json" and (
        gate.reasons or gate.baseline_matched or gate.suppressed or gate.expired_rules
    ):
        _emit_gate_summary(gate)

    if not gate.passed:
        sys.exit(1)


def _emit_fix_patches(findings) -> None:
    """Emit one unified-diff patch per failing finding that has a fixer.

    Output goes to stdout so a user can ``pipeline_check --fix | git
    apply``. File read errors are silently skipped — a missing file is
    almost always due to a finding with a synthetic resource name
    (e.g. an AWS check), not a real on-disk workflow.
    """
    import os
    for f in findings:
        if f.passed:
            continue
        path = f.resource
        if not path or not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as fh:
                before = fh.read()
        except (OSError, UnicodeDecodeError):
            continue
        after = _autofix.generate_fix(f, before)
        if after is None:
            continue
        click.echo(_autofix.render_patch(path, before, after), nl=False)


def _emit_gate_summary(gate) -> None:
    """Render the gate outcome to stderr so JSON/SARIF on stdout stays clean."""
    if gate.passed:
        msg_lines = ["[gate] PASS"]
    else:
        msg_lines = ["[gate] FAIL"]
        for reason in gate.reasons:
            msg_lines.append(f"        - {reason}")
    if gate.baseline_matched:
        msg_lines.append(
            f"[gate] {len(gate.baseline_matched)} finding(s) suppressed by baseline"
        )
    if gate.suppressed:
        msg_lines.append(
            f"[gate] {len(gate.suppressed)} finding(s) suppressed by ignore file"
        )
    if gate.expired_rules:
        for r in gate.expired_rules:
            scope = f":{r.resource}" if r.resource else ""
            msg_lines.append(
                f"[gate] ignore rule expired on {r.expires}: "
                f"{r.check_id}{scope} (no longer suppressing)"
            )
    for line in msg_lines:
        click.echo(line, err=True)
