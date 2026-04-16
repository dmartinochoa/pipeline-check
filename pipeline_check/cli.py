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
import re
import sys

import click

from . import __version__
from .core import autofix as _autofix
from .core import providers as _providers
from .core import standards as _standards
from .core.checks.base import Severity
from .core.config import load_config
from .core.gate import GateConfig, evaluate_gate, load_ignore_file
from .core.html_reporter import report_html
from .core.reporter import report_json, report_terminal
from .core.sarif_reporter import report_sarif
from .core.scanner import Scanner
from .core.scorer import score

# ────────────────────────────────────────────────────────────────────────────
# Shell completion helpers
# ────────────────────────────────────────────────────────────────────────────


def _complete_check_ids(ctx, param, incomplete):
    """Tab-complete check IDs (GHA-001, GL-002, CB-001, etc.)."""
    from click.shell_completion import CompletionItem
    try:
        ids = _all_check_ids()
    except Exception:
        return []
    return [
        CompletionItem(cid)
        for cid in ids
        if cid.lower().startswith(incomplete.lower())
    ]


def _complete_standards(ctx, param, incomplete):
    """Tab-complete standard names."""
    from click.shell_completion import CompletionItem
    try:
        names = _standards.available()
    except Exception:
        return []
    return [
        CompletionItem(n)
        for n in names
        if n.lower().startswith(incomplete.lower())
    ]


def _complete_man_topics(ctx, param, incomplete):
    """Tab-complete --man topic names."""
    from click.shell_completion import CompletionItem
    try:
        from .core.manual import topics
        names = topics()
    except Exception:
        return []
    return [
        CompletionItem(t)
        for t in names
        if t.lower().startswith(incomplete.lower())
    ]


_CHECK_IDS_CACHE: list[str] | None = None


def _all_check_ids() -> list[str]:
    """Collect every check ID from every provider's rules registry.

    Cached after the first call so repeated completions are fast.
    CI providers use the ``Rule`` registry; AWS and Terraform check
    IDs are extracted from source via regex since they use class-based
    checks without a ``Rule`` dataclass.
    """
    global _CHECK_IDS_CACHE
    if _CHECK_IDS_CACHE is not None:
        return _CHECK_IDS_CACHE
    ids: list[str] = []
    # CI providers — each has a rules/ package with RULE.id
    for pkg in (
        "pipeline_check.core.checks.github.rules",
        "pipeline_check.core.checks.gitlab.rules",
        "pipeline_check.core.checks.bitbucket.rules",
        "pipeline_check.core.checks.azure.rules",
        "pipeline_check.core.checks.jenkins.rules",
    ):
        try:
            from .core.checks.rule import discover_rules
            for rule, _ in discover_rules(pkg):
                ids.append(rule.id)
        except Exception:
            pass
    # AWS / Terraform — class-based checks with hardcoded check_id strings.
    _id_re = re.compile(r'check_id="([A-Z]+-\d+)"')
    for provider_pkg_name in (
        "pipeline_check.core.checks.aws",
        "pipeline_check.core.checks.terraform",
    ):
        try:
            import importlib
            import pkgutil
            pkg = importlib.import_module(provider_pkg_name)
            for info in pkgutil.iter_modules(pkg.__path__):
                mod = importlib.import_module(f"{provider_pkg_name}.{info.name}")
                if mod.__file__:
                    with open(mod.__file__, encoding="utf-8") as fh:
                        ids.extend(_id_re.findall(fh.read()))
        except Exception:
            pass
    ids = sorted(set(ids))
    _CHECK_IDS_CACHE = ids
    return ids


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


def _install_completion_callback(ctx, _param, value):
    """Print instructions or install completion for the given shell."""
    if not value:
        return
    shell = value
    if shell == "bash":
        line = 'eval "$(_PIPELINE_CHECK_COMPLETE=bash_source pipeline_check)"'
        rc = os.path.expanduser("~/.bashrc")
        marker = "# pipeline_check completion"
        try:
            existing = open(rc, encoding="utf-8").read() if os.path.exists(rc) else ""
        except OSError:
            existing = ""
        if marker in existing:
            click.echo(f"Completion already installed in {rc}")
        else:
            with open(rc, "a", encoding="utf-8") as f:
                f.write(f"\n{marker}\n{line}\n")
            click.echo(f"Completion installed in {rc}. Restart your shell or run:")
            click.echo(f"  source {rc}")
    elif shell == "zsh":
        line = 'eval "$(_PIPELINE_CHECK_COMPLETE=zsh_source pipeline_check)"'
        rc = os.path.expanduser("~/.zshrc")
        marker = "# pipeline_check completion"
        try:
            existing = open(rc, encoding="utf-8").read() if os.path.exists(rc) else ""
        except OSError:
            existing = ""
        if marker in existing:
            click.echo(f"Completion already installed in {rc}")
        else:
            with open(rc, "a", encoding="utf-8") as f:
                f.write(f"\n{marker}\n{line}\n")
            click.echo(f"Completion installed in {rc}. Restart your shell or run:")
            click.echo(f"  source {rc}")
    elif shell == "fish":
        comp_dir = os.path.expanduser("~/.config/fish/completions")
        os.makedirs(comp_dir, exist_ok=True)
        comp_file = os.path.join(comp_dir, "pipeline_check.fish")
        # Fish uses a generated script, not an eval.
        env = os.environ.copy()
        env["_PIPELINE_CHECK_COMPLETE"] = "fish_source"
        import subprocess
        result = subprocess.run(
            ["pipeline_check"], env=env,
            capture_output=True, text=True,
        )
        if result.stdout.strip():
            with open(comp_file, "w", encoding="utf-8") as f:
                f.write(result.stdout)
            click.echo(f"Completion installed to {comp_file}")
        else:
            click.echo(
                "Add this to ~/.config/fish/completions/pipeline_check.fish:\n"
                "  _PIPELINE_CHECK_COMPLETE=fish_source pipeline_check | source"
            )
    ctx.exit(0)


@click.command()
@click.version_option(version=__version__, prog_name="pipeline_check")
@click.option(
    "--install-completion",
    type=click.Choice(["bash", "zsh", "fish"]),
    default=None,
    is_eager=True,
    expose_value=False,
    callback=_install_completion_callback,
    help="Install shell completion for the given shell and exit.",
)
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
    shell_complete=_complete_check_ids,
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
    "--jenkinsfile-path",
    default=None,
    metavar="PATH",
    help=(
        "Path to a Jenkinsfile or a directory containing one "
        "(required when --pipeline jenkins). Auto-detects ./Jenkinsfile."
    ),
)
@click.option(
    "--circleci-path",
    default=None,
    metavar="PATH",
    help=(
        "Path to a CircleCI config.yml file or a directory containing one "
        "(required when --pipeline circleci). Auto-detects .circleci/config.yml."
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
    shell_complete=_complete_standards,
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
    "--man",
    "man_topic",
    is_flag=False,
    flag_value="index",
    default=None,
    metavar="[TOPIC]",
    shell_complete=_complete_man_topics,
    help=(
        "Print extended documentation for TOPIC and exit. Without "
        "TOPIC, prints the index of available topics. Topics: "
        "gate, autofix, diff, secrets, standards, config, output, "
        "lambda, recipes."
    ),
)
@click.option(
    "--standard-report",
    default=None,
    metavar="NAME",
    shell_complete=_complete_standards,
    help=(
        "Print the control → check matrix for the named standard and "
        "exit. Includes a 'gaps' section listing controls with no "
        "mapped checks — useful for auditing standard coverage."
    ),
)
@click.option(
    "--config-check",
    is_flag=True,
    help=(
        "Parse the config file, report any unknown keys, and exit. "
        "Exits non-zero when a dropped key is detected so CI can "
        "fail on typos. Use alongside --config PATH for explicit files."
    ),
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
    shell_complete=_complete_check_ids,
    help=(
        "Fail the gate if the named check fails. Repeat for multiple "
        "(e.g. --fail-on-check IAM-001 --fail-on-check CB-002)."
    ),
)
@click.option(
    "--secret-pattern",
    "secret_patterns",
    multiple=True,
    metavar="REGEX",
    help=(
        "Extra regex (Python syntax) for the secret-scanning checks "
        "(GHA-008, GL-008, BB-008, ADO-008) to match against every "
        "string token. Repeat for multiple. Anchor with ^...$ for "
        "whole-token match. Also configurable via "
        "`secret_patterns: [...]` in the config file."
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
    "--apply",
    "apply_fixes",
    is_flag=True,
    default=False,
    help=(
        "Apply autofixes in place instead of emitting a patch. Only "
        "meaningful with --fix. Prints an 'N files modified' summary "
        "to stderr."
    ),
)
@click.option(
    "--baseline-from-git",
    default=None,
    metavar="REF:PATH",
    help=(
        "Load the baseline JSON from a prior commit via "
        "`git show REF:PATH`. Mirrors --diff-base for the baseline "
        "workflow. Example: --baseline-from-git origin/main:baseline.json"
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
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    default=False,
    help=(
        "Emit additional [debug] messages to stderr showing provider "
        "resolution, check execution details, and gate configuration. "
        "Suppressed when --quiet is also set."
    ),
)
@click.option(
    "--quiet",
    "-q",
    is_flag=True,
    default=False,
    help=(
        "Suppress all terminal output. Only the exit code indicates "
        "pass (0) or fail (1). Useful for CI scripts that parse exit "
        "codes without needing human-readable output."
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
    jenkinsfile_path: str | None,
    circleci_path: str | None,
    output: str,
    output_file: str | None,
    standards: tuple[str, ...],
    list_standards: bool,
    man_topic: str | None,
    standard_report: str | None,
    config_check: bool,
    severity_threshold: str,
    fail_on: str | None,
    min_grade: str | None,
    max_failures: int | None,
    fail_on_checks: tuple[str, ...],
    secret_patterns: tuple[str, ...],
    fix: bool,
    apply_fixes: bool,
    baseline_from_git: str | None,
    diff_base: str | None,
    baseline: str | None,
    ignore_file: str | None,
    verbose: bool,
    quiet: bool,
) -> None:
    """PipelineCheck — CI/CD Security Posture Scanner.

    Analyses CI/CD configurations and scores them against the
    OWASP Top 10 CI/CD Security Risks framework.
    """
    # --quiet wins over --verbose.
    verbose = verbose and not quiet

    def _debug(msg: str) -> None:
        if verbose:
            click.echo(f"[debug] {msg}", err=True)

    if man_topic is not None:
        from .core import manual as _manual
        click.echo(_manual.render(man_topic), nl=False)
        return

    if list_standards:
        for std in _standards.resolve():
            click.echo(f"{std.name}  —  {std.title} (v{std.version or 'n/a'})")
            if std.url:
                click.echo(f"    {std.url}")
        return

    if standard_report:
        std = _standards.get(standard_report)
        if std is None:
            available = ", ".join(_standards.available())
            raise click.UsageError(
                f"Unknown standard {standard_report!r}. "
                f"Available: {available or 'none'}."
            )
        click.echo(f"{std.name}  —  {std.title} (v{std.version or 'n/a'})")
        if std.url:
            click.echo(f"  {std.url}")
        click.echo("")
        click.echo("Control → check mapping:")
        gaps: list[tuple[str, str]] = []
        for ctrl_id in sorted(std.controls):
            title = std.controls[ctrl_id]
            check_ids = [
                cid for cid, controls in std.mappings.items()
                if ctrl_id in controls
            ]
            if check_ids:
                joined = ", ".join(sorted(check_ids))
                click.echo(f"  [{ctrl_id}] {title}")
                click.echo(f"      checks: {joined}")
            else:
                gaps.append((ctrl_id, title))
        if gaps:
            click.echo("")
            click.echo(f"Gaps ({len(gaps)} control(s) with no mapped check):")
            for ctrl_id, title in gaps:
                click.echo(f"  [{ctrl_id}] {title}")
        return

    if config_check:
        from .core.config import last_unknown_keys
        dropped = last_unknown_keys()
        if not dropped:
            click.echo("[config] OK — no unknown keys.")
            return
        for source, key, reason in dropped:
            click.echo(f"[config] {source}: {key!r} — {reason}", err=True)
        click.echo(f"[config] {len(dropped)} unknown key(s) detected.", err=True)
        sys.exit(3)

    if apply_fixes and not fix:
        raise click.UsageError("--apply requires --fix.")

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
    elif pipeline_lc == "jenkins":
        if not jenkinsfile_path and os.path.isfile("Jenkinsfile"):
            jenkinsfile_path = "Jenkinsfile"
            click.echo(f"[auto] using --jenkinsfile-path {jenkinsfile_path}", err=True)
        if not jenkinsfile_path:
            raise click.UsageError(
                "--jenkinsfile-path PATH is required when --pipeline jenkins "
                "(no Jenkinsfile found in the current directory)."
            )
        if not os.path.exists(jenkinsfile_path):
            raise click.UsageError(f"--jenkinsfile-path not found: {jenkinsfile_path}")
    elif pipeline_lc == "circleci":
        if not circleci_path and os.path.isfile(".circleci/config.yml"):
            circleci_path = ".circleci/config.yml"
            click.echo(f"[auto] using --circleci-path {circleci_path}", err=True)
        if not circleci_path:
            raise click.UsageError(
                "--circleci-path PATH is required when --pipeline circleci "
                "(no .circleci/config.yml found in the current directory)."
            )
        if not os.path.exists(circleci_path):
            raise click.UsageError(f"--circleci-path not found: {circleci_path}")

    if output == "html" and not output_file:
        raise click.UsageError(
            "--output-file PATH is required when --output html."
        )

    for pat in secret_patterns:
        try:
            re.compile(pat)
        except re.error as exc:
            raise click.UsageError(
                f"--secret-pattern {pat!r} is not a valid regex: {exc}"
            ) from exc

    threshold = Severity(severity_threshold.upper())

    if not quiet:
        from .core.config import last_loaded_source as _config_source
        _cfg_src = _config_source()
        if _cfg_src:
            click.echo(f"[config] loaded {_cfg_src}", err=True)

    _debug(f"provider: {pipeline}")

    scanner = Scanner(
        pipeline=pipeline,
        region=region,
        profile=profile,
        diff_base=diff_base,
        secret_patterns=secret_patterns or None,
        log=_debug if verbose else None,
        tf_plan=tf_plan,
        gha_path=gha_path,
        gitlab_path=gitlab_path,
        bitbucket_path=bitbucket_path,
        azure_path=azure_path,
        jenkinsfile_path=jenkinsfile_path,
        circleci_path=circleci_path,
    )

    if verbose:
        meta = scanner.metadata
        if meta.files_scanned or meta.files_skipped:
            _debug(f"loaded {meta.files_scanned} file(s), {meta.files_skipped} skipped")
        _debug(f"checks to run: {len(scanner._check_classes)} check class(es)")

    try:
        findings = scanner.run(
            checks=list(checks) if checks else None,
            target=target,
            standards=list(standards) if standards else None,
        )
    except Exception as exc:
        # Print the traceback to stderr so operators have something to
        # take to support. Keep the single-line summary above it for
        # teams that grep logs for "[error] Scan failed".
        import traceback
        click.echo(f"[error] Scan failed: {exc}", err=True)
        click.echo(traceback.format_exc(), err=True, nl=False)
        sys.exit(2)

    if not quiet:
        _emit_scan_summary(scanner.metadata)

    n_passed = sum(1 for f in findings if f.passed)
    n_failed = sum(1 for f in findings if not f.passed)
    _debug(f"findings: {len(findings)} total ({n_failed} failed, {n_passed} passed)")

    score_result = score(findings)

    if not quiet:
        if output in ("terminal", "both"):
            # When emitting both terminal and JSON, send the human-readable report to
            # stderr so the JSON on stdout remains clean and machine-parseable.
            from rich.console import Console as _Console  # local import — only needed here
            console = _Console(stderr=(output == "both"))
            report_terminal(findings, score_result, severity_threshold=threshold, console=console)

        if output in ("json", "both"):
            click.echo(report_json(findings, score_result, tool_version=__version__))

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
            if apply_fixes:
                _apply_fix_patches(findings)
            else:
                # Route patches to stderr whenever stdout is carrying a machine-
                # readable report, so `--output json --fix` doesn't produce
                # "JSON...--- a/file" and break downstream parsers. The
                # documented `pipeline_check --fix | git apply` recipe uses the
                # default terminal output where stdout is free for the patch.
                _emit_fix_patches(findings, to_stderr=output != "terminal")

    # CI gate evaluation. See pipeline_check.core.gate for the full contract.
    ignore_path = ignore_file or ".pipelinecheckignore"
    baseline_git_pair: tuple[str, str] | None = None
    if baseline_from_git:
        if ":" not in baseline_from_git:
            raise click.UsageError(
                "--baseline-from-git expects REF:PATH (e.g. origin/main:baseline.json)"
            )
        ref_part, path_part = baseline_from_git.split(":", 1)
        baseline_git_pair = (ref_part, path_part)
    gate_config = GateConfig(
        fail_on=Severity(fail_on.upper()) if fail_on else None,
        min_grade=min_grade.upper() if min_grade else None,
        max_failures=max_failures,
        fail_on_checks={c.upper() for c in fail_on_checks},
        baseline_path=baseline,
        baseline_from_git=baseline_git_pair,
        ignore_rules=load_ignore_file(ignore_path),
    )

    if verbose:
        parts = []
        parts.append(f"fail-on={fail_on or 'CRITICAL (default)'}")
        if min_grade:
            parts.append(f"min-grade={min_grade}")
        if max_failures is not None:
            parts.append(f"max-failures={max_failures}")
        if baseline:
            parts.append(f"baseline={baseline}")
        elif baseline_from_git:
            parts.append(f"baseline-from-git={baseline_from_git}")
        _debug(f"gate config: {', '.join(parts)}")

    gate = evaluate_gate(findings, score_result, gate_config)

    if not quiet and output != "json":
        _emit_gate_summary(gate)

    if not gate.passed:
        sys.exit(1)


def _emit_fix_patches(findings, *, to_stderr: bool = False) -> None:
    """Emit one unified-diff patch per failing finding that has a fixer.

    Patches go to stdout by default so a user can pipe straight into
    ``git apply``. When a machine-readable report is already occupying
    stdout (``--output json/sarif/html/both``), the caller sets
    ``to_stderr=True`` to avoid corrupting that stream.

    File read errors are silently skipped — a missing file is almost
    always due to a finding with a synthetic resource name (e.g. an
    AWS check), not a real on-disk workflow. Per-path content is
    cached so multiple findings against the same file only re-read
    the source once.
    """
    import os
    cache: dict[str, str] = {}
    patch_count = 0
    patched_files: set[str] = set()
    for f in findings:
        if f.passed:
            continue
        path = f.resource
        if not path or not os.path.isfile(path):
            continue
        before = cache.get(path)
        if before is None:
            try:
                with open(path, encoding="utf-8") as fh:
                    before = fh.read()
            except (OSError, UnicodeDecodeError):
                continue
            cache[path] = before
        try:
            after = _autofix.generate_fix(f, before)
        except Exception as exc:
            # One broken fixer must not abort the whole --fix run. Log
            # to stderr so the bug is still visible to whoever is
            # debugging it.
            click.echo(
                f"[autofix] fixer for {f.check_id} raised {type(exc).__name__}: {exc}",
                err=True,
            )
            continue
        if after is None:
            continue
        patch_count += 1
        patched_files.add(path)
        click.echo(
            _autofix.render_patch(path, before, after),
            nl=False,
            err=to_stderr,
        )
    if patch_count:
        click.echo(
            f"[autofix] {patch_count} patch(es) for {len(patched_files)} file(s)."
            f" Run with --apply to modify in place.",
            err=True,
        )


def _apply_fix_patches(findings) -> None:
    """Apply autofixes in place; print an N-files-modified summary to stderr.

    Each fixer is idempotent, so it's safe to re-run after an apply —
    already-fixed files produce no further patch. Unfixable findings
    are silently skipped.
    """
    import os
    cache: dict[str, str] = {}
    dirty: dict[str, str] = {}  # path → final content
    for f in findings:
        if f.passed:
            continue
        path = f.resource
        if not path or not os.path.isfile(path):
            continue
        before = dirty.get(path) or cache.get(path)
        if before is None:
            try:
                with open(path, encoding="utf-8") as fh:
                    before = fh.read()
            except (OSError, UnicodeDecodeError):
                continue
            cache[path] = before
        try:
            after = _autofix.generate_fix(f, before)
        except Exception as exc:
            click.echo(
                f"[autofix] fixer for {f.check_id} raised {type(exc).__name__}: {exc}",
                err=True,
            )
            continue
        if after is None:
            continue
        dirty[path] = after
    for path, content in dirty.items():
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
        except OSError as exc:
            click.echo(f"[autofix] could not write {path}: {exc}", err=True)
    click.echo(f"[autofix] {len(dirty)} file(s) modified.", err=True)


def _emit_scan_summary(meta) -> None:
    """Render the scan summary line and any parse warnings to stderr."""
    from .core.scanner import ScanMetadata
    if not isinstance(meta, ScanMetadata):
        return
    for w in meta.warnings:
        click.echo(f"[warn] {w}", err=True)
    if meta.files_scanned == 0 and meta.files_skipped == 0:
        click.echo("[warn] no pipeline files found to scan", err=True)
        return
    skip_part = f" ({meta.files_skipped} skipped)" if meta.files_skipped else ""
    click.echo(
        f"[scan] {meta.provider}: scanned {meta.files_scanned} file(s){skip_part}"
        f" in {meta.elapsed_seconds:.1f}s",
        err=True,
    )


def _emit_gate_summary(gate) -> None:
    """Render the gate outcome to stderr so JSON/SARIF on stdout stays clean."""
    n_effective = len(gate.effective)
    if gate.passed:
        msg_lines = [f"[gate] PASS ({n_effective} effective finding(s) evaluated)"]
        for cond in getattr(gate, "conditions_evaluated", []):
            msg_lines.append(f"        - {cond}")
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
