"""CLI entry point.

Usage
-----
    pipeline_check [OPTIONS]
    pipeline_check init [--path PATH] [--force]

Examples
--------
    # Auto-detect every supported provider in cwd and scan each.
    # Single match = single-provider scan; multiple matches = automatic
    # multi-provider run with cross-provider chain correlation.
    pipeline_check

    # Scaffold a starter config file pre-filled from cwd.
    pipeline_check init

    # Short flags work for the most-typed options.
    pipeline_check -p github -o json -c GHA-001 -f HIGH

    # Scan a live AWS account.
    pipeline_check --pipeline aws --region eu-west-1 --output both --severity-threshold HIGH

    # Run specific checks only.
    pipeline_check --pipeline aws --checks CB-001 --checks CB-003

    # Scan a Terraform plan, no AWS credentials needed.
    pipeline_check --pipeline terraform --tf-plan plan.json
    pipeline_check --pipeline terraform --tf-source ./infra/  # direct HCL

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
from collections.abc import Callable
from typing import Any

import click

from . import __version__
from .cli_aux_commands import (
    explain_cmd,
    fp_stats_cmd,
    history_cmd,
    verify_artifact_cmd,
)
from .cli_completion import (
    _complete_check_ids,
    _complete_man_topics,
    _complete_standards,
    _known_attacked_check_ids,
)
from .cli_hints import (
    _maybe_emit_degraded_scan_warning,
    _maybe_emit_npm_alongside_github_hint,
    _maybe_emit_wrong_provider_hint,
)
from .cli_info_commands import (
    _eager_print_explain_chain,
    _eager_print_list_chains,
    _eager_print_standard_report,
    _list_checks_for_pipeline,
)
from .cli_ops_commands import (
    fix_pr_cmd,
    fleet_cmd,
    init_cmd,
)
from .cli_paths import ProviderPathArgs, _resolve_provider_paths

# Re-export for the test suite (it imports this from ``cli``); ``cli``
# itself only reaches it through ``_emit_gate_summary``, so the redundant
# alias marks an intentional re-export and keeps it past ruff's F401 sweep.
from .cli_scan_output import _build_gate_trailer as _build_gate_trailer
from .cli_scan_output import (
    _emit_gate_summary,
    _emit_scan_summary,
    _scan_incomplete_reason,
    _scan_status,
)

# Re-exported for the test suite, which reaches ``_autofix`` /
# ``_detect_pipeline_from_cwd`` through the ``cli`` namespace
# (``test_cli_fix`` patches ``cli._autofix``; ``test_cli_ease_of_use``
# imports ``cli._detect_pipeline_from_cwd``). The init/fleet/fix-pr split
# moved their only in-module users into ``cli_ops_commands``, so the
# trailing per-line ignores mark the intentional re-export past ruff.
from .core import autofix as _autofix  # noqa: F401
from .core import providers as _providers
from .core import standards as _standards
from .core.checks.base import Confidence, Severity, confidence_rank
from .core.config import load_config
from .core.detect import (
    detect_all_pipelines_from_cwd as _detect_all_pipelines_from_cwd,
)
from .core.detect import (
    detect_pipeline_from_cwd as _detect_pipeline_from_cwd,  # noqa: F401
)
from .core.fix_apply import (
    apply_fix_patches as _apply_fix_patches,
)
from .core.fix_apply import (
    emit_fix_patches as _emit_fix_patches,
)
from .core.gate import (
    GateConfig,
    evaluate_gate,
    load_ignore_file,
    parse_expiry_window,
)
from .core.inline_ignore import (
    InlineIgnoreIndex,
    InlineIgnoreRule,
    build_inline_index,
    extract_inline_ignores,
)
from .core.policies import (
    PolicyError,
    builtin_policies,
    discover_policies,
    load_policy,
    policy_to_config_map,
)
from .core.reporter import (
    next_steps_tip,
    report_chains_terminal,
    report_inventory_terminal,
    report_json,
    report_terminal,
)
from .core.scanner import MultiScanner, Scanner
from .core.scorer import score


def _tolerate_unencodable_stdio() -> None:
    """Make stdout/stderr tolerate non-ASCII characters on legacy consoles.

    Two related Windows problems this fixes:

    1. ``UnicodeEncodeError`` on help text. Windows' default ``cmd.exe``
       uses cp1252 for stdout. When click or our own code emits help
       text containing characters cp1252 can't encode (box-drawing,
       arrow, ``>=``), Python raises ``UnicodeEncodeError`` and the
       program dies before printing anything useful. Reconfiguring
       with ``errors='replace'`` degrades un-encodable characters to
       ``?`` instead of crashing.

    2. cp1252 bytes when stdout is redirected. On Windows, when stdout
       is redirected to a file or pipe (CI logs, ``> report.json``,
       piping into a UTF-8 consumer), Python opens it with the system
       locale encoding (cp1252) rather than the terminal's. Rich's
       rendering of ``·`` (U+00B7) and ``…`` (U+2026) lands as raw cp1252
       bytes, which mojibake every UTF-8 consumer downstream. When we
       detect a redirected (non-TTY) stream we force the encoding to
       UTF-8 so the bytes downstream tools see match the bytes a Linux
       runner would produce. TTY streams keep the system encoding so
       the interactive console renders correctly.

    Runs at import time so it takes effect before click's argument-
    parsing emits help text on --help.
    """
    for stream in (sys.stdout, sys.stderr):
        # ``reconfigure`` is only present on ``io.TextIOWrapper``, which
        # is the type sys.stdout/stderr carry when not redirected.
        # When they're redirected (a pipe, a captured fixture in tests)
        # they may be a plain TextIO without ``reconfigure``, caught
        # by the AttributeError below.
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        # Force UTF-8 on Windows when the stream isn't a TTY (i.e. it's
        # been redirected). Leaving the system locale would write cp1252
        # bytes that downstream UTF-8 consumers reject. On non-Windows
        # the default is already UTF-8, so we skip the override there.
        is_tty = getattr(stream, "isatty", lambda: False)()
        try:
            if sys.platform == "win32" and not is_tty:
                reconfigure(encoding="utf-8", errors="replace")
            else:
                reconfigure(errors="replace")
        except OSError:
            # Stream rejects the reconfigure (e.g. detached). Non-fatal:
            # the worst case is the original crash on cp1252, which only
            # affects Windows default console.
            pass


# NOTE: ``_tolerate_unencodable_stdio()`` runs from ``main()`` below,
# not at import time. MCP / LSP callers import this module to access
# the Scanner / Finding / chain helpers but never enter ``main()``
# (their stdio is JSON-RPC, not human-readable text); deferring keeps
# their streams untouched.


class _GroupedCommand(click.Command):
    """Click command that renders ``--help`` options under named sections.

    Keeps option declarations unchanged, the section→flag mapping lives
    here so adding an option only forces a mapping edit when the author
    wants it in a specific section. Unmapped options fall into
    ``Other`` so nothing silently vanishes from help.
    """

    _SECTIONS: tuple[tuple[str, frozenset[str]], ...] = (
        ("Target", frozenset({
            "--pipeline", "--target", "--region", "--profile",
            "--subscription-id", "--azure-tenant-id", "--gcp-project",
            "--tf-plan", "--tf-source", "--gha-path", "--gitlab-path",
            "--bitbucket-path", "--azure-path", "--jenkinsfile-path",
            "--circleci-path", "--cfn-template", "--cloudbuild-path",
            "--dockerfile-path", "--k8s-path", "--helm-path",
            "--buildkite-path", "--tekton-path", "--argo-path",
            "--argocd-path",
            "--helm-values", "--helm-set", "--oci-manifest",
            "--drone-path", "--harness-path", "--npm-path", "--pypi-path",
            "--maven-path", "--nuget-path", "--gomod-path",
            "--cargo-path", "--pulumi-path", "--composer-path",
            "--rubygems-path", "--devenv-path", "--modelfile-path",
            "--gitea-path", "--pipelines",
            "--scm-platform", "--scm-repo", "--scm-org",
            "--scm-include", "--scm-exclude", "--scm-max-repos",
            "--scm-fixture-dir",
            "--gh-token", "--gitlab-token", "--gitlab-url",
            "--resolve-remote", "--gha-search-path", "--gha-resolve-depth",
            "--npm-base-ref", "--audit-runs-logs", "--no-cache",
        })),
        ("Filtering", frozenset({
            "--checks", "--severity-threshold", "--min-confidence",
            "--no-best-practice", "--only-known-attacked",
            "--secret-pattern", "--detect-entropy", "--custom-rules",
            "--rego-rules",
            "--verify-secrets", "--verify-secrets-show-identity",
            "--annotate-fp", "--fp-file",
        })),
        ("Output", frozenset({
            "--output", "--output-file", "--standard",
            "--inventory", "--inventory-type", "--inventory-only",
            "--show-passed", "--show-controls", "--no-group",
            "--inline-explain", "--ingest",
            "--triage", "--triage-endpoint", "--triage-model",
        })),
        ("Gate", frozenset({
            "--fail-on", "--min-grade", "--max-failures",
            "--fail-on-check", "--fail-on-parse-error",
            "--baseline", "--baseline-from-git",
            "--write-baseline", "--vex",
            "--diff-base", "--pr-diff", "--ignore-file", "--no-inline-ignore",
            "--fail-on-chain", "--fail-on-any-chain",
            "--warn-expiring-suppressions",
        })),
        ("Attack chains", frozenset({
            "--no-chains", "--list-chains", "--explain-chain",
            "--chains-require-dataflow", "--chains-require-reachability",
        })),
        ("Autofix", frozenset({"--fix", "--apply", "--list-fixers", "--safety"})),
        ("Info & Help", frozenset({
            "--list-checks", "--list-standards", "--standard-report",
            "--list-verifiers",
            "--explain", "--man", "--config-check", "--config-strict",
            "--install-completion", "--config", "--version",
            "--policy", "--list-policies", "--serve",
            "--help", "--verbose", "--quiet",
        })),
        ("AI augmentation (opt-in)", frozenset({
            "--ai-explain", "--ai-model", "--ai-context-file",
        })),
    )

    def format_options(
        self, ctx: click.Context, formatter: click.HelpFormatter,
    ) -> None:
        bucketed: dict[str, list[tuple[str, str]]] = {}
        section_order = [name for name, _ in self._SECTIONS] + ["Other"]
        for param in self.get_params(ctx):
            record = param.get_help_record(ctx)
            if record is None:
                continue
            opts = list(getattr(param, "opts", []))
            opts.extend(getattr(param, "secondary_opts", []))
            section = "Other"
            for name, flags in self._SECTIONS:
                if any(o in flags for o in opts):
                    section = name
                    break
            bucketed.setdefault(section, []).append(record)
        for name in section_order:
            rows = bucketed.get(name)
            if not rows:
                continue
            with formatter.section(name):
                formatter.write_dl(rows)


class _FuzzyChoice(click.Choice[str]):
    """Click Choice that appends 'Did you mean: X?' on a bad value.

    Mirrors the suggestion style used by ``--explain`` for unknown check
    IDs (see ``core/explain.py``). Case-insensitive match is up to the
    base class via ``case_sensitive=False``.
    """

    def convert(
        self,
        value: Any,
        param: click.Parameter | None,
        ctx: click.Context | None,
    ) -> Any:
        try:
            return super().convert(value, param, ctx)
        except click.exceptions.BadParameter:
            import difflib
            suggestions = difflib.get_close_matches(
                str(value).lower(),
                [c.lower() for c in self.choices],
                n=3,
            )
            hint = (
                f" Did you mean: {', '.join(suggestions)}?"
                if suggestions else ""
            )
            self.fail(
                f"{value!r} is not one of {', '.join(self.choices)}.{hint}",
                param,
                ctx,
            )


# ────────────────────────────────────────────────────────────────────────────
# Report emission helper
# ────────────────────────────────────────────────────────────────────────────


def _emit_report(
    text: str, output_file: str | None, label: str, *, quiet: bool,
) -> None:
    """Write *text* to *output_file* or stdout; log destination to stderr.

    Every text-shaped reporter (JSON, SARIF, JUnit, markdown, codequality,
    cyclonedx, spdx, threatmodel) shares the same write-or-stdout-or-quiet
    cascade. Centralizing it here turns each output branch into one line
    so adding a new format only edits the dispatch site.
    """
    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as exc:
            # A directory path, a missing parent dir, or a read-only
            # destination should be a clean usage error, not a traceback.
            raise click.UsageError(
                f"could not write {label} to {output_file}: {exc}"
            ) from exc
        if not quiet:
            click.echo(f"{label} written to {output_file}", err=True)
    elif not quiet:
        click.echo(text)




# ── Inline ignore collection ─────────────────────────────────────────────

#: Maps provider names to (glob_patterns, base_path_kwarg). When a
#: provider is active, the glob patterns are expanded relative to the
#: provider's resolved path (or cwd) to find files that may carry
#: inline ``# pipeline-check: ignore[...]`` comments.
_INLINE_IGNORE_GLOBS: dict[str, tuple[str, ...]] = {
    "github": ("*.yml", "*.yaml"),
    "gitea": ("*.yml", "*.yaml"),
    "gitlab": ("*.yml", "*.yaml"),
    "bitbucket": ("*.yml", "*.yaml"),
    "azure": ("*.yml", "*.yaml"),
    "circleci": ("*.yml", "*.yaml"),
    "cloudbuild": ("*.yml", "*.yaml"),
    "buildkite": ("*.yml", "*.yaml"),
    "drone": ("*.yml", "*.yaml"),
    "harness": ("*.yml", "*.yaml"),
    "tekton": ("*.yml", "*.yaml"),
    "argo": ("*.yml", "*.yaml"),
    "argocd": ("*.yml", "*.yaml"),
    "kubernetes": ("*.yml", "*.yaml"),
    "helm": ("*.yml", "*.yaml"),
    "dockerfile": ("Dockerfile", "Containerfile", "*.Dockerfile"),
    "jenkins": ("Jenkinsfile",),
    "terraform": ("*.tf",),
    "cloudformation": ("*.yml", "*.yaml", "*.json"),
    "npm": ("package.json", "package-lock.json", ".npmrc"),
    "pypi": ("requirements*.txt", "*.in", "pyproject.toml"),
    "maven": ("pom.xml", "settings.xml"),
    "nuget": ("*.csproj", "NuGet.config"),
}

#: Maps provider names to the kwarg name used for the provider path.
_PROVIDER_PATH_KWARG: dict[str, str] = {
    "github": "gha_path",
    "gitea": "gitea_path",
    "gitlab": "gitlab_path",
    "bitbucket": "bitbucket_path",
    "azure": "azure_path",
    "jenkins": "jenkinsfile_path",
    "circleci": "circleci_path",
    "cloudbuild": "cloudbuild_path",
    "buildkite": "buildkite_path",
    "drone": "drone_path",
    "harness": "harness_path",
    "tekton": "tekton_path",
    "argo": "argo_path",
    "argocd": "argocd_path",
    "cloudformation": "cfn_template",
    "dockerfile": "dockerfile_path",
    "modelfile": "modelfile_path",
    "kubernetes": "k8s_path",
    "helm": "helm_path",
    "terraform": "tf_source",
    "npm": "npm_path",
    "pypi": "pypi_path",
    "maven": "maven_path",
    "nuget": "nuget_path",
    "gomod": "gomod_path",
    "cargo": "cargo_path",
    "composer": "composer_path",
    "rubygems": "rubygems_path",
    "pulumi": "pulumi_path",
    "devenv": "devenv_path",
}


def _collect_inline_ignores(
    pipelines: list[str],
    path_kwargs: dict[str, str | None],
) -> InlineIgnoreIndex:
    """Walk scanned files and extract inline ignore comments."""
    import glob as _glob

    all_rules: list[InlineIgnoreRule] = []
    for provider in pipelines:
        globs = _INLINE_IGNORE_GLOBS.get(provider)
        if not globs:
            continue
        kwarg_name = _PROVIDER_PATH_KWARG.get(provider)
        base = (path_kwargs.get(kwarg_name) if kwarg_name else None) or "."
        if not os.path.isdir(base):
            if os.path.isfile(base):
                base = os.path.dirname(base) or "."
            else:
                continue
        for pattern in globs:
            for filepath in _glob.glob(os.path.join(base, pattern)):
                if not os.path.isfile(filepath):
                    continue
                try:
                    with open(filepath, encoding="utf-8") as _fh:
                        text = _fh.read()
                except (OSError, UnicodeDecodeError):
                    # Skip unreadable or non-UTF-8 files rather than
                    # aborting the whole scan over one stray byte.
                    continue
                try:
                    rel = os.path.relpath(filepath).replace("\\", "/")
                except ValueError:
                    rel = filepath.replace("\\", "/")
                all_rules.extend(extract_inline_ignores(rel, text))
    return build_inline_index(all_rules)


_SEVERITY_CHOICES = [
    s.value
    for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
]

# Derived from the provider registry, no manual list to maintain.
# Registering a new provider in core/providers/__init__.py automatically
# makes it available here. ``auto`` is a CLI-only sentinel that picks
# a provider by looking at cwd; it is resolved before Scanner runs.
_PIPELINE_CHOICES = ["auto", *_providers.available()]


def _load_policy_callback(
    ctx: click.Context, _param: click.Parameter, value: str | None,
) -> str | None:
    """Resolve ``--policy NAME`` and prepend its values to ``default_map``.

    Policy values sit one rung below the config file in the precedence
    stack: they fill in option defaults, but the config file, env vars,
    and explicit CLI flags all override them. This callback is declared
    above ``--config`` so click processes it first; the config callback
    then merges its own values on top.

    Per-rule severity overrides aren't a CLI option, so they're stashed
    on ``ctx.meta`` instead and merged with the config-file overrides
    inside the scan body.
    """
    if not value:
        return value
    try:
        policy = load_policy(value)
    except PolicyError as exc:
        raise click.UsageError(f"--policy: {exc}") from exc
    base = dict(ctx.default_map or {})
    base.update(policy_to_config_map(policy))
    ctx.default_map = base
    # Stash the loaded policy so the scan body can: (a) merge per-rule
    # overrides with the config-file overrides, and (b) print a
    # ``[policy] loaded …`` line for parity with ``[config] loaded …``.
    ctx.meta["pipeline_check.policy"] = policy
    return value


def _list_policies_callback(
    ctx: click.Context, _param: click.Parameter, value: bool,
) -> None:
    """Print every discoverable policy and exit. Eager, no scan runs."""
    if not value:
        return
    local = discover_policies()
    # Built-in packs always exist; a local policy of the same name
    # shadows the built-in (matching ``load_policy`` resolution order).
    local_names = {p.name for p in local}
    builtins = [p for p in builtin_policies() if p.name not in local_names]
    policies = local + builtins
    name_w = max(len(p.name) for p in policies)
    for p in policies:
        suffix = f"  -- {p.description}" if p.description else ""
        click.echo(f"{p.name:<{name_w}}  ({p.source}){suffix}")
    ctx.exit(0)


def _load_config_callback(
    ctx: click.Context, _param: click.Parameter, value: str | None,
) -> str | None:
    """Eager callback, populates ``ctx.default_map`` so every other flag's
    default is pre-filled from the config file + environment.

    Precedence flows naturally from click here: ``default_map`` supplies
    defaults, CLI-provided values override them, and env/file values
    already live inside ``default_map`` with env winning over file (see
    :func:`pipeline_check.core.config.load_config`).

    A ``--policy NAME`` callback may have populated ``ctx.default_map``
    already; merging here preserves those values for keys the config
    file / env don't touch, so policies act as a baseline.
    """
    try:
        config_map = load_config(explicit_path=value)
    except FileNotFoundError as exc:
        raise click.UsageError(str(exc)) from exc
    if ctx.default_map:
        merged = {**ctx.default_map, **config_map}
        ctx.default_map = merged
    else:
        ctx.default_map = config_map
    return value


def _install_completion_callback(
    ctx: click.Context, _param: click.Parameter, value: str | None,
) -> None:
    """Print instructions or install completion for the given shell."""
    if not value:
        return
    shell = value
    if shell == "bash":
        line = 'eval "$(_PIPELINE_CHECK_COMPLETE=bash_source pipeline_check)"'
        rc = os.path.expanduser("~/.bashrc")
        marker = "# pipeline_check completion"
        existing = ""
        try:
            if os.path.exists(rc):
                with open(rc, encoding="utf-8") as _fh:
                    existing = _fh.read()
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
        existing = ""
        try:
            if os.path.exists(rc):
                with open(rc, encoding="utf-8") as _fh:
                    existing = _fh.read()
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


@click.command(cls=_GroupedCommand, epilog=(
    "Subcommands:\n"
    "  init      Scaffold a starter .pipeline-check.yml in the current directory.\n"
    "  fix-pr    Apply autofixes and open a pull / merge request.\n"
    "  explain   Print the full reference for one check (severity, fix, controls).\n"
    "  history   Render an HTML dashboard from past scan outputs.\n"
    "  fleet     Scan many repos and emit a unified posture digest.\n"
    "  fp-stats  Print false-positive annotation totals."
))
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
    "--policy",
    "policy_name",
    default=None,
    metavar="NAME",
    is_eager=True,
    expose_value=False,
    callback=_load_policy_callback,
    help=(
        "Load a named scan profile from ./policies/<NAME>.yml or "
        "./.pipeline-check/policies/<NAME>.yml, or one of the built-in "
        "packs (pr-gate, release-gate, slsa-l3, pci-dss, "
        "supply-chain-strict) shipped with the tool. A local policy of "
        "the same name shadows the built-in. Policies bundle a rule "
        "filter, standards filter, gate thresholds, and per-rule "
        "severity overrides. Values become click defaults: explicit CLI "
        "flags, env vars, and the config file override them. Run "
        "--list-policies to see what's available. A NAME with a path "
        "separator is treated as a literal path; an https:// URL fetches "
        "a shareable policy pack (cached for offline reuse). A remote "
        "policy can only configure the gate, never run code, but it can "
        "weaken the gate, so its source is printed when it loads."
    ),
)
@click.option(
    "--list-policies",
    is_flag=True,
    default=False,
    is_eager=True,
    expose_value=False,
    callback=_list_policies_callback,
    help=(
        "List every policy YAML file discoverable under ./policies/ "
        "or ./.pipeline-check/policies/ and exit. No scan is performed."
    ),
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
    "-p",
    type=_FuzzyChoice(_PIPELINE_CHOICES, case_sensitive=False),
    default="auto",
    show_default=True,
    help=(
        "Pipeline environment to scan. One of: "
        + ", ".join(_PIPELINE_CHOICES)
        + ". ``auto`` (default) walks cwd for recognized CI files "
        "(``.github/workflows``, ``.gitlab-ci.yml``, ``Jenkinsfile``, "
        "``Dockerfile``, ``Chart.yaml``, etc.). One match runs a "
        "single-provider scan; two or more matches automatically "
        "switch to multi-provider mode (equivalent to ``--pipelines "
        "X,Y,Z``) so cross-provider attack chains (``XPC-NNN``) fire. "
        "OCI is not auto-detected because ``index.json`` is too "
        "generic; pass ``--pipeline oci`` or ``--pipelines github,oci`` "
        "explicitly. Falls back to ``aws`` when nothing matches. "
        "Each provider has a companion path flag "
        "(--tf-plan, --tf-source, --cfn-template, --gha-path, --gitlab-path, "
        "--bitbucket-path, --azure-path, --jenkinsfile-path, "
        "--circleci-path, --cloudbuild-path, --dockerfile-path, "
        "--k8s-path, --helm-path, --buildkite-path, --tekton-path, "
        "--argo-path, --argocd-path, --oci-manifest, --drone-path, "
        "--harness-path, --npm-path, "
        "--pypi-path, --maven-path); "
        "AWS scans the live account via boto3. For multi-provider "
        "scans (so cross-provider attack chains like XPC-001 fire) "
        "use ``--pipelines github,oci`` instead."
    ),
)
@click.option(
    "--pipelines",
    "pipelines_csv",
    default="",
    metavar="LIST",
    help=(
        "Comma-separated list of providers to scan in one run "
        "(``--pipelines github,oci``). Mutually exclusive with "
        "``--pipeline``. Each name must be a registered provider "
        "(same vocabulary as ``--pipeline`` minus ``auto``). "
        "Findings from every provider are unified before the chain "
        "engine evaluates, which is what activates cross-provider "
        "attack chains (the ``XPC-NNN`` family). Each provider's "
        "input path is taken from the corresponding flag (``--gha-"
        "path``, ``--oci-manifest``, etc.) and auto-detection runs "
        "the same way it does for the single-provider flow."
    ),
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
    "-c",
    multiple=True,
    metavar="CHECK_ID",
    shell_complete=_complete_check_ids,
    help=(
        "Run only the specified check ID(s).  Repeat to include multiple "
        "(e.g. --checks CB-001 --checks CB-003).  Omit to run all checks."
    ),
)
@click.option(
    "--only-known-attacked",
    is_flag=True,
    default=False,
    help=(
        "Restrict the rule set to rules whose detection shape is "
        "anchored to a documented real-world incident, CVE, or "
        "vendor disclosure (Rule.incident_refs non-empty). Useful "
        "for burning down the incident-driven worklist on a fresh "
        "repo without the full pack noise. Composes with --checks: "
        "if both are set, the intersection runs."
    ),
)
@click.option(
    "--region",
    "-r",
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
    "--subscription-id",
    default=None,
    help="Azure subscription ID (azure_cloud only).",
)
@click.option(
    "--azure-tenant-id",
    default=None,
    help="Azure tenant ID override for multi-tenant scenarios (azure_cloud only).",
)
@click.option(
    "--gcp-project",
    default=None,
    help="GCP project ID (gcp only).",
)
@click.option(
    "--tf-plan",
    default=None,
    metavar="PATH",
    help=(
        "Path to the JSON output of `terraform show -json` "
        "(Terraform provider only; mutually exclusive with --tf-source)."
    ),
)
@click.option(
    "--tf-source",
    default=None,
    metavar="PATH",
    help=(
        "Path to a directory containing *.tf files. Parses HCL directly "
        "without requiring `terraform plan` (best-effort variable "
        "resolution). Requires `pip install pipeline-check[hcl]`. "
        "Mutually exclusive with --tf-plan."
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
    "--gitea-path",
    default=None,
    metavar="PATH",
    help=(
        "Path to the Gitea / Forgejo Actions workflows directory, "
        "typically `.gitea/workflows` or `.forgejo/workflows` "
        "(required when --pipeline gitea)."
    ),
)
@click.option(
    "--resolve-remote/--no-resolve-remote",
    "resolve_remote",
    default=False,
    show_default=True,
    help=(
        "Enable network-dependent resolution. GitHub Actions: follow "
        "reusable workflow and composite action refs to the called body. "
        "GitLab CI: fetch include: { project/remote/template/component } "
        "directives and merge them into the pipeline document. Also "
        "enables live advisory lookups (OSV, GHSA) and secret "
        "verification. Default off, the scanner stays read-from-disk-only "
        "by default."
    ),
)
@click.option(
    "--gh-token",
    "gh_token",
    default=None,
    metavar="TOKEN",
    help=(
        "GitHub token used by --resolve-remote when fetching from "
        "raw.githubusercontent.com. Falls back to $GITHUB_TOKEN. "
        "Only required for private callee repos."
    ),
)
@click.option(
    "--gitlab-token",
    "gitlab_token",
    default=None,
    metavar="TOKEN",
    help=(
        "GitLab token used by --resolve-remote when fetching "
        "include: { project/template/component } directives. "
        "Falls back to $GITLAB_TOKEN. Only required for private "
        "projects."
    ),
)
@click.option(
    "--gitlab-url",
    "gitlab_url",
    default="https://gitlab.com",
    show_default=True,
    metavar="URL",
    help=(
        "GitLab instance URL for API calls when resolving remote "
        "includes. Set to your self-hosted instance URL if not "
        "using gitlab.com."
    ),
)
@click.option(
    "--no-cache",
    "no_cache",
    is_flag=True,
    default=False,
    help=(
        "Bypass the on-disk resolver cache "
        "(~/.cache/pipeline-check/) for this scan. "
        "Useful when a tag was force-pushed to a different SHA "
        "and you want the new bytes."
    ),
)
@click.option(
    "--verify-secrets",
    "verify_secrets",
    is_flag=True,
    default=False,
    help=(
        "Probe every credential-shaped finding against its issuing "
        "API to determine whether the credential is currently active. "
        "Results: VERIFIED (active, promote to CRITICAL), UNVERIFIED "
        "(revoked/rotated, demote to LOW), or UNKNOWN (ambiguous). "
        "Requires --resolve-remote (no network calls without it)."
    ),
)
@click.option(
    "--verify-secrets-show-identity",
    "verify_secrets_show_identity",
    is_flag=True,
    default=False,
    help=(
        "Include the full identity string (e.g., GitHub login, NPM "
        "username) returned by verified credentials in the finding "
        "description. Off by default to avoid leaking identity info "
        "into CI logs."
    ),
)
@click.option(
    "--triage",
    "triage",
    is_flag=True,
    default=False,
    help=(
        "After the report, ask a LOCAL LLM (Ollama / llama.cpp / LM "
        "Studio) whether each failing finding is exploitable in this "
        "repo's context, labeling it confirmed / needs_review / "
        "likely_fp. Strictly advisory: it never changes severity, the "
        "grade, or the gate. Local endpoint only unless "
        "--triage-endpoint is given."
    ),
)
@click.option(
    "--triage-endpoint",
    "triage_endpoint",
    metavar="URL",
    default="http://localhost:11434/api/generate",
    show_default=True,
    help=(
        "Ollama-style /api/generate endpoint for --triage. A non-loopback "
        "URL prints a one-line warning before any finding is sent."
    ),
)
@click.option(
    "--triage-model",
    "triage_model",
    metavar="NAME",
    default="llama3.2",
    show_default=True,
    help="Model name passed to the --triage endpoint.",
)
@click.option(
    "--gha-search-path",
    "gha_search_paths",
    multiple=True,
    metavar="PATH",
    help=(
        "On-disk root searched before the network when --resolve-"
        "remote is on. Repeat for multiple roots. Each is laid out "
        "as ``<root>/<owner>/<repo>/<workflow-path>``. Lets monorepos "
        "with sibling checkouts resolve fully offline."
    ),
)
@click.option(
    "--gha-resolve-depth",
    "gha_resolve_depth",
    type=int,
    default=3,
    show_default=True,
    help=(
        "Maximum depth the resolver follows transitive ``uses:`` "
        "calls. Hard ceiling 10. Cycles are detected and stop "
        "earlier."
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
    "--cfn-template",
    default=None,
    metavar="PATH",
    help=(
        "Path to a CloudFormation template (YAML or JSON) or a directory "
        "containing one (required when --pipeline cloudformation). "
        "Auto-detects common names like template.yml, template.json, "
        "cloudformation.yml, cfn.yaml."
    ),
)
@click.option(
    "--cloudbuild-path",
    default=None,
    metavar="PATH",
    help=(
        "Path to a cloudbuild.yaml file or a directory containing one "
        "(required when --pipeline cloudbuild). Auto-detects "
        "./cloudbuild.yaml and ./cloudbuild.yml."
    ),
)
@click.option(
    "--dockerfile-path",
    default=None,
    metavar="PATH",
    help=(
        "Path to a Dockerfile / Containerfile or a directory containing "
        "one (required when --pipeline dockerfile). Auto-detects "
        "./Dockerfile and ./Containerfile."
    ),
)
@click.option(
    "--npm-path",
    default=None,
    metavar="PATH",
    help=(
        "Path to a package.json / package-lock.json or a directory "
        "containing one (required when --pipeline npm). Auto-detects "
        "./package.json and ./package-lock.json."
    ),
)
@click.option(
    "--npm-base-ref",
    "npm_base_ref",
    default=None,
    metavar="REF",
    help=(
        "Git ref (branch, tag, or SHA) to diff each loaded lockfile "
        "against. Enables NPM-009 (new-transitive-dependency diff "
        "gate). Resolves each lockfile's contents at REF via "
        "``git show REF:<relpath>`` and pairs the loaded current "
        "lockfile against the base. When a base lockfile can't be "
        "resolved (new file in this branch, ref missing, git "
        "unavailable) NPM-009 silent-passes for that lockfile."
    ),
)
@click.option(
    "--pypi-path",
    default=None,
    metavar="PATH",
    help=(
        "Path to a requirements.txt or a directory containing one "
        "(required when --pipeline pypi). Auto-detects "
        "./requirements.txt and ./requirements/*.txt."
    ),
)
@click.option(
    "--maven-path",
    default=None,
    metavar="PATH",
    help=(
        "Path to a pom.xml / settings.xml or a directory containing "
        "one (required when --pipeline maven). Auto-detects "
        "./pom.xml."
    ),
)
@click.option(
    "--nuget-path",
    default=None,
    metavar="PATH",
    help=(
        "Path to a directory containing *.csproj, NuGet.config, or "
        "packages.lock.json (required when --pipeline nuget)."
    ),
)
@click.option(
    "--gomod-path",
    default=None,
    metavar="PATH",
    help=(
        "Path to a go.mod file or a directory containing one "
        "(required when --pipeline gomod). Auto-detects ./go.mod."
    ),
)
@click.option(
    "--cargo-path",
    default=None,
    metavar="PATH",
    help=(
        "Path to a Cargo.toml file or a directory containing one "
        "(required when --pipeline cargo). Auto-detects "
        "./Cargo.toml."
    ),
)
@click.option(
    "--composer-path",
    default=None,
    metavar="PATH",
    help=(
        "Path to a composer.json file or a directory containing "
        "one (required when --pipeline composer). Auto-detects "
        "./composer.json."
    ),
)
@click.option(
    "--rubygems-path",
    default=None,
    metavar="PATH",
    help=(
        "Path to a Gemfile or a directory containing one "
        "(required when --pipeline rubygems). Auto-detects "
        "./Gemfile."
    ),
)
@click.option(
    "--pulumi-path",
    default=None,
    metavar="PATH",
    help=(
        "Path to a Pulumi.yaml file or a directory containing one "
        "(required when --pipeline pulumi). Auto-detects "
        "./Pulumi.yaml."
    ),
)
@click.option(
    "--devenv-path",
    default=None,
    metavar="PATH",
    help=(
        "Path to a repository root, or a .vscode/tasks.json / "
        "devcontainer.json / .claude/settings.json file (used when "
        "--pipeline devenv). Defaults to the current directory and "
        "discovers the editor / agent / container configs that "
        "auto-execute on repo open."
    ),
)
@click.option(
    "--modelfile-path",
    default=None,
    metavar="PATH",
    help=(
        "Path to an Ollama Modelfile or a directory containing one "
        "(used when --pipeline modelfile). Defaults to the current "
        "directory and discovers Modelfile / *.Modelfile declarations."
    ),
)
@click.option(
    "--k8s-path",
    default=None,
    metavar="PATH",
    help=(
        "Path to a Kubernetes manifest (YAML) or a directory containing "
        "one (required when --pipeline kubernetes). Auto-detects "
        "./kubernetes/, ./k8s/, ./manifests/."
    ),
)
@click.option(
    "--buildkite-path",
    default=None,
    metavar="PATH",
    help=(
        "Path to a Buildkite pipeline.yml file or a directory "
        "containing one (required when --pipeline buildkite). "
        "Auto-detects ./.buildkite/pipeline.yml."
    ),
)
@click.option(
    "--tekton-path",
    default=None,
    metavar="PATH",
    help=(
        "Path to a Tekton YAML file or a directory containing one "
        "(required when --pipeline tekton). Documents are filtered "
        "to ``apiVersion: tekton.dev/*`` so a directory mixing "
        "Tekton and plain Kubernetes manifests is safe to point at."
    ),
)
@click.option(
    "--argo-path",
    default=None,
    metavar="PATH",
    help=(
        "Path to an Argo Workflow YAML file or a directory "
        "containing one (required when --pipeline argo). Documents "
        "are filtered to ``apiVersion: argoproj.io/*``."
    ),
)
@click.option(
    "--argocd-path",
    default=None,
    metavar="PATH",
    help=(
        "Path to an Argo CD YAML file (Application / ApplicationSet "
        "/ AppProject, or the argocd-cm / argocd-rbac-cm "
        "ConfigMaps) or a directory containing one (required when "
        "--pipeline argocd). Documents that aren't Argo CD CRDs or "
        "named config ConfigMaps are silently skipped."
    ),
)
@click.option(
    "--helm-path",
    default=None,
    metavar="PATH",
    help=(
        "Path to a Helm chart directory (one containing Chart.yaml), a "
        "packaged .tgz chart, or a parent directory containing one or "
        "more charts (required when --pipeline helm). Auto-detects "
        "./Chart.yaml, ./charts/. Requires the 'helm' (Helm 3) binary "
        "on PATH."
    ),
)
@click.option(
    "--helm-values",
    "helm_values",
    multiple=True,
    metavar="FILE",
    help=(
        "Helm values file forwarded to ``helm template -f``. Repeat "
        "for multiple files; later files override earlier ones, "
        "matching helm's own precedence. Only meaningful with "
        "--pipeline helm."
    ),
)
@click.option(
    "--helm-set",
    "helm_set",
    multiple=True,
    metavar="KEY=VALUE",
    help=(
        "Helm value override forwarded to ``helm template --set``. "
        "Repeat for multiple overrides. Use the same syntax helm "
        "expects (``image.tag=v1`` or ``replicas=3``). Only "
        "meaningful with --pipeline helm."
    ),
)
@click.option(
    "--oci-manifest",
    "oci_manifest",
    default=None,
    metavar="PATH",
    help=(
        "Path to an OCI image manifest / image-index JSON file (the "
        "output of ``docker buildx imagetools inspect --raw <ref>`` "
        "or ``oras manifest fetch``), or a directory containing one "
        "(required when --pipeline oci). Pure parser, no registry "
        "pull, no daemon access. Auto-detects ./index.json."
    ),
)
@click.option(
    "--drone-path",
    "drone_path",
    default=None,
    metavar="PATH",
    help=(
        "Path to a Drone CI ``.drone.yml`` / ``.drone.yaml`` file "
        "or a directory containing one (required when --pipeline "
        "drone). Auto-detects ./.drone.yml or ./.drone.yaml."
    ),
)
@click.option(
    "--harness-path",
    "harness_path",
    default=None,
    metavar="PATH",
    help=(
        "Path to a Harness pipeline YAML file or a directory "
        "containing Harness pipelines (required when --pipeline "
        "harness). Auto-detects ./.harness/."
    ),
)
@click.option(
    "--scm-platform",
    "scm_platform",
    default=None,
    metavar="PLATFORM",
    help=(
        "SCM platform for the posture scanner (required when "
        "--pipeline scm). Supported: ``github`` (full rule pack), "
        "``gitlab`` and ``bitbucket`` (universal subset of seven "
        "rules: SCM-001/002/006/007/008/009/017)."
    ),
)
@click.option(
    "--scm-repo",
    "scm_repo",
    default=None,
    metavar="OWNER/NAME",
    help=(
        "Repository to scan (required when --pipeline scm), e.g. "
        "``--scm-repo octocat/hello-world``. Token comes from "
        "``--gh-token`` or ``$GITHUB_TOKEN``; without one only "
        "public-repo endpoints succeed (rate-limited to 60 req/hr)."
    ),
)
@click.option(
    "--scm-org",
    "scm_org",
    default=None,
    metavar="ORG",
    help=(
        "GitHub organization to audit. With --pipeline scm_org, audits the "
        "org-wide governance settings (2FA requirement, default member "
        "permission). With --pipeline scm (and no --scm-repo), fans the "
        "per-repo posture pack out across every non-archived repo in the "
        "org. E.g. ``--scm-org my-org``. Needs a token (``--gh-token`` / "
        "``$GITHUB_TOKEN``) with ``admin:org`` / ``read:org``."
    ),
)
@click.option(
    "--scm-include",
    "scm_include",
    multiple=True,
    metavar="GLOB",
    help=(
        "For the --scm-org fan-out: include only repos whose name matches "
        "this glob (repeatable, fnmatch syntax). Applied after enumeration."
    ),
)
@click.option(
    "--scm-exclude",
    "scm_exclude",
    multiple=True,
    metavar="GLOB",
    help=(
        "For the --scm-org fan-out: exclude repos whose name matches this "
        "glob (repeatable, fnmatch syntax). Applied after --scm-include."
    ),
)
@click.option(
    "--scm-max-repos",
    "scm_max_repos",
    type=int,
    default=0,
    show_default=True,
    metavar="N",
    help=(
        "For the --scm-org fan-out: cap the number of repos audited "
        "(0 = unlimited). A safety net for very large orgs; truncation is "
        "reported as a scan warning."
    ),
)
@click.option(
    "--scm-fixture-dir",
    "scm_fixture_dir",
    default=None,
    metavar="DIR",
    help=(
        "Read SCM API responses from JSON files under DIR instead of "
        "hitting the network. Each endpoint maps to "
        "``<endpoint-with-slashes-as-underscores>.json``. Useful for "
        "offline tests and CI runs that don't hold an API token."
    ),
)
@click.option(
    "--audit-runs-logs",
    "audit_runs_logs",
    is_flag=True,
    help=(
        "With ``--pipeline runs``: also download recent privileged-trigger "
        "run logs (the Actions ``.../logs`` archive) and scan them for "
        "leaked secrets (RUN-003). Heavier than the default metadata-only "
        "audit (one download per run, needs the ``actions:read`` scope)."
    ),
)
@click.option(
    "--ingest",
    "ingest_paths",
    multiple=True,
    metavar="PATH",
    help=(
        "Ingest a SARIF 2.1.0 file from another scanner (Trivy, "
        "Checkov, Snyk, KICS, …). Findings are merged into this "
        "scan's output before the chain engine runs, so the existing "
        "``XPC-NNN`` chains can fire on the union. Repeatable for "
        "multiple feeds. Ingested findings carry the synthesized "
        "check_id ``INGEST-<tool>-<rule_id>`` so they're "
        "distinguishable from native findings at a glance. Failures "
        "to parse a feed surface as warnings; the rest of the scan "
        "continues."
    ),
)
@click.option(
    "--inventory",
    "inventory_flag",
    is_flag=True,
    default=False,
    help=(
        "Emit a component inventory alongside findings. Lists every "
        "resource/workflow/template the scanner discovered, "
        "complements the findings view and feeds asset-register "
        "dashboards. Added to JSON output as an ``inventory`` top-level "
        "array; rendered as a table after the findings for terminal "
        "output."
    ),
)
@click.option(
    "--inventory-type",
    "inventory_types",
    multiple=True,
    metavar="PATTERN",
    help=(
        "Glob pattern to scope --inventory output by component type "
        "(e.g. ``AWS::IAM::*``, ``aws_iam_role``, ``workflow``). "
        "Repeat for multiple patterns, a component is kept when its "
        "type matches any of them. Implies --inventory."
    ),
)
@click.option(
    "--inventory-only",
    is_flag=True,
    default=False,
    help=(
        "Skip running checks entirely; emit only the component "
        "inventory. Useful when the scanner is driving an asset "
        "register and you don't need security findings on every "
        "run. Implies --inventory. Mutually exclusive with --fix, "
        "--diff-base, and --baseline (each is rejected with a usage "
        "error when combined). See ``--man inventory``."
    ),
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(
        [
            "terminal", "json", "jsonl", "html", "sarif", "junit",
            "markdown", "threatmodel", "cyclonedx", "spdx", "openvex",
            "codequality", "csv", "annotations", "both",
        ],
        case_sensitive=False,
    ),
    default="terminal",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--output-file",
    "-O",
    default=None,
    metavar="PATH",
    help=(
        "Write the report to this file. Required for --output html. "
        "Optional for --output json/sarif/junit/markdown/threatmodel/"
        "codequality (stdout is used if unset). Ignored for --output "
        "terminal and --output both (the latter always writes JSON to stdout)."
    ),
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
        "TOPIC, prints the index of available topics. Topics are "
        "generated from the manual registry; run ``--man`` with no "
        "argument for the current list. Unknown topic exits with code 3."
    ),
)
@click.option(
    "--standard-report",
    default=None,
    metavar="NAME",
    shell_complete=_complete_standards,
    help=(
        "Print the control -> check matrix for the named standard and "
        "exit. Includes a 'gaps' section listing controls with no "
        "mapped checks - useful for auditing standard coverage."
    ),
)
@click.option(
    "--list-checks",
    is_flag=True,
    default=False,
    help=(
        "List every check available for --pipeline (one per line: "
        "``ID  SEVERITY  TITLE``) and exit. Pipes well into ``grep`` "
        "for narrowing --checks patterns. No scan is performed."
    ),
)
@click.option(
    "--list-fixers",
    is_flag=True,
    default=False,
    help=(
        "List every check ID with a registered autofixer (one per "
        "line: ``ID  SEVERITY  TIER  TITLE``) and exit. Narrow the "
        "tier with ``--safety safe|unsafe|all``. Pipes well into "
        "``grep`` for a provider prefix. No scan is performed."
    ),
)
@click.option(
    "--safety",
    "fixer_safety_filter",
    type=click.Choice(["safe", "unsafe", "all"], case_sensitive=False),
    default="all",
    show_default=True,
    help=(
        "Filter ``--list-fixers`` by autofix tier: 'safe' (semantically "
        "equivalent or additive edits), 'unsafe' (inference-dependent), "
        "or 'all'. Only meaningful with ``--list-fixers``."
    ),
)
@click.option(
    "--list-verifiers",
    "list_verifiers",
    is_flag=True,
    default=False,
    help=(
        "List every secret detector that ``--verify-secrets`` can probe "
        "against its issuing API to confirm whether the credential is "
        "live (one per line: ``detector  shape``) and exit. No scan is "
        "performed."
    ),
)
@click.option(
    "--explain",
    "explain_id",
    default=None,
    metavar="CHECK_ID",
    shell_complete=_complete_check_ids,
    help=(
        "Print the full reference for one check (severity, confidence, "
        "compliance mappings, docs note, known FP modes, and how to "
        "fix it) and exit. Takes any ID from --list-checks. Exits 3 "
        "for an unknown ID and suggests near-matches."
    ),
)
@click.option(
    "--ai-explain",
    "ai_explain_id",
    default=None,
    metavar="CHECK_ID",
    shell_complete=_complete_check_ids,
    help=(
        "Augment ``--explain CHECK_ID`` with an AI-generated, project-"
        "specific remediation grounded in your README and (optionally) "
        "an offending file (``--ai-context-file PATH``). Opt-in. "
        "Bring your own key via ``ANTHROPIC_API_KEY`` / "
        "``OPENAI_API_KEY`` or run ``ollama serve`` locally. Output "
        "is clearly framed as ``[AI-generated, non-deterministic]`` "
        "and never affects the score / gate / SARIF output. Pick a "
        "provider with ``--ai-model anthropic`` / ``openai`` / "
        "``ollama`` (or a fully-qualified ``provider:model`` like "
        "``anthropic:claude-opus-4-7``)."
    ),
)
@click.option(
    "--ai-model",
    "ai_model_spec",
    default=None,
    metavar="SPEC",
    help=(
        "Provider for ``--ai-explain``. ``anthropic`` / ``openai`` / "
        "``ollama`` (default model) or ``provider:model`` (e.g. "
        "``anthropic:claude-opus-4-7``, ``ollama:llama3.2``). "
        "Falls back to ``$PIPELINE_CHECK_AI_MODEL`` and then to "
        "whichever provider has credentials in the environment."
    ),
)
@click.option(
    "--ai-context-file",
    "ai_context_file",
    default=None,
    type=click.Path(exists=True, dir_okay=False, readable=True),
    metavar="PATH",
    help=(
        "Optional file whose contents (first ~200 lines) get sent to "
        "the AI provider alongside the rule metadata so the response "
        "can be grounded in your actual code. Only used by "
        "``--ai-explain``."
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
    "--config-strict",
    is_flag=True,
    help=(
        "Promote an unknown config-file key from a warning to a hard "
        "error before scanning, so a typo like 'fail_on: HIGH' at the "
        "top level (instead of under 'gate:') fails fast instead of "
        "silently disabling the setting. Unlike --config-check, this "
        "runs the scan when the config is clean. (ruff --config-strict.)"
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
    "--min-confidence",
    type=click.Choice(["HIGH", "MEDIUM", "LOW"], case_sensitive=False),
    default="LOW",
    show_default=True,
    help=(
        "Minimum confidence to display and gate on. HIGH = only "
        "findings the scanner is certain about; MEDIUM = active-risk "
        "findings plus well-known heuristics, but drops the "
        "best-practice / missing-control hygiene family (no timeout, no "
        "SBOM, no signing, no vuln scan); LOW (default) = everything, "
        "including that hygiene family and the blob-search patterns that "
        "have FP modes. For a high-signal view focused on active risk, "
        "pass ``--min-confidence MEDIUM``."
    ),
)
@click.option(
    "--fail-on",
    "-f",
    type=click.Choice(_SEVERITY_CHOICES, case_sensitive=False),
    default=None,
    help=(
        "Fail the CI gate if any effective finding's severity is >= this "
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
    "--fail-on-parse-error",
    is_flag=True,
    help=(
        "Fail the gate if any file could not be parsed (malformed YAML / "
        "JSON, read error). A clean grade only reflects what was actually "
        "scanned, so this refuses a scan that silently skipped part of "
        "its input. Layers on top of the other gate conditions; see the "
        "JSON / SARIF ``scan_status`` for the count."
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
    "--detect-entropy",
    "detect_entropy",
    is_flag=True,
    default=False,
    help=(
        "Opt in to the Shannon-entropy secret detector. When enabled, "
        "the ``*-008`` literal-secret rules add an additional pass "
        "that flags high-entropy values (>= 3.5 bits/char, length "
        ">= 20) appearing in YAML key contexts that suggest a "
        "credential (``API_KEY``, ``apiToken``, ``password``, ...) "
        "and that the prefix-shape catalog hasn't already matched. "
        "Hits are labeled ``entropy:<redacted>``. Off by default "
        "because turning it on can introduce new findings on "
        "previously-clean scans, suppress per-resource via "
        "``--ignore-file`` once you've validated the heuristic."
    ),
)
@click.option(
    "--fix",
    is_flag=False,
    flag_value="safe",
    default=None,
    type=click.Choice(["safe", "unsafe", "unsafe-only"], case_sensitive=False),
    help=(
        "Emit patches for failing findings with registered autofixes. "
        "Tiers: 'safe' (default when bare --fix) runs only fixers that "
        "produce semantically equivalent edits; 'unsafe' runs all fixers "
        "(safe + inference-dependent); 'unsafe-only' runs only the "
        "inference-dependent fixers. Does not modify files; pipe the "
        "output into `git apply` or combine with --apply."
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
    "--pr-diff",
    "pr_diff",
    default=None,
    metavar="REF",
    help=(
        "Compare the current state of the worktree against REF and emit "
        "a Markdown PR-comment summarizing which findings the branch "
        "introduced, resolved, or preserved. Re-scans both sides: HEAD "
        "in-process, REF in a throwaway ``git worktree`` so no state "
        "from the parent leaks across. Fingerprint matches the existing "
        "``--baseline`` convention (``check_id`` + ``resource``), so "
        "line shifts on otherwise-unchanged code do not produce false "
        "'introduced' rows. Mutually exclusive with --inventory-only, "
        "--fix, --baseline*, and --diff-base (each carries a competing "
        "notion of 'what to compare'). Combine with ``--fail-on SEV`` "
        "to gate the PR on introduced findings only: the gate ignores "
        "preserved findings entirely. ``--output-file PATH`` writes "
        "the markdown to disk; without it, output goes to stdout."
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
    "--vex",
    "vex_paths",
    multiple=True,
    metavar="PATH",
    help=(
        "Path to an OpenVEX document (repeatable). An OSV advisory finding "
        "(NPM-010 / PYPI-009 / MVN-009 / NUGET-009) whose (vulnerability, "
        "product) a maintainer marked not_affected or fixed is excluded from "
        "gate evaluation (but still reported), the same baseline-style "
        "handling --baseline gets. Scoped to the advisory subset; a "
        "misconfiguration finding is never VEX-suppressed. Emit a matching "
        "document for the scan's own advisory findings with --output openvex."
    ),
)
@click.option(
    "--write-baseline",
    "write_baseline",
    default=None,
    metavar="PATH",
    help=(
        "After the scan completes, write the JSON-shaped findings list to "
        "PATH. Pair with --baseline on the next run to gate only on new "
        "issues. The output is the same shape --output json emits, so "
        "downstream tooling that already parses pipeline-check JSON works "
        "as-is. Does not interfere with --output (you can write a baseline "
        "and emit a different report in the same run)."
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
    "--no-inline-ignore",
    is_flag=True,
    default=False,
    help=(
        "Disable inline ``# pipeline-check: ignore[RULE-ID]`` comments. "
        "When set, only the ignore file (--ignore-file) suppresses findings."
    ),
)
@click.option(
    "--warn-expiring-suppressions",
    "warn_expiring_suppressions",
    default="14d",
    show_default=True,
    metavar="DAYS",
    help=(
        "Forewarn (stderr) when an ignore rule's ``expires`` date falls "
        "within this many days, so the team revisits it before the gate "
        "flips. Accepts '7' or '7d'; '0' or 'off' disables the "
        "forewarning. Already-expired rules are always reported."
    ),
)
@click.option(
    "--custom-rules",
    "custom_rules",
    multiple=True,
    metavar="PATH",
    help=(
        "YAML rule file (or directory of rule files) to load alongside "
        "the built-in catalog. Repeat for multiple paths. Loaded rules "
        "appear in findings, scoring, gating, --explain, and SARIF "
        "exactly like built-ins. See docs/writing_a_custom_rule.md for "
        "the rule-file shape and per-provider doc-tree reference."
    ),
)
@click.option(
    "--rego-rules",
    "rego_rules",
    multiple=True,
    metavar="PATH",
    help=(
        "Directory of OPA Rego policy files (.rego) to evaluate alongside "
        "the built-in catalog. Repeat for multiple paths. Requires the "
        "'opa' binary on PATH (https://openpolicyagent.org). Each .rego "
        "file must declare rule metadata via OPA METADATA annotations. "
        "See docs/writing_a_rego_rule.md for the policy convention."
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
@click.option(
    "--show-controls",
    is_flag=True,
    default=False,
    help=(
        "Include the full compliance-control mapping (OWASP, ESF, "
        "SLSA, SOC 2, NIST CSF, OpenSSF Scorecard, S2C2F, ...) in "
        "each finding's terminal panel. Off by default to keep the "
        "human-readable report scannable; controls are always present "
        "in JSON / SARIF outputs regardless of this flag."
    ),
)
@click.option(
    "--show-passed",
    is_flag=True,
    default=False,
    help=(
        "Include passed checks in the terminal table and the JSON "
        "report. Off by default so both focus on failures; the headline "
        "and the JSON ``score.summary`` block still carry the "
        "failed-vs-passed counts. SARIF is always failures-only "
        "(code-scanning semantics); JUnit always lists every check "
        "(test-report semantics), both regardless of this flag."
    ),
)
@click.option(
    "--no-group",
    "no_group",
    is_flag=True,
    default=False,
    help=(
        "Render every finding on its own row. By default the terminal "
        "table collapses repeated ``(check_id, resource)`` failures "
        "into one visible row plus a single ``+N similar finding(s)`` "
        "summary line so a rule that fires across many files doesn't "
        "drown the report. Grouping never affects JSON / SARIF / "
        "JUnit outputs, which always carry every finding."
    ),
)
@click.option(
    "--inline-explain",
    "inline_explain",
    is_flag=True,
    help=(
        "Surface the rule's ``exploit_example`` (when present) "
        "alongside each failing finding, saving the "
        "``pipeline_check --explain CHECK_ID`` round-trip. Honored by "
        "``terminal`` / ``both`` (under the panel), ``sarif`` (rule "
        "``help`` text), ``junit`` (``<failure>`` body), ``markdown`` "
        "(a collapsible Proof-of-exploit section), and ``codequality`` "
        "(issue ``description``). ``--output json`` and ``--output "
        "html`` always include ``exploit_example`` regardless of this "
        "flag."
    ),
)
@click.option(
    "--no-chains",
    is_flag=True,
    default=False,
    help=(
        "Disable attack-chain correlation. By default the scanner "
        "correlates findings into multi-step attack narratives mapped "
        "to MITRE ATT&CK (e.g. AC-001 fork-PR credential theft). "
        "Disable when a downstream consumer doesn't understand the "
        "``chains`` JSON field, or to shave a few ms off a CI hot path."
    ),
)
@click.option(
    "--no-best-practice",
    is_flag=True,
    default=False,
    help=(
        "Drop best-practice / missing-control findings (unbounded build "
        "/ no timeout, no SBOM, no artifact signing, no SLSA provenance, "
        "no vulnerability-scan step, ...). These are structurally true "
        "but fire on most pipelines regardless of the specific "
        "vulnerability under review, so they dominate the list as noise. "
        "Hiding them focuses the output and the gate on active-"
        "vulnerability findings. Severity and confidence are unchanged; "
        "this is purely an output filter."
    ),
)
@click.option(
    "--chains-require-reachability",
    "chains_require_reachability",
    is_flag=True,
    default=False,
    help=(
        "Drop attack chains whose legs co-occur on the same resource "
        "but have no confirmed dataflow connection between them. Only "
        "chains whose triggering findings share an anchor job (an "
        "executable path connects the source to the sink) survive. "
        "Strictest signal, lowest false-positive rate; pair with "
        "``--fail-on-any-chain`` (or a specific "
        "``--fail-on-chain AC-...``) for a high-confidence CI gate."
    ),
)
@click.option(
    "--chains-require-dataflow",
    "chains_require_dataflow",
    is_flag=True,
    default=False,
    help=(
        "Stricter than --chains-require-reachability: keep only chains "
        "confirmed by a real source-to-sink taint path (phase-2 "
        "dataflow reachability), dropping those confirmed by shared-job "
        "co-location alone. Highest-precision chain gate; pairs with "
        "``--fail-on-any-chain`` for a CI gate that fires only on a "
        "proven executable dataflow."
    ),
)
@click.option(
    "--list-chains",
    is_flag=True,
    default=False,
    help=(
        "List every registered attack chain (one per line: "
        "``ID  SEVERITY  TITLE``) and exit. No scan is performed."
    ),
)
@click.option(
    "--annotate-fp",
    "annotate_fp",
    nargs=2,
    default=None,
    metavar="CHECK_ID RESOURCE",
    help=(
        "Record a confirmed false positive into the local "
        "``.pipeline-check-fp.json`` annotation file and exit. "
        "Subsequent scans demote that ``(check_id, resource)`` "
        "pair's confidence one rung (HIGH -> MEDIUM, MEDIUM -> "
        "LOW), keeping the finding visible while letting "
        "``--min-confidence MEDIUM`` filter it out at the gate. "
        "Idempotent: re-running with the same args is a no-op. "
        "No scan is performed in this mode. Run "
        "``pipeline_check fp-stats`` to print rule -> vote "
        "totals."
    ),
)
@click.option(
    "--fp-file",
    "fp_path",
    default=None,
    metavar="PATH",
    help=(
        "Path to the false-positive annotation file. Defaults to "
        "``.pipeline-check-fp.json`` at cwd. Read on every scan to "
        "demote annotated findings; written by ``--annotate-fp``."
    ),
)
@click.option(
    "--serve",
    is_flag=True,
    default=False,
    help=(
        "Run pipeline-check as a Model Context Protocol (MCP) "
        "server on stdio. Lets MCP-aware AI clients (Claude "
        "Desktop, Claude Code, Cursor, Continue, Zed) introspect "
        "the rule catalog and run scans on demand. Requires the "
        "optional ``[mcp]`` extra: ``pip install "
        "'pipeline-check[mcp]'``. The process blocks until the "
        "client disconnects; no scan flags are honored in this "
        "mode (each scan is requested as an MCP tool call)."
    ),
)
@click.option(
    "--explain-chain",
    "explain_chain_id",
    default=None,
    metavar="CHAIN_ID",
    help=(
        "Print the full reference for one attack chain (summary, "
        "narrative template, MITRE ATT&CK techniques, kill-chain "
        "phase, references) and exit. Takes any ID from --list-chains."
    ),
)
@click.option(
    "--fail-on-chain",
    "fail_on_chain_ids",
    multiple=True,
    metavar="CHAIN_ID",
    help=(
        "Fail the gate if the named attack chain matched. Repeat for "
        "multiple (e.g. --fail-on-chain AC-001 --fail-on-chain AC-007). "
        "Chain matches bypass baseline/ignore filtering, a correlated "
        "attack path is intrinsically a new finding."
    ),
)
@click.option(
    "--fail-on-any-chain",
    is_flag=True,
    default=False,
    help=(
        "Fail the gate if any attack chain matched. Use as a blanket "
        "'no correlated attack paths in this branch' guard for "
        "high-trust repositories."
    ),
)
def scan(
    pipeline: str,
    pipelines_csv: str,
    target: str | None,
    checks: tuple[str, ...],
    only_known_attacked: bool,
    region: str,
    profile: str | None,
    subscription_id: str | None,
    azure_tenant_id: str | None,
    gcp_project: str | None,
    tf_plan: str | None,
    tf_source: str | None,
    gha_path: str | None,
    gitea_path: str | None,
    gitlab_path: str | None,
    bitbucket_path: str | None,
    azure_path: str | None,
    jenkinsfile_path: str | None,
    circleci_path: str | None,
    cfn_template: str | None,
    cloudbuild_path: str | None,
    buildkite_path: str | None,
    tekton_path: str | None,
    argo_path: str | None,
    argocd_path: str | None,
    dockerfile_path: str | None,
    k8s_path: str | None,
    helm_path: str | None,
    npm_path: str | None,
    npm_base_ref: str | None,
    pypi_path: str | None,
    maven_path: str | None,
    nuget_path: str | None,
    gomod_path: str | None,
    cargo_path: str | None,
    composer_path: str | None,
    rubygems_path: str | None,
    pulumi_path: str | None,
    devenv_path: str | None,
    modelfile_path: str | None,
    helm_values: tuple[str, ...],
    helm_set: tuple[str, ...],
    oci_manifest: str | None,
    drone_path: str | None,
    harness_path: str | None,
    scm_platform: str | None,
    scm_repo: str | None,
    scm_org: str | None,
    scm_include: tuple[str, ...],
    scm_exclude: tuple[str, ...],
    scm_max_repos: int,
    scm_fixture_dir: str | None,
    audit_runs_logs: bool,
    ingest_paths: tuple[str, ...],
    inventory_flag: bool,
    inventory_types: tuple[str, ...],
    inventory_only: bool,
    output: str,
    output_file: str | None,
    standards: tuple[str, ...],
    list_standards: bool,
    man_topic: str | None,
    standard_report: str | None,
    list_checks: bool,
    list_fixers: bool,
    fixer_safety_filter: str,
    list_verifiers: bool,
    explain_id: str | None,
    ai_explain_id: str | None,
    ai_model_spec: str | None,
    ai_context_file: str | None,
    config_check: bool,
    config_strict: bool,
    severity_threshold: str,
    min_confidence: str,
    fail_on: str | None,
    min_grade: str | None,
    max_failures: int | None,
    fail_on_checks: tuple[str, ...],
    fail_on_parse_error: bool,
    secret_patterns: tuple[str, ...],
    detect_entropy: bool,
    fix: str | None,
    apply_fixes: bool,
    baseline_from_git: str | None,
    diff_base: str | None,
    pr_diff: str | None,
    baseline: str | None,
    vex_paths: tuple[str, ...],
    write_baseline: str | None,
    ignore_file: str | None,
    no_inline_ignore: bool,
    warn_expiring_suppressions: str,
    custom_rules: tuple[str, ...],
    rego_rules: tuple[str, ...],
    verbose: bool,
    quiet: bool,
    show_controls: bool,
    show_passed: bool,
    no_group: bool,
    inline_explain: bool,
    no_chains: bool,
    no_best_practice: bool,
    chains_require_reachability: bool,
    chains_require_dataflow: bool,
    list_chains: bool,
    annotate_fp: tuple[str, str] | None,
    fp_path: str | None,
    explain_chain_id: str | None,
    fail_on_chain_ids: tuple[str, ...],
    fail_on_any_chain: bool,
    serve: bool = False,
    resolve_remote: bool = False,
    gh_token: str | None = None,
    gitlab_token: str | None = None,
    gitlab_url: str = "https://gitlab.com",
    no_cache: bool = False,
    verify_secrets: bool = False,
    verify_secrets_show_identity: bool = False,
    triage: bool = False,
    triage_endpoint: str = "http://localhost:11434/api/generate",
    triage_model: str = "llama3.2",
    gha_search_paths: tuple[str, ...] = (),
    gha_resolve_depth: int = 3,
) -> None:
    """Pipeline-Check. CI/CD Security Posture Scanner.

    Scores CI/CD configs against the OWASP Top 10 CI/CD Security Risks
    and 17 other compliance frameworks, then grades the result A-D.

    \b
    Getting started:
      pipeline_check                   scan the current repo (auto-detects providers)
      pipeline_check init              set up a CI gate + baseline, with next steps
      pipeline_check --policy pr-gate  block PRs on new HIGH+ findings
      pipeline_check explain GHA-001   understand one finding and how to fix it
      pipeline_check --man recipes     copy-paste recipes for common workflows

    Run --man for the full topic list; the flags below are grouped by task.
    """
    # --quiet wins over --verbose.
    verbose = verbose and not quiet

    # --verify-secrets requires --resolve-remote (no-network default).
    if verify_secrets and not resolve_remote:
        click.echo(
            "Error: --verify-secrets requires --resolve-remote "
            "(secret verification makes network calls).",
            err=True,
        )
        raise SystemExit(2)

    def _debug(msg: str) -> None:
        if verbose:
            click.echo(f"[debug] {msg}", err=True)

    if _run_informational_commands(
        man_topic=man_topic,
        list_standards=list_standards,
        serve=serve,
        list_checks=list_checks,
        list_fixers=list_fixers,
        fixer_safety_filter=fixer_safety_filter,
        list_verifiers=list_verifiers,
        annotate_fp=annotate_fp,
        fp_path=fp_path,
        list_chains=list_chains,
        explain_chain_id=explain_chain_id,
        explain_id=explain_id,
        ai_explain_id=ai_explain_id,
        ai_model_spec=ai_model_spec,
        ai_context_file=ai_context_file,
        standard_report=standard_report,
        config_check=config_check,
        pipeline=pipeline,
    ):
        return

    _validate_scan_flags_early(
        config_strict=config_strict,
        apply_fixes=apply_fixes,
        fix=fix,
        inventory_only=inventory_only,
        diff_base=diff_base,
        baseline=baseline,
        ingest_paths=ingest_paths,
    )

    # Parse --pipelines (multi-provider mode). Mutually exclusive
    # with the single-valued --pipeline flag, the user picks one or
    # the other, never both. When --pipelines is set, every provider
    # in the list runs in one scan and the chain engine evaluates
    # over the union of every sub-scan's findings, which is what
    # activates cross-provider attack chains (the XPC-NNN family).
    pipelines_list: list[str] = []
    if pipelines_csv:
        if pipeline.lower() != "auto":
            raise click.UsageError(
                "--pipelines is mutually exclusive with --pipeline; "
                "drop --pipeline (it defaults to ``auto`` and is "
                "ignored when --pipelines is set)."
            )
        seen: set[str] = set()
        for raw in pipelines_csv.split(","):
            name = raw.strip().lower()
            if not name or name in seen:
                continue
            seen.add(name)
            pipelines_list.append(name)
        if not pipelines_list:
            raise click.UsageError(
                "--pipelines parsed empty after splitting on commas."
            )
        valid = set(_providers.available())
        invalid = [p for p in pipelines_list if p not in valid]
        if invalid:
            raise click.UsageError(
                f"unknown provider(s) in --pipelines: "
                f"{', '.join(invalid)}. Valid: "
                f"{', '.join(sorted(valid))}"
            )

    pipeline_lc = pipeline.lower()
    if not pipelines_list and pipeline_lc == "auto":
        detected_all = _detect_all_pipelines_from_cwd()
        if len(detected_all) >= 2:
            # Multi-provider repo: route through MultiScanner so
            # cross-provider attack chains (XPC-NNN) fire on the
            # union of every sub-scan's findings. Each provider's
            # path flag is auto-detected by the per-provider
            # resolver below, the same way --pipelines does.
            pipelines_list = detected_all
            click.echo(
                "[auto] detected providers: "
                f"{', '.join(detected_all)} (running --pipelines "
                f"{','.join(detected_all)})",
                err=True,
            )
        elif detected_all:
            pipeline_lc = detected_all[0]
            click.echo(f"[auto] detected --pipeline {pipeline_lc}", err=True)
        else:
            # No CI files at cwd. Previously this silently fell through
            # to ``--pipeline aws``, which then degraded to "API access
            # failed" findings on machines without AWS credentials and
            # produced a misleading "Grade A / Score 100" headline (the
            # API-failure findings are INFO-severity so they don't
            # count toward the score). Refuse to scan instead, with a
            # concrete hint pointing at the explicit-AWS form for
            # users who actually wanted that path.
            raise click.UsageError(
                "no CI/CD config files detected at cwd. Pipeline-check "
                "looks for: .github/workflows/, .gitlab-ci.yml, "
                "Jenkinsfile, bitbucket-pipelines.yml, azure-pipelines.yml, "
                ".circleci/config.yml, cloudbuild.yaml, "
                ".buildkite/pipeline.yml, .drone.yml, tekton/, argo "
                "manifests, Dockerfile / Containerfile, Kubernetes "
                "manifests under k8s/ or kubernetes/, a Helm Chart.yaml, "
                "or an OCI image manifest. Pass --pipeline <name> to "
                "scan a specific provider, --<provider>-path to point "
                "at a non-standard location, or --pipeline aws (with "
                "AWS credentials configured) to scan a live AWS account."
            )

    # Per-provider path resolution. In single-pipeline mode the
    # if/elif chain below runs once for ``pipeline_lc``; in
    # multi-pipeline mode it runs once per provider so each
    # provider's path flag (--gha-path, --oci-manifest, etc.) is
    # resolved + auto-detected the same way as a single-pipeline
    # invocation.
    pipelines_to_resolve = pipelines_list or [pipeline_lc]
    _paths = _resolve_provider_paths(
        pipelines_to_resolve,
        ProviderPathArgs(
            tf_plan=tf_plan,
            tf_source=tf_source,
            gha_path=gha_path,
            gitea_path=gitea_path,
            gitlab_path=gitlab_path,
            bitbucket_path=bitbucket_path,
            azure_path=azure_path,
            jenkinsfile_path=jenkinsfile_path,
            circleci_path=circleci_path,
            cfn_template=cfn_template,
            cloudbuild_path=cloudbuild_path,
            buildkite_path=buildkite_path,
            tekton_path=tekton_path,
            argo_path=argo_path,
            argocd_path=argocd_path,
            dockerfile_path=dockerfile_path,
            k8s_path=k8s_path,
            helm_path=helm_path,
            oci_manifest=oci_manifest,
            drone_path=drone_path,
            harness_path=harness_path,
            npm_path=npm_path,
            pypi_path=pypi_path,
            maven_path=maven_path,
            nuget_path=nuget_path,
            gomod_path=gomod_path,
            cargo_path=cargo_path,
            composer_path=composer_path,
            rubygems_path=rubygems_path,
            pulumi_path=pulumi_path,
            helm_values=helm_values,
        ),
    )

    _validate_scan_inputs(
        output=output,
        output_file=output_file,
        secret_patterns=secret_patterns,
        custom_rules=custom_rules,
        rego_rules=rego_rules,
        diff_base=diff_base,
        pr_diff=pr_diff,
        inventory_only=inventory_only,
        fix=fix,
        baseline=baseline,
        baseline_from_git=baseline_from_git,
    )

    threshold = Severity(severity_threshold.upper())
    confidence_threshold = Confidence(min_confidence.upper())

    ctx = click.get_current_context()
    active_policy = ctx.meta.get("pipeline_check.policy")
    if not quiet:
        from .core.config import last_loaded_source as _config_source
        _cfg_src = _config_source()
        if _cfg_src:
            click.echo(f"[config] loaded {_cfg_src}", err=True)
        if active_policy is not None:
            click.echo(
                f"[policy] loaded {active_policy.name!r} from "
                f"{active_policy.source}",
                err=True,
            )

    from .core.config import last_overrides as _config_overrides
    cli_overrides = _config_overrides()
    if active_policy is not None and active_policy.overrides:
        # Config-file overrides win over policy overrides, mirroring how
        # the rest of the config layering treats policy values as
        # defaults. Merge per-rule so a policy can carry a default
        # severity while the config tightens individual entries.
        merged_overrides: dict[str, dict[str, str]] = {
            cid: dict(body) for cid, body in active_policy.overrides.items()
        }
        for cid, body in cli_overrides.items():
            merged_overrides.setdefault(cid, {}).update(body)
        cli_overrides = merged_overrides

    if pipelines_list:
        _debug(f"providers: {', '.join(pipelines_list)}")
    else:
        _debug(f"provider: {pipeline_lc}")

    # Shared kwargs forwarded to every (Multi)Scanner sub-scan.
    # Each provider's path flag is in here; the providers that
    # don't recognize a given flag silently ignore it.
    _scanner_kwargs: dict[str, Any] = dict(
        region=region,
        profile=profile,
        subscription_id=subscription_id,
        azure_tenant_id=azure_tenant_id,
        gcp_project=gcp_project,
        diff_base=diff_base,
        secret_patterns=secret_patterns or None,
        detect_entropy=detect_entropy,
        overrides=cli_overrides or None,
        custom_rules=list(custom_rules) or None,
        rego_rules=list(rego_rules) or None,
        fp_annotations_path=fp_path,
        log=_debug if verbose else None,
        tf_plan=_paths.tf_plan,
        tf_source=_paths.tf_source,
        gha_path=_paths.gha_path,
        gitea_path=_paths.gitea_path,
        gitlab_path=_paths.gitlab_path,
        bitbucket_path=_paths.bitbucket_path,
        azure_path=_paths.azure_path,
        jenkinsfile_path=_paths.jenkinsfile_path,
        circleci_path=_paths.circleci_path,
        cfn_template=_paths.cfn_template,
        cloudbuild_path=_paths.cloudbuild_path,
        buildkite_path=_paths.buildkite_path,
        tekton_path=_paths.tekton_path,
        argo_path=_paths.argo_path,
        argocd_path=_paths.argocd_path,
        resolve_remote=resolve_remote,
        gh_token=gh_token,
        gitlab_token=gitlab_token,
        gitlab_url=gitlab_url,
        no_cache=no_cache,
        verify_secrets=verify_secrets,
        verify_secrets_show_identity=verify_secrets_show_identity,
        gha_search_paths=list(gha_search_paths),
        gha_resolve_depth=gha_resolve_depth,
        dockerfile_path=_paths.dockerfile_path,
        k8s_path=_paths.k8s_path,
        helm_path=_paths.helm_path,
        helm_values=list(helm_values) or None,
        helm_set=list(helm_set) or None,
        oci_manifest=_paths.oci_manifest,
        drone_path=_paths.drone_path,
        harness_path=_paths.harness_path,
        npm_path=_paths.npm_path,
        npm_base_ref=npm_base_ref,
        pypi_path=_paths.pypi_path,
        maven_path=_paths.maven_path,
        nuget_path=_paths.nuget_path,
        gomod_path=_paths.gomod_path,
        cargo_path=_paths.cargo_path,
        composer_path=_paths.composer_path,
        rubygems_path=_paths.rubygems_path,
        pulumi_path=_paths.pulumi_path,
        devenv_path=devenv_path,
        modelfile_path=modelfile_path,
        scm_platform=scm_platform,
        scm_repo=scm_repo,
        scm_org=scm_org,
        scm_include=scm_include,
        scm_exclude=scm_exclude,
        scm_max_repos=scm_max_repos,
        scm_fixture_dir=scm_fixture_dir,
        audit_runs_logs=audit_runs_logs,
    )

    scanner: Scanner | MultiScanner
    # A provider's ``build_context()`` runs during Scanner construction
    # (it loads the target up front). Providers that need a flag the
    # path-resolver doesn't validate (``scm`` / ``runs``) raise
    # ``ValueError`` on a missing / malformed value, and the live-cloud
    # SDK providers (``gcp`` / ``azure_cloud``) raise ``ImportError`` when
    # their optional extra isn't installed. Catch both and surface the
    # provider's own (already user-friendly) message as a clean exit-2
    # error rather than a raw traceback. Narrowly scoped so a genuine bug
    # still surfaces its stack.
    try:
        if pipelines_list:
            # Multi-provider mode. Each sub-scanner's chain pass is
            # suppressed regardless; ``MultiScanner.run`` evaluates
            # chains once over the union (when ``chains_enabled=True``)
            # so cross-provider chains (XPC-NNN) fire. Single-provider
            # chains still match in that union pass, so AC-NNN coverage
            # carries through. ``--no-chains`` disables the union pass
            # too.
            scanner = MultiScanner(
                pipelines=pipelines_list,
                chains_enabled=not no_chains,
                **_scanner_kwargs,
            )
        else:
            scanner = Scanner(
                pipeline=pipeline_lc,
                chains_enabled=not no_chains,
                **_scanner_kwargs,
            )
    except (ValueError, ImportError) as exc:
        click.echo(f"Error: {exc}", err=True)
        raise click.exceptions.Exit(2) from exc

    if verbose:
        meta = scanner.metadata
        if meta.files_scanned or meta.files_skipped:
            _debug(f"loaded {meta.files_scanned} file(s), {meta.files_skipped} skipped")
        _debug(f"checks to run: {len(scanner._check_classes)} check class(es)")

    # ``--inventory-only``, ``--inventory-type``, and ``--output
    # threatmodel`` all imply ``--inventory``. Threat-model generation
    # populates its Assets and trust-boundary sections from the
    # inventory, so a run with ``--output threatmodel`` and no
    # explicit ``--inventory`` flag transparently turns it on.
    want_inventory = (
        inventory_flag
        or inventory_only
        or bool(inventory_types)
        or output == "threatmodel"
    )

    # ``--only-known-attacked`` narrows the rule set to rules whose
    # ``Rule.incident_refs`` is non-empty. If ``--checks`` is also
    # set, the intersection runs (rules that are BOTH explicitly
    # requested AND known-attacked).
    effective_checks: list[str] | None
    if only_known_attacked:
        known = set(_known_attacked_check_ids())
        if checks:
            effective_checks = sorted(set(checks) & known)
        else:
            effective_checks = sorted(known)
        if verbose:
            _debug(
                f"--only-known-attacked: {len(effective_checks)} "
                f"check(s) carry incident_refs"
            )
        if not effective_checks:
            click.echo(
                "[warn] --only-known-attacked filtered the rule set "
                "to zero checks; no findings will be produced.",
                err=True,
            )
    elif checks:
        effective_checks = list(checks)
    else:
        effective_checks = None

    findings: list[Any] = []
    if not inventory_only:
        try:
            findings = scanner.run(
                checks=effective_checks,
                target=target,
                standards=list(standards) if standards else None,
            )
        except Exception as exc:
            # Always print the one-line summary (teams grep logs for
            # "[error] Scan failed"). The full traceback is noise for an
            # operator unless they're filing a bug, so gate it behind
            # --verbose and otherwise point them at the flag.
            click.echo(f"[error] Scan failed: {exc}", err=True)
            if verbose:
                import traceback
                click.echo(traceback.format_exc(), err=True, nl=False)
            else:
                click.echo(
                    "[error] Re-run with --verbose for the full traceback.",
                    err=True,
                )
            raise click.exceptions.Exit(2) from exc

    # Stderr nudge: when secret-shaped findings were found but live
    # verification wasn't enabled, print a one-liner so the operator
    # knows the option exists.
    if not verify_secrets and not quiet:
        from .core.scanner import _SECRET_CHECK_IDS
        secret_hits = [
            f for f in findings
            if f.check_id in _SECRET_CHECK_IDS and not f.passed
        ]
        if secret_hits:
            click.echo(
                f"hint: {len(secret_hits)} credential-shaped finding(s) "
                f"found. Verify with --resolve-remote --verify-secrets",
                err=True,
            )

    # External SARIF ingest. ``--ingest`` (repeatable) loads each
    # SARIF file, converts every result to a Finding, and merges
    # the union into the scan output. The chain engine then
    # re-runs over the combined set so ``XPC-NNN`` chains can fire
    # on cross-tool compositions (e.g. an ingested Trivy finding +
    # a native pipeline-check finding). Failures to parse a feed
    # surface as warnings; the scan keeps going.
    if ingest_paths and not inventory_only:
        from .core import chains as _chains
        from .core.sarif_ingest import parse_sarif_file
        ingested_total = 0
        for sarif_path in ingest_paths:
            result = parse_sarif_file(sarif_path)
            for warning in result.warnings:
                click.echo(warning, err=True)
            findings.extend(result.findings)
            ingested_total += len(result.findings)
            if not quiet and result.findings:
                click.echo(
                    f"[ingest] {sarif_path}: loaded "
                    f"{len(result.findings)} finding(s) from "
                    f"{result.source or 'unknown tool'}"
                    + (f" {result.source_version}"
                       if result.source_version else ""),
                    err=True,
                )
        # Re-evaluate the chain engine over the union so XPC-NNN
        # rules can fire on cross-tool compositions. Only when at
        # least one ingested finding landed and chains haven't been
        # globally disabled — ``--no-chains`` is honored by leaving
        # the scanner's evaluated chain list untouched.
        if ingested_total > 0 and not no_chains:
            try:
                # Replace scanner.chains with the union evaluation so
                # downstream readers (terminal report, JSON, gate)
                # see chains over the merged findings list.
                scanner.chains = _chains.evaluate(findings)
            except Exception as exc:
                click.echo(
                    f"[ingest] chain re-evaluation failed: {exc}",
                    err=True,
                )

    if not quiet:
        _emit_scan_summary(scanner.metadata)
        _maybe_emit_wrong_provider_hint(pipeline_lc, findings)
        _maybe_emit_npm_alongside_github_hint(pipelines_to_resolve, findings)
        _maybe_emit_degraded_scan_warning(findings)

    # Confidence filter applies BEFORE scoring + gate so scores reflect
    # the trusted finding set. ``--min-confidence LOW`` (the default)
    # keeps everything; higher thresholds drop heuristic findings the
    # scanner is less certain about.
    pre_filter_count = len(findings)
    min_conf_rank = confidence_rank(confidence_threshold)
    findings = [
        f for f in findings if confidence_rank(f.confidence) >= min_conf_rank
    ]
    if verbose and pre_filter_count != len(findings):
        _debug(
            f"--min-confidence {confidence_threshold.value}: dropped "
            f"{pre_filter_count - len(findings)} finding(s)"
        )

    # Best-practice filter: drop missing-control hygiene findings (no
    # timeout / SBOM / signing / SLSA provenance / vuln-scan step) so the
    # output and the gate focus on active-vulnerability findings. Applied
    # before scoring + gate, like the confidence filter above.
    if no_best_practice:
        from .core.checks._best_practice import is_best_practice
        bp_before = len(findings)
        findings = [f for f in findings if not is_best_practice(f.check_id)]
        if verbose and bp_before != len(findings):
            _debug(
                f"--no-best-practice: dropped "
                f"{bp_before - len(findings)} best-practice finding(s)"
            )

    n_passed = sum(1 for f in findings if f.passed)
    n_failed = sum(1 for f in findings if not f.passed)
    _debug(f"findings: {len(findings)} total ({n_failed} failed, {n_passed} passed)")

    if pr_diff:
        # Diff mode owns the rest of the flow: the HEAD findings we
        # just produced become one half of the comparison; the BASE
        # side runs in a worktree subprocess. The normal output /
        # gate path is skipped; pr-diff has its own renderer and its
        # own gate semantics (gate on *introduced* findings only).
        from .core.pr_diff import any_at_or_above, run_pr_diff
        from .core.pr_diff_reporter import report_pr_diff

        forwarded_argv = _build_pr_diff_subprocess_argv(
            pipeline_lc=pipeline_lc,
            pipelines_list=pipelines_list,
            checks=checks,
            severity_threshold=severity_threshold,
            min_confidence=min_confidence,
            standards=standards,
            custom_rules=custom_rules,
            rego_rules=rego_rules,
            secret_patterns=secret_patterns,
            detect_entropy=detect_entropy,
            ignore_file=ignore_file,
            fp_path=fp_path,
            tf_plan=tf_plan,
            tf_source=tf_source,
            gha_path=gha_path,
            gitea_path=gitea_path,
            gitlab_path=gitlab_path,
            bitbucket_path=bitbucket_path,
            azure_path=azure_path,
            jenkinsfile_path=jenkinsfile_path,
            circleci_path=circleci_path,
            cfn_template=cfn_template,
            cloudbuild_path=cloudbuild_path,
            buildkite_path=buildkite_path,
            tekton_path=tekton_path,
            argo_path=argo_path,
            argocd_path=argocd_path,
            dockerfile_path=dockerfile_path,
            k8s_path=k8s_path,
            helm_path=helm_path,
            helm_values=helm_values,
            helm_set=helm_set,
            oci_manifest=oci_manifest,
            drone_path=drone_path,
            harness_path=harness_path,
            npm_path=npm_path,
            pypi_path=pypi_path,
            maven_path=maven_path,
            nuget_path=nuget_path,
            gomod_path=gomod_path,
            cargo_path=cargo_path,
            composer_path=composer_path,
            rubygems_path=rubygems_path,
            pulumi_path=pulumi_path,
        )
        _debug(f"--pr-diff: forwarded argv = {forwarded_argv}")
        head_findings_raw = [f.to_dict() for f in findings]
        delta = run_pr_diff(
            pr_diff,
            head_findings_raw,
            forwarded_argv,
            cwd=".",
        )
        markdown = report_pr_diff(delta, tool_version=__version__)
        if output_file:
            try:
                with open(output_file, "w", encoding="utf-8") as fh:
                    fh.write(markdown)
                    fh.write("\n")
            except OSError as exc:
                raise click.UsageError(
                    f"--output-file: could not write {output_file}: {exc}"
                ) from exc
            if not quiet:
                click.echo(
                    f"PR-diff report written to {output_file}", err=True,
                )
        else:
            click.echo(markdown)
        if not quiet:
            for w in delta.warnings:
                click.echo(f"[pr-diff] {w}", err=True)
            click.echo(
                f"[pr-diff] +{len(delta.introduced)} introduced, "
                f"-{len(delta.resolved)} resolved, "
                f"={len(delta.preserved)} preserved",
                err=True,
            )
        # Gate: the diff gate applies ``--fail-on`` to *introduced*
        # findings only. Preserved findings are explicitly not the
        # PR's responsibility; resolved findings are good news.
        # Without ``--fail-on``, pr-diff is informational (always exits 0).
        if fail_on:
            if any_at_or_above(delta.introduced, fail_on.upper()):
                raise click.exceptions.Exit(1)
        return

    score_result = score(findings)

    # Collect the component inventory only when requested, some
    # providers (AWS runtime) perform extra API calls to build it.
    components = None
    if want_inventory:
        try:
            components = scanner.inventory(
                type_patterns=list(inventory_types) if inventory_types else None,
            )
        except Exception as exc:
            click.echo(f"[inventory] failed: {exc}", err=True)
            components = []

    chains = list(getattr(scanner, "chains", []) or [])
    # Step-level pipeline DAGs (one per pipeline file); empty for IaC /
    # SCA / cloud providers. Only the HTML reporter renders them.
    pipeline_graphs = list(getattr(scanner, "pipeline_graphs", []) or [])
    # ``--chains-require-reachability`` filters out chains whose
    # triggering findings only co-occur on the same resource without
    # a confirmed dataflow link between them. Chains that opted out
    # of the reachability model (most XPC-NNN cross-tool chains and
    # legacy AC-NNN chains that haven't been migrated) keep the
    # default ``confirmed_reachable=False`` and are dropped here.
    # The flag is opt-in precisely so that pre-migration chains
    # don't silently disappear from existing CI runs.
    if chains_require_reachability and chains:
        before = len(chains)
        chains = [c for c in chains if c.confirmed_reachable]
        if verbose and before != len(chains):
            _debug(
                f"--chains-require-reachability: dropped "
                f"{before - len(chains)} unreachable chain(s)"
            )
    # ``--chains-require-dataflow`` is the stricter phase-2 gate: keep
    # only chains backed by a proven source-to-sink taint path, dropping
    # those confirmed by shared-job co-location alone.
    if chains_require_dataflow and chains:
        before = len(chains)
        chains = [c for c in chains if c.via_dataflow]
        if verbose and before != len(chains):
            _debug(
                f"--chains-require-dataflow: dropped "
                f"{before - len(chains)} non-dataflow chain(s)"
            )

    _emit_scan_report(
        output,
        findings=findings,
        score_result=score_result,
        chains=chains,
        components=components,
        pipeline_graphs=pipeline_graphs,
        scanner=scanner,
        threshold=threshold,
        show_controls=show_controls,
        show_passed=show_passed,
        no_group=no_group,
        inline_explain=inline_explain,
        no_chains=no_chains,
        output_file=output_file,
        quiet=quiet,
        region=region,
        target=target,
    )

    if triage:
        _emit_triage(
            findings,
            endpoint=triage_endpoint,
            model=triage_model,
            output=output,
            output_file=output_file,
            quiet=quiet,
        )

    if fix:
        if apply_fixes:
            _apply_fix_patches(findings, tier=fix)
        else:
            _emit_fix_patches(findings, to_stderr=output != "terminal", tier=fix)

    # --write-baseline snapshots the current findings to disk before
    # gating so the next run can suppress them via --baseline PATH.
    # Independent of --output: a CI lane can emit SARIF for code-
    # scanning while simultaneously writing the JSON baseline that
    # the next scheduled run gates against.
    if write_baseline:
        try:
            with open(write_baseline, "w", encoding="utf-8") as fh:
                fh.write(report_json(
                    findings, score_result, tool_version=__version__,
                    inventory=components,
                    chains=chains if not no_chains else None,
                ))
        except OSError as exc:
            raise click.UsageError(
                f"--write-baseline: could not write {write_baseline}: {exc}"
            ) from exc
        if not quiet:
            failing = sum(1 for f in findings if not f.passed)
            click.echo(
                f"[baseline] wrote {failing} failing finding(s) to "
                f"{write_baseline}",
                err=True,
            )

    # CI gate evaluation. See pipeline_check.core.gate for the full contract.
    ignore_path = ignore_file or ".pipelinecheckignore"
    baseline_git_pair: tuple[str, str] | None = None
    if baseline and baseline_from_git:
        raise click.UsageError(
            "--baseline and --baseline-from-git are mutually exclusive. "
            "Pick one: a file path, or a git REF:PATH lookup."
        )
    if baseline_from_git:
        if ":" not in baseline_from_git:
            raise click.UsageError(
                "--baseline-from-git expects REF:PATH (e.g. origin/main:baseline.json)"
            )
        ref_part, path_part = baseline_from_git.split(":", 1)
        # ``ref_part`` and ``path_part`` flow into ``git show`` as
        # positional arguments composed via f-string. Reject leading
        # ``-`` here so the CLI surfaces a clean UsageError instead of
        # the lower-layer ValueError; the helper validates again as a
        # second line of defense (CWE-88, argument injection).
        if ref_part.startswith("-") or path_part.startswith("-"):
            raise click.UsageError(
                "--baseline-from-git REF and PATH must not start with '-' "
                "(would be parsed as a git flag, not a positional argument)"
            )
        baseline_git_pair = (ref_part, path_part)
    inline_index: InlineIgnoreIndex | None = None
    if not no_inline_ignore:
        active_pipelines = pipelines_list or [pipeline_lc]
        path_kwargs: dict[str, str | None] = {
            "gha_path": gha_path,
            "gitea_path": gitea_path,
            "gitlab_path": gitlab_path,
            "bitbucket_path": bitbucket_path,
            "azure_path": azure_path,
            "jenkinsfile_path": jenkinsfile_path,
            "circleci_path": circleci_path,
            "cloudbuild_path": cloudbuild_path,
            "buildkite_path": buildkite_path,
            "drone_path": drone_path,
            "harness_path": harness_path,
            "tekton_path": tekton_path,
            "argo_path": argo_path,
            "argocd_path": argocd_path,
            "dockerfile_path": dockerfile_path,
            "k8s_path": k8s_path,
            "helm_path": helm_path,
            "tf_source": tf_source,
            "npm_path": npm_path,
            "pypi_path": pypi_path,
            "maven_path": maven_path,
            "nuget_path": nuget_path,
            "gomod_path": gomod_path,
            "cargo_path": cargo_path,
            "composer_path": composer_path,
            "rubygems_path": rubygems_path,
            "pulumi_path": pulumi_path,
        }
        inline_index = _collect_inline_ignores(active_pipelines, path_kwargs)

    try:
        expiry_window = parse_expiry_window(warn_expiring_suppressions)
    except ValueError as exc:
        raise click.UsageError(
            f"--warn-expiring-suppressions: {exc}"
        ) from exc

    vex_index = None
    if vex_paths:
        from pipeline_check.core.openvex import VexError, load_vex
        try:
            vex_index = load_vex(vex_paths)
        except VexError as exc:
            raise click.UsageError(f"--vex: {exc}") from exc

    gate_config = GateConfig(
        fail_on=Severity(fail_on.upper()) if fail_on else None,
        min_grade=min_grade.upper() if min_grade else None,
        max_failures=max_failures,
        fail_on_checks={c.upper() for c in fail_on_checks},
        baseline_path=baseline,
        baseline_from_git=baseline_git_pair,
        ignore_rules=load_ignore_file(ignore_path),
        inline_ignores=inline_index,
        fail_on_chains={c.upper() for c in fail_on_chain_ids},
        fail_on_any_chain=fail_on_any_chain,
        fail_on_parse_error=fail_on_parse_error,
        expiry_warning_days=expiry_window,
        vex_index=vex_index,
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

    gate = evaluate_gate(
        findings, score_result, gate_config, chains=chains,
        parse_error_count=_scan_status(scanner.metadata, findings)["files_unparsed"],
    )

    if not quiet and output != "json":
        _emit_gate_summary(
            gate,
            grade=score_result["grade"],
            baseline_path=baseline,
            baseline_from_git=baseline_from_git,
        )

    if not gate.passed:
        raise click.exceptions.Exit(1)


def _validate_scan_flags_early(
    *,
    config_strict: bool,
    apply_fixes: bool,
    fix: str | None,
    inventory_only: bool,
    diff_base: str | None,
    baseline: str | None,
    ingest_paths: tuple[str, ...],
) -> None:
    """Validate flags before the provider context is built.

    ``--config-strict`` aborts when the loaded config carried an unknown
    key; the rest are mutual-exclusion / existence guards (``--apply``
    needs ``--fix``; ``--inventory-only`` can't combine with fix /
    diff-base / baseline / ingest; ``--baseline`` must point at a real
    file). Raising here points the error at the conflict rather than a
    silent no-op later. Raises ``click.UsageError``.
    """
    # --config-strict: abort a real scan when the loaded config carried an
    # unknown key, rather than the default warn-and-drop. Catches a typo
    # that would otherwise silently disable a setting (e.g. a gate key
    # written at the top level instead of under 'gate:').
    if config_strict:
        from .core.config import last_unknown_keys
        dropped = last_unknown_keys()
        if dropped:
            for source, key, reason in dropped:
                click.echo(f"[config] {source}: {key!r}, {reason}", err=True)
            raise click.UsageError(
                f"--config-strict: {len(dropped)} unknown config key(s) "
                f"detected (see above). Fix the key(s) or drop "
                f"--config-strict."
            )

    if apply_fixes and not fix:
        raise click.UsageError("--apply requires --fix.")

    # Mutually-exclusive flag combinations, catch these before the
    # provider context is built so the error points at the conflict
    # rather than surfacing as a silent no-op later.
    if inventory_only and fix:
        raise click.UsageError(
            "--fix cannot be combined with --inventory-only "
            "(no findings are produced to fix)."
        )
    if inventory_only and diff_base:
        raise click.UsageError(
            "--diff-base cannot be combined with --inventory-only "
            "(inventory is a full-state snapshot, not a per-commit delta)."
        )
    if inventory_only and baseline:
        raise click.UsageError(
            "--baseline cannot be combined with --inventory-only "
            "(baselines gate findings; --inventory-only emits no findings)."
        )
    if inventory_only and ingest_paths:
        raise click.UsageError(
            "--ingest cannot be combined with --inventory-only "
            "(inventory-only emits no findings or chains for the "
            "ingested SARIF to merge into)."
        )

    # Validate --baseline early so a typo'd path doesn't surface as
    # "no regressions found" after a full scan completes.
    if baseline and not os.path.isfile(baseline):
        raise click.UsageError(
            f"--baseline file not found: {baseline}. Create one from the "
            f"current findings with `pipeline_check --write-baseline {baseline}`, "
            f"then pass `--baseline {baseline}` to gate only on new findings."
        )


def _validate_scan_inputs(
    *,
    output: str,
    output_file: str | None,
    secret_patterns: tuple[str, ...],
    custom_rules: tuple[str, ...],
    rego_rules: tuple[str, ...],
    diff_base: str | None,
    pr_diff: str | None,
    inventory_only: bool,
    fix: str | None,
    baseline: str | None,
    baseline_from_git: str | None,
) -> None:
    """Validate flag combinations checked after provider/path resolution.

    These don't depend on the resolved paths: the ``--output html`` file
    requirement, the regex / file-existence checks for
    ``--secret-pattern`` / ``--custom-rules`` / ``--rego-rules``, and the
    argument-injection + mutual-exclusivity guards on ``--diff-base`` /
    ``--pr-diff``. Raises ``click.UsageError`` on the first problem.
    """
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

    for crp in custom_rules:
        if not os.path.exists(crp):
            raise click.UsageError(f"--custom-rules not found: {crp}")

    for rrp in rego_rules:
        if not os.path.exists(rrp):
            raise click.UsageError(f"--rego-rules not found: {rrp}")

    if diff_base is not None and diff_base.startswith("-"):
        # ``diff_base`` is composed into ``git diff --name-only
        # <base>...HEAD``. A leading ``-`` makes git parse the value
        # as an option (e.g. ``--output=path``, write-anywhere
        # primitive). Catch it here so the CLI shows a clean
        # UsageError; the helper also validates as defense in depth
        # (CWE-88, argument injection).
        raise click.UsageError(
            "--diff-base must not start with '-' "
            "(would be parsed as a git flag, not a positional ref)"
        )

    if pr_diff is not None:
        if pr_diff.startswith("-"):
            # Same argument-injection concern as ``--diff-base``: the
            # ref string flows into ``git worktree add`` and ``git
            # rev-parse``. The pr_diff module re-validates as a second
            # line of defense.
            raise click.UsageError(
                "--pr-diff must not start with '-' "
                "(would be parsed as a git flag, not a positional ref)"
            )
        if inventory_only:
            raise click.UsageError(
                "--pr-diff cannot be combined with --inventory-only "
                "(inventory is a full-state snapshot, not a per-PR delta)."
            )
        if fix:
            raise click.UsageError(
                "--pr-diff cannot be combined with --fix "
                "(diff mode reports the delta; it does not modify either side)."
            )
        if baseline or baseline_from_git:
            raise click.UsageError(
                "--pr-diff is mutually exclusive with --baseline / "
                "--baseline-from-git (both define a comparison; pick one)."
            )
        if diff_base:
            raise click.UsageError(
                "--pr-diff is mutually exclusive with --diff-base. "
                "--diff-base scopes the scan to changed files only, "
                "which would leave the base side empty by construction."
            )
        # ``--pr-diff`` always emits Markdown to stdout (or
        # ``--output-file``). The other formats don't fit the
        # "delta of failures" shape we ship today, and silently
        # honoring ``--output json`` while emitting Markdown was a
        # surprising mismatch. Accept the default (``terminal``)
        # since it's what every invocation without an explicit
        # ``--output`` carries; accept ``markdown`` for an
        # explicit-intent invocation; reject everything else.
        if output not in ("terminal", "markdown"):
            raise click.UsageError(
                f"--pr-diff produces a Markdown delta report; "
                f"--output {output!r} is not supported. Drop "
                f"``--output`` or pass ``--output markdown``."
            )


def _emit_triage(
    findings: list[Any],
    *,
    endpoint: str,
    model: str,
    output: str,
    output_file: str | None,
    quiet: bool,
) -> None:
    """Run the opt-in local-LLM triage pass and print its advisory section.

    Advisory only: it runs after the report and never touches findings,
    the grade, or the gate. The section goes to stdout unless a
    machine-readable format is already occupying stdout (no ``--output-
    file``), in which case it's suppressed with a one-line stderr note so
    the structured stream stays clean.
    """
    from pipeline_check.core.report_view import ReportView
    from pipeline_check.core.triage import is_local_endpoint, triage_findings
    from pipeline_check.core.triage_reporter import report_triage

    failed = ReportView(findings).failed
    if not failed:
        if not quiet:
            click.echo("LLM triage: no failing findings to triage.", err=True)
        return
    if not is_local_endpoint(endpoint):
        click.echo(
            f"warning: --triage is sending {len(failed)} finding(s) to a "
            f"non-local endpoint ({endpoint}).",
            err=True,
        )
    results = triage_findings(failed, endpoint=endpoint, model=model)
    section = report_triage(results, endpoint=endpoint, model=model)
    stdout_is_machine = output_file is None and output not in (
        "terminal", "both",
    )
    if stdout_is_machine:
        if not quiet:
            click.echo(
                "LLM triage ran; section suppressed to keep the "
                f"{output} stream on stdout clean (use --output-file).",
                err=True,
            )
        return
    click.echo("")
    click.echo(section, nl=False)


def _emit_scan_report(
    output: str,
    *,
    findings: list[Any],
    score_result: Any,
    chains: list[Any],
    components: list[Any] | None,
    pipeline_graphs: list[Any],
    scanner: "Scanner | MultiScanner",
    threshold: Severity,
    show_controls: bool,
    show_passed: bool,
    no_group: bool,
    inline_explain: bool,
    no_chains: bool,
    output_file: str | None,
    quiet: bool,
    region: str,
    target: str | None,
) -> None:
    """Render the scan results in the requested output format(s).

    ``terminal`` / ``both`` print the rich report (plus chains, inventory,
    and the next-step tip), and ``both`` additionally streams JSON to
    stdout. ``html`` writes its own bundled file. Every other format is a
    single text artifact emitted via :func:`_emit_report`.
    """
    if not quiet and output in ("terminal", "both"):
        from rich.console import Console as _Console  # local import, only needed here
        console = _Console(stderr=(output == "both"))
        report_terminal(
            findings, score_result,
            severity_threshold=threshold, console=console,
            show_controls=show_controls,
            show_passed=show_passed,
            group_similar=not no_group,
            inline_explain=inline_explain,
            incomplete_reason=_scan_incomplete_reason(scanner.metadata, findings),
        )
        if chains:
            report_chains_terminal(chains, console=console)
        if components is not None:
            report_inventory_terminal(components, console=console)
        # Final line of a terminal scan: a single "what next" nudge,
        # rendered after every panel so it's the last thing on screen.
        tip = next_steps_tip(findings, severity_threshold=threshold)
        if tip:
            console.print()
            console.print(tip)

    if output in ("json", "both"):
        json_text = report_json(
            findings, score_result, tool_version=__version__,
            inventory=components,
            chains=chains if not no_chains else None,
            scan_status=_scan_status(scanner.metadata, findings),
            show_passed=show_passed,
        )
        # ``both`` always streams JSON to stdout regardless of
        # ``--output-file``; the file destination is only honored
        # when JSON is the sole format the user asked for.
        if output == "both":
            if not quiet:
                click.echo(json_text)
        else:
            _emit_report(json_text, output_file, "JSON report", quiet=quiet)

    if output == "html":
        # HTML reporter writes the file itself (it bundles assets), so
        # we don't route it through ``_emit_report``.
        from pipeline_check.core.html_reporter import report_html
        try:
            report_html(
                findings, score_result, region=region, target=target or "",
                output_path=output_file, chains=chains,
                pipeline_graphs=pipeline_graphs,
            )
        except OSError as exc:
            raise click.UsageError(
                f"could not write HTML report to {output_file}: {exc}"
            ) from exc
        if not quiet:
            click.echo(f"HTML report written to {output_file}", err=True)

    # Single-artifact text formats. Each builder imports its reporter
    # lazily, so only the selected format's module loads, and nothing
    # loads on a ``--version`` / ``--list-*`` run. Notably this keeps
    # ``xml.sax`` (pulled in by the JUnit reporter) off every invocation's
    # startup path, where it cost ~20 ms. A dispatch table keeps the
    # per-format wiring in one place instead of a seven-way if-chain.
    def _sarif_text() -> str:
        from pipeline_check.core.sarif_reporter import report_sarif
        return report_sarif(
            findings, score_result, tool_version=__version__,
            chains=chains, inline_explain=inline_explain,
            scan_status=_scan_status(scanner.metadata, findings),
        )

    def _junit_text() -> str:
        from pipeline_check.core.junit_reporter import report_junit
        return report_junit(
            findings, score_result, inline_explain=inline_explain,
        )

    def _markdown_text() -> str:
        from pipeline_check.core.markdown_reporter import report_markdown
        return report_markdown(
            findings, score_result, chains=chains,
            inline_explain=inline_explain,
        )

    def _codequality_text() -> str:
        from pipeline_check.core.codequality_reporter import report_codequality
        return report_codequality(findings, inline_explain=inline_explain)

    def _jsonl_text() -> str:
        from pipeline_check.core.jsonl_reporter import report_jsonl
        return report_jsonl(findings, inline_explain=inline_explain)

    def _csv_text() -> str:
        from pipeline_check.core.csv_reporter import report_csv
        return report_csv(findings, inline_explain=inline_explain)

    def _annotations_text() -> str:
        from pipeline_check.core.github_annotations_reporter import (
            report_github_annotations,
        )
        return report_github_annotations(findings, inline_explain=inline_explain)

    def _cyclonedx_text() -> str:
        from pipeline_check.core.cyclonedx_reporter import report_cyclonedx
        return report_cyclonedx(
            scanner.sbom(), tool_version=__version__, scanned_path=target or ".",
        )

    def _spdx_text() -> str:
        from pipeline_check.core.spdx_reporter import report_spdx
        return report_spdx(
            scanner.sbom(), tool_version=__version__, scanned_path=target or ".",
        )

    def _openvex_text() -> str:
        from pipeline_check.core.openvex_reporter import report_openvex
        return report_openvex(
            findings, tool_version=__version__, scanned_path=target or ".",
        )

    def _threatmodel_text() -> str:
        from pipeline_check.core.threatmodel_reporter import report_threatmodel
        return report_threatmodel(
            findings, score_result, inventory=components, chains=chains,
            tool_version=__version__, region=region or "", target=target or "",
        )

    text_reporters: dict[str, tuple[Callable[[], str], str]] = {
        "jsonl": (_jsonl_text, "JSON Lines report"),
        "sarif": (_sarif_text, "SARIF report"),
        "junit": (_junit_text, "JUnit report"),
        "markdown": (_markdown_text, "Markdown report"),
        "codequality": (_codequality_text, "Code Quality report"),
        "csv": (_csv_text, "CSV report"),
        "annotations": (_annotations_text, "GitHub Actions annotations"),
        "cyclonedx": (_cyclonedx_text, "CycloneDX SBOM"),
        "spdx": (_spdx_text, "SPDX SBOM"),
        "openvex": (_openvex_text, "OpenVEX document"),
        "threatmodel": (_threatmodel_text, "Threat-model report"),
    }
    reporter = text_reporters.get(output)
    if reporter is not None:
        build_text, label = reporter
        _emit_report(build_text(), output_file, label, quiet=quiet)


def _run_informational_commands(
    *,
    man_topic: str | None,
    list_standards: bool,
    serve: bool,
    list_checks: bool,
    list_fixers: bool,
    fixer_safety_filter: str,
    list_verifiers: bool,
    annotate_fp: tuple[str, str] | None,
    fp_path: str | None,
    list_chains: bool,
    explain_chain_id: str | None,
    explain_id: str | None,
    ai_explain_id: str | None,
    ai_model_spec: str | None,
    ai_context_file: str | None,
    standard_report: str | None,
    config_check: bool,
    pipeline: str,
) -> bool:
    """Handle the informational / eager-exit flags that short-circuit a scan.

    These flags (``--man``, ``--list-standards``, ``--serve``,
    ``--list-checks``, ``--list-fixers``, ``--annotate-fp``,
    ``--list-chains``, ``--explain-chain``, ``--explain`` /
    ``--ai-explain``, ``--standard-report``, ``--config-check``) each do
    their own thing and stop before any provider is scanned. Returns True
    when one handled the invocation (the caller then returns); the ones
    that carry a specific exit code raise ``click.exceptions.Exit``
    directly. Returns False when none matched and a real scan should run.
    """
    if man_topic is not None:
        from .core import manual as _manual
        known = set(_manual.topics())
        requested = (man_topic or "").lower()
        # ``--man`` alone (empty string) prints the index; only flag a
        # typo when the user supplied a non-empty topic that isn't in
        # the registry so scripts piping this through ``| grep`` get
        # a non-zero exit on misuse.
        click.echo(_manual.render(man_topic), nl=False)
        if requested and requested != "index" and requested not in known:
            raise click.exceptions.Exit(3)
        return True

    if list_standards:
        for std in _standards.resolve():
            click.echo(f"{std.name} ,  {std.title} (v{std.version or 'n/a'})")
            if std.url:
                click.echo(f"    {std.url}")
        return True

    if serve:
        # Lazy import so the optional ``mcp`` SDK doesn't load at
        # CLI startup. The harness raises a clean RuntimeError when
        # the package isn't installed; surface it as exit 3.
        try:
            from .mcp_server import run_stdio
        except ImportError as exc:  # pragma: no cover - import-time safeguard
            click.echo(
                f"[error] MCP support unavailable: {exc}. "
                "Install with ``pip install 'pipeline-check[mcp]'``.",
                err=True,
            )
            raise click.exceptions.Exit(3) from exc
        try:
            run_stdio()
        except RuntimeError as exc:
            click.echo(f"[error] {exc}", err=True)
            raise click.exceptions.Exit(3) from exc
        except KeyboardInterrupt:
            pass
        return True

    if list_checks:
        _list_checks_for_pipeline(pipeline.lower())
        return True

    if list_fixers:
        from rich.console import Console

        from .core.autofix import iter_fixers
        from .core.explain import render_fixers

        # Color the severity column on a terminal; piped / redirected
        # output stays plain (greppable, byte-identical to before).
        _fixers_console = Console()
        _fixers_color = _fixers_console.is_terminal
        fixers_body, fixers_code = render_fixers(
            fixer_safety_filter, color=_fixers_color,
        )
        if _fixers_color:
            _fixers_console.print(
                fixers_body, highlight=False, soft_wrap=True, end="",
            )
        else:
            click.echo(fixers_body, nl=False)
        if fixers_code == 0:
            all_fixers = iter_fixers()
            safe_n = sum(1 for _, s in all_fixers if s == "safe")
            unsafe_n = len(all_fixers) - safe_n
            click.echo(
                f"\n{len(all_fixers)} autofixers registered "
                f"({safe_n} safe, {unsafe_n} unsafe). `--fix` runs safe "
                "only; `--fix=unsafe` runs both. A registered fixer still "
                "emits no patch when the finding is already remediated or "
                "the edit wouldn't round-trip as valid YAML.",
                err=True,
            )
        raise click.exceptions.Exit(fixers_code)

    if list_verifiers:
        from .core.checks._primitives.secret_verifiers import verifier_names
        from .core.manual import detector_description

        names = verifier_names()
        width = max((len(n) for n in names), default=0)
        for name in names:
            click.echo(f"{name.ljust(width)}  {detector_description(name)}")
        click.echo(
            f"\n{len(names)} detectors have a live verifier. Run "
            "`--verify-secrets` (with `--resolve-remote`) to probe matching "
            "findings against their issuing API.",
            err=True,
        )
        raise click.exceptions.Exit(0)

    if annotate_fp:
        # ``--annotate-fp CHECK_ID RESOURCE`` writes the local
        # annotation file and exits without scanning. Idempotent.
        from .core.fp_annotations import (
            DEFAULT_FP_PATH,
            append_annotation,
        )

        cid, resource = annotate_fp
        target_path = fp_path or DEFAULT_FP_PATH
        try:
            wrote = append_annotation(cid, resource, path=target_path)
        except (OSError, ValueError) as exc:
            raise click.UsageError(
                f"could not write {target_path}: {exc}"
            ) from exc
        if wrote:
            click.echo(
                f"[annotate-fp] recorded {cid.upper()}:{resource} "
                f"in {target_path}"
            )
        else:
            click.echo(
                f"[annotate-fp] {cid.upper()}:{resource} already "
                f"present in {target_path} (no change)"
            )
        return True

    if list_chains:
        raise click.exceptions.Exit(_eager_print_list_chains())

    if explain_chain_id:
        raise click.exceptions.Exit(_eager_print_explain_chain(explain_chain_id))

    if explain_id and ai_explain_id:
        # ``--ai-explain`` already runs the deterministic body before
        # the AI section, so passing both flags is always a mistake.
        # Reject it explicitly instead of silently letting ``--explain``
        # win (which used to drop the AI section without any signal).
        raise click.UsageError(
            "--explain and --ai-explain are mutually exclusive. "
            "Use --ai-explain CHECK_ID for the deterministic body "
            "plus the AI-generated section, or --explain CHECK_ID "
            "for the deterministic body alone."
        )

    if explain_id:
        from .core.explain import print_explain
        raise click.exceptions.Exit(print_explain(explain_id))

    if ai_explain_id:
        raise click.exceptions.Exit(_run_ai_explain(
            ai_explain_id,
            model_spec=ai_model_spec,
            context_file=ai_context_file,
        ))

    if standard_report:
        _eager_print_standard_report(standard_report)
        return True

    if config_check:
        from .core.config import last_unknown_keys
        dropped = last_unknown_keys()
        if not dropped:
            click.echo("[config] OK, no unknown keys.")
            return True
        for source, key, reason in dropped:
            click.echo(f"[config] {source}: {key!r}, {reason}", err=True)
        click.echo(f"[config] {len(dropped)} unknown key(s) detected.", err=True)
        raise click.exceptions.Exit(3)
    return False


def _run_ai_explain(
    check_id: str,
    *,
    model_spec: str | None,
    context_file: str | None,
) -> int:
    """Print the deterministic explain body, then an AI-augmented section.

    Returns the exit code: 0 on success, 3 for an unknown check ID
    (matching the deterministic ``--explain`` contract), 4 for an
    AI-side configuration / dependency / network failure (so CI
    can distinguish "your scan is broken" from "the AI provider is").
    """
    # Always print the deterministic body first. If the ID is bad, the
    # deterministic path already exits 3 with a near-match suggestion;
    # the AI side never gets called for an unknown ID.
    from .core.explain import (
        _build_index,
        print_explain,
    )
    body_code = print_explain(check_id)
    # Flush so the deterministic body lands on screen before any AI-
    # side error / output. Without this, an unbuffered stderr message
    # ("no AI provider configured") prints before the still-buffered
    # stdout body when the caller redirects 2>&1.
    sys.stdout.flush()
    if body_code != 0:
        return body_code

    # Resolve the rule (we already know it exists since print_explain
    # returned 0). The deterministic explain renders by ``_CheckMeta``
    # which carries the rule for rule-based packs; class-based packs
    # only have ``id`` / ``title`` / ``severity``, in which case we
    # synthesise a minimal Rule for the prompt.
    from .core.ai_explain import (
        AIAuthError,
        AIDependencyError,
        AIRequestError,
        default_spec_from_env,
        explain_check,
        render_section,
        select_client,
    )
    from .core.checks.rule import Rule as _Rule

    cid = check_id.strip().upper()
    meta = _build_index().get(cid)
    if meta is None:
        # Belt and suspenders: print_explain already returned 0, so
        # the index lookup should succeed; this guards against drift.
        click.echo(
            f"\n[ai-explain] internal: rule {cid!r} not in index", err=True,
        )
        return 4

    if meta.rule is not None:
        rule = meta.rule
    else:
        # Class-based pack — synthesise a minimal Rule so the prompt
        # builder still has a stable shape.
        rule = _Rule(
            id=meta.id,
            title=meta.title,
            severity=meta.severity,
            recommendation="(class-based check; no rule-level prose)",
            docs_note=meta.docstring or "",
        )

    spec = model_spec or default_spec_from_env()
    if not spec:
        click.echo(
            "\n[ai-explain] no AI provider configured. Set "
            "ANTHROPIC_API_KEY / OPENAI_API_KEY, or pass "
            "``--ai-model ollama`` to use a local Ollama daemon.",
            err=True,
        )
        return 4

    try:
        client = select_client(spec)
    except (ValueError, AIDependencyError, AIAuthError) as exc:
        click.echo(f"\n[ai-explain] {exc}", err=True)
        return 4

    try:
        response = explain_check(
            rule, client=client, context_file=context_file,
        )
    except AIRequestError as exc:
        click.echo(f"\n[ai-explain] {exc}", err=True)
        return 4

    # Extra blank line so the AI section visually separates from the
    # deterministic body above.
    click.echo("")
    click.echo(render_section(client.name, response))
    return 0


def _build_pr_diff_subprocess_argv(
    *,
    pipeline_lc: str,
    pipelines_list: list[str],
    checks: tuple[str, ...],
    severity_threshold: str,
    min_confidence: str,
    standards: tuple[str, ...],
    custom_rules: tuple[str, ...],
    rego_rules: tuple[str, ...],
    secret_patterns: tuple[str, ...],
    detect_entropy: bool,
    ignore_file: str | None,
    fp_path: str | None,
    tf_plan: str | None,
    tf_source: str | None,
    gha_path: str | None,
    gitea_path: str | None,
    gitlab_path: str | None,
    bitbucket_path: str | None,
    azure_path: str | None,
    jenkinsfile_path: str | None,
    circleci_path: str | None,
    cfn_template: str | None,
    cloudbuild_path: str | None,
    buildkite_path: str | None,
    tekton_path: str | None,
    argo_path: str | None,
    argocd_path: str | None,
    dockerfile_path: str | None,
    k8s_path: str | None,
    helm_path: str | None,
    helm_values: tuple[str, ...],
    helm_set: tuple[str, ...],
    oci_manifest: str | None,
    drone_path: str | None,
    harness_path: str | None,
    npm_path: str | None,
    pypi_path: str | None,
    maven_path: str | None,
    nuget_path: str | None,
    gomod_path: str | None = None,
    cargo_path: str | None = None,
    composer_path: str | None = None,
    rubygems_path: str | None = None,
    pulumi_path: str | None = None,
) -> list[str]:
    """Build the argv for the BASE-side ``pipeline_check`` subprocess.

    Reconstructs flag form from already-parsed values rather than
    re-splitting :data:`sys.argv`. The whitelist below is deliberate,
    a flag the BASE scan shouldn't see ends up *not* in this list,
    which is the safer default than "forward everything and remember
    what to suppress". Anything that affects what the scanner *finds*
    on the BASE side is in; gate / output / write-baseline / fix /
    ai-explain / inventory / pr-diff itself are all out.

    Chains are *always* disabled on the BASE side because the delta
    layer doesn't compare chains yet (followup), and computing them
    in the subprocess is wasted work.
    """
    argv: list[str] = []
    if pipelines_list:
        argv.extend(["--pipelines", ",".join(pipelines_list)])
    else:
        argv.extend(["--pipeline", pipeline_lc])
    for c in checks:
        argv.extend(["--checks", c])
    argv.extend(["--severity-threshold", severity_threshold])
    argv.extend(["--min-confidence", min_confidence])
    for s in standards:
        argv.extend(["--standard", s])
    for cr in custom_rules:
        argv.extend(["--custom-rules", cr])
    for rr in rego_rules:
        argv.extend(["--rego-rules", rr])
    for pat in secret_patterns:
        argv.extend(["--secret-pattern", pat])
    if detect_entropy:
        argv.append("--detect-entropy")
    if ignore_file:
        argv.extend(["--ignore-file", ignore_file])
    if fp_path:
        argv.extend(["--fp-file", fp_path])

    # Path flags: forward only the ones the user actually provided.
    # Relative paths resolve against the worktree's cwd (the desired
    # behavior); absolute paths point at the user's original location
    # (rare but explicit user intent).
    _path_pairs: tuple[tuple[str, str | None], ...] = (
        ("--tf-plan", tf_plan),
        ("--tf-source", tf_source),
        ("--gha-path", gha_path),
        ("--gitea-path", gitea_path),
        ("--gitlab-path", gitlab_path),
        ("--bitbucket-path", bitbucket_path),
        ("--azure-path", azure_path),
        ("--jenkinsfile-path", jenkinsfile_path),
        ("--circleci-path", circleci_path),
        ("--cfn-template", cfn_template),
        ("--cloudbuild-path", cloudbuild_path),
        ("--buildkite-path", buildkite_path),
        ("--tekton-path", tekton_path),
        ("--argo-path", argo_path),
        ("--argocd-path", argocd_path),
        ("--dockerfile-path", dockerfile_path),
        ("--k8s-path", k8s_path),
        ("--helm-path", helm_path),
        ("--oci-manifest", oci_manifest),
        ("--drone-path", drone_path),
        ("--harness-path", harness_path),
        ("--npm-path", npm_path),
        ("--pypi-path", pypi_path),
        ("--maven-path", maven_path),
        ("--nuget-path", nuget_path),
        ("--gomod-path", gomod_path),
        ("--cargo-path", cargo_path),
        ("--composer-path", composer_path),
        ("--rubygems-path", rubygems_path),
        ("--pulumi-path", pulumi_path),
    )
    for flag, value in _path_pairs:
        if value:
            argv.extend([flag, value])
    for vf in helm_values:
        argv.extend(["--helm-values", vf])
    for hs in helm_set:
        argv.extend(["--helm-set", hs])

    # Chains aren't compared in the delta yet; suppressing them on
    # the BASE side avoids spending subprocess time on output the
    # delta layer ignores. ``--quiet`` is deliberately *not* set:
    # that flag suppresses the JSON output we need to parse. The
    # subprocess's stderr (which carries the scan summary) is
    # captured separately and discarded by the orchestrator.
    argv.append("--no-chains")
    return argv


def main() -> None:
    """Console entry point: dispatches between ``scan`` and subcommands.

    Keeping the top-level command as ``scan`` preserves backward
    compatibility, every documented ``pipeline_check --flag ...``
    invocation keeps working. Subcommands are opt-in via a bare
    argv[1] match, so adding more later is cheap.

    Stdio reconfiguration runs here (not at import time) so MCP / LSP
    callers that pull names out of this module don't inherit the
    Windows console workarounds when their stdio is JSON-RPC.
    """
    _tolerate_unencodable_stdio()
    if len(sys.argv) >= 2 and sys.argv[1] == "init":
        sys.argv.pop(1)
        init_cmd()
        return
    if len(sys.argv) >= 2 and sys.argv[1] == "explain":
        sys.argv.pop(1)
        explain_cmd()
        return
    if len(sys.argv) >= 2 and sys.argv[1] == "fp-stats":
        sys.argv.pop(1)
        fp_stats_cmd()
        return
    if len(sys.argv) >= 2 and sys.argv[1] == "history":
        sys.argv.pop(1)
        history_cmd()
        return
    if len(sys.argv) >= 2 and sys.argv[1] == "fleet":
        sys.argv.pop(1)
        fleet_cmd()
        return
    if len(sys.argv) >= 2 and sys.argv[1] == "fix-pr":
        sys.argv.pop(1)
        fix_pr_cmd()
        return
    if len(sys.argv) >= 2 and sys.argv[1] == "verify-artifact":
        sys.argv.pop(1)
        verify_artifact_cmd()
        return
    scan()
