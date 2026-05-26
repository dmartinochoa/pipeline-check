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
from typing import Any

import click

from . import __version__
from .core import autofix as _autofix
from .core import providers as _providers
from .core import standards as _standards
from .core.checks.base import Confidence, Severity, confidence_rank
from .core.config import load_config
from .core.gate import GateConfig, evaluate_gate, load_ignore_file
from .core.html_reporter import report_html
from .core.inline_ignore import (
    InlineIgnoreIndex,
    InlineIgnoreRule,
    build_inline_index,
    extract_inline_ignores,
)
from .core.junit_reporter import report_junit
from .core.markdown_reporter import report_markdown
from .core.policies import (
    POLICY_DIRS,
    PolicyError,
    discover_policies,
    load_policy,
    policy_to_config_map,
)
from .core.reporter import (
    report_chains_terminal,
    report_inventory_terminal,
    report_json,
    report_terminal,
)
from .core.sarif_reporter import report_sarif
from .core.scanner import MultiScanner, Scanner
from .core.scorer import score
from .core.threatmodel_reporter import report_threatmodel


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
            "--tf-plan", "--tf-source", "--gha-path", "--gitlab-path",
            "--bitbucket-path", "--azure-path", "--jenkinsfile-path",
            "--circleci-path", "--cfn-template", "--cloudbuild-path",
            "--dockerfile-path", "--k8s-path", "--helm-path",
            "--buildkite-path", "--tekton-path", "--argo-path",
            "--argocd-path",
            "--helm-values", "--helm-set", "--oci-manifest",
            "--drone-path", "--npm-path", "--pypi-path",
            "--maven-path", "--nuget-path",
        })),
        ("Filtering", frozenset({
            "--checks", "--severity-threshold", "--min-confidence",
            "--secret-pattern", "--detect-entropy", "--custom-rules",
        })),
        ("Output", frozenset({
            "--output", "--output-file", "--standard",
            "--inventory", "--inventory-type", "--inventory-only",
        })),
        ("Gate", frozenset({
            "--fail-on", "--min-grade", "--max-failures",
            "--fail-on-check", "--baseline", "--baseline-from-git",
            "--write-baseline",
            "--diff-base", "--pr-diff", "--ignore-file", "--no-inline-ignore",
            "--fail-on-chain", "--fail-on-any-chain",
        })),
        ("Attack chains", frozenset({
            "--no-chains", "--list-chains", "--explain-chain",
        })),
        ("Autofix", frozenset({"--fix", "--apply"})),
        ("Info & Help", frozenset({
            "--list-checks", "--list-standards", "--standard-report",
            "--explain", "--man", "--config-check",
            "--install-completion", "--config", "--version",
            "--policy", "--list-policies",
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
# Shell completion helpers
# ────────────────────────────────────────────────────────────────────────────


def _completion_debug(source: str, exc: BaseException) -> None:
    """Log a completion-helper exception to stderr when ``$PIPELINE_CHECK_DEBUG``
    is truthy.

    Tab-completion runs in the user's interactive shell, where stderr
    output during a Tab press is invisible (the shell renders the
    candidate list, not stderr). Silent ``except`` is therefore the
    only reasonable production behavior: a broken helper must not eat
    the keypress with a traceback. But debugging "why does my Tab
    show no candidates" requires *some* breadcrumb, so we honor an
    opt-in env var. Default off to keep the live path quiet.
    """
    if os.environ.get("PIPELINE_CHECK_DEBUG"):
        click.echo(
            f"[completion] {source}: {type(exc).__name__}: {exc}",
            err=True,
        )


def _complete_check_ids(
    ctx: click.Context, param: click.Parameter, incomplete: str,
) -> list[Any]:
    """Tab-complete check IDs (GHA-001, GL-002, CB-001, etc.)."""
    from click.shell_completion import CompletionItem
    try:
        ids = _all_check_ids()
    except Exception as exc:
        _completion_debug("check-ids", exc)
        return []
    return [
        CompletionItem(cid)
        for cid in ids
        if cid.lower().startswith(incomplete.lower())
    ]


def _complete_standards(
    ctx: click.Context, param: click.Parameter, incomplete: str,
) -> list[Any]:
    """Tab-complete standard names."""
    from click.shell_completion import CompletionItem
    try:
        names = _standards.available()
    except Exception as exc:
        _completion_debug("standards", exc)
        return []
    return [
        CompletionItem(n)
        for n in names
        if n.lower().startswith(incomplete.lower())
    ]


def _complete_man_topics(
    ctx: click.Context, param: click.Parameter, incomplete: str,
) -> list[Any]:
    """Tab-complete --man topic names."""
    from click.shell_completion import CompletionItem
    try:
        from .core.manual import topics
        names = topics()
    except Exception as exc:
        _completion_debug("man-topics", exc)
        return []
    return [
        CompletionItem(t)
        for t in names
        if t.lower().startswith(incomplete.lower())
    ]


def _list_checks_for_pipeline(pipeline: str) -> None:
    """Render every available check for *pipeline* as ``ID  SEV  TITLE``.

    Rule-based providers (all workflow providers + ``aws/rules/`` +
    ``cloudformation/*`` + ``terraform/*``) expose ``Rule`` metadata via
    ``discover_rules``. Class-based modules (AWS core services,
    Terraform core services) have the same info in their module
    docstring header. We parse it so the output is uniform.
    """
    rows: list[tuple[str, str, str]] = []
    # Rule-based packages are derived from the filesystem so a new
    # provider under ``pipeline_check/core/checks/<name>/rules/``
    # is auto-listed without a CLI edit. Same source-of-truth
    # pattern as ``_all_check_ids`` and the custom-rule loader's
    # built-in-ID collision check.
    from pathlib import Path as _Path
    _checks_root = _Path(__file__).parent / "core" / "checks"
    _provider_rule_dir = _checks_root / pipeline / "rules"
    rule_packages: dict[str, list[str]] = {}
    if _provider_rule_dir.is_dir():
        rule_packages[pipeline] = [
            f"pipeline_check.core.checks.{pipeline}.rules"
        ]
    from .core.checks.rule import discover_rules
    for pkg in rule_packages.get(pipeline, []):
        try:
            for rule, _ in discover_rules(pkg):
                rows.append((rule.id, rule.severity.value, rule.title))
        except Exception as exc:  # pragma: no cover - defensive
            click.echo(f"[warn] could not load {pkg}: {exc}", err=True)

    # Class-based modules, parse the docstring header. CloudFormation
    # modules don't carry the table header (their docstrings point at
    # Terraform's mirror); scan Terraform's source as a fallback so
    # ``--pipeline cloudformation --list-checks`` produces the same
    # IDs/severities a CFN scan would.
    import importlib
    import pkgutil
    _class_packages = {
        "aws": ["pipeline_check.core.checks.aws"],
        "terraform": ["pipeline_check.core.checks.terraform"],
        "cloudformation": [
            "pipeline_check.core.checks.terraform",
            "pipeline_check.core.checks.cloudformation",
        ],
    }
    class_pkg_names = _class_packages.get(pipeline) or []
    if class_pkg_names:
        _row_re = re.compile(
            r"^\s*(?P<id>[A-Z]+-\d+)\s{2,}(?P<title>.+?)\s{2,}"
            r"(?P<sev>CRITICAL|HIGH|MEDIUM|LOW|INFO)\b",
            re.MULTILINE,
        )
        for class_pkg_name in class_pkg_names:
            try:
                # ``class_pkg_module`` is distinct from the ``pkg`` loop
                # variables earlier and later in this function (which are
                # strings) so mypy doesn't carry a stale ``str`` inference.
                class_pkg_module = importlib.import_module(class_pkg_name)
                for info in pkgutil.iter_modules(class_pkg_module.__path__):
                    if info.name.startswith("_") or info.name == "rules":
                        continue
                    mod = importlib.import_module(f"{class_pkg_name}.{info.name}")
                    doc = mod.__doc__ or ""
                    for m in _row_re.finditer(doc):
                        rows.append((m["id"], m["sev"], m["title"].strip()))
            except Exception as exc:  # pragma: no cover - defensive
                click.echo(f"[warn] could not scan {class_pkg_name}: {exc}", err=True)

    if not rows:
        click.echo(
            f"[list-checks] no checks registered for --pipeline {pipeline}.",
            err=True,
        )
        raise click.exceptions.Exit(3)

    # Deduplicate (rule-based + class-based overlap on IDs like CB-001)
    # and sort so ``GHA-001`` < ``GHA-010`` reads naturally.
    dedup: dict[str, tuple[str, str, str]] = {}
    for row in rows:
        dedup.setdefault(row[0], row)
    id_width = max(len(i) for i in dedup) if dedup else 0
    sev_width = max(len(r[1]) for r in dedup.values()) if dedup else 0
    for cid in sorted(dedup):
        _, sev, title = dedup[cid]
        click.echo(f"{cid:<{id_width}}  {sev:<{sev_width}}  {title}")


def _eager_print_list_chains() -> int:
    """``--list-chains`` handler. Returns the exit code the CLI
    should propagate to ``sys.exit``."""
    from .core import chains as _chains_pkg
    rules = _chains_pkg.list_rules()
    if not rules:
        click.echo("[list-chains] no attack chains registered.", err=True)
        return 3
    id_w = max(len(r.id) for r in rules)
    sev_w = max(len(r.severity.value) for r in rules)
    for r in sorted(rules, key=lambda x: x.id):
        click.echo(f"{r.id:<{id_w}}  {r.severity.value:<{sev_w}}  {r.title}")
    return 0


def _eager_print_explain_chain(chain_id: str) -> int:
    """``--explain-chain <ID>`` handler. Returns the exit code."""
    from .core import chains as _chains_pkg
    # Distinct local name so mypy doesn't fold the list-typed
    # ``list_rules()`` inference into the dict reassignment.
    rules_by_id = {r.id.upper(): r for r in _chains_pkg.list_rules()}
    target_id = chain_id.upper()
    rule = rules_by_id.get(target_id)
    if rule is None:
        import difflib
        rule_ids: list[str] = list(rules_by_id.keys())
        suggestions = difflib.get_close_matches(target_id, rule_ids, n=3)
        hint = f" Did you mean: {', '.join(suggestions)}?" if suggestions else ""
        click.echo(
            f"[explain-chain] unknown chain {chain_id!r}.{hint}",
            err=True,
        )
        return 3
    click.echo(f"{rule.id}, {rule.title}")
    click.echo(f"  Severity: {rule.severity.value}")
    if rule.providers:
        click.echo(f"  Providers: {', '.join(rule.providers)}")
    if rule.kill_chain_phase:
        click.echo(f"  Kill chain: {rule.kill_chain_phase}")
    if rule.mitre_attack:
        click.echo(f"  MITRE ATT&CK: {', '.join(rule.mitre_attack)}")
    click.echo("")
    click.echo("Summary:")
    click.echo(f"  {rule.summary}")
    click.echo("")
    click.echo("Recommendation:")
    click.echo(f"  {rule.recommendation}")
    if rule.references:
        click.echo("")
        click.echo("References:")
        for ref in rule.references:
            click.echo(f"  - {ref}")
    return 0


def _eager_print_standard_report(standard_id: str) -> None:
    """``--standard-report <std>`` handler. Raises ``UsageError`` on
    unknown standard so the CLI surfaces a clean argument error
    instead of an exit code."""
    report_std = _standards.get(standard_id)
    if report_std is None:
        available = ", ".join(_standards.available())
        raise click.UsageError(
            f"Unknown standard {standard_id!r}. "
            f"Available: {available or 'none'}."
        )
    click.echo(f"{report_std.name} ,  {report_std.title} (v{report_std.version or 'n/a'})")
    if report_std.url:
        click.echo(f"  {report_std.url}")
    click.echo("")
    click.echo("Control -> check mapping:")
    gaps: list[tuple[str, str]] = []
    for ctrl_id in sorted(report_std.controls):
        title = report_std.controls[ctrl_id]
        check_ids = [
            cid for cid, controls in report_std.mappings.items()
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


def _resolve_provider_path(
    provider_lc: str,
    *,
    flag: str,
    value: str | None,
    candidates: tuple[str, ...] = (),
    candidate_kind: str = "file",
    validate_kind: str = "exists",
    detect_label: str = "",
    not_found_label: str = "",
) -> str:
    """Auto-detect, validate, and return a per-provider input path.

    Replaces the per-provider elif ladder that ``main()`` used to
    carry. Cloudformation and helm have edge cases (template-folder
    detection, ``--helm-values`` validation) so they stay inline;
    every other provider's contract is exactly:

      1. If the user didn't pass ``--<flag>``, walk *candidates*
         and pick the first one that exists. ``candidate_kind`` is
         ``file`` for canonical files (``.gitlab-ci.yml``) or
         ``dir`` for canonical directories (``.github/workflows``).
      2. If still empty, raise ``UsageError`` with a hint that names
         the canonical files we looked for (*detect_label*).
      3. Validate that the resolved path exists. ``validate_kind``
         is ``exists`` (default; file or dir), ``file``, or ``dir``.
         ``not_found_label`` ("directory" / "path") inserts a noun
         into the error message when the validation kind is stricter
         than ``exists``.
    """
    if not value:
        check = os.path.isdir if candidate_kind == "dir" else os.path.isfile
        for cand in candidates:
            if check(cand):
                value = cand
                click.echo(f"[auto] using --{flag} {value}", err=True)
                break
    if not value:
        suffix = (
            f" (no {detect_label} found in the current directory)."
            if detect_label else "."
        )
        raise click.UsageError(
            f"--{flag} PATH is required when --pipeline {provider_lc}{suffix}"
        )
    validators = {
        "exists": os.path.exists,
        "file": os.path.isfile,
        "dir": os.path.isdir,
    }
    if not validators[validate_kind](value):
        kind_word = (not_found_label + " ") if not_found_label else ""
        raise click.UsageError(
            f"--{flag} {kind_word}not found: {value}"
        )
    return value


# Provider detection table. Each entry maps a provider name to the list
# of cwd-relative paths whose presence signals "this provider should
# scan here". File entries use ``os.path.isfile``; directory entries use
# ``os.path.isdir``. Iterated by both :func:`_detect_pipeline_from_cwd`
# (first-match-wins single-provider detection) and
# :func:`_detect_all_pipelines_from_cwd` (multi-provider walk that
# returns every provider whose canonical path is present).
#
# Order matters: helm before kubernetes because a ``Chart.yaml`` at
# the repo root is an unambiguous signal, whereas the k8s indicators
# (``kubernetes/``, ``k8s/``, ``manifests/``) are generic directory
# names that helm charts often use too. Multi-detect drops the
# ambiguous-k8s case when helm already matched (see below).
_PROVIDER_DETECT_FILES: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    # (provider, files, directories)
    ("github", (), (".github/workflows",)),
    ("gitlab", (".gitlab-ci.yml",), ()),
    ("circleci", (".circleci/config.yml",), ()),
    ("jenkins", ("Jenkinsfile",), ()),
    ("azure", ("azure-pipelines.yml",), ()),
    ("bitbucket", ("bitbucket-pipelines.yml",), ()),
    ("cloudbuild", ("cloudbuild.yaml", "cloudbuild.yml"), ()),
    ("buildkite", (".buildkite/pipeline.yml", ".buildkite/pipeline.yaml"), ()),
    ("drone", (".drone.yml", ".drone.yaml"), ()),
    ("dockerfile", ("Dockerfile", "Containerfile"), ()),
    ("npm", ("package.json", "package-lock.json"), ()),
    ("pypi", ("requirements.txt",), ()),
    ("maven", ("pom.xml",), ()),
    ("nuget", ("Directory.Packages.props",), ()),
    ("terraform", ("main.tf",), ()),
    (
        "cloudformation",
        (
            "template.yml", "template.yaml", "template.json",
            "cloudformation.yml", "cloudformation.yaml",
            "cfn.yml", "cfn.yaml",
        ),
        (),
    ),
    # OCI deliberately omitted from auto-detect: ``index.json`` is too
    # generic a filename to promote on presence alone (Backstage,
    # Sphinx, and various Node tooling produce unrelated index.json
    # files at repo roots). ``--pipeline oci`` still auto-resolves
    # ``index.json`` when explicitly selected; multi-provider runs
    # that want OCI in scope use ``--pipelines github,oci``.
    ("helm", ("Chart.yaml",), ()),
    ("kubernetes", (), ("kubernetes", "k8s", "manifests")),
)


def _provider_present(files: tuple[str, ...], dirs: tuple[str, ...]) -> bool:
    return any(os.path.isfile(f) for f in files) or any(os.path.isdir(d) for d in dirs)


def _detect_pipeline_from_cwd() -> str | None:
    """Return the best-guess pipeline name based on files present at cwd.

    First match wins. Returns None when nothing recognizable is found;
    the caller then falls back to ``aws`` (preserves prior default).
    """
    for name, files, dirs in _PROVIDER_DETECT_FILES:
        if _provider_present(files, dirs):
            return name
    return None


def _detect_all_pipelines_from_cwd() -> list[str]:
    """Return every provider whose canonical path is present at cwd.

    Used by the no-args / ``--pipeline auto`` flow to switch into
    multi-provider mode automatically when a repo carries more than
    one pipeline-shape file (e.g. ``.github/workflows`` and a
    ``Dockerfile``). Order follows :data:`_PROVIDER_DETECT_FILES` so
    multi-mode runs sub-scanners in a stable, repeatable sequence.

    Helm / Kubernetes disambiguation: a Helm chart's templates often
    sit under ``charts/`` next to a ``Chart.yaml``, so when both helm
    and kubernetes match at cwd, kubernetes is dropped to avoid
    rendering the same charts twice (helm renders templates and
    feeds them to the K8s rule pack already).
    """
    detected: list[str] = []
    for name, files, dirs in _PROVIDER_DETECT_FILES:
        if _provider_present(files, dirs):
            detected.append(name)
    if "helm" in detected and "kubernetes" in detected:
        detected.remove("kubernetes")
    return detected


# ── Inline ignore collection ─────────────────────────────────────────────

#: Maps provider names to (glob_patterns, base_path_kwarg). When a
#: provider is active, the glob patterns are expanded relative to the
#: provider's resolved path (or cwd) to find files that may carry
#: inline ``# pipeline-check: ignore[...]`` comments.
_INLINE_IGNORE_GLOBS: dict[str, tuple[str, ...]] = {
    "github": ("*.yml", "*.yaml"),
    "gitlab": ("*.yml", "*.yaml"),
    "bitbucket": ("*.yml", "*.yaml"),
    "azure": ("*.yml", "*.yaml"),
    "circleci": ("*.yml", "*.yaml"),
    "cloudbuild": ("*.yml", "*.yaml"),
    "buildkite": ("*.yml", "*.yaml"),
    "drone": ("*.yml", "*.yaml"),
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
    "gitlab": "gitlab_path",
    "bitbucket": "bitbucket_path",
    "azure": "azure_path",
    "jenkins": "jenkinsfile_path",
    "circleci": "circleci_path",
    "cloudbuild": "cloudbuild_path",
    "buildkite": "buildkite_path",
    "drone": "drone_path",
    "tekton": "tekton_path",
    "argo": "argo_path",
    "argocd": "argocd_path",
    "cloudformation": "cfn_template",
    "dockerfile": "dockerfile_path",
    "kubernetes": "k8s_path",
    "helm": "helm_path",
    "terraform": "tf_source",
    "npm": "npm_path",
    "pypi": "pypi_path",
    "maven": "maven_path",
    "nuget": "nuget_path",
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
                    text = open(filepath, encoding="utf-8").read()
                except OSError:
                    continue
                try:
                    rel = os.path.relpath(filepath).replace("\\", "/")
                except ValueError:
                    rel = filepath.replace("\\", "/")
                all_rules.extend(extract_inline_ignores(rel, text))
    return build_inline_index(all_rules)


_CHECK_IDS_CACHE: list[str] | None = None
_KNOWN_ATTACKED_IDS_CACHE: list[str] | None = None


def _known_attacked_check_ids() -> list[str]:
    """Collect check IDs whose ``Rule.incident_refs`` is non-empty.

    The ``--only-known-attacked`` filter (zizmor proposal #1135)
    narrows the rule set to rules whose detection shape is anchored
    to a documented real-world incident, CVE, or vendor disclosure.
    Useful for burning down the incident-driven worklist on a fresh
    repo without the full pack noise.

    Cached after the first call. AWS / Terraform class-based checks
    don't currently carry ``Rule.incident_refs`` (their metadata
    lives in module docstrings); they're omitted from the filter
    surface today.
    """
    global _KNOWN_ATTACKED_IDS_CACHE
    if _KNOWN_ATTACKED_IDS_CACHE is not None:
        return _KNOWN_ATTACKED_IDS_CACHE
    ids: list[str] = []
    from pathlib import Path
    checks_root = Path(__file__).parent / "core" / "checks"
    rule_pkgs = sorted(
        f"pipeline_check.core.checks.{p.parent.parent.name}.rules"
        for p in checks_root.glob("*/rules/__init__.py")
    )
    for pkg in rule_pkgs:
        try:
            from .core.checks.rule import discover_rules
            for rule, _ in discover_rules(pkg):
                if rule.incident_refs:
                    ids.append(rule.id)
        except Exception as exc:
            _completion_debug(f"known-attacked-discover {pkg}", exc)
    _KNOWN_ATTACKED_IDS_CACHE = ids
    return ids


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
    # Rule-based providers, each has a rules/ package with RULE.id.
    # Derive the package list from the filesystem so adding a new
    # provider under ``pipeline_check/core/checks/<name>/rules/``
    # automatically surfaces in ``--list-checks`` / ``--explain`` /
    # autocomplete. Class-based AWS / Terraform IDs are scanned by
    # the regex pass below; ``set`` deduplication catches any overlap.
    from pathlib import Path
    checks_root = Path(__file__).parent / "core" / "checks"
    rule_pkgs = sorted(
        f"pipeline_check.core.checks.{p.parent.parent.name}.rules"
        for p in checks_root.glob("*/rules/__init__.py")
    )
    for pkg in rule_pkgs:
        try:
            from .core.checks.rule import discover_rules
            for rule, _ in discover_rules(pkg):
                ids.append(rule.id)
        except Exception as exc:
            _completion_debug(f"rule-discover {pkg}", exc)
    # AWS / Terraform, class-based checks with hardcoded check_id strings.
    _id_re = re.compile(r'check_id="([A-Z]+-\d+)"')
    for provider_pkg_name in (
        "pipeline_check.core.checks.aws",
        "pipeline_check.core.checks.terraform",
    ):
        try:
            import importlib
            import pkgutil
            # Distinct from the ``pkg`` loop variables earlier (lines
            # 264, 378) which iterate over strings, the inferred
            # ``str`` type would conflict with this Module assignment.
            provider_pkg_module = importlib.import_module(provider_pkg_name)
            for info in pkgutil.iter_modules(provider_pkg_module.__path__):
                mod = importlib.import_module(f"{provider_pkg_name}.{info.name}")
                if mod.__file__:
                    with open(mod.__file__, encoding="utf-8") as fh:
                        ids.extend(_id_re.findall(fh.read()))
        except Exception as exc:
            _completion_debug(f"id-scan {provider_pkg_name}", exc)
    ids = sorted(set(ids))
    _CHECK_IDS_CACHE = ids
    return ids


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
    policies = discover_policies()
    if not policies:
        click.echo(
            "[list-policies] no policies found. Searched: "
            + ", ".join(POLICY_DIRS),
            err=True,
        )
        ctx.exit(3)
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


@click.command(cls=_GroupedCommand, epilog=(
    "Subcommands:\n"
    "  init    Scaffold a starter .pipeline-check.yml in the current directory."
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
        "./.pipeline-check/policies/<NAME>.yml. Policies bundle a "
        "rule filter, standards filter, gate thresholds, and "
        "per-rule severity overrides into a single file. Values "
        "become click defaults: explicit CLI flags, env vars, and "
        "the config file override them. Run --list-policies to see "
        "what's available. A NAME with a path separator is treated "
        "as a literal path."
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
        "--argo-path, --argocd-path, --oci-manifest, --drone-path, --npm-path, "
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
    "--resolve-remote/--no-resolve-remote",
    "resolve_remote",
    default=False,
    show_default=True,
    help=(
        "Follow ``jobs.<id>.uses: owner/repo/.github/workflows/x.yml@<sha>`` "
        "to the called workflow body and run the GHA rule pack against "
        "it with the caller's permissions context. Default off, the "
        "scanner stays read-from-disk-only by default. When off and a "
        "remote ref is encountered, a one-line stderr warning lists "
        "the count so users know what they're missing."
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
    "--no-cache",
    "no_cache",
    is_flag=True,
    default=False,
    help=(
        "Bypass the on-disk resolver cache "
        "(~/.cache/pipeline-check/gha-resolver) for this scan. "
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
            "terminal", "json", "html", "sarif", "junit",
            "markdown", "threatmodel", "both",
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
        "Optional for --output json/sarif/junit/markdown/threatmodel "
        "(stdout is used if unset). Ignored for --output terminal "
        "and --output both (the latter always writes JSON to stdout)."
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
        "findings the scanner is certain about; MEDIUM = includes "
        "well-known heuristics; LOW (default) = includes blob-search "
        "patterns that have FP modes. For CI gates that only block "
        "on high-signal evidence, pass ``--min-confidence HIGH``."
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
        "Include passed checks in the terminal table. Off by default "
        "so the table focuses on failures; the headline still shows "
        "the failed-vs-passed counts. Passed findings always appear "
        "in JSON / SARIF / JUnit outputs regardless of this flag."
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
    tf_plan: str | None,
    tf_source: str | None,
    gha_path: str | None,
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
    helm_values: tuple[str, ...],
    helm_set: tuple[str, ...],
    oci_manifest: str | None,
    drone_path: str | None,
    scm_platform: str | None,
    scm_repo: str | None,
    scm_fixture_dir: str | None,
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
    explain_id: str | None,
    ai_explain_id: str | None,
    ai_model_spec: str | None,
    ai_context_file: str | None,
    config_check: bool,
    severity_threshold: str,
    min_confidence: str,
    fail_on: str | None,
    min_grade: str | None,
    max_failures: int | None,
    fail_on_checks: tuple[str, ...],
    secret_patterns: tuple[str, ...],
    detect_entropy: bool,
    fix: str | None,
    apply_fixes: bool,
    baseline_from_git: str | None,
    diff_base: str | None,
    pr_diff: str | None,
    baseline: str | None,
    write_baseline: str | None,
    ignore_file: str | None,
    no_inline_ignore: bool,
    custom_rules: tuple[str, ...],
    verbose: bool,
    quiet: bool,
    show_controls: bool,
    show_passed: bool,
    no_group: bool,
    no_chains: bool,
    chains_require_reachability: bool,
    list_chains: bool,
    annotate_fp: tuple[str, str] | None,
    fp_path: str | None,
    explain_chain_id: str | None,
    fail_on_chain_ids: tuple[str, ...],
    fail_on_any_chain: bool,
    serve: bool = False,
    resolve_remote: bool = False,
    gh_token: str | None = None,
    no_cache: bool = False,
    verify_secrets: bool = False,
    verify_secrets_show_identity: bool = False,
    gha_search_paths: tuple[str, ...] = (),
    gha_resolve_depth: int = 3,
) -> None:
    """Pipeline-Check. CI/CD Security Posture Scanner.

    Analyzes CI/CD configurations and scores them against the
    OWASP Top 10 CI/CD Security Risks framework.
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
        return

    if list_standards:
        for std in _standards.resolve():
            click.echo(f"{std.name} ,  {std.title} (v{std.version or 'n/a'})")
            if std.url:
                click.echo(f"    {std.url}")
        return

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
        return

    if list_checks:
        _list_checks_for_pipeline(pipeline.lower())
        return

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
        return

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
        return

    if config_check:
        from .core.config import last_unknown_keys
        dropped = last_unknown_keys()
        if not dropped:
            click.echo("[config] OK, no unknown keys.")
            return
        for source, key, reason in dropped:
            click.echo(f"[config] {source}: {key!r}, {reason}", err=True)
        click.echo(f"[config] {len(dropped)} unknown key(s) detected.", err=True)
        raise click.exceptions.Exit(3)

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
        raise click.UsageError(f"--baseline file not found: {baseline}")

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
    for pipeline_lc in pipelines_to_resolve:
        if pipeline_lc == "terraform":
            if tf_plan and tf_source:
                raise click.UsageError(
                    "--tf-plan and --tf-source are mutually exclusive."
                )
            if tf_plan:
                tf_plan = _resolve_provider_path(
                    "terraform", flag="tf-plan", value=tf_plan,
                    validate_kind="file", not_found_label="path",
                )
            elif tf_source:
                tf_source = _resolve_provider_path(
                    "terraform", flag="tf-source", value=tf_source,
                    validate_kind="dir", not_found_label="directory",
                )
            elif os.path.isfile("main.tf"):
                tf_source = "."
                click.echo(
                    "[auto] using --tf-source . (main.tf detected)",
                    err=True,
                )
        elif pipeline_lc == "github":
            gha_path = _resolve_provider_path(
                "github", flag="gha-path", value=gha_path,
                candidates=(".github/workflows",), candidate_kind="dir",
                validate_kind="dir", detect_label=".github/workflows",
                not_found_label="directory",
            )
        elif pipeline_lc == "gitlab":
            gitlab_path = _resolve_provider_path(
                "gitlab", flag="gitlab-path", value=gitlab_path,
                candidates=(".gitlab-ci.yml",),
                detect_label=".gitlab-ci.yml",
            )
        elif pipeline_lc == "bitbucket":
            bitbucket_path = _resolve_provider_path(
                "bitbucket", flag="bitbucket-path", value=bitbucket_path,
                candidates=("bitbucket-pipelines.yml",),
                detect_label="bitbucket-pipelines.yml",
            )
        elif pipeline_lc == "azure":
            azure_path = _resolve_provider_path(
                "azure", flag="azure-path", value=azure_path,
                candidates=("azure-pipelines.yml",),
                detect_label="azure-pipelines.yml",
            )
        elif pipeline_lc == "jenkins":
            jenkinsfile_path = _resolve_provider_path(
                "jenkins", flag="jenkinsfile-path", value=jenkinsfile_path,
                candidates=("Jenkinsfile",),
                detect_label="Jenkinsfile",
            )
        elif pipeline_lc == "circleci":
            circleci_path = _resolve_provider_path(
                "circleci", flag="circleci-path", value=circleci_path,
                candidates=(".circleci/config.yml",),
                detect_label=".circleci/config.yml",
            )
        elif pipeline_lc == "cloudformation":
            if not cfn_template:
                for _candidate in (
                    "template.yml", "template.yaml", "template.json",
                    "cloudformation.yml", "cloudformation.yaml",
                    "cfn.yml", "cfn.yaml",
                ):
                    if os.path.isfile(_candidate):
                        cfn_template = _candidate
                        click.echo(
                            f"[auto] using --cfn-template {cfn_template}",
                            err=True,
                        )
                        break
            if not cfn_template:
                raise click.UsageError(
                    "--cfn-template PATH is required when --pipeline "
                    "cloudformation (no template.yml / template.json / "
                    "cloudformation.yml / cfn.yaml found in the current "
                    "directory)."
                )
            if not os.path.exists(cfn_template):
                raise click.UsageError(
                    f"--cfn-template not found: {cfn_template}"
                )
            # Distinguish "directory but no templates" from "file not found" —
            # the former is a common mistake when someone points the flag at
            # their project root instead of an infrastructure subdirectory.
            if os.path.isdir(cfn_template):
                _exts = (".yml", ".yaml", ".json", ".template")
                has_templates = any(
                    _ent.is_file() and _ent.name.lower().endswith(_exts)
                    for _ent in os.scandir(cfn_template)
                )
                if not has_templates:
                    raise click.UsageError(
                        f"--cfn-template directory {cfn_template!r} contains "
                        f"no .yml / .yaml / .json / .template files."
                    )
        elif pipeline_lc == "cloudbuild":
            cloudbuild_path = _resolve_provider_path(
                "cloudbuild", flag="cloudbuild-path", value=cloudbuild_path,
                candidates=("cloudbuild.yaml", "cloudbuild.yml"),
                detect_label="cloudbuild.yaml/cloudbuild.yml",
            )
        elif pipeline_lc == "buildkite":
            buildkite_path = _resolve_provider_path(
                "buildkite", flag="buildkite-path", value=buildkite_path,
                candidates=(".buildkite/pipeline.yml", ".buildkite/pipeline.yaml"),
                detect_label=".buildkite/pipeline.yml",
            )
        elif pipeline_lc == "tekton":
            tekton_path = _resolve_provider_path(
                "tekton", flag="tekton-path", value=tekton_path,
            )
        elif pipeline_lc == "argo":
            argo_path = _resolve_provider_path(
                "argo", flag="argo-path", value=argo_path,
            )
        elif pipeline_lc == "argocd":
            argocd_path = _resolve_provider_path(
                "argocd", flag="argocd-path", value=argocd_path,
            )
        elif pipeline_lc == "dockerfile":
            dockerfile_path = _resolve_provider_path(
                "dockerfile", flag="dockerfile-path", value=dockerfile_path,
                candidates=("Dockerfile", "Containerfile"),
                detect_label="Dockerfile/Containerfile",
            )
        elif pipeline_lc == "kubernetes":
            k8s_path = _resolve_provider_path(
                "kubernetes", flag="k8s-path", value=k8s_path,
                candidates=("kubernetes", "k8s", "manifests"),
                candidate_kind="dir",
                detect_label="kubernetes/, k8s/, or manifests/ directory",
            )
        elif pipeline_lc == "helm":
            if not helm_path:
                if os.path.isfile("Chart.yaml"):
                    helm_path = "."
                    click.echo("[auto] using --helm-path .", err=True)
                elif os.path.isdir("charts"):
                    helm_path = "charts"
                    click.echo("[auto] using --helm-path charts", err=True)
            if not helm_path:
                raise click.UsageError(
                    "--helm-path PATH is required when --pipeline helm "
                    "(no Chart.yaml or charts/ directory found in cwd)."
                )
            if not os.path.exists(helm_path):
                raise click.UsageError(
                    f"--helm-path not found: {helm_path}"
                )
            for vf in helm_values:
                if not os.path.isfile(vf):
                    raise click.UsageError(
                        f"--helm-values not found: {vf}"
                    )
        elif pipeline_lc == "oci":
            oci_manifest = _resolve_provider_path(
                "oci", flag="oci-manifest", value=oci_manifest,
                candidates=("index.json",),
                detect_label="index.json",
            )
        elif pipeline_lc == "drone":
            drone_path = _resolve_provider_path(
                "drone", flag="drone-path", value=drone_path,
                candidates=(".drone.yml", ".drone.yaml"),
                detect_label=".drone.yml/.drone.yaml",
            )
        elif pipeline_lc == "npm":
            npm_path = _resolve_provider_path(
                "npm", flag="npm-path", value=npm_path,
                candidates=("package.json", "package-lock.json"),
                detect_label="package.json/package-lock.json",
            )
        elif pipeline_lc == "pypi":
            pypi_path = _resolve_provider_path(
                "pypi", flag="pypi-path", value=pypi_path,
                candidates=("requirements.txt",),
                detect_label="requirements.txt",
            )
        elif pipeline_lc == "maven":
            maven_path = _resolve_provider_path(
                "maven", flag="maven-path", value=maven_path,
                candidates=("pom.xml",),
                detect_label="pom.xml",
            )
        elif pipeline_lc == "nuget":
            nuget_path = _resolve_provider_path(
                "nuget", flag="nuget-path", value=nuget_path,
                candidates=("Directory.Packages.props",),
                detect_label="Directory.Packages.props",
            )

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
        diff_base=diff_base,
        secret_patterns=secret_patterns or None,
        detect_entropy=detect_entropy,
        overrides=cli_overrides or None,
        custom_rules=list(custom_rules) or None,
        fp_annotations_path=fp_path,
        log=_debug if verbose else None,
        tf_plan=tf_plan,
        tf_source=tf_source,
        gha_path=gha_path,
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
        resolve_remote=resolve_remote,
        gh_token=gh_token,
        no_cache=no_cache,
        verify_secrets=verify_secrets,
        verify_secrets_show_identity=verify_secrets_show_identity,
        gha_search_paths=list(gha_search_paths),
        gha_resolve_depth=gha_resolve_depth,
        dockerfile_path=dockerfile_path,
        k8s_path=k8s_path,
        helm_path=helm_path,
        helm_values=list(helm_values) or None,
        helm_set=list(helm_set) or None,
        oci_manifest=oci_manifest,
        drone_path=drone_path,
        npm_path=npm_path,
        npm_base_ref=npm_base_ref,
        pypi_path=pypi_path,
        maven_path=maven_path,
        nuget_path=nuget_path,
        scm_platform=scm_platform,
        scm_repo=scm_repo,
        scm_fixture_dir=scm_fixture_dir,
    )

    scanner: Scanner | MultiScanner
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
            # Print the traceback to stderr so operators have something to
            # take to support. Keep the single-line summary above it for
            # teams that grep logs for "[error] Scan failed".
            import traceback
            click.echo(f"[error] Scan failed: {exc}", err=True)
            click.echo(traceback.format_exc(), err=True, nl=False)
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
            secret_patterns=secret_patterns,
            detect_entropy=detect_entropy,
            ignore_file=ignore_file,
            fp_path=fp_path,
            tf_plan=tf_plan,
            tf_source=tf_source,
            gha_path=gha_path,
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
            npm_path=npm_path,
            pypi_path=pypi_path,
            maven_path=maven_path,
            nuget_path=nuget_path,
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

    if not quiet and output in ("terminal", "both"):
        from rich.console import Console as _Console  # local import, only needed here
        console = _Console(stderr=(output == "both"))
        report_terminal(
            findings, score_result,
            severity_threshold=threshold, console=console,
            show_controls=show_controls,
            show_passed=show_passed,
            group_similar=not no_group,
        )
        if chains:
            report_chains_terminal(chains, console=console)
        if components is not None:
            report_inventory_terminal(components, console=console)

    if output in ("json", "both"):
        json_text = report_json(
            findings, score_result, tool_version=__version__,
            inventory=components,
            chains=chains if not no_chains else None,
        )
        if output == "json" and output_file:
            with open(output_file, "w", encoding="utf-8") as fh:
                fh.write(json_text)
            if not quiet:
                click.echo(f"JSON report written to {output_file}", err=True)
        elif not quiet:
            click.echo(json_text)

    if output == "html":
        report_html(
            findings, score_result, region=region, target=target or "",
            output_path=output_file, chains=chains,
        )
        if not quiet:
            click.echo(f"HTML report written to {output_file}", err=True)

    if output == "sarif":
        sarif_text = report_sarif(
            findings, score_result, tool_version=__version__, chains=chains,
        )
        if output_file:
            with open(output_file, "w", encoding="utf-8") as fh:
                fh.write(sarif_text)
            if not quiet:
                click.echo(f"SARIF report written to {output_file}", err=True)
        elif not quiet:
            click.echo(sarif_text)

    if output == "junit":
        junit_text = report_junit(findings, score_result)
        if output_file:
            with open(output_file, "w", encoding="utf-8") as fh:
                fh.write(junit_text)
            if not quiet:
                click.echo(f"JUnit report written to {output_file}", err=True)
        elif not quiet:
            click.echo(junit_text)

    if output == "markdown":
        md_text = report_markdown(findings, score_result, chains=chains)
        if output_file:
            with open(output_file, "w", encoding="utf-8") as fh:
                fh.write(md_text)
            if not quiet:
                click.echo(f"Markdown report written to {output_file}", err=True)
        elif not quiet:
            click.echo(md_text)

    if output == "threatmodel":
        tm_text = report_threatmodel(
            findings, score_result,
            inventory=components, chains=chains,
            tool_version=__version__,
            region=region or "", target=target or "",
        )
        if output_file:
            with open(output_file, "w", encoding="utf-8") as fh:
                fh.write(tm_text)
            if not quiet:
                click.echo(
                    f"Threat-model report written to {output_file}",
                    err=True,
                )
        elif not quiet:
            click.echo(tm_text)

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
            "gitlab_path": gitlab_path,
            "bitbucket_path": bitbucket_path,
            "azure_path": azure_path,
            "jenkinsfile_path": jenkinsfile_path,
            "circleci_path": circleci_path,
            "cloudbuild_path": cloudbuild_path,
            "buildkite_path": buildkite_path,
            "drone_path": drone_path,
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
        }
        inline_index = _collect_inline_ignores(active_pipelines, path_kwargs)

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

    gate = evaluate_gate(findings, score_result, gate_config, chains=chains)

    if not quiet and output != "json":
        _emit_gate_summary(
            gate,
            baseline_path=baseline,
            baseline_from_git=baseline_from_git,
        )

    if not gate.passed:
        raise click.exceptions.Exit(1)


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
    secret_patterns: tuple[str, ...],
    detect_entropy: bool,
    ignore_file: str | None,
    fp_path: str | None,
    tf_plan: str | None,
    tf_source: str | None,
    gha_path: str | None,
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
    npm_path: str | None,
    pypi_path: str | None,
    maven_path: str | None,
    nuget_path: str | None,
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
        ("--npm-path", npm_path),
        ("--pypi-path", pypi_path),
        ("--maven-path", maven_path),
        ("--nuget-path", nuget_path),
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


def _emit_fix_patches(findings: list[Any], *, to_stderr: bool = False, tier: str = "safe") -> None:
    """Emit one unified-diff patch per failing finding that has a fixer.

    Patches go to stdout by default so a user can pipe straight into
    ``git apply``. When a machine-readable report is already occupying
    stdout (``--output json/sarif/html/both``), the caller sets
    ``to_stderr=True`` to avoid corrupting that stream.

    File read errors are silently skipped, a missing file is almost
    always due to a finding with a synthetic resource name (e.g. an
    AWS check), not a real on-disk workflow. Per-path content is
    cached so multiple findings against the same file only re-read
    the source once.
    """
    import os
    cache: dict[str, str] = {}
    dirty: dict[str, str] = {}
    patch_count = 0
    patched_files: set[str] = set()
    for f in findings:
        if f.passed:
            continue
        path = f.resource
        if not path or not os.path.isfile(path):
            continue
        before = dirty[path] if path in dirty else cache.get(path)
        if before is None:
            try:
                with open(path, encoding="utf-8") as fh:
                    before = fh.read()
            except (OSError, UnicodeDecodeError):
                continue
            cache[path] = before
        try:
            after = _autofix.generate_fix(f, before, tier=tier)
        except Exception as exc:
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
        dirty[path] = after
    if patch_count:
        click.echo(
            f"[autofix] {patch_count} patch(es) for {len(patched_files)} file(s)."
            f" Run with --apply to modify in place.",
            err=True,
        )


def _apply_fix_patches(findings: list[Any], *, tier: str = "safe") -> None:
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
        before = dirty[path] if path in dirty else cache.get(path)
        if before is None:
            try:
                with open(path, encoding="utf-8") as fh:
                    before = fh.read()
            except (OSError, UnicodeDecodeError):
                continue
            cache[path] = before
        try:
            after = _autofix.generate_fix(f, before, tier=tier)
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


def _find_sibling_package_jsons(root: str, max_depth: int = 3) -> list[str]:
    """Return up to a handful of ``package.json`` paths under *root*.

    Bounded by ``max_depth`` and skipping the usual heavy directories
    (``node_modules`` chief among them — a single transitive install
    can land tens of thousands of nested ``package.json`` files, and
    none of them belong to the consuming repo). Used by the
    npm-alongside-github hint so the scanner can nudge users who
    invoke ``--pipeline github`` alone in a repo that also ships
    JavaScript code.
    """
    skip_dirs: frozenset[str] = frozenset({
        "node_modules", ".git", "vendor", "dist", "build",
        ".venv", "venv", "__pycache__", ".tox", ".mypy_cache",
        ".pytest_cache", "target",
    })
    hits: list[str] = []
    root_abs = os.path.abspath(root)
    root_depth = root_abs.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root_abs):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        if dirpath.count(os.sep) - root_depth > max_depth:
            dirnames[:] = []
            continue
        if "package.json" in filenames:
            hits.append(os.path.join(dirpath, "package.json"))
            if len(hits) >= 5:
                break
    return hits


def _maybe_emit_npm_alongside_github_hint(
    pipelines_resolved: list[str],
    findings: list[Any],
) -> None:
    """Nudge the user when ``--pipeline github`` scanned a tree that
    also ships ``package.json`` files.

    The npm provider catches dependency-confusion / floating-range /
    lockfile-integrity issues that the github pipeline can't see (it
    only inspects workflow YAML, not the consumed manifests). Fires
    only on single-provider ``--pipeline github`` invocations where
    a quick depth-bounded walk of cwd finds a ``package.json``
    outside ``node_modules`` / build / vendor directories. Off when
    the user explicitly multi-provider-ran ``github,npm`` (the npm
    coverage is already in scope).
    """
    if pipelines_resolved != ["github"]:
        return
    pjs = _find_sibling_package_jsons(".")
    if not pjs:
        return
    def _safe_relpath(p: str) -> str:
        try:
            return os.path.relpath(p)
        except ValueError:
            return p

    sample = ", ".join(_safe_relpath(p) for p in pjs[:3])
    more = "" if len(pjs) <= 3 else f" (+{len(pjs) - 3} more)"
    # One ``package.json`` at the repo root resolves via the npm
    # provider's own cwd auto-detection (``pipeline_check --pipeline
    # npm`` without ``--npm-path``); multiple or nested manifests need
    # an explicit ``--npm-path <dir>`` per manifest, so the hint
    # surfaces the directory the user would point at.
    pj_dirs = sorted({
        _safe_relpath(os.path.dirname(p)) or "." for p in pjs
    })
    if len(pj_dirs) == 1 and pj_dirs[0] in (".", ""):
        suggestion = (
            "rerun with ``--pipelines github,npm`` to also scan the "
            "manifest"
        )
    else:
        dir_sample = ", ".join(pj_dirs[:3])
        suggestion = (
            f"rerun with ``--pipeline npm --npm-path <dir>`` for each "
            f"({dir_sample})"
        )
    click.echo(
        f"[hint] this repo also ships package.json files ({sample}"
        f"{more}). ``--pipeline github`` only inspects workflow "
        f"YAML; {suggestion} for dependency-confusion / "
        f"lockfile-integrity / floating-range coverage.",
        err=True,
    )


def _maybe_emit_wrong_provider_hint(pipeline_lc: str, findings: list[Any]) -> None:
    """Nudge the user when AWS was scanned but a CI config file exists.

    Fires only when the caller explicitly picked ``--pipeline aws`` (or
    configured it) AND every finding is a degraded ``*-000`` API-access
    probe AND cwd looks like a CI repo. Designed to catch the common
    'wrong credentials / wrong provider' first-run mistake without
    spamming legitimate AWS runs.
    """
    if pipeline_lc != "aws" or not findings:
        return
    if not all(getattr(f, "check_id", "").endswith("-000") for f in findings):
        return
    detected = _detect_pipeline_from_cwd()
    if not detected:
        return
    click.echo(
        f"[hint] no real AWS results. This looks like a '{detected}' "
        f"repo; try: pipeline_check --pipeline {detected}",
        err=True,
    )


def _maybe_emit_degraded_scan_warning(findings: list[Any]) -> None:
    """Surface a ``[warn]`` line when degraded-mode findings dominate.

    Every AWS module emits a single ``<PREFIX>-000`` INFO-severity
    finding when its boto3 enumeration fails (missing credentials,
    AccessDenied, throttling). Those findings are NOT security gaps —
    they're tool-status — but they still render as "FAIL" rows in the
    table, and they don't count toward the score (INFO is ignored by
    the weighted formula), so a fully-degraded scan can confusingly
    display "Score 100 / Grade A" right next to fourteen FAIL rows.

    This helper bridges that gap: when ``>0`` degraded-mode findings
    exist, emit a stderr ``[warn]`` line listing how many modules
    failed API access so the operator knows the score reflects only
    the modules that actually returned data.
    """
    degraded = [
        f for f in findings
        if getattr(f, "check_id", "").endswith("-000")
        and not getattr(f, "passed", True)
    ]
    if not degraded:
        return
    n = len(degraded)
    click.echo(
        f"[warn] scan degraded: {n} module(s) failed API access. The "
        f"score reflects only the modules that returned data; run "
        f"with --verbose to see which modules were skipped.",
        err=True,
    )


def _emit_scan_summary(meta: Any) -> None:
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


def _build_gate_trailer(
    gate: Any,
    *,
    baseline_path: str | None,
    baseline_from_git: str | None,
) -> str | None:
    """Construct the one-line "what next" hint for a failing gate.

    Picks the most actionable suggestion based on the failing set:
    autofix when at least one finding has a registered fixer,
    otherwise a baseline-write when none was provided, otherwise
    point the user at ``explain`` for the highest-severity failure.
    """
    effective = list(gate.effective)
    if not effective:
        return None
    from .core.autofix import available_fixers
    fixers = set(available_fixers())
    fixable = [f for f in effective if f.check_id.upper() in fixers]
    n_total = len(effective)
    if fixable:
        message = (
            f"{len(fixable)} of {n_total} failing findings "
            f"are autofixable; run `pipeline_check --fix --apply` to apply them"
        )
    elif not baseline_path and not baseline_from_git:
        message = (
            "no baseline configured; run `pipeline_check "
            "--write-baseline baseline.json` then pair with "
            "`--baseline baseline.json` to gate only on new findings"
        )
    else:
        from .core.checks.base import severity_rank
        top = sorted(
            effective,
            key=lambda f: (-severity_rank(f.severity), f.check_id),
        )[0]
        message = (
            f"start with the highest-severity rule: "
            f"`pipeline_check explain {top.check_id}`"
        )
    return f"[gate] next: {message}"


def _emit_gate_summary(
    gate: Any,
    *,
    baseline_path: str | None = None,
    baseline_from_git: str | None = None,
) -> None:
    """Render the gate outcome to stderr so JSON/SARIF on stdout stays clean.

    When the gate fails, also emit a single-line "what next" trailer:
    how many of the failing findings have autofixers, and the
    one-command path to close the loop (fix-and-apply, baseline-write,
    or explain-the-rule). The trailer is intentionally short so a CI
    log scan picks it up without scrolling.
    """
    n_effective = len(gate.effective)
    n_chains_tripped = len(getattr(gate, "tripped_chains", []) or [])
    if gate.passed:
        msg_lines = [f"[gate] PASS ({n_effective} effective finding(s) evaluated)"]
        for cond in getattr(gate, "conditions_evaluated", []):
            msg_lines.append(f"        - {cond}")
    else:
        msg_lines = ["[gate] FAIL"]
        for reason in gate.reasons:
            msg_lines.append(f"        - {reason}")
        trailer = _build_gate_trailer(
            gate,
            baseline_path=baseline_path,
            baseline_from_git=baseline_from_git,
        )
        if trailer:
            msg_lines.append(trailer)
    if n_chains_tripped:
        ids = ", ".join(sorted({c.chain_id for c in gate.tripped_chains}))
        msg_lines.append(f"[gate] {n_chains_tripped} attack chain(s) tripped: {ids}")
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
    if gate.expiring_soon:
        # Forewarn before expiry so the team schedules a revisit
        # rather than discovering the lapsed suppression in CI.
        for r in gate.expiring_soon:
            scope = f":{r.resource}" if r.resource else ""
            days = r.days_until_expiry()
            day_word = "day" if days == 1 else "days"
            when = "today" if days == 0 else f"in {days} {day_word}"
            msg_lines.append(
                f"[gate] ignore rule expires {when} on {r.expires}: "
                f"{r.check_id}{scope} (still suppressing, but plan to revisit)"
            )
    for line in msg_lines:
        click.echo(line, err=True)


# ────────────────────────────────────────────────────────────────────────────
# `init` subcommand, scaffold a starter config file.
# ────────────────────────────────────────────────────────────────────────────


#: Cwd-relative paths each provider needs to find its target files when
#: ``init`` constructs a Scanner with no flags. Keys must match the
#: names returned by :func:`_detect_pipeline_from_cwd`. Each value is a
#: tuple of ``(scanner_kwarg, candidate_paths)``; init picks the first
#: candidate that exists. Providers that need credentials or a remote
#: target the scaffold can't guess (AWS, oci, scm) are listed in
#: :data:`_INIT_SKIP_PROVIDERS` instead and bypass the scan entirely.
_INIT_SCANNER_KWARGS: dict[str, tuple[str, tuple[str, ...]]] = {
    "github": ("gha_path", (".github/workflows",)),
    "gitlab": ("gitlab_path", (".gitlab-ci.yml",)),
    "bitbucket": ("bitbucket_path", ("bitbucket-pipelines.yml",)),
    "azure": ("azure_path", ("azure-pipelines.yml",)),
    "jenkins": ("jenkinsfile_path", ("Jenkinsfile",)),
    "circleci": ("circleci_path", (".circleci/config.yml",)),
    "cloudbuild": ("cloudbuild_path", ("cloudbuild.yaml", "cloudbuild.yml")),
    "buildkite": (
        "buildkite_path",
        (".buildkite/pipeline.yml", ".buildkite/pipeline.yaml"),
    ),
    "drone": ("drone_path", (".drone.yml", ".drone.yaml")),
    "dockerfile": ("dockerfile_path", ("Dockerfile", "Containerfile")),
    "kubernetes": ("k8s_path", ("kubernetes", "k8s", "manifests")),
    "helm": ("helm_path", (".",)),
    "npm": ("npm_path", (".",)),
    "pypi": ("pypi_path", (".",)),
    "maven": ("maven_path", ("pom.xml",)),
    "cloudformation": (
        "cfn_template",
        (
            "template.yml", "template.yaml", "template.json",
            "cloudformation.yml", "cloudformation.yaml",
            "cfn.yml", "cfn.yaml",
        ),
    ),
}

#: Providers that smart-init can detect but not scan unattended (live
#: cloud credentials, registry pulls, GitHub admin tokens). For these,
#: the CLI writes a static scaffold and skips the scan instead of
#: surfacing a confusing "scan failed" exception in stderr.
_INIT_SKIP_PROVIDERS: frozenset[str] = frozenset({"aws", "oci", "scm"})


def _init_scanner_kwargs_for(detected: str) -> dict[str, Any]:
    """Return Scanner constructor kwargs for the smart-init flow.

    Returns ``{}`` when the provider doesn't need a path. Callers
    should still try to construct the Scanner; if it fails, the caller
    falls back to writing a static scaffold.

    Return type is ``dict[str, Any]`` because the Scanner constructor
    type-checks each kwarg against its named parameter (a path string
    is fine for ``gha_path``, but mypy reads ``dict[str, str]`` as
    "every kwarg is ``str``" and trips on the unrelated keyword
    parameters that share its dict signature).
    """
    entry = _INIT_SCANNER_KWARGS.get(detected)
    if entry is None:
        return {}
    kwarg, candidates = entry
    for candidate in candidates:
        if os.path.exists(candidate):
            return {kwarg: candidate}
    return {}


@click.command(name="init")
@click.option(
    "--path",
    "target_path",
    default=".pipeline-check.yml",
    show_default=True,
    metavar="PATH",
    help="Write the scaffold to this path.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Overwrite the target file if it already exists.",
)
@click.option(
    "--no-scan",
    "no_scan",
    is_flag=True,
    default=False,
    help=(
        "Skip the one-shot scan and write a static scaffold instead. Use "
        "when you want the bare template with no recommended gate / "
        "baseline."
    ),
)
@click.option(
    "--baseline-path",
    "baseline_path",
    default=None,
    metavar="PATH",
    help=(
        "Where to write the baseline JSON. Defaults to "
        "``.pipeline-check-baseline.json``. Ignored with --no-scan."
    ),
)
def init_cmd(
    target_path: str,
    force: bool,
    no_scan: bool,
    baseline_path: str | None,
) -> None:
    """Initialize pipeline_check in this repo: scan, baseline, scaffold.

    By default ``init`` runs one scan against whatever pipeline files
    it auto-detects, writes a baseline JSON capturing the current
    failing findings, and emits ``.pipeline-check.yml`` with a
    recommended ``gate.fail_on`` plus a baseline pointer so future CI
    runs only block on *new* regressions. Prints a "top 5 to fix"
    summary to stderr so the operator has a starting point.

    With ``--no-scan`` it falls back to the legacy behavior: write a
    commented-out scaffold only. ``--force`` overwrites an existing
    config file; existing baselines are always overwritten.
    """
    from .core.init_scan import (
        DEFAULT_BASELINE_PATH,
        build_init_scan_result,
    )
    from .core.init_template import render as _render_template

    if os.path.exists(target_path) and not force:
        raise click.UsageError(
            f"{target_path} already exists. Re-run with --force to overwrite."
        )

    detected = _detect_pipeline_from_cwd()

    if no_scan or detected is None or detected in _INIT_SKIP_PROVIDERS:
        # Either the user opted out, there's nothing to scan, or the
        # detected provider needs credentials / a remote target that
        # smart-init can't guess (AWS account, OCI registry, SCM
        # token). Fall back to the static scaffold so ``init`` still
        # does something useful.
        try:
            with open(target_path, "w", encoding="utf-8") as fh:
                fh.write(_render_template(detected))
        except OSError as exc:
            raise click.UsageError(
                f"could not write {target_path}: {exc}"
            ) from exc
        if no_scan:
            suffix = (
                f" (pipeline: {detected})"
                if detected
                else " (no CI files detected, edit the 'pipeline:' line "
                "before use)"
            )
        elif detected in _INIT_SKIP_PROVIDERS:
            suffix = (
                f" (pipeline: {detected}; this provider needs "
                f"credentials, smart-init skipped the scan. Run "
                f"`pipeline_check --pipeline {detected}` to scan once "
                f"those are set.)"
            )
        else:
            suffix = (
                " (no CI files detected; edit 'pipeline:' or rerun "
                "after adding one)"
            )
        click.echo(f"[init] wrote {target_path}{suffix}")
        return

    # Smart path: run a scan, write baseline + tuned config. Re-use
    # the module-level Scanner import so tests can patch
    # ``pipeline_check.cli.Scanner`` and have init see the mock.
    from .core.autofix import available_fixers

    bpath = baseline_path or DEFAULT_BASELINE_PATH

    click.echo(f"[init] scanning {detected!r} to tune the gate...", err=True)
    scanner_kwargs = _init_scanner_kwargs_for(detected)
    try:
        scanner = Scanner(pipeline=detected, **scanner_kwargs)
        findings = scanner.run()
    except Exception as exc:
        click.echo(
            f"[init] scan failed ({exc}); writing a static scaffold instead. "
            f"Rerun with --no-scan to skip the scan permanently.",
            err=True,
        )
        try:
            with open(target_path, "w", encoding="utf-8") as fh:
                fh.write(_render_template(detected))
        except OSError as inner:
            raise click.UsageError(
                f"could not write {target_path}: {inner}"
            ) from inner
        click.echo(f"[init] wrote {target_path} (pipeline: {detected})")
        return

    result = build_init_scan_result(
        findings,
        detected_pipeline=detected,
        tool_version=__version__,
        fixers=set(available_fixers()),
        baseline_path=bpath,
    )

    try:
        with open(target_path, "w", encoding="utf-8") as fh:
            fh.write(result.config_yaml)
    except OSError as exc:
        raise click.UsageError(
            f"could not write {target_path}: {exc}"
        ) from exc

    if result.has_failures:
        try:
            with open(bpath, "w", encoding="utf-8") as fh:
                fh.write(result.baseline_json)
        except OSError as exc:
            click.echo(
                f"[init] could not write baseline {bpath}: {exc}. Config "
                f"file is still written; remove the 'baseline:' line or "
                f"fix the path before running CI.",
                err=True,
            )

    _print_init_summary(result, target_path)


def _print_init_summary(result: Any, config_path: str) -> None:
    """Render the post-scan summary the smart-init flow prints to stderr."""
    click.echo(f"[init] wrote {config_path} (pipeline: {result.detected_pipeline})", err=True)
    if result.has_failures:
        click.echo(
            f"[init] wrote {result.baseline_path} "
            f"({result.failing_findings} failing finding(s) baselined)",
            err=True,
        )
    else:
        click.echo(
            "[init] no failing findings to baseline; gate runs against "
            "every future finding from a clean slate.",
            err=True,
        )
    click.echo(
        f"[init] score {result.score}/100, grade {result.grade}; "
        f"recommended gate: fail_on={result.recommended_fail_on.value}",
        err=True,
    )
    if result.top:
        click.echo("[init] top to fix first:", err=True)
        width = max(len(t.check_id) for t in result.top)
        for t in result.top:
            tag = " [autofix available]" if t.fixable else ""
            click.echo(
                f"        {t.check_id:<{width}}  {t.severity.value:<8}  "
                f"{t.title}  ({t.resource}){tag}",
                err=True,
            )
        click.echo(
            "[init] run `pipeline_check explain <ID>` for any of the above, "
            "or `pipeline_check --fix --apply` to apply autofixes.",
            err=True,
        )


# ────────────────────────────────────────────────────────────────────────────
# `explain` subcommand, render a per-check reference. Mirrors the
# behavior of ``pipeline_check --explain CHECK-ID`` but is a top-level
# verb, which is what new users reach for first ("explain X") and what
# the smart-init / gate-failure trailer point them at.
# ────────────────────────────────────────────────────────────────────────────


@click.command(name="explain")
@click.argument("check_id", required=False, metavar="CHECK_ID")
def explain_cmd(check_id: str | None) -> None:
    """Print the full reference for one check (severity, fix, controls).

    Equivalent to ``pipeline_check --explain CHECK_ID`` but more
    discoverable. Same exit-code contract: 0 when the ID is known, 3
    when it's not (with a "did you mean" list).
    """
    if not check_id:
        raise click.UsageError(
            "missing CHECK_ID. Example: pipeline_check explain GHA-001"
        )
    from .core.explain import print_explain
    raise click.exceptions.Exit(print_explain(check_id))


# ────────────────────────────────────────────────────────────────────────────
# `fp-stats` subcommand, print false-positive annotation totals.
# ────────────────────────────────────────────────────────────────────────────


@click.command(name="fp-stats")
@click.option(
    "--fp-file",
    "fp_path",
    default=None,
    metavar="PATH",
    help=(
        "Path to the false-positive annotation file. Defaults to "
        "``.pipeline-check-fp.json`` at cwd."
    ),
)
def fp_stats_cmd(fp_path: str | None) -> None:
    """Print rule -> FP-vote totals from the local annotation file.

    Surfaces which rules accumulate the most ``--annotate-fp``
    annotations across the repo so rule authors can prioritize
    triage. Rules with the highest counts are likely candidates for
    re-tuning, narrower heuristics, or a default-confidence
    demotion.
    """
    from .core.fp_annotations import (
        DEFAULT_FP_PATH,
        fp_stats,
        load_annotations,
    )

    path = fp_path or DEFAULT_FP_PATH
    annotations = load_annotations(path)
    if not annotations:
        click.echo(
            f"[fp-stats] no annotations found in {path} "
            f"(file missing or empty)",
            err=True,
        )
        return

    stats = fp_stats(annotations)
    width = max((len(cid) for cid, _ in stats), default=0)
    click.echo(f"[fp-stats] {len(annotations)} annotation(s) in {path}")
    for cid, count in stats:
        suffix = "vote" if count == 1 else "votes"
        click.echo(f"  {cid:<{width}}  {count} {suffix}")


# ────────────────────────────────────────────────────────────────────────────
# `history` subcommand, render a static-HTML findings-history dashboard.
# ────────────────────────────────────────────────────────────────────────────


@click.command(name="history")
@click.option(
    "--dir",
    "history_dir",
    default=".pipeline-check-history",
    metavar="PATH",
    show_default=True,
    help=(
        "Directory of timestamped scan-output JSON files (each "
        "produced by ``pipeline_check ... --output json "
        "--output-file scan-YYYYMMDD-HHMMSS.json``)."
    ),
)
@click.option(
    "--output",
    "output_path",
    default="pipeline-check-history.html",
    metavar="PATH",
    show_default=True,
    help="Destination for the rendered HTML dashboard.",
)
@click.option(
    "--top-rules",
    "top_n",
    default=15,
    show_default=True,
    type=click.IntRange(1, 100),
    help=(
        "Number of rules to show in the burn-down table (ranked by "
        "total failed findings across the history window)."
    ),
)
def history_cmd(history_dir: str, output_path: str, top_n: int) -> None:
    """Render a self-contained HTML dashboard from past scan outputs.

    Reads every ``*.json`` under ``--dir`` (default
    ``.pipeline-check-history/``), extracts a timestamp from each
    filename (``YYYYMMDD-HHMMSS`` or ``YYYY-MM-DD``; falls back to
    mtime), and writes one static HTML page with trend graphs and a
    top-N firing-rules burn-down. No JavaScript, no CDN, no web
    server — just a file the user can open locally, email, or commit.
    """
    from pathlib import Path

    from .core.history import load_history, render_html

    try:
        report = load_history(history_dir)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    html = render_html(report, top_n=top_n)
    out = Path(output_path)
    try:
        out.write_text(html, encoding="utf-8")
    except OSError as exc:
        raise click.UsageError(
            f"[history] could not write {out}: {exc}"
        ) from exc
    click.echo(
        f"[history] {len(report.snapshots)} snapshot(s) -> {out} "
        f"({len(report.warnings)} warning(s))"
    )
    for w in report.warnings:
        click.echo(f"  warn: {w}", err=True)


# ────────────────────────────────────────────────────────────────────────────
# `fleet` subcommand, scan a list of repos and emit a unified digest.
# ────────────────────────────────────────────────────────────────────────────


@click.command(name="fleet")
@click.option(
    "--repos",
    "repos_path",
    default=None,
    metavar="PATH",
    help=(
        "YAML file with repo coordinates. Entries can be bare "
        "'owner/repo' (GitHub), prefixed 'gitlab:group/project', "
        "or mappings with 'coord' + 'platform' keys."
    ),
)
@click.option(
    "--from-org",
    "from_org",
    default=None,
    metavar="ORG",
    help=(
        "Enumerate repos from an org/group/workspace via the SCM "
        "API. Requires a platform token in the environment "
        "(GITHUB_TOKEN, GITLAB_TOKEN, or BITBUCKET_TOKEN). "
        "Mutually exclusive with --repos."
    ),
)
@click.option(
    "--platform",
    "platform",
    default="github",
    show_default=True,
    type=click.Choice(["github", "gitlab", "bitbucket"]),
    help="SCM platform for --from-org enumeration.",
)
@click.option(
    "--include",
    "include_patterns",
    multiple=True,
    metavar="GLOB",
    help=(
        "Include only repos whose name matches this glob "
        "(repeatable, fnmatch syntax). Applied after repo discovery."
    ),
)
@click.option(
    "--exclude",
    "exclude_patterns",
    multiple=True,
    metavar="GLOB",
    help=(
        "Exclude repos whose name matches this glob "
        "(repeatable, fnmatch syntax). Applied after repo discovery."
    ),
)
@click.option(
    "--output-dir",
    "output_dir",
    default="fleet-out",
    show_default=True,
    metavar="PATH",
    help=(
        "Directory for the unified digest tree. Per-repo findings "
        "land at <output-dir>/<platform>/<owner>/<repo>/findings.json; "
        "the aggregate is at <output-dir>/fleet.json + fleet.md."
    ),
)
@click.option(
    "--per-repo-timeout",
    "timeout_sec",
    default=600,
    show_default=True,
    type=click.IntRange(30, 3600),
    help=(
        "Maximum seconds to spend on any single repo (clone + scan "
        "combined). A repo that exceeds this surfaces as a "
        "warning in the digest and the run continues with the "
        "remaining repos."
    ),
)
@click.option(
    "--jobs",
    "jobs",
    default=None,
    type=click.IntRange(0, 32),
    metavar="N",
    help=(
        "Number of repos to scan in parallel. "
        "0 runs sequentially (useful for debugging). "
        "Omit to auto-detect based on CPU count and repo count."
    ),
)
@click.option(
    "--scan-flags",
    "scan_flags_str",
    default=None,
    metavar="FLAGS",
    help=(
        "Extra flags forwarded verbatim to each per-repo "
        "pipeline_check subprocess, e.g. "
        "'--standard owasp_cicd_top_10 --resolve-remote'. "
        "Quote the whole value as a single string."
    ),
)
def fleet_cmd(
    repos_path: str | None,
    from_org: str | None,
    platform: str,
    include_patterns: tuple[str, ...],
    exclude_patterns: tuple[str, ...],
    output_dir: str,
    timeout_sec: int,
    jobs: int | None,
    scan_flags_str: str | None,
) -> None:
    """Scan a list of repositories and emit a unified posture digest.

    Each coordinate is shallow-cloned to a tmpdir, scanned via a
    fresh ``pipeline_check`` subprocess, and the per-repo findings
    plus a fleet-wide digest land under ``--output-dir``. A single
    repo's clone / scan failure becomes a warning, not an abort.
    """
    import shlex
    from pathlib import Path

    from .core.fleet import (
        apply_filters,
        default_worker_count,
        enumerate_org_repos,
        load_repo_list,
        run_fleet,
    )

    if repos_path and from_org:
        raise click.UsageError(
            "--repos and --from-org are mutually exclusive."
        )
    if not repos_path and not from_org:
        raise click.UsageError(
            "Provide either --repos or --from-org."
        )
    if from_org:
        try:
            repos = enumerate_org_repos(from_org, platform)
        except ValueError as exc:
            raise click.UsageError(str(exc)) from exc
    else:
        assert repos_path is not None
        try:
            repos = load_repo_list(repos_path)
        except ValueError as exc:
            raise click.UsageError(str(exc)) from exc
    if include_patterns or exclude_patterns:
        repos = apply_filters(
            repos,
            include=list(include_patterns) or None,
            exclude=list(exclude_patterns) or None,
        )
    if not repos:
        source = repos_path if repos_path else f"--from-org {from_org}"
        raise click.UsageError(
            f"[fleet] {source} yielded no repo coordinates."
        )
    out_dir = Path(output_dir)
    scan_flags = shlex.split(scan_flags_str) if scan_flags_str else None
    effective_jobs = jobs if jobs is not None else default_worker_count(len(repos))
    digest = run_fleet(
        repos, out_dir,
        timeout_sec=timeout_sec,
        jobs=effective_jobs,
        scan_flags=scan_flags,
    )
    ok = sum(1 for s in digest.snapshots if s.ok)
    click.echo(
        f"[fleet] scanned {len(digest.snapshots)} repo(s) "
        f"({ok} OK, {len(digest.snapshots) - ok} errored) -> "
        f"{out_dir}/fleet.md"
    )
    for w in digest.warnings:
        click.echo(f"  warn: {w}", err=True)


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
    scan()
