"""Informational early-exit command handlers.

The ``--list-checks`` / ``--list-chains`` / ``--explain-chain`` /
``--standard-report`` handlers: each renders a registry view to stdout
and exits, without running a scan. Extracted from ``cli.py`` to keep
that module focused on argument wiring; everything here reads only the
registries (rule packs, chains, standards) and is re-imported into
``cli`` so the option call sites are unchanged.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

import click

from .core import standards as _standards

if TYPE_CHECKING:
    from rich.console import Console


def _emit_id_sev_rows(
    rows: list[tuple[str, str, str]],
    id_w: int,
    sev_w: int,
    console: Console | None = None,
) -> None:
    """Emit ``ID  SEV  TITLE`` rows to stdout.

    The SEV column is colored when stdout is a terminal; piped or
    redirected output stays plain so it remains greppable and the format
    tests still see the literal ``ID  SEV  TITLE`` layout (the leading
    token is the check / chain id). Titles are escaped on the colored
    path because some carry literal ``[...]`` tokens the Rich markup
    parser would otherwise eat. *console* is injectable for tests; the
    CLI lets it default to a stdout console.
    """
    from rich.console import Console
    from rich.markup import escape

    from .core.reporter import severity_style_for

    if console is None:
        console = Console()
    if not console.is_terminal:
        for cid, sev, title in rows:
            click.echo(f"{cid:<{id_w}}  {sev:<{sev_w}}  {title}")
        return
    for cid, sev, title in rows:
        style = severity_style_for(sev)
        console.print(
            f"{cid:<{id_w}}  [{style}]{sev:<{sev_w}}[/{style}]  {escape(title)}",
            highlight=False,
            soft_wrap=True,
        )


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
    listing_rows = [
        (cid, dedup[cid][1], dedup[cid][2]) for cid in sorted(dedup)
    ]
    _emit_id_sev_rows(listing_rows, id_width, sev_width)


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
    listing_rows = [
        (r.id, r.severity.value, r.title)
        for r in sorted(rules, key=lambda x: x.id)
    ]
    _emit_id_sev_rows(listing_rows, id_w, sev_w)
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
