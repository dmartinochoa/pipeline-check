"""Shell-completion callbacks and the check-ID enumeration they rely on.

Tab-completion helpers for ``--explain`` / ``--standard`` / ``--man`` plus
the cached check-ID / known-attacked-ID enumerators that back them (and
the ``--only-known-attacked`` filter). Extracted from ``cli.py`` to keep
that module focused on argument wiring; everything here depends only on
the registries (no ``cli`` internals), and the callbacks / enumerators
are re-imported into ``cli`` so the ``shell_complete=`` references and the
``--only-known-attacked`` call site are unchanged.
"""
from __future__ import annotations

import os
import re
from typing import Any

import click

from .core import standards as _standards

_CHECK_IDS_CACHE: list[str] | None = None
_KNOWN_ATTACKED_IDS_CACHE: list[str] | None = None


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
            # The ``pkg`` loop variables above iterate over strings; the
            # inferred ``str`` type would conflict with this Module
            # assignment, so use a distinct name.
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
