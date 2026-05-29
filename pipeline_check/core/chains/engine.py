"""Auto-discover chain rules and evaluate them against a findings set."""
from __future__ import annotations

import importlib
import logging
import pkgutil
from collections.abc import Callable

from ..checks.base import Finding, severity_rank
from .base import Chain, ChainRule

_RULES_CACHE: list[tuple[ChainRule, Callable[[list[Finding]], list[Chain]]]] | None = None
_CXPC_RULES_CACHE: list[
    tuple[ChainRule, Callable[[dict[str, list[Finding]]], list[Chain]]]
] | None = None

_log = logging.getLogger(__name__)


def _discover() -> list[tuple[ChainRule, Callable[[list[Finding]], list[Chain]]]]:
    """Import every module under ``chains/rules/`` and collect ``(RULE, match)`` pairs.

    Mirrors the per-provider rule discovery in ``checks/rule.py`` —
    cached after first call, lexical ordering by module name (so
    ``ac001_*`` precedes ``ac010_*`` naturally), modules starting with
    ``_`` are skipped.
    """
    global _RULES_CACHE
    if _RULES_CACHE is not None:
        return _RULES_CACHE

    package_fqn = "pipeline_check.core.chains.rules"
    package = importlib.import_module(package_fqn)
    pairs: list[tuple[ChainRule, Callable[[list[Finding]], list[Chain]]]] = []
    for info in sorted(
        pkgutil.iter_modules(package.__path__),
        key=lambda m: m.name,
    ):
        if info.name.startswith("_"):
            continue
        mod = importlib.import_module(f"{package_fqn}.{info.name}")
        rule = getattr(mod, "RULE", None)
        match = getattr(mod, "match", None)
        if isinstance(rule, ChainRule) and callable(match):
            pairs.append((rule, match))
    _RULES_CACHE = pairs
    return pairs


def _discover_cxpc() -> list[
    tuple[ChainRule, Callable[[dict[str, list[Finding]]], list[Chain]]]
]:
    """Import CXPC modules (``cxpc*``) under ``chains/rules/`` and collect pairs.

    CXPC (cross-repo) chain rules export ``RULE`` and
    ``match_cross_repo(findings_by_repo)`` instead of the per-repo
    ``match(findings)``. They are discovered separately so per-repo
    evaluation never accidentally calls a cross-repo matcher.
    """
    global _CXPC_RULES_CACHE
    if _CXPC_RULES_CACHE is not None:
        return _CXPC_RULES_CACHE

    package_fqn = "pipeline_check.core.chains.rules"
    package = importlib.import_module(package_fqn)
    pairs: list[
        tuple[ChainRule, Callable[[dict[str, list[Finding]]], list[Chain]]]
    ] = []
    for info in sorted(
        pkgutil.iter_modules(package.__path__),
        key=lambda m: m.name,
    ):
        if not info.name.startswith("cxpc"):
            continue
        mod = importlib.import_module(f"{package_fqn}.{info.name}")
        rule = getattr(mod, "RULE", None)
        match_fn = getattr(mod, "match_cross_repo", None)
        if isinstance(rule, ChainRule) and callable(match_fn):
            pairs.append((rule, match_fn))
    _CXPC_RULES_CACHE = pairs
    return pairs


def list_rules() -> list[ChainRule]:
    """Return every registered :class:`ChainRule` (per-repo and cross-repo)."""
    return [r for r, _ in _discover()] + [r for r, _ in _discover_cxpc()]


def evaluate(
    findings: list[Finding],
    enabled: set[str] | None = None,
) -> list[Chain]:
    """Evaluate every chain rule against *findings* and return matches.

    Parameters
    ----------
    findings:
        The full set of findings produced by ``Scanner.run()``. Both
        passing and failing findings are passed; rules filter as needed.
    enabled:
        Optional allowlist of chain IDs (``{"AC-001", "AC-003"}``).
        When None (the default), every registered chain is evaluated.

    A single :class:`Chain` rule may emit multiple chain instances
    (e.g. the same attack pattern firing in two different workflow
    files); the engine concatenates them all into one flat list,
    sorted by chain_id then severity then resources.
    """
    out: list[Chain] = []
    # Chain rules correlate FAILING findings only: every helper
    # (failing / group_by_resource / group_by_anchor / has_failing) and
    # every rule body skips ``f.passed``. The orchestrators emit a
    # Finding for every check on every doc, so on a large repo this list
    # is dominated by passing findings no rule looks at. Filter once here
    # instead of making each of the ~45 rules re-walk the full list,
    # collapsing ~45 full passes into one filter plus per-rule passes over
    # the (much smaller) failing subset.
    failing_only = [f for f in findings if not f.passed]
    for rule, match in _discover():
        if enabled is not None and rule.id not in enabled:
            continue
        try:
            matches = match(failing_only) or []
        except Exception:  # pragma: no cover - defensive
            # A buggy chain rule must not abort evaluation of the others
            # (chains are an additive signal, never a gate by
            # themselves), but a silent swallow makes broken rules
            # invisible. Log at WARNING so the breadcrumb shows up in
            # ``--verbose`` runs while the scan stays green.
            _log.warning(
                "chain rule %s raised during evaluation; skipping",
                rule.id, exc_info=True,
            )
            continue
        out.extend(matches)
    out.sort(key=lambda c: (c.chain_id, severity_rank(c.severity), ",".join(c.resources)))
    return out


def evaluate_cross_repo(
    findings_by_repo: dict[str, list[Finding]],
    enabled: set[str] | None = None,
) -> list[Chain]:
    """Evaluate every cross-repo chain rule and return matches.

    Parameters
    ----------
    findings_by_repo:
        Mapping from repo coordinate string to its findings list.
        Typically built by :func:`fleet._load_repo_findings` after
        all per-repo scans complete.
    enabled:
        Optional allowlist of chain IDs. When None, every registered
        CXPC chain is evaluated.
    """
    out: list[Chain] = []
    for rule, match_fn in _discover_cxpc():
        if enabled is not None and rule.id not in enabled:
            continue
        try:
            matches = match_fn(findings_by_repo) or []
        except Exception:
            _log.warning(
                "cross-repo chain rule %s raised during evaluation; skipping",
                rule.id, exc_info=True,
            )
            continue
        out.extend(matches)
    out.sort(key=lambda c: (c.chain_id, severity_rank(c.severity), ",".join(c.resources)))
    return out


def reset_cache() -> None:
    """Clear the rule-discovery cache. Test-only, production scans
    don't reload rules at runtime."""
    global _RULES_CACHE, _CXPC_RULES_CACHE
    _RULES_CACHE = None
    _CXPC_RULES_CACHE = None
