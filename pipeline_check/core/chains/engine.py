"""Auto-discover chain rules and evaluate them against a findings set."""
from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Callable

from ..checks.base import Finding
from .base import Chain, ChainRule

_RULES_CACHE: list[tuple[ChainRule, Callable[[list[Finding]], list[Chain]]]] | None = None


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


def list_rules() -> list[ChainRule]:
    """Return every registered :class:`ChainRule`."""
    return [r for r, _ in _discover()]


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
    for rule, match in _discover():
        if enabled is not None and rule.id not in enabled:
            continue
        try:
            matches = match(findings) or []
        except Exception:  # pragma: no cover - defensive
            # A buggy chain rule must not abort evaluation of the others.
            # Silent continue is intentional: chains are an additive
            # signal, never a gate by themselves.
            continue
        out.extend(matches)
    out.sort(key=lambda c: (c.chain_id, c.severity.value, ",".join(c.resources)))
    return out


def reset_cache() -> None:
    """Clear the rule-discovery cache. Test-only — production scans
    don't reload rules at runtime."""
    global _RULES_CACHE
    _RULES_CACHE = None
