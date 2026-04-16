"""Rule framework — metadata + behaviour for a single check, in one module.

Before this lived, every provider packed its checks into one class
with hundreds of inlined methods, and the accompanying prose was
hand-maintained in ``docs/providers/<provider>.md`` as parallel
state. Adding a check required edits in three places: the check
class, the standards registry, and the provider doc.

With this pattern, a rule is a self-contained module:

    pipeline_check/core/checks/github/rules/gha001_pinned_actions.py

that exposes a ``RULE`` (metadata) and a ``check(...)`` (behaviour).
The provider's orchestrator auto-discovers every rule in its
``rules/`` package; the doc generator (``scripts/gen_provider_docs.py``)
walks the same registry so the provider reference doc is produced
from the rule prose, never drifts, and doesn't need to be manually
regenerated for small edits.

The Rule dataclass owns:

  - stable metadata (``id``, ``title``, ``severity``) used to build
    the ``Finding`` the orchestrator returns;
  - compliance mappings (``owasp`` / ``esf``) that supplement — but
    do NOT replace — the ``core/standards/data`` registry (the
    authoritative source for standard-to-check mappings remains the
    standards package; these are for doc generation only);
  - prose fields (``recommendation``, ``docs_note``) that feed the
    provider reference doc directly.

Rule ``check`` callables return a ``Finding`` directly. They have
full control over the dynamic ``description`` — which matters because
the real signal is usually a list of offending items, not a static
template.
"""
from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .base import Finding, Severity


@dataclass(frozen=True)
class Rule:
    """Static metadata for a check. Paired 1:1 with a ``check`` callable
    that the orchestrator invokes."""

    id: str
    title: str
    severity: Severity
    #: OWASP Top 10 CI/CD controls this rule evidences. Doc-only —
    #: the authoritative mapping lives in ``core/standards/data``.
    owasp: tuple[str, ...] = ()
    #: NSA/CISA ESF supply-chain controls. Same caveat.
    esf: tuple[str, ...] = ()
    #: One-paragraph recommendation shown in reports and the
    #: provider reference doc.
    recommendation: str = ""
    #: Longer prose for the provider doc. Multi-paragraph markdown OK.
    docs_note: str = ""


def discover_rules(package_fqn: str) -> list[tuple[Any, Callable[..., Finding]]]:
    """Import every submodule under ``package_fqn`` and collect
    ``(RULE, check)`` pairs.

    Called once at provider orchestrator construction; the returned
    list is the ordered registry the orchestrator iterates on each
    workflow. Ordering: lexical by module name, which means rule
    IDs should be numerically sortable (``GHA-001`` < ``GHA-010``)
    so the doc generator emits them in the natural order.
    """
    package = importlib.import_module(package_fqn)
    pairs: list[tuple[Rule, Callable[..., Finding]]] = []
    for info in sorted(
        pkgutil.iter_modules(package.__path__),
        key=lambda m: m.name,
    ):
        if info.name.startswith("_"):
            continue
        mod = importlib.import_module(f"{package_fqn}.{info.name}")
        rule = getattr(mod, "RULE", None)
        check = getattr(mod, "check", None)
        if isinstance(rule, Rule) and callable(check):
            pairs.append((rule, check))
    return pairs
