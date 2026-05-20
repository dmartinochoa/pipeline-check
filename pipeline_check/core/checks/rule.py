"""Rule framework, metadata + behavior for a single check, in one module.

Before this lived, every provider packed its checks into one class
with hundreds of inlined methods, and the accompanying prose was
hand-maintained in ``docs/providers/<provider>.md`` as parallel
state. Adding a check required edits in three places: the check
class, the standards registry, and the provider doc.

With this pattern, a rule is a self-contained module:

    pipeline_check/core/checks/github/rules/gha001_pinned_actions.py

that exposes a ``RULE`` (metadata) and a ``check(...)`` (behavior).
The provider's orchestrator auto-discovers every rule in its
``rules/`` package; the doc generator (``scripts/gen_provider_docs.py``)
walks the same registry so the provider reference doc is produced
from the rule prose, never drifts, and doesn't need to be manually
regenerated for small edits.

The Rule dataclass owns:

  - stable metadata (``id``, ``title``, ``severity``) used to build
    the ``Finding`` the orchestrator returns;
  - compliance mappings (``owasp`` / ``esf``) that supplement, but
    do NOT replace, the ``core/standards/data`` registry (the
    authoritative source for standard-to-check mappings remains the
    standards package; these are for doc generation only);
  - prose fields (``recommendation``, ``docs_note``) that feed the
    provider reference doc directly.

Rule ``check`` callables return a ``Finding`` directly. They have
full control over the dynamic ``description``, which matters because
the real signal is usually a list of offending items, not a static
template.
"""
from __future__ import annotations

import importlib
import inspect
import pkgutil
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .base import Finding, Severity


@dataclass(frozen=True, slots=True)
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
    #: CWE identifiers for vulnerability classification (e.g. "CWE-78").
    #: Surfaced in SARIF output and JSON reports.
    cwe: tuple[str, ...] = ()
    #: One-paragraph recommendation shown in reports and the
    #: provider reference doc.
    recommendation: str = ""
    #: Longer prose for the provider doc. Multi-paragraph markdown OK.
    docs_note: str = ""
    #: Known false-positive modes surfaced by ``pipeline_check explain``.
    #: Empty for most rules; populated for rules whose heuristic shape
    #: is known to misfire on specific legitimate patterns so the user
    #: can see the escape hatch before dismissing the whole check.
    known_fp: tuple[str, ...] = ()
    #: Real-world incident references — CVEs, breach postmortems,
    #: vendor disclosures where the same pattern this rule detects
    #: caused damage in the wild. Each entry is a one-line citation,
    #: optionally containing an HTTPS URL. Surfaced in
    #: ``pipeline_check --explain`` and the HTML report under a
    #: "Seen in the wild" footer so the rule is anchored to a
    #: concrete cost rather than abstract security debt. Empty for
    #: rules whose risk is hypothetical or who have no public
    #: incident on record.
    incident_refs: tuple[str, ...] = ()
    #: Concrete proof-of-exploit snippet for HIGH / CRITICAL rules:
    #: the minimal payload, manifest fragment, or attack sequence
    #: that demonstrably triggers the failure mode the rule detects.
    #: Surfaced in ``pipeline_check --explain`` and the HTML report
    #: under a "Proof of exploit" section so reviewers see the
    #: concrete attack instead of inferring it from prose. Multi-line
    #: code blocks are rendered verbatim. Empty for rules where the
    #: bad pattern is itself the exploit (e.g. a hardcoded credential
    #: literal) or where no public exploitation primitive exists.
    exploit_example: str | None = None


_RULES_CACHE: dict[str, list[tuple[Any, Callable[..., Finding]]]] = {}


def discover_rules(package_fqn: str) -> list[tuple[Any, Callable[..., Finding]]]:
    """Import every submodule under ``package_fqn`` and collect
    ``(RULE, check)`` pairs.

    Results are cached after the first call, rule modules don't
    change at runtime, and the pkgutil filesystem scan is the
    dominant cost for repeated orchestrator construction (e.g. when
    scanning many files in a directory).

    Ordering: lexical by module name, which means rule IDs should be
    numerically sortable (``GHA-001`` < ``GHA-010``) so the doc
    generator emits them in the natural order.
    """
    cached = _RULES_CACHE.get(package_fqn)
    if cached is not None:
        return cached

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
    _RULES_CACHE[package_fqn] = pairs
    return pairs


def wants_ctx_kwarg(check_fn: Callable[..., Finding]) -> bool:
    """Return ``True`` if *check_fn* declares a second positional parameter.

    Used by the npm / pypi / maven orchestrators to opt-in cross-target
    state (e.g. NPM-008 / PYPI-008 / MVN-008 reading the publish-time
    table populated by ``--resolve-remote``): rules that need the
    provider context declare a second parameter, the orchestrator
    routes it through here, one-arg rules stay unaffected.
    """
    try:
        params = list(inspect.signature(check_fn).parameters.values())
    except (TypeError, ValueError):
        return False
    return len(params) >= 2


def apply_rule_metadata(finding: Finding, rule: Rule) -> None:
    """Copy rule-level metadata onto a finding the rule didn't set.

    Every orchestrator runs the same three-field copy (``cwe`` /
    ``incident_refs`` / ``exploit_example``) after invoking the rule's
    ``check()`` callable. Centralizing the copy lets new ``Rule``
    fields propagate without touching every orchestrator.
    """
    finding.cwe = list(rule.cwe)
    if not finding.incident_refs:
        finding.incident_refs = list(rule.incident_refs)
    if finding.exploit_example is None:
        finding.exploit_example = rule.exploit_example
