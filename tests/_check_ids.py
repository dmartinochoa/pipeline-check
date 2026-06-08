"""Derive a provider's registered check-ID set from the live rule
registry.

Several tests assert that an autodetect / scan emitted exactly the
provider's check set. Hardcoding that set as a hand-maintained
enumeration (``{f"GHA-{i:03d}" for i in range(1, 74)} | {...}``) means
every new rule has to edit each of those lists, and an ID gap silently
breaks a contiguous ``range(...)``. Deriving the set from
``discover_rules`` removes that whole class of new-rule friction: the
assertion becomes "the scan ran every registered check for the
provider", which is what those tests actually mean, and it updates
itself when a rule is added or removed.
"""
from __future__ import annotations

from pipeline_check.core.checks.rule import discover_rules


def registered_ids(provider: str) -> set[str]:
    """The set of check IDs the *provider*'s rule pack registers.

    Works for the per-rule-module rule-pack providers whose rules live
    under ``pipeline_check.core.checks.<provider>.rules`` (github,
    gitlab, bitbucket, ...). The set includes any cross-cutting rules
    (e.g. ``TAINT-*``) that live in the same package.
    """
    pkg = f"pipeline_check.core.checks.{provider}.rules"
    return {rule.id for rule, _ in discover_rules(pkg)}
