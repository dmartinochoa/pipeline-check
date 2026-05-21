"""Shared helpers for the per-ecosystem compromised-package registries.

The ``CompromisedPackage`` dataclass on the npm / pypi / maven providers
each carries a near-identical ``matches(version)`` method: an exact-
string check against ``malicious_versions`` with an optional
``version_pattern`` regex fallback for "everything before X.Y.Z is
poisoned" advisories. The dataclasses themselves keep ecosystem-
specific identifier fields (``name`` for npm/pypi, ``group_id`` +
``artifact_id`` for maven) so they don't share a base class — but the
version-matching logic factors out cleanly into one place.

Centralizing here means a future semver-range extension (e.g. matching
``< 2.14.1`` directly instead of enumerating every affected literal)
lands in one module and every ecosystem picks it up.
"""
from __future__ import annotations

import re


def match_version(
    version: str,
    *,
    malicious_versions: tuple[str, ...],
    version_pattern: re.Pattern[str] | None,
) -> bool:
    """Return ``True`` when *version* matches one of the malicious literals
    or the optional regex fallback.

    The semantics mirror what each provider's ``CompromisedPackage.
    matches`` implemented inline: exact string equality on the literal
    list, falling back to ``version_pattern.search`` when none of the
    literals match. ``False`` when both checks miss.
    """
    if any(version == bad for bad in malicious_versions):
        return True
    if version_pattern is not None and version_pattern.search(version):
        return True
    return False
