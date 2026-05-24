"""Lightweight semver range matcher for GHSA vulnerability ranges.

The GitHub Advisory Database describes affected versions using ranges
like ``< 4.2.2``, ``>= 3.0.0, < 3.5.1``, or ``= 4.2.1``.  This
module parses those ranges and checks whether a dotted version string
falls within them.  Only numeric segments are compared (pre-release
suffixes are stripped); the intent is "good enough for advisory
triage," not full semver compliance.
"""
from __future__ import annotations

import re
from collections.abc import Sequence

_VER_RE = re.compile(r"v?(\d+(?:\.\d+)*)")
_CONSTRAINT_RE = re.compile(
    r"(>=|<=|!=|>|<|=)\s*v?(\d+(?:\.\d+)*)",
)


def parse_version(raw: str) -> tuple[int, ...] | None:
    """Extract a numeric tuple from a version string.

    >>> parse_version("v4.2.1")
    (4, 2, 1)
    >>> parse_version("4.2")
    (4, 2)
    >>> parse_version("not-a-version") is None
    True
    """
    m = _VER_RE.match(raw.strip())
    if m is None:
        return None
    return tuple(int(seg) for seg in m.group(1).split("."))


def _pad(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[
    tuple[int, ...], tuple[int, ...]
]:
    length = max(len(a), len(b))
    return a + (0,) * (length - len(a)), b + (0,) * (length - len(b))


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    pa, pb = _pad(a, b)
    if pa < pb:
        return -1
    if pa > pb:
        return 1
    return 0


def _satisfies_constraint(
    ver: tuple[int, ...], op: str, bound: tuple[int, ...],
) -> bool:
    c = _cmp(ver, bound)
    if op == ">=":
        return c >= 0
    if op == ">":
        return c > 0
    if op == "<=":
        return c <= 0
    if op == "<":
        return c < 0
    if op in ("=", "=="):
        return c == 0
    if op == "!=":
        return c != 0
    return False


def version_in_range(version: str, vuln_range: str) -> bool | None:
    """Check whether *version* falls within a GHSA *vuln_range*.

    Returns ``True`` if the version is affected, ``False`` if it is
    clearly outside the range, and ``None`` if either the version or
    the range string could not be parsed (caller should treat as
    "unknown").

    >>> version_in_range("4.2.0", ">= 3.0.0, < 4.2.2")
    True
    >>> version_in_range("4.2.2", ">= 3.0.0, < 4.2.2")
    False
    >>> version_in_range("v1.0.0", "< 1.0.1")
    True
    """
    ver = parse_version(version)
    if ver is None:
        return None
    constraints = _CONSTRAINT_RE.findall(vuln_range)
    if not constraints:
        return None
    for op, bound_str in constraints:
        bound = parse_version(bound_str)
        if bound is None:
            return None
        if not _satisfies_constraint(ver, op, bound):
            return False
    return True


def any_range_matches(
    version: str, ranges: Sequence[str],
) -> tuple[bool, list[str]]:
    """Check *version* against multiple GHSA vulnerability ranges.

    Returns ``(matched, matching_ranges)`` where *matched* is ``True``
    when at least one range covers the version. Unparseable ranges are
    skipped (conservative: they don't cause a match on their own).
    """
    hits: list[str] = []
    for r in ranges:
        result = version_in_range(version, r)
        if result is True:
            hits.append(r)
    return bool(hits), hits
