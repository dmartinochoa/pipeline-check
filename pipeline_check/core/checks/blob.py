"""String-blob utilities shared across providers.

Many checks answer questions of the form "does this workflow mention
token X anywhere in its string content?" (signing, SBOM, vulnerability
scanning, artifact-production heuristic). Doing that as N independent
tree walks is quadratic in rule count; instead we flatten every string
scalar into a single lowercase blob once per document and memoize on
``id(doc)``.

The cache is cleared in :class:`~pipeline_check.core.checks.base.BaseCheck`
``__init__`` and in :meth:`Scanner._scan_provider` so entries from a
previous scan (especially in long-lived Lambda containers) can't pin
memory or, worse, collide with a newly-allocated doc that reused a
freed ``id()``.
"""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any


def walk_strings(node: Any) -> Iterator[str]:
    """Yield every string scalar under a dict/list tree (iterative).

    Uses an explicit stack instead of recursion to reduce function-call
    overhead, a single large workflow can have hundreds of nested
    dict/list nodes, each of which would be a separate generator frame
    in the recursive version.
    """
    stack = [node]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            yield item
        elif isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)


_BLOB_CACHE: dict[int, str] = {}


_BLOB_RAW_CACHE: dict[int, str] = {}


def blob_raw(doc: Any) -> str:
    """Concatenate all string values in ``doc`` into one blob, preserving case.

    Memoized on object identity, same contract as :func:`blob_lower`.
    Use this when the scanner needs to distinguish characters whose
    case carries semantic meaning (e.g. ``curl -k`` vs ``curl -K``).
    """
    key = id(doc)
    cached = _BLOB_RAW_CACHE.get(key)
    if cached is not None:
        return cached
    blob = "\n".join(walk_strings(doc))
    _BLOB_RAW_CACHE[key] = blob
    return blob


def blob_lower(doc: Any) -> str:
    """Concatenate all string values in ``doc`` into one lowercase blob.

    Memoized on object identity so that the multiple callers each
    provider uses (``has_signing``, ``has_sbom``, and, through the
    secrets helper, ``find_secret_values``) share one tree walk per
    workflow. ``id(doc)`` is stable for as long as the document
    object is alive, which is the whole ``run()`` invocation.
    """
    key = id(doc)
    cached = _BLOB_CACHE.get(key)
    if cached is not None:
        return cached
    blob = "\n".join(walk_strings(doc)).lower()
    _BLOB_CACHE[key] = blob
    return blob


def clear_blob_cache() -> None:
    _BLOB_CACHE.clear()
    _BLOB_RAW_CACHE.clear()
    # ``looks_like_example`` keys its prefix-line index on ``id(blob)``
    # the same way ``blob_lower`` does, so callers that already invoke
    # ``clear_blob_cache`` between tests pick up the secondary cache
    # for free.
    from ._context import clear_context_cache
    clear_context_cache()
    # GHA-062's IaC sidecar walk is keyed on the repo-root path string,
    # not on ``id(doc)``, so it must be cleared explicitly to avoid
    # stale results in long-lived processes.
    from .github.rules.gha062_oidc_iac_subject import clear_iac_scan_cache
    clear_iac_scan_cache()
