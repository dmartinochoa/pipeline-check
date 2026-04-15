"""Shared secret-scanning helper used by every workflow-provider check.

Each provider already has a YAML-declared-variable check (GL-003, BB-003,
ADO-003) scoped to the ``variables:`` block and keyed by variable name.
This module adds a broader detector that walks every string scalar in a
document and flags any value matching a known credential pattern
(``_patterns.SECRET_VALUE_RE``). That catches secrets pasted into
``script:`` bodies, ``run:`` blocks, custom env blocks, and anywhere
else a contributor might land them — places the name-based detector
can't see.

The detector is deliberately value-shape only: no entropy heuristics,
no GitHub-token online validation. False positives are cheap to
suppress via the ignore file; false negatives from entropy-based rules
are not.
"""
from __future__ import annotations

from typing import Any, Iterable

from ._patterns import SECRET_VALUE_RE


def _walk(node: Any) -> Iterable[str]:
    """Yield every string scalar under ``node``."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from _walk(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk(v)


def find_secret_values(doc: Any) -> list[str]:
    """Return every string in ``doc`` that matches a credential pattern.

    Results are deduplicated and truncated to the first 8 characters of
    each match — we never want to echo a full secret back into logs.
    """
    hits: list[str] = []
    seen: set[str] = set()
    for s in _walk(doc):
        # Trim surrounding whitespace — a copy-paste secret often has a
        # leading or trailing newline.
        candidate = s.strip()
        if not candidate:
            continue
        # ``script:`` bodies can contain multiple tokens separated by
        # whitespace or shell metacharacters. Split permissively.
        for token in _tokenize(candidate):
            if SECRET_VALUE_RE.match(token) and token not in seen:
                seen.add(token)
                hits.append(_redact(token))
    return hits


def _tokenize(s: str) -> Iterable[str]:
    """Split ``s`` on whitespace + common shell separators.

    Yields each token for pattern-matching. SECRET_VALUE_RE is anchored
    (``^...$``) so whole-string matches only; tokenising lets a secret
    embedded in ``echo "AKIA…"`` still fire.
    """
    import re
    for tok in re.split(r"[\s=\"'`,;<>|&()]+", s):
        if tok:
            yield tok


def _redact(token: str) -> str:
    """Show just enough of the match to identify the provider, not the secret."""
    if len(token) <= 8:
        return token[:4] + "…"
    return token[:4] + "…" + token[-2:]
