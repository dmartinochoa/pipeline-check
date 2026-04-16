"""Shared secret-scanning helper used by every workflow-provider check.

Each provider already has a YAML-declared-variable check (GL-003, BB-003,
ADO-003) scoped to the ``variables:`` block and keyed by variable name.
This module adds a broader detector that walks every string scalar in a
document and flags any value matching a known credential pattern from
``_patterns.SECRET_DETECTORS``. That catches secrets pasted into
``script:`` bodies, ``run:`` blocks, custom env blocks, and anywhere
else a contributor might land them — places the name-based detector
can't see.

The detector catalogue is shape-based, not entropy-based. False
positives are cheap to suppress via the ignore file (and the
``PLACEHOLDER_MARKER_RE`` filter handles obvious documentation
placeholders before they ever reach the user); false negatives from
entropy heuristics tend to surface as silently-missed real secrets,
which is the wrong direction.

Three signal types fire:

  1. Token-shape match — a tokenised value matches a built-in or
     user-registered credential regex. Hit label: ``<detector>:<token>``.
  2. PEM private-key block — multi-line ``-----BEGIN PRIVATE KEY-----``
     marker anywhere in the document. Hit label: ``private_key:<kind>``.
  3. User-registered custom pattern (via ``register_pattern`` or
     ``--secret-pattern``). Hit label: ``custom:<token>``.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from re import Pattern
from typing import Any

from ._patterns import (
    PEM_BLOCK_RE,
    PLACEHOLDER_MARKER_RE,
    SECRET_DETECTORS,
    SECRET_VALUE_RE,
)

# Mutable registry — appended to by :func:`register_pattern` so users
# can extend the detector with org-specific credential shapes (e.g.
# internal token prefixes) without vendoring the package.
_USER_PATTERNS: list[Pattern[str]] = []


def register_pattern(pattern: str | Pattern[str]) -> None:
    """Add ``pattern`` to the set of regexes :func:`find_secret_values` checks.

    The pattern is anchored by the caller — tokens are whole-string
    matched (``re.fullmatch``) after tokenisation, so a pattern like
    ``^acme_[a-z0-9]{32}$`` matches the token ``acme_…`` but not a
    substring of a larger blob. Duplicate patterns are ignored.
    """
    compiled = re.compile(pattern) if isinstance(pattern, str) else pattern
    for existing in _USER_PATTERNS:
        if existing.pattern == compiled.pattern:
            return
    _USER_PATTERNS.append(compiled)


def reset_patterns() -> None:
    """Drop every custom pattern, keeping only the built-in catalogue.

    Exists for test isolation and for the long-lived Lambda container
    case where a prior invocation's patterns shouldn't leak into the
    next one — see ``Scanner.__init__`` for the lifecycle hook.
    """
    _USER_PATTERNS.clear()


# Backwards-compat alias for tests that introspected the old internal
# name. Keeps a stable surface even though the storage moved.
_PATTERNS = _USER_PATTERNS


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
    """Return labelled credential hits found anywhere in ``doc``.

    Each hit is a string of the form ``"<detector>:<redacted-token>"``
    (or ``"private_key:<kind>"`` for PEM blocks). The detector label
    lets operators write targeted ignore rules and lets reports group
    findings by secret type.

    Results are deduplicated within a single call and the token body
    is redacted to first-4 + last-2 characters so we never echo a full
    secret back into logs or report output.
    """
    hits: list[str] = []
    seen_tokens: set[str] = set()
    seen_pem: set[str] = set()

    for s in _walk(doc):
        # Trim surrounding whitespace — copy-paste secrets often have
        # a leading or trailing newline.
        candidate = s.strip()
        if not candidate:
            continue

        # PEM blocks span many lines — a token-split would shred them
        # into base64 fragments. Match the BEGIN marker anywhere in
        # the string and emit a single hit per kind.
        for pem in PEM_BLOCK_RE.finditer(candidate):
            kind = pem.group("kind").lower().replace(" ", "_")
            label = f"private_key:{kind}"
            if label not in seen_pem:
                seen_pem.add(label)
                hits.append(label)

        # ``script:`` bodies can contain multiple tokens separated by
        # whitespace or shell metacharacters. Split permissively.
        for token in _tokenize(candidate):
            if token in seen_tokens:
                continue
            if PLACEHOLDER_MARKER_RE.search(token):
                # Documentation placeholder — skip without consuming
                # the seen slot so a real secret with the same prefix
                # later can still fire.
                continue
            label = _classify(token)
            if label is None:
                continue
            seen_tokens.add(token)
            hits.append(f"{label}:{_redact(token)}")
    return hits


def _classify(token: str) -> str | None:
    """Return the detector name for ``token``, or None if no detector matches.

    Built-in detectors are tried in registry order. User-registered
    patterns get a generic ``custom`` label so report descriptions
    distinguish "shipped detector fired" from "operator-supplied
    pattern fired".
    """
    for name, pattern in SECRET_DETECTORS:
        if pattern.fullmatch(token):
            return name
    for pattern in _USER_PATTERNS:
        if pattern.fullmatch(token):
            return "custom"
    return None


def _tokenize(s: str) -> Iterable[str]:
    """Split ``s`` on whitespace + common shell separators.

    Yields each token for pattern-matching. Built-in patterns are
    anchored (``^...$``), so tokenising lets a secret embedded in
    ``echo "AKIA…"`` still fire.
    """
    for tok in re.split(r"[\s=\"'`,;<>|&()]+", s):
        if tok:
            yield tok


def _redact(token: str) -> str:
    """Show just enough of the match to identify the provider, not the secret."""
    if len(token) <= 8:
        return token[:4] + "…"
    return token[:4] + "…" + token[-2:]


# Re-export for callers that historically did
# ``from ._secrets import SECRET_VALUE_RE``.
__all__ = [
    "find_secret_values",
    "register_pattern",
    "reset_patterns",
    "SECRET_VALUE_RE",
    "SECRET_DETECTORS",
]
