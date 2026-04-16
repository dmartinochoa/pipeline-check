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


def find_secret_values(doc: Any) -> list[str]:
    """Return labelled credential hits found anywhere in ``doc``.

    Each hit is a string of the form ``"<detector>:<redacted-token>"``
    (or ``"private_key:<kind>"`` for PEM blocks). The detector label
    lets operators write targeted ignore rules and lets reports group
    findings by secret type.

    Results are deduplicated within a single call and the token body
    is redacted to first-4 + last-2 characters so we never echo a full
    secret back into logs or report output.

    Accepts either a parsed YAML dict/list (walks all string values)
    or a pre-collected list of strings (skips the walk). The latter is
    used by Jenkins checks that pass ``[jf.text]``.
    """
    from .base import walk_strings

    hits: list[str] = []
    seen_tokens: set[str] = set()
    seen_pem: set[str] = set()

    strings: Iterable[str]
    if isinstance(doc, list) and doc and isinstance(doc[0], str):
        strings = doc  # pre-collected string list
    else:
        strings = walk_strings(doc)

    for s in strings:
        candidate = s.strip()
        if not candidate:
            continue

        # PEM blocks span many lines — match the BEGIN marker anywhere.
        for pem in PEM_BLOCK_RE.finditer(candidate):
            kind = pem.group("kind").lower().replace(" ", "_")
            label = f"private_key:{kind}"
            if label not in seen_pem:
                seen_pem.add(label)
                hits.append(label)

        for token in _tokenize(candidate):
            if token in seen_tokens:
                continue
            if PLACEHOLDER_MARKER_RE.search(token):
                continue
            label = _classify(token)
            if label is None:
                continue
            seen_tokens.add(token)
            hits.append(f"{label}:{_redact(token)}")
    return hits


def _classify(token: str) -> str | None:
    """Return the detector name for ``token``, or None if no detector matches.

    Uses a two-level dispatch: first by the token's first 2 characters
    (catches 39 of 41 built-in detectors), then a short fallback list
    for patterns with no fixed prefix (mailchimp hex, telegram numeric).

    Tokens shorter than 8 characters are rejected early — no built-in
    credential shape is that short.
    """
    if len(token) < 8:
        return None
    # Two-char prefix dispatch — covers ~95% of detectors.
    prefix2 = token[:2]
    candidates = _PREFIX_DISPATCH.get(prefix2)
    if candidates:
        for name, pattern in candidates:
            if pattern.fullmatch(token):
                return name
    # Fallback for patterns with no fixed prefix (numeric/hex start).
    for name, pattern in _VARIABLE_PREFIX_DETECTORS:
        if pattern.fullmatch(token):
            return name
    for pattern in _USER_PATTERNS:
        if pattern.fullmatch(token):
            return "custom"
    return None


def _build_prefix_dispatch() -> tuple[
    dict[str, list[tuple[str, re.Pattern[str]]]],
    list[tuple[str, re.Pattern[str]]],
]:
    """Partition detectors into prefix-dispatchable and variable-prefix.

    Extracts 2-char literal prefixes from each detector's regex. For
    alternation groups like ``A(?:KIA|SIA)`` or ``gh[pousr]_``, expands
    into multiple 2-char keys. Only patterns that start with a digit or
    raw hex (no fixed prefix) go into the fallback list.
    """
    # Hand-tuned dispatch for patterns with regex-syntax prefixes.
    # Maps detector name → list of 2-char prefixes it can match.
    _MULTI_PREFIX: dict[str, list[str]] = {
        "aws_access_key":     ["AK", "AS"],       # A(?:KIA|SIA)
        "github_token":       ["gh"],              # gh[pousr]_
        "slack_token":        ["xo"],              # xox[abprs]-
        "jwt":                ["ey"],              # eyJ
        "stripe_secret":      ["sk", "rk"],        # (?:sk|rk)_
        "stripe_publishable": ["pk"],              # pk_
        "sendgrid":           ["SG"],              # SG\.
        "hashicorp_vault":    ["hv"],              # hvs\.
        "twilio_api_key":     ["SK"],              # SK[hex]
        "twilio_account_sid": ["AC"],              # AC[hex]
        "shopify_token":      ["sh"],              # shp
        "openai_api_key":     ["sk"],              # sk- (overlaps stripe)
        "huggingface_token":  ["hf"],              # hf_
        "doppler_token":      ["dp"],              # dp\.
    }

    dispatch: dict[str, list[tuple[str, re.Pattern[str]]]] = {}
    variable: list[tuple[str, re.Pattern[str]]] = []

    for name, pattern in SECRET_DETECTORS:
        if name in _MULTI_PREFIX:
            for key in _MULTI_PREFIX[name]:
                dispatch.setdefault(key, []).append((name, pattern))
            continue
        # Try extracting a literal 2-char prefix.
        body = pattern.pattern.lstrip("^")
        prefix_chars = []
        for ch in body:
            if ch in r".[]*+?{}()|\\^$":
                break
            prefix_chars.append(ch)
        if len(prefix_chars) >= 2:
            key = "".join(prefix_chars[:2])
            dispatch.setdefault(key, []).append((name, pattern))
        else:
            variable.append((name, pattern))
    return dispatch, variable


_PREFIX_DISPATCH, _VARIABLE_PREFIX_DETECTORS = _build_prefix_dispatch()


_TOKENIZE_RE = re.compile(r"[\s=\"'`,;<>|&()]+")


def _tokenize(s: str) -> Iterable[str]:
    """Split ``s`` on whitespace + common shell separators.

    Yields each token for pattern-matching. Built-in patterns are
    anchored (``^...$``), so tokenising lets a secret embedded in
    ``echo "AKIA…"`` still fire.
    """
    for tok in _TOKENIZE_RE.split(s):
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
