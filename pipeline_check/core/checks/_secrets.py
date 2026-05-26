"""Shared secret-scanning helper used by every workflow-provider check.

Each provider already has a YAML-declared-variable check (GL-003, BB-003,
ADO-003) scoped to the ``variables:`` block and keyed by variable name.
This module adds a broader detector that walks every string scalar in a
document and flags any value matching a known credential pattern from
``_patterns.SECRET_DETECTORS``. That catches secrets pasted into
``script:`` bodies, ``run:`` blocks, custom env blocks, and anywhere
else a contributor might land them, places the name-based detector
can't see.

The deterministic catalog is shape-based: a hit means the value
matches a known token format (``AKIA``, ``ghp_``, ``sk-ant-api03-``,
...). False positives are cheap to suppress via the ignore file
(and the ``PLACEHOLDER_MARKER_RE`` filter handles obvious
documentation placeholders before they ever reach the user); false
negatives from prefix-shape detection tend to be custom org tokens
that lack a publicly-documented shape.

Four signal types can fire:

  1. **Token-shape match.** Tokenised value matches a built-in
     credential regex. Hit label: ``<detector>:<token>``.
  2. **PEM private-key block.** Multi-line ``-----BEGIN PRIVATE
     KEY-----`` marker anywhere in the document. Hit label:
     ``private_key:<kind>``.
  3. **User-registered custom pattern** (via ``register_pattern``
     or ``--secret-pattern``). Hit label: ``custom:<token>``.
  4. **Shannon-entropy detector** (opt-in via
     ``enable_entropy_detection`` / ``--detect-entropy``). Fires
     when a high-entropy value (>= 3.5 bits/char, length >= 20)
     appears in a YAML key-context that suggests a credential
     (``API_KEY``, ``apiToken``, ``password``, ...) and the
     deterministic catalog hasn't already flagged it. Hit label:
     ``entropy:<token>``. Off by default to keep upgrades
     backward-compatible — opting in introduces new findings on
     existing scans.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterable, Iterator
from re import Pattern
from typing import Any

from ._patterns import (
    PEM_BLOCK_RE,
    PLACEHOLDER_MARKER_RE,
    SECRET_DETECTORS,
    SECRET_VALUE_RE,
)

# Mutable registry, appended to by :func:`register_pattern` so users
# can extend the detector with org-specific credential shapes (e.g.
# internal token prefixes) without vendoring the package.
_USER_PATTERNS: list[Pattern[str]] = []


def register_pattern(pattern: str | Pattern[str]) -> None:
    """Add ``pattern`` to the set of regexes :func:`find_secret_values` checks.

    The pattern is anchored by the caller, tokens are whole-string
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
    """Drop every custom pattern, keeping only the built-in catalog.

    Exists for test isolation and for the long-lived Lambda container
    case where a prior invocation's patterns shouldn't leak into the
    next one, see ``Scanner.__init__`` for the lifecycle hook. Also
    resets the entropy-detection flag so a Lambda container that
    enabled it for one invocation doesn't carry the setting into the
    next.
    """
    _USER_PATTERNS.clear()
    enable_entropy_detection(False)


# Backward-compat alias for tests that introspected the old internal
# name. Keeps a stable surface even though the storage moved.
_PATTERNS = _USER_PATTERNS


# ── Entropy-based detector (opt-in) ─────────────────────────────────


#: Minimum Shannon entropy (bits/char) required for a value to be
#: classified as a high-entropy token candidate. 3.5 catches random
#: hex (theoretical max 4.0; observed ~3.8-4.0 on 32-char hex) while
#: letting natural-language values through (English is ~4.0 in
#: theory but typical short strings land at 3.0-3.5 because of
#: limited character variety).
MIN_ENTROPY_BITS_PER_CHAR = 3.5

#: Minimum value length before the entropy detector even tries.
#: Real credential tokens are at least 16-20 characters (AWS access
#: keys are 20, GitHub PATs are 40+). Tightening this knob is the
#: easiest way to suppress noise on configuration values that
#: happen to look random.
MIN_ENTROPY_LENGTH = 20

#: Character set a value must consist of to be considered a
#: token-shaped candidate. Real tokens use base62 / base64 / hex
#: alphabets plus a few separators; values containing whitespace,
#: punctuation, or quote marks are almost certainly natural prose
#: (or a templated config string), not a credential.
_TOKEN_SHAPED_RE = re.compile(r"^[A-Za-z0-9+/=_\-.]+$")

#: Substrings that, when they appear as a *whole word* in the YAML
#: key name, signal that the value side carries a credential. Words
#: are matched after a normalization pass that splits on ``-``, ``_``,
#: whitespace, and camel-case boundaries (``apiKey`` -> ``api`` +
#: ``key``), so all of ``API_KEY``, ``apiKey``, ``api-key``, and
#: ``api key`` resolve to the same parts.
#:
#: ``api`` and ``private`` are deliberately NOT included as
#: standalone words because they collide with non-credential
#: fields that are very common in YAML configs: ``apiVersion`` /
#: ``apiGroups`` (Kubernetes / Argo / Tekton manifest schemas) and
#: ``private_subnet`` / ``private_dns_zone`` / ``private_link``
#: (cloud networking config). A real credential field that wants
#: to use ``api`` always pairs it with another word
#: (``api_key``, ``apiSecret``), and the multi-part match still
#: fires on the paired form because ``key`` / ``secret`` carry the
#: heuristic on their own.
_CRED_KEY_TOKENS: frozenset[str] = frozenset({
    "key", "keys",
    "token", "tokens",
    "secret", "secrets",
    "password", "passwd", "pwd",
    "auth", "authorization",
    "credential", "credentials",
    "passkey",
    # Cloud-vendor-specific shapes that don't fit the generic words.
    "accesskey", "secretkey",
    # ``apikey`` is a single-word spelling some vendors use; matches
    # only when the whole key is literally ``apikey`` (not when a
    # camel-case split produces ``api`` + something).
    "apikey",
})

#: Splitter used by :func:`_key_suggests_credential`. Matches any of
#: ``-``, ``_``, whitespace, OR a camel-case boundary
#: (lowercase / uppercase pair).
_KEY_PART_SPLIT_RE = re.compile(r"[-_\s]+|(?<=[a-z])(?=[A-Z])")


_ENTROPY_ENABLED = False


def enable_entropy_detection(enabled: bool = True) -> None:
    """Toggle the opt-in Shannon-entropy secret detector.

    Off by default. The deterministic prefix-shape detectors run
    regardless. When enabled, :func:`find_secret_values` adds a
    second pass that walks ``(key, value)`` pairs in the document
    and emits an ``entropy:<redacted>`` hit when a value is
    high-entropy AND token-shaped AND its enclosing YAML key name
    suggests a credential AND no deterministic detector already
    matched.

    The flag is module-level for the same reason :func:`register_pattern`
    is module-level: each :class:`~pipeline_check.core.scanner.Scanner`
    invocation owns the registry for its scan. The Scanner constructor
    calls :func:`reset_patterns` to clear lingering state from a
    prior invocation; this flag rides the same reset.
    """
    global _ENTROPY_ENABLED
    _ENTROPY_ENABLED = enabled


def shannon_entropy(s: str) -> float:
    """Return the Shannon entropy of *s* in bits per character.

    Empty string returns 0.0. The result is the *expected* number of
    bits a perfect compressor would need per character; random hex
    over a 16-symbol alphabet caps at log2(16) = 4 bits/char, random
    base64 caps at log2(64) = 6 bits/char, English prose tends to
    sit around 4.0 bits/char on long passages but lower on short
    snippets because the limited symbol set hasn't had room to vary.
    """
    if not s:
        return 0.0
    n = len(s)
    counts = Counter(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _key_suggests_credential(key_name: str) -> bool:
    """True when the YAML key name reads as a credential field.

    Splits the name on ``_`` / ``-`` / whitespace AND camel-case
    boundaries, then tests each part against
    :data:`_CRED_KEY_TOKENS`. ``API_KEY``, ``apiKey``,
    ``aws_access_key_id``, ``database-password``, and ``my secret``
    all match; ``monkey``, ``api_version``, ``serviceaccount``, and
    ``filekey`` do not (the parts are whole words).
    """
    if not key_name:
        return False
    parts = _KEY_PART_SPLIT_RE.split(key_name)
    return any(part.lower() in _CRED_KEY_TOKENS for part in parts if part)


def _walk_key_value_pairs(doc: Any) -> Iterator[tuple[str, str]]:
    """Yield ``(effective_key, value)`` pairs for every string leaf.

    Handles two shapes that matter for credential detection:

    1. **Direct key-value mappings.** ``API_KEY: "AKIA..."`` yields
       ``("API_KEY", "AKIA...")``.
    2. **Kubernetes / CFN / Terraform env-list shape.** The
       ``[{name: K, value: V}, ...]`` pattern yields
       ``("K", "V")`` rather than the literal ``("value", "V")``,
       since the *meaningful* key for a human reader is the sibling
       ``name`` field. Same for ``{key: K, value: V}`` shapes.
    3. **List values inherit their parent key** — a list of strings
       under ``passwords:`` yields ``("passwords", item)`` for each
       string item.

    Skips dict keys that aren't strings (PyYAML 1.1 parses bare
    ``yes`` / ``no`` as bools; we don't try to use those as key
    contexts).
    """
    stack: list[tuple[str | None, dict[Any, Any] | None, Any]] = [(None, None, doc)]
    while stack:
        parent_key, parent_dict, item = stack.pop()
        if isinstance(item, str):
            effective = parent_key
            # Env-list shape: bias toward the sibling ``name`` /
            # ``key`` field as the credential-context label.
            if parent_dict is not None and parent_key in (
                "value", "Value", "stringValue",
            ):
                for sibling_key in ("name", "Name", "key", "Key"):
                    sibling = parent_dict.get(sibling_key)
                    if isinstance(sibling, str):
                        effective = sibling
                        break
            if effective:
                yield (effective, item)
        elif isinstance(item, dict):
            for k, v in item.items():
                kname = k if isinstance(k, str) else None
                stack.append((kname, item, v))
        elif isinstance(item, list):
            # Propagate the parent key so list items inherit context.
            for child in item:
                stack.append((parent_key, parent_dict, child))


#: 40-char lowercase-hex shape. Covers legacy GitHub PATs (pre-``ghp_``
#: migration), Datadog API keys, GitLab v1 PATs, Codecov v3 / AppVeyor /
#: CircleCI v1 tokens, and several other CI vendor shapes that have no
#: vendor-specific prefix. Wider hex shapes (32, 64) collide with commit
#: SHAs / SHA-256 digests, so they stay out of the deterministic pass.
_KEYED_HEX40_RE = re.compile(r"^[0-9a-f]{40}$")


def _find_keyed_hex_hits(doc: Any) -> list[str]:
    """Return ``hex40_keyed:<redacted>`` hits.

    Fires when a 40-char lowercase-hex value is bound to a YAML key
    whose name reads as a credential field (the same
    :func:`_key_suggests_credential` filter the entropy pass uses).
    Always on (unlike the opt-in entropy detector), because the
    combination of "40 lowercase hex" + "credential-named key" is
    narrow enough that natural-language and commit-SHA noise stays
    out: the key context filters out ``deploy_commit``,
    ``head_revision``, and any other non-credential 40-hex shape.

    Catches the shape scenario 15 of the ``greylag-ci/cicd-goat``
    matrix exercises and the 'legacy unprefixed vendor token' family
    in general. KICS / GitGuardian flag this shape; the deterministic
    catalog had a deliberate gap on bare hex tokens because the
    pattern is generic, the key-context gate is what makes it
    actionable.
    """
    hits: list[str] = []
    seen: set[str] = set()
    for key_name, raw_value in _walk_key_value_pairs(doc):
        if not _key_suggests_credential(key_name):
            continue
        candidate = raw_value.strip().strip("\"'")
        if not _KEYED_HEX40_RE.match(candidate):
            continue
        if PLACEHOLDER_MARKER_RE.search(candidate):
            continue
        # Don't double-emit if a deterministic detector already
        # classifies this token (rare for a bare 40-hex — most vendor
        # 40-hex shapes carry a prefix — but the guard keeps the
        # contract consistent with the entropy pass).
        if _classify(candidate) is not None:
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        hits.append(f"hex40_keyed:{_redact(candidate)}")
    return hits


def _find_entropy_hits(doc: Any) -> list[str]:
    """Return ``entropy:<redacted>`` hits for high-entropy values
    appearing in credential-shaped YAML key contexts.

    The detector deliberately layers four conditions before firing,
    each one independently catching a class of false positive:

    1. The enclosing key name must suggest a credential
       (:func:`_key_suggests_credential`). Catches FPs on random-
       looking values in non-credential contexts (commit SHAs in
       ``version:`` fields, hash prefixes in ``id:`` fields).
    2. The value must be at least :data:`MIN_ENTROPY_LENGTH` chars.
       Catches FPs on short hex values (UUIDs are technically
       high-entropy at 4.0 bits/char but short).
    3. The value must consist only of token-shaped characters
       (``[A-Za-z0-9+/=_-.]``). Catches FPs on encoded paths,
       templated config strings, log lines.
    4. No deterministic detector already classifies the value. Avoids
       double-emitting the same value with two different labels.

    The placeholder filter (``replaceme``, ``<your-key>``, etc.) is
    applied last because the prefix-shape pass already does the same
    thing; running it here keeps the entropy hit behavior consistent
    with the deterministic side.
    """
    hits: list[str] = []
    seen: set[str] = set()
    for key_name, raw_value in _walk_key_value_pairs(doc):
        if not _key_suggests_credential(key_name):
            continue
        candidate = raw_value.strip().strip("\"'")
        if len(candidate) < MIN_ENTROPY_LENGTH:
            continue
        if not _TOKEN_SHAPED_RE.match(candidate):
            continue
        if PLACEHOLDER_MARKER_RE.search(candidate):
            continue
        # Skip if a deterministic detector already would catch this —
        # the deterministic label is more useful to operators than a
        # generic ``entropy:`` label. ``_classify`` covers both the
        # built-in catalog and user-registered ``--secret-pattern``s
        # so a custom token never gets emitted twice.
        if _classify(candidate) is not None:
            continue
        if shannon_entropy(candidate) < MIN_ENTROPY_BITS_PER_CHAR:
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        hits.append(f"entropy:{_redact(candidate)}")
    return hits


def classify_tokens_raw(doc: Any) -> list[tuple[str, str]]:
    """Return ``(detector_name, raw_value)`` pairs for every classified token.

    Unlike :func:`find_secret_values`, the raw value is NOT redacted.
    This function exists solely for the live-verification pipeline
    (``--verify-secrets``), which needs the actual credential value to
    probe the upstream API. Callers must never persist, log, or surface
    the raw values in output.

    Only the deterministic prefix-shape catalog participates; PEM
    blocks, keyed-hex, and entropy hits are excluded because they
    don't have corresponding verifier endpoints.
    """
    from .base import walk_strings

    results: list[tuple[str, str]] = []
    seen: set[str] = set()
    pre_collected = isinstance(doc, list) and doc and isinstance(doc[0], str)
    strings: Iterable[str] = doc if pre_collected else walk_strings(doc)

    for s in strings:
        candidate = s.strip()
        if not candidate:
            continue
        for token in _tokenize(candidate):
            if token in seen:
                continue
            if PLACEHOLDER_MARKER_RE.search(token):
                continue
            label = _classify(token)
            if label is None:
                continue
            seen.add(token)
            results.append((label, token))
    return results


def find_secret_values(doc: Any) -> list[str]:
    """Return labeled credential hits found anywhere in ``doc``.

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

    When :func:`enable_entropy_detection` has been turned on, a
    second pass adds ``entropy:<redacted>`` hits for high-entropy
    values appearing in credential-shaped YAML key contexts that
    the prefix-shape catalog didn't already catch. The entropy pass
    needs the YAML key context, so it's skipped for the
    pre-collected-string-list call shape (Jenkins). The
    deterministic catalog still runs for those callers.
    """
    from .base import walk_strings

    hits: list[str] = []
    seen_tokens: set[str] = set()
    seen_pem: set[str] = set()

    strings: Iterable[str]
    pre_collected = isinstance(doc, list) and doc and isinstance(doc[0], str)
    if pre_collected:
        strings = doc  # pre-collected string list
    else:
        strings = walk_strings(doc)

    for s in strings:
        candidate = s.strip()
        if not candidate:
            continue

        # PEM blocks span many lines, match the BEGIN marker anywhere.
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
            # ``token_label`` is distinct from the ``label`` used for
            # PEM blocks above (always ``str``) so mypy doesn't widen
            # the variable's inferred type to ``str | None``.
            token_label = _classify(token)
            if token_label is None:
                continue
            seen_tokens.add(token)
            hits.append(f"{token_label}:{_redact(token)}")

    # Keyed-hex pass: always on, narrow shape (40 lowercase hex) gated
    # on a credential-named YAML key. Same key-context plumbing as
    # the entropy pass, so it skips for pre-collected string lists.
    if not pre_collected:
        hits.extend(_find_keyed_hex_hits(doc))
    # Entropy pass: opt-in, additive, requires YAML key context (so
    # pre-collected string lists skip it — there's no key for those).
    if _ENTROPY_ENABLED and not pre_collected:
        hits.extend(_find_entropy_hits(doc))
    return hits


def _classify(token: str) -> str | None:
    """Return the detector name for ``token``, or None if no detector matches.

    Uses a two-level dispatch: first by the token's first 2 characters
    (catches 39 of 41 built-in detectors), then a short fallback list
    for patterns with no fixed prefix (mailchimp hex, telegram numeric).

    Tokens shorter than 8 characters are rejected early, no built-in
    credential shape is that short.
    """
    if len(token) < 8:
        return None
    # Two-char prefix dispatch, covers ~95% of detectors.
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
    "MIN_ENTROPY_BITS_PER_CHAR",
    "MIN_ENTROPY_LENGTH",
    "SECRET_DETECTORS",
    "SECRET_VALUE_RE",
    "classify_tokens_raw",
    "enable_entropy_detection",
    "find_secret_values",
    "register_pattern",
    "reset_patterns",
    "shannon_entropy",
]
