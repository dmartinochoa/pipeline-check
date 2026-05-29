"""Shared secret-shape regexes used across provider rules.

Long-lived secret credentials have recognizable lexical shapes that are
independent of the CI/CD provider carrying them. Consolidating the
regexes here means that when the shape catalog grows (e.g. a new AWS
key prefix, additional secret-looking identifiers), the update lands in
one place and every provider picks it up.

Providers still own their own *context* regex (which YAML fields or
variable names are attacker-controlled). That part is legitimately
per-provider and lives in the per-provider ``_helpers.py``.
"""
from __future__ import annotations

import re

from .._patterns import PLACEHOLDER_MARKER_RE, VENDOR_EXAMPLE_TOKENS

# A long-lived AWS access key id. ``AKIA`` is the prefix for a root/IAM
# user access key; ``ASIA`` (temporary STS credentials) is deliberately
# NOT matched here. Those are short-lived and their presence in a
# pipeline is not a finding on its own.
AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")

# Names that *look* like credential fields. Matched against variable
# names, env-var keys, and YAML key names. Case-insensitive because
# providers vary on casing conventions (``AWS_SECRET_ACCESS_KEY`` vs
# ``DatabasePassword``).
SECRETISH_KEY_RE = re.compile(
    r"(?i)(?:password|passwd|secret|token|apikey|api_key|private_key)"
)


def aws_key_in(value: object) -> str | None:
    """Return the long-lived AWS access-key id in *value*, or ``None``.

    Returns ``None`` when *value* isn't a string, carries no AKIA-shaped
    key, or the only match is a vendor-published example
    (``AKIAIOSFODNN7EXAMPLE`` and friends in
    :data:`~pipeline_check.core.checks._patterns.VENDOR_EXAMPLE_TOKENS`).
    Vendor docs keys are documentation artifacts, never valid
    credentials, so flagging them was the catalog's noisiest false
    positive. The entropy-based secret path already suppressed them; this
    brings the shape-based path in line.
    """
    if not isinstance(value, str):
        return None
    m = AWS_KEY_RE.search(value)
    if m is None or m.group(0) in VENDOR_EXAMPLE_TOKENS:
        return None
    return m.group(0)


def is_placeholder_value(value: object) -> bool:
    """True when *value* is an obvious placeholder / redaction marker.

    Catches ``REPLACE_ME`` / ``changeme`` / ``<your-token>`` / ``XXXXX``
    and the rest of
    :data:`~pipeline_check.core.checks._patterns.PLACEHOLDER_MARKER_RE`.
    A credential-shaped key name carrying one of these is a template,
    not a leaked secret. (Rules that deliberately flag placeholders,
    e.g. the Kubernetes Secret manifest checks, simply don't call this.)
    """
    return isinstance(value, str) and bool(PLACEHOLDER_MARKER_RE.search(value))
