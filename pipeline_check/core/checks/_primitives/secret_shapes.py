"""Shared secret-shape regexes used across provider rules.

Long-lived secret credentials have recognizable lexical shapes that are
independent of the CI/CD provider carrying them. Consolidating the
regexes here means that when the shape catalogue grows (e.g. a new AWS
key prefix, additional secret-looking identifiers), the update lands in
one place and every provider picks it up.

Providers still own their own *context* regex (which YAML fields or
variable names are attacker-controlled) — that part is legitimately
per-provider and lives in the per-provider ``_helpers.py``.
"""
from __future__ import annotations

import re

# A long-lived AWS access key id. ``AKIA`` is the prefix for a root/IAM
# user access key; ``ASIA`` (temporary STS credentials) is deliberately
# NOT matched here — those are short-lived and their presence in a
# pipeline is not a finding on its own.
AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")

# Names that *look* like credential fields. Matched against variable
# names, env-var keys, and YAML key names. Case-insensitive because
# providers vary on casing conventions (``AWS_SECRET_ACCESS_KEY`` vs
# ``DatabasePassword``).
SECRETISH_KEY_RE = re.compile(
    r"(?i)(?:password|passwd|secret|token|apikey|api_key|private_key)"
)
