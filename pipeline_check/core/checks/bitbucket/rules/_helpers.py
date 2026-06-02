"""Shared regexes and constants for BB rules."""
from __future__ import annotations

import re

from ..._primitives.deploy_names import DEPLOY_RE as DEPLOY_RE
from ..._primitives.secret_shapes import AWS_KEY_RE as AWS_KEY_RE
from ..._primitives.secret_shapes import SECRETISH_KEY_RE as SECRETISH_KEY_RE
from ..._primitives.secret_shapes import aws_key_in as aws_key_in
from ..._primitives.secret_shapes import is_placeholder_value as is_placeholder_value

# Pinned pipe ref = full semver `:x.y.z` (patch required) or sha256 digest.
# Major.minor tags like `:1.4` are rejected — they are floating and can be
# republished without notice.
VER_OK_RE = re.compile(r":(?:\d+\.\d+\.\d+(?:[-.][\w\d]+)*|[0-9a-f]{40})$")

UNTRUSTED_VAR_RE = re.compile(
    r"\$\{?(?:"
    r"BITBUCKET_BRANCH|BITBUCKET_TAG"
    r"|BITBUCKET_PR_DESTINATION_BRANCH|BITBUCKET_PR_ID"
    r"|BITBUCKET_BOOKMARK"
    r")\}?"
)

PIPE_REF_RE = re.compile(r"\s*pipe:\s*(\S+)")


def extract_pipe_ref(entry: object) -> str | None:
    """Return the pipe reference from a script entry (dict or string form)."""
    if isinstance(entry, dict) and "pipe" in entry:
        v = entry["pipe"]
        if isinstance(v, str):
            return v.strip()
    elif isinstance(entry, str):
        m = PIPE_REF_RE.match(entry)
        if m:
            return m.group(1).strip().strip('"').strip("'")
    return None
