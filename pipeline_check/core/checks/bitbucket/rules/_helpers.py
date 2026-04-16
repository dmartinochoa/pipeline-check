"""Shared regexes and constants for BB rules."""
from __future__ import annotations

import re

# Pinned pipe ref = full semver `:x.y.z` or sha256 digest.
VER_OK_RE = re.compile(r":(?:\d+\.\d+(?:\.\d+)?(?:[-.][\w\d]+)*|[0-9a-f]{40})$")

UNTRUSTED_VAR_RE = re.compile(
    r"\$\{?(?:"
    r"BITBUCKET_BRANCH|BITBUCKET_TAG"
    r"|BITBUCKET_PR_DESTINATION_BRANCH|BITBUCKET_PR_ID"
    r"|BITBUCKET_BOOKMARK"
    r")\}?"
)

AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
SECRETISH_KEY_RE = re.compile(
    r"(?i)(?:password|passwd|secret|token|apikey|api_key|private_key)"
)
DEPLOY_RE = re.compile(r"(?i)(deploy|release|publish|promote)")
PIPE_REF_RE = re.compile(r"\s*pipe:\s*(\S+)")


def extract_pipe_ref(entry):
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
