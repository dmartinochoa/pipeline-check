"""Shared regexes and helpers for ADO rules."""
from __future__ import annotations

import re

TASK_PIN_RE = re.compile(r"@\d+\.\d+(?:\.\d+)?(?:[-.][\w\d]+)*$")

UNTRUSTED_VAR_RE = re.compile(
    r"\$\(\s*(?:"
    r"Build\.SourceBranch(?:Name)?"
    r"|Build\.SourceVersion(?:Message)?"
    r"|Build\.RequestedFor(?:Email)?"
    r"|System\.PullRequest\.(?:SourceBranch|SourceRepositoryURI|PullRequestId|PullRequestNumber)"
    r")\s*\)"
)

AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
SECRETISH_KEY_RE = re.compile(
    r"(?i)(?:password|passwd|secret|token|apikey|api_key|private_key)"
)

DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
VERSION_TAG_RE = re.compile(r":[^:]*\d[^:]*$")

# Cache-key taint regex used by ADO-012.
CACHE_TAINT_RE = re.compile(
    r"\$\(\s*(?:"
    r"System\.PullRequest\.[A-Za-z]+"
    r"|Build\.SourceBranch(?:Name)?"
    r"|Build\.SourceVersion(?:Message)?"
    r")\s*\)"
)

# Pool names that route to Microsoft-hosted agents regardless of shape.
MS_HOSTED_NAMES = frozenset({"azure pipelines", "default"})


def image_reason(img: str) -> str | None:
    """Return a human reason an image is unpinned, or None if pinned."""
    if DIGEST_RE.search(img):
        return None
    if ":" not in img.rsplit("/", 1)[-1]:
        return f"{img} (no tag)"
    tag = img.rsplit(":", 1)[1]
    if tag == "latest" or not VERSION_TAG_RE.search(img):
        return img
    return None
