"""Shared regexes and helpers for ADO rules."""
from __future__ import annotations

import re

from ..._primitives.secret_shapes import AWS_KEY_RE as AWS_KEY_RE
from ..._primitives.secret_shapes import SECRETISH_KEY_RE as SECRETISH_KEY_RE

TASK_PIN_RE = re.compile(r"@\d+\.\d+(?:\.\d+)?(?:[-.][\w\d]+)*$")

UNTRUSTED_VAR_RE = re.compile(
    r"\$\(\s*(?:"
    r"Build\.SourceBranch(?:Name)?"
    r"|Build\.SourceVersion(?:Message)?"
    r"|Build\.RequestedFor(?:Email)?"
    r"|Build\.DefinitionName"
    r"|System\.PullRequest\.(?:SourceBranch|SourceRepositoryURI|SourceCommitId"
    r"|PullRequestId|PullRequestNumber)"
    r")\s*\)"
)

DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
VERSION_TAG_RE = re.compile(r":[^:]*\d[^:]*$")

# Cache-key taint regex used by ADO-012.
CACHE_TAINT_RE = re.compile(
    r"\$\(\s*(?:"
    r"System\.PullRequest\.[A-Za-z]+"
    r"|Build\.SourceBranch(?:Name)?"
    r"|Build\.SourceVersion(?:Message)?"
    r"|Build\.RequestedFor(?:Email)?"
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
