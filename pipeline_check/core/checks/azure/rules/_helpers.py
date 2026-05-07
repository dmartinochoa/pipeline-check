"""Shared regexes and helpers for ADO rules."""
from __future__ import annotations

import re

from ..._primitives.image_pinning import DIGEST_RE as DIGEST_RE
from ..._primitives.image_pinning import VERSION_TAG_RE as VERSION_TAG_RE
from ..._primitives.image_pinning import PinKind, classify
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

# Pool / agent-targeting taint regex used by ADO-030. Composed from
# ``UNTRUSTED_VAR_RE`` (runtime SCM macros) plus the additional
# ``${{ parameters.X }}`` template-parameter shape (caller-controlled
# at trigger time). Composing rather than restating means future
# additions to ``UNTRUSTED_VAR_RE`` flow into ADO-030 automatically.
# Pipeline variables defined in the workflow's own ``variables:``
# block are author-controlled and intentionally NOT included.
POOL_TAINT_RE = re.compile(
    UNTRUSTED_VAR_RE.pattern
    + r"|\$\{\{\s*parameters\.[A-Za-z_][A-Za-z0-9_]*\s*\}\}"
)

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
    kind = classify(img)
    if kind in (PinKind.DIGEST, PinKind.PINNED_TAG):
        return None
    if kind is PinKind.NO_TAG:
        return f"{img} (no tag)"
    return img
