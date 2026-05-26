"""Shared regex patterns and constants used by multiple GHA rules.

Keeping these in one module means when the attacker-controllable-
context catalog (``_UNTRUSTED_CONTEXT_RE``) grows, only one place
needs editing, and every rule that shares the regex picks up the
change automatically.
"""
from __future__ import annotations

import re

from ..._primitives.sha_ref import SHA_RE  # re-exported for callers

__all__ = [
    "SHA_RE",
    "UNTRUSTED_CONTEXT_RE",
    "PR_HEAD_REF_RE",
    "CACHE_TAINT_RE",
    "UNTRUSTED_TRIGGERS",
]

# Untrusted attacker-controllable context expressions inside `run:`
# bodies. Catalog assembled from StepSecurity / GitHub Security Lab
# advisories plus PPE write-ups (CICD-SEC-4). Three classes of
# expression:
#
#   1. ``github.event.<field>``, payload fields the SCM event author
#      populates (PR title/body, commit message, comment body, …).
#   2. ``github.<top-level>``, derived shortcuts that resolve to the
#      same untrusted ref (head_ref, ref_name on push). The pusher
#      controls these through branch/tag naming.
#   3. ``inputs.<name>``, workflow_dispatch / workflow_call inputs.
#      Caller-controlled; safe ONLY when the trigger is restricted to
#      privileged actors, which the workflow YAML can't enforce.
UNTRUSTED_CONTEXT_RE = re.compile(
    r"\$\{\{\s*"
    # Optional function wrappers around the untrusted context. Common
    # shapes: ``toJSON(...)``, ``fromJSON(...)``, ``format(...)``.
    # Nested calls (``fromJSON(toJSON(...))``) are matched up to two
    # levels deep, which covers every shape seen in the wild.
    r"(?:(?:toJSON|fromJSON|format)\s*\(\s*){0,2}"
    r"(?:"
    r"github\.event\.(?:"
    r"issue\.(?:title|body)"
    r"|pull_request\.(?:title|body|head\.ref|head\.label"
    # ``labels.*.name`` (and ``.description``) lets a PR author or any
    # labeler land arbitrary text in a list a downstream job iterates.
    # Targets the GitHub Security Lab matrix-injection writeup shape.
    r"|labels(?:\[\d+\])?\.\*?\.(?:name|description))"
    r"|comment\.body"
    r"|review\.body"
    r"|review_comment\.body"
    r"|commits(?:\[\d+\])?\.(?:message|author\.(?:name|email))"
    r"|pages(?:\[\d+\])?\.\w+"
    r"|head_commit\.(?:message|author\.(?:name|email))"
    r"|discussion\.(?:title|body)"
    r"|release\.(?:name|body|tag_name)"
    r"|deployment\.payload\.[^\})]*"
    r"|workflow_run\.(?:head_branch|display_title|head_commit\.message)"
    r")"
    r"|github\.(?:head_ref|ref_name|actor)"
    r"|github\.event\.pull_request\.base\.ref"
    r"|github\.event\.client_payload\.[^\})]*"
    r"|inputs\.[A-Za-z_][A-Za-z0-9_]*"
    r")"
    # Closing parens for any function wrappers, then optional
    # ``,<anything>`` for the format() second argument.
    r"(?:[^\}]*)?\s*\}\}"
)

# A ``ref:`` value pointing at the PR head, used by GHA-002.
PR_HEAD_REF_RE = re.compile(
    r"\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)\s*\}\}"
)

# Cache-key taint regex used by GHA-011.
CACHE_TAINT_RE = re.compile(
    r"\$\{\{\s*(?:"
    r"github\.event\.(?:pull_request|issue|comment|release|deployment|"
    r"head_commit|workflow_run|discussion|review|pages)\."
    r"|github\.head_ref"
    r"|inputs\."
    r")[^\}]*\}\}"
)

# Triggers on which the checked-out workspace can contain
# PR-controlled content. Used by GHA-010.
UNTRUSTED_TRIGGERS = frozenset({"pull_request_target", "workflow_run"})
