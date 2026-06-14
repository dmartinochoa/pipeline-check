"""Shared regex patterns and constants used by multiple GHA rules.

Keeping these in one module means when the attacker-controllable-
context catalog (``_UNTRUSTED_CONTEXT_RE``) grows, only one place
needs editing, and every rule that shares the regex picks up the
change automatically.
"""
from __future__ import annotations

import re

from ..._primitives.agentic_cli import (  # re-exported for callers
    AGENTIC_CLI_RE,
)
from ..._primitives.agentic_cli import (
    invokes_agentic_cli as step_invokes_agentic_cli,
)
from ..._primitives.sha_ref import SHA_RE  # re-exported for callers

__all__ = [
    "SHA_RE",
    "UNTRUSTED_CONTEXT_RE",
    "PR_HEAD_REF_RE",
    "CACHE_TAINT_RE",
    "UNTRUSTED_TRIGGERS",
    "AGENTIC_CLI_RE",
    "step_invokes_agentic_cli",
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
    # levels deep, which covers every shape seen in the wild. The
    # ``(?:[^,()]*,\s*)*?`` after each ``(`` skips any leading arguments
    # so ``format('PR {0}', github.event.issue.title)`` is caught (the
    # untrusted value is the second argument, not the literal template).
    r"(?:(?:toJSON|fromJSON|format)\s*\(\s*(?:[^,()]*,\s*)*?){0,2}"
    r"(?:"
    r"github\.event\.(?:"
    r"issue\.(?:title|body)"
    r"|pull_request\.(?:title|body|head\.ref|head\.label"
    # A fork PR author fully controls their fork repo's free-form text
    # fields. ``head.repo.description`` / ``.homepage`` are arbitrary
    # text; ``.default_branch`` is an attacker-chosen ref name (git refs
    # permit ``$()``, backticks, ``;``). All are documented untrusted
    # sinks under pull_request_target.
    r"|head\.repo\.(?:description|homepage|default_branch)"
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
    r"|workflow_run\.(?:head_branch|display_title|head_commit\.message"
    r"|head_repository\.(?:description|homepage|default_branch))"
    r")"
    # ``\b`` after the alternation so ``github.actor`` matches but
    # ``github.actor_id`` (a numeric account ID, never injectable) does
    # not get swallowed by the trailing ``[^\}]*`` wildcard below.
    r"|github\.(?:head_ref|ref_name|actor)\b"
    r"|github\.event\.pull_request\.base\.ref"
    r"|github\.event\.client_payload\.[^\})]*"
    # ``github.event.inputs.<name>`` is the original workflow_dispatch
    # input syntax (still valid and common); ``inputs.<name>`` is the
    # newer shorthand. Both are caller-controlled and must be caught.
    r"|github\.event\.inputs\.[A-Za-z_][A-Za-z0-9_]*"
    r"|inputs\.[A-Za-z_][A-Za-z0-9_]*"
    r")"
    # Closing parens for any function wrappers, then optional
    # ``,<anything>`` for the format() second argument.
    r"(?:[^\}]*)?\s*\}\}",
    # GitHub expression function names and context paths are
    # case-insensitive (``fromJSON`` == ``fromjson``), so match both.
    re.IGNORECASE,
)

# A ``ref:`` value pointing at the PR head, used by GHA-002.
# ``github.head_ref`` is the documented shorthand for
# ``github.event.pull_request.head.ref`` and is the more common way
# to write a PR-head checkout, so it must be caught too.
#
# ``merge_commit_sha`` is the auto-generated merge of the PR into the
# base: checking it out still runs the attacker's PR code, so it is the
# same hazard as ``head.sha`` and is a documented ``pull_request_target``
# bypass. ``refs/pull/<n>/head`` (the PR head) and ``refs/pull/<n>/merge``
# (the merge ref) are the literal-ref forms of the same checkout, written
# without a ``${{ }}`` expression; the ``<n>`` is often itself an
# expression (``refs/pull/${{ github.event.number }}/merge``) so the
# middle segment is matched loosely. Case-insensitive because GitHub
# context names are case-insensitive.
PR_HEAD_REF_RE = re.compile(
    r"\$\{\{\s*(?:"
    r"github\.event\.pull_request(?:_target)?\."
    r"(?:head\.(?:sha|ref)|merge_commit_sha)"
    r"|github\.head_ref"
    r")\s*\}\}"
    r"|refs/pull/[^/\n]+/(?:head|merge)(?![A-Za-z])",
    re.IGNORECASE,
)

# Cache-key taint regex used by GHA-011.
CACHE_TAINT_RE = re.compile(
    r"\$\{\{\s*(?:"
    r"github\.event\.(?:pull_request|issue|comment|release|deployment|"
    r"head_commit|workflow_run|discussion|review|pages|inputs)\."
    r"|github\.head_ref"
    r"|inputs\."
    r")[^\}]*\}\}"
)

# Triggers on which the checked-out workspace can contain
# PR-controlled content. Used by GHA-010.
UNTRUSTED_TRIGGERS = frozenset({"pull_request_target", "workflow_run"})

# Agentic AI CLIs: tools that read a prompt and then act (run shell,
# write files, call tools) rather than just returning text. Shared by
# GHA-058 (permission-bypass flags) and GHA-119 (prompt injection). The
# set is the agentic ones specifically. ``AGENTIC_CLI_RE`` and
# ``step_invokes_agentic_cli`` now live in ``_primitives/agentic_cli`` (shared
# with the GitLab analog GL-048) and are re-exported at the top of this module.
