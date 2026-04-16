"""Shared regex patterns and constants used by multiple GHA rules.

Keeping these in one module means when the attacker-controllable-
context catalogue (``_UNTRUSTED_CONTEXT_RE``) grows, only one place
needs editing — and every rule that shares the regex picks up the
change automatically.
"""
from __future__ import annotations

import re

# A 40-character lowercase hex string — a git commit SHA.
SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# Untrusted attacker-controllable context expressions inside `run:`
# bodies. Catalogue assembled from StepSecurity / GitHub Security Lab
# advisories plus PPE write-ups (CICD-SEC-4). Three classes of
# expression:
#
#   1. ``github.event.<field>`` — payload fields the SCM event author
#      populates (PR title/body, commit message, comment body, …).
#   2. ``github.<top-level>`` — derived shortcuts that resolve to the
#      same untrusted ref (head_ref, ref_name on push). The pusher
#      controls these through branch/tag naming.
#   3. ``inputs.<name>`` — workflow_dispatch / workflow_call inputs.
#      Caller-controlled; safe ONLY when the trigger is restricted to
#      privileged actors, which the workflow YAML can't enforce.
UNTRUSTED_CONTEXT_RE = re.compile(
    r"\$\{\{\s*(?:"
    r"github\.event\.(?:"
    r"issue\.(?:title|body)"
    r"|pull_request\.(?:title|body|head\.ref|head\.label)"
    r"|comment\.body"
    r"|review\.body"
    r"|pages\.[^\}]*?\.page_name"
    r"|head_commit\.(?:message|author\.(?:name|email))"
    r"|discussion\.(?:title|body)"
    r"|release\.(?:name|body|tag_name)"
    r"|deployment\.payload\.[^\}]*"
    r"|workflow_run\.(?:head_branch|display_title|head_commit\.message)"
    r")"
    r"|github\.(?:head_ref|ref_name|actor)"
    r"|github\.event\.pull_request\.base\.ref"
    r"|github\.event\.client_payload\.[^\}]*"
    r"|inputs\.[A-Za-z_][A-Za-z0-9_]*"
    r")\s*\}\}"
)

# A ``ref:`` value pointing at the PR head — used by GHA-002.
PR_HEAD_REF_RE = re.compile(
    r"\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)\s*\}\}"
)

# Cache-key taint regex used by GHA-011.
CACHE_TAINT_RE = re.compile(
    r"\$\{\{\s*(?:"
    r"github\.event\.(?:pull_request|issue|comment|release|deployment|"
    r"head_commit|workflow_run|discussion|review|page)\."
    r"|github\.head_ref"
    r"|inputs\."
    r")[^\}]*\}\}"
)

# Triggers on which the checked-out workspace can contain
# PR-controlled content. Used by GHA-010.
UNTRUSTED_TRIGGERS = frozenset({"pull_request_target", "workflow_run"})
