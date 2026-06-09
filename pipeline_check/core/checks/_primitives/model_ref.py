"""Shared detection for an unpinned model-registry fetch.

A model is pulled from a registry (Hugging Face Hub and friends) by a
*mutable* reference and supplied no revision pin, so the registry serves
whatever the repo's default branch points at *now*. The owner (or anyone
who compromises the account or the upstream repo) can then swap the
weights, the tokenizer, or the custom loader code under a green build,
with no diff in the consumer's repo. Pinning the revision is the one
control that makes a poisoned-model swap show up as a diff.

Used by GHA-121 (per ``run:`` step) and GL-046 (per GitLab job
``script:``). Pure text-level analysis: callers pass a command body and
get back the offending ``org/model`` id, or ``None``.
"""
from __future__ import annotations

import re

# Calls / commands that fetch an artifact from a model registry.
_FETCH_ANCHOR_RE = re.compile(
    r"\b(?:from_pretrained|hf_hub_download|snapshot_download)\b"
    r"|\bhuggingface-cli\s+download\b"
    r"|\bhf\s+download\b",
    re.IGNORECASE,
)

# An ``org/model`` (optionally ``org/model/subpath``) hub id. The
# lookbehind stops the match inside a longer path or URL segment
# (``/models/x``, ``a/b/c/d``); the lookahead stops it on a docker tag
# (``org/img:tag``), a git pin (``org/repo@sha``), or a deeper path so
# we capture the whole id, not a prefix. ``$`` / ``{`` are outside the
# charset, so ``${{ env.MODEL }}`` never matches.
_REPO_ID_RE = re.compile(
    r"(?<![\w./@$~-])"
    r"([A-Za-z0-9_][\w.-]*/[\w.-]+(?:/[\w.-]+)?)"
    r"(?![\w/@:-])"
)

# A pinned revision anywhere in the window: the ``revision`` kwarg, the
# ``--revision`` flag, or an ``@<commit-ish>`` suffix.
_REVISION_RE = re.compile(
    r"\brevision\s*[=:]\s*['\"]?[\w.\-]+"
    r"|--revision[=\s]"
    r"|@[0-9a-fA-F]{7,40}\b",
    re.IGNORECASE,
)


def _logical_lines(body: str) -> list[str]:
    r"""Join shell line-continuations (a trailing ``\``) into one logical
    line, so a ``--revision`` / ``revision=`` pin wrapped onto the next
    line still counts as belonging to the same call."""
    out: list[str] = []
    buf = ""
    for raw in body.splitlines():
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
            continue
        buf += stripped
        out.append(buf)
        buf = ""
    if buf:
        out.append(buf)
    return out


def _line_windows(body: str) -> list[str]:
    """Each logical line plus each adjacent two-line pair (the pair
    absorbs a call wrapped across lines without a backslash)."""
    lines = _logical_lines(body)
    out: list[str] = list(lines)
    for i in range(len(lines) - 1):
        out.append(lines[i] + " " + lines[i + 1])
    return out


def unpinned_model_id(body: str) -> str | None:
    """Return the offending repo id in *body*, or ``None``.

    Fires when a single command-window holds a registry-fetch call and an
    ``org/model`` id with no revision pin alongside it. Scoped to
    org-namespaced ids (``org/model``) so it targets third-party models,
    not the canonical first-party hub names (``bert-base-uncased``); a
    local path or a ``${{ }}`` interpolation can't be judged statically
    and does not fire.
    """
    for window in _line_windows(body):
        if not _FETCH_ANCHOR_RE.search(window):
            continue
        if _REVISION_RE.search(window):
            continue
        repo = _REPO_ID_RE.search(window)
        if repo:
            return repo.group(1)
    return None
