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
# ``--revision`` flag, or an ``@<commit-ish>`` suffix. ``revision=None``
# / ``null`` is the explicit "use the mutable default branch" value, so
# it is excluded — it is not a pin (the negative lookahead rejects it).
_REVISION_RE = re.compile(
    r"\brevision\s*[=:]\s*['\"]?(?!(?:none|null)\b)[\w.\-]+"
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


#: Extract the ``repo_id=`` kwarg value from a Python fetch call.
_REPO_ID_KWARG_RE = re.compile(r"repo_id\s*=\s*['\"]([^'\"]+)", re.IGNORECASE)
#: The first string literal argument to a Python fetch call.
_FIRST_STRING_ARG_RE = re.compile(r"['\"]([^'\"]+)['\"]")


def _fetched_ref(window: str, anchor: re.Match[str]) -> str | None:
    """Extract the model reference the fetch call actually targets.

    For the CLI forms (``huggingface-cli download`` / ``hf download``) the
    model is the first positional (non-flag) argument. For the Python
    forms it is the ``repo_id=`` kwarg or the first string-literal arg.
    Extracting it positionally avoids matching an unrelated slash-shaped
    token elsewhere in the command (``--local-dir models/gpt2``).
    """
    rest = window[anchor.end():]
    if "download" in anchor.group(0).lower():
        for tok in rest.split():
            if tok.startswith("-"):
                continue
            return tok
        return None
    kw = _REPO_ID_KWARG_RE.search(rest)
    if kw:
        return kw.group(1)
    s = _FIRST_STRING_ARG_RE.search(rest)
    return s.group(1) if s else None


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
        anchor = _FETCH_ANCHOR_RE.search(window)
        if anchor is None:
            continue
        if _REVISION_RE.search(window):
            continue
        ref = _fetched_ref(window, anchor)
        if ref is None:
            continue
        repo = _REPO_ID_RE.search(ref)
        if repo:
            return repo.group(1)
    return None
