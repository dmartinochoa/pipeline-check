"""Shared detection for unsafe deserialization of a fetched artifact.

Loading a model / artifact through a pickle-backed deserializer executes
arbitrary Python embedded in the file at load time. In CI, where the file
is routinely *downloaded* rather than locally produced, that is remote
code execution under the job's secrets and token. ``torch.load`` used the
pickle path by default before PyTorch 2.6; ``pickle.load`` / ``joblib.load``
have no safe mode; ``numpy.load(..., allow_pickle=True)`` opts back into it
explicitly.

Two firing shapes, both scoped to one command body (a GitHub ``run:`` step
or a GitLab job's joined ``script``):

  A. **Explicit unsafe opt-in** (always fires): ``weights_only=False`` on a
     load, or ``allow_pickle=True`` on ``numpy.load``.

  B. **Fetch + unpickle** (fires only together): the body both fetches a
     remote artifact and deserializes via a pickle-backed loader, with no
     safe path (``weights_only=True`` or safetensors) present. The
     download-then-unpickle pair is the actual RCE vector; a pickle load of
     a purely local, self-produced file does not fetch and does not fire.

Used by GHA-122 (per ``run:`` step) and GL-047 (per GitLab job ``script``).
Pure text-level analysis: callers pass a command body and get back a short
label for the unsafe shape, or ``None``.
"""
from __future__ import annotations

import re

# Explicit, unambiguous opt-ins to unsafe deserialization.
_EXPLICIT_UNSAFE_RE = re.compile(
    r"weights_only\s*=\s*False|allow_pickle\s*=\s*True",
    re.IGNORECASE,
)

# Pickle-backed loaders (the unsafe deserialization sinks).
_PICKLE_LOADER_RE = re.compile(
    r"\b(?:torch\.load|c?pickle\.loads?|joblib\.load)\s*\(",
    re.IGNORECASE,
)

# A remote artifact fetch in the same body.
_FETCH_RE = re.compile(
    r"\b(?:curl|wget)\b"
    r"|\b(?:hf_hub_download|snapshot_download|urlretrieve|urlopen)\s*\("
    r"|\brequests\.(?:get|post)\s*\("
    r"|\bhuggingface-cli\s+download\b"
    r"|\bhf\s+download\b",
    re.IGNORECASE,
)

# The safe path: tensor-only torch load, or safetensors.
_SAFE_PATH_RE = re.compile(
    r"weights_only\s*=\s*True|\bsafetensors\b|\b(?:safe_open|load_file)\s*\(",
    re.IGNORECASE,
)


def unsafe_deser_label(body: str) -> str | None:
    """Return a short label for the unsafe deserialization shape in *body*,
    or ``None`` when neither shape is present.

    Shape A (explicit ``weights_only=False`` / ``allow_pickle=True``) always
    fires. Shape B (a remote fetch alongside a pickle-backed loader, with no
    safe path in the same body) is the download-then-unpickle RCE vector.
    """
    if _EXPLICIT_UNSAFE_RE.search(body):
        return "explicit unsafe opt-in (weights_only=False / allow_pickle=True)"
    if (
        _PICKLE_LOADER_RE.search(body)
        and _FETCH_RE.search(body)
        and not _SAFE_PATH_RE.search(body)
    ):
        return "fetched artifact deserialized via pickle"
    return None
