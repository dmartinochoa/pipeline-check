"""Canonical parser for GitHub Actions ``uses:`` references.

A single ``uses:`` value can name several distinct things:

  - ``actions/checkout@v4``                         action / public repo
  - ``actions/setup-node/lib@v4``                   action in a subpath
  - ``./.github/actions/build``                     local action
  - ``./.github/workflows/release.yml``             local reusable workflow
  - ``owner/repo/.github/workflows/release.yml@v1`` remote reusable workflow
  - ``docker://ghcr.io/foo/bar:1.2.3``              docker image step

Before this module existed, every rule that cared about ``uses:``
parsed the string itself with ad-hoc ``rsplit("@", 1)`` calls. The
remote-ref resolver needs a structured decomposition (owner, repo,
path, ref) shared with the rules so they all classify the same way.

The parser is conservative — it returns ``None`` for anything it
doesn't recognize, and rules treat ``None`` as "not a uses we care
about." It never raises.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# A workflow reference always ends in ``.yml`` or ``.yaml`` and lives
# under ``.github/workflows/`` in the called repo.
_WORKFLOW_FILE_RE = re.compile(r"\.ya?ml$", re.IGNORECASE)


UsesKind = Literal["local-action", "local-workflow", "remote-workflow",
                   "remote-action", "docker"]


@dataclass(frozen=True, slots=True)
class UsesRef:
    """Structured form of a ``uses:`` reference.

    ``ref`` is the right-hand side of the trailing ``@`` (commit SHA,
    tag, or branch). It's empty for local refs, which inherit the
    caller's commit.
    """

    raw: str
    kind: UsesKind
    owner: str = ""
    repo: str = ""
    path: str = ""        # repo-relative path, e.g. ``.github/workflows/release.yml``
    ref: str = ""

    @property
    def is_remote_workflow(self) -> bool:
        return self.kind == "remote-workflow"

    @property
    def is_pinned_to_sha(self) -> bool:
        """True iff ``ref`` is a 40-char hex commit SHA."""
        return bool(self.ref) and bool(_SHA_RE.match(self.ref))


def parse_uses(value: Any) -> UsesRef | None:
    """Parse a ``uses:`` value into a :class:`UsesRef`, or ``None``.

    Accepts ``Any`` because callers fish ``uses`` out of YAML mappings
    where the value's static type is ``Any | None``. Non-string input
    returns ``None``. Doesn't raise.
    """
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None

    # Docker image refs.
    if raw.startswith("docker://"):
        return UsesRef(raw=raw, kind="docker")

    # Local refs ride on the caller's commit; no ``@ref`` to parse.
    if raw.startswith(("./", "/")):
        if _WORKFLOW_FILE_RE.search(raw):
            return UsesRef(raw=raw, kind="local-workflow", path=raw)
        return UsesRef(raw=raw, kind="local-action", path=raw)

    # Remote refs always carry an ``@<ref>``. Anything else without an
    # ``@`` is malformed for our purposes — return None so the rules
    # ignore it the same way they ignore docker refs.
    if "@" not in raw:
        return None

    # Refs themselves never contain ``@`` (refs/tags/v1 has slashes,
    # not @-signs); a single rsplit is safe even when the path has @
    # in it (legal but vanishingly rare).
    body, _, ref = raw.rpartition("@")
    if not body or not ref:
        return None

    parts = body.split("/")
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    path = "/".join(parts[2:]) if len(parts) > 2 else ""

    if path and _WORKFLOW_FILE_RE.search(path):
        return UsesRef(
            raw=raw, kind="remote-workflow",
            owner=owner, repo=repo, path=path, ref=ref,
        )
    return UsesRef(
        raw=raw, kind="remote-action",
        owner=owner, repo=repo, path=path, ref=ref,
    )
