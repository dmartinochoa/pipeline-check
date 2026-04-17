"""Detect package-install commands that bypass registry integrity.

``PKG_NO_LOCKFILE_RE`` in :mod:`pipeline_check.core.checks.base`
already catches the most common integrity miss — running
``npm install`` or ``pip install <bare>`` without a lockfile flag.
This primitive covers the adjacent class: install commands that do
use a resolver but aim it at a source the lockfile doesn't protect.

Three vectors:

1. **Git URL deps** — ``pip install git+https://…``,
   ``npm install git+ssh://…``, ``cargo install --git …``. The
   lockfile only records the repo URL, not an immutable commit;
   HEAD moving on the remote silently changes what CI installs.
   Safe only when the URL pins a commit SHA: ``@<sha>`` for pip
   (``git+https://…/repo.git@<40-hex>``), ``#<sha>`` for npm
   (``git+https://…/repo.git#<40-hex>``), ``--rev <sha>`` for
   cargo. The SHA check is a simple "40-hex anywhere in the match"
   test — weaker than parsing each ecosystem's pin syntax but
   equivalent in practice since nothing else in a typical install
   command shape matches that pattern.
2. **Local path deps** — ``pip install ./dir`` / ``file:…`` /
   ``npm install /abs/path``. Depends on whatever is present at
   that path at build time — often a sibling checkout whose commit
   isn't captured by the primary lockfile.
3. **Direct tarball URL** — ``pip install https://…/x.tar.gz``,
   ``npm install https://…/x.tgz``. Registry authentication and
   mirror policies don't apply; the download is trust-on-first-use.

This primitive is intentionally conservative: it requires an
explicit install verb (``pip install``, ``npm install``, …) before
scanning arguments, so a curl-pipe to a tarball URL that happens
to live in the same line won't false-positive on CURL_PIPE_RE's
territory.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# 40-char lowercase hex — a git commit SHA. Re-used across the three
# git-URL ecosystems to decide whether a git dep is pinned.
_SHA_RE = re.compile(r"\b[0-9a-f]{40}\b")

# pip / pip3: ``pip install git+<scheme>://…`` — without ``@<sha>``
# suffix the install follows the remote HEAD. pip also supports
# ``#egg=…`` but that's orthogonal; we only care about whether a
# commit is pinned.
_PIP_GIT_RE = re.compile(
    r"\bpip3?\s+install\s+[^\n;&|]*\bgit\+[^\s;&|]+",
)

# npm / yarn: ``npm install git+…`` or shorthand ``npm install user/repo``.
# Shorthand must start with a non-path char (not ``/`` or ``.``) and
# is limited to one slash so ``/opt/shared/pkg`` falls through to the
# local-path matcher. ``<user>/<repo>`` shorthand resolves to the
# GitHub default branch — same TOFU risk as an un-pinned git URL.
_NPM_GIT_RE = re.compile(
    r"\b(?:npm\s+install|yarn\s+add)\s+"
    r"(?:git\+[^\s;&|]+"
    r"|[a-zA-Z0-9_-][a-zA-Z0-9_-]*/[a-zA-Z0-9_.-]+(?:\s|$))",
)

# cargo: ``cargo install --git <url>`` — pinned only with --rev <sha>
# or --tag (tag is weaker but still named). Greedy capture up to a
# newline or statement separator so a trailing ``--rev <sha>`` is
# included in the match for the SHA check to see.
_CARGO_GIT_RE = re.compile(
    r"\bcargo\s+install\s+[^\n;&|]*--git\s+[^\n;&|]+",
)

# Local-path installs:
# ``pip install ./thing`` / ``pip install -e ./thing`` /
# ``pip install file:///…`` / ``npm install /abs/path`` /
# ``npm install ./dir``. Excludes the bare ``.`` (current package
# build — legitimate) by requiring at least one path separator.
# Absolute paths under npm must start with ``/`` followed by a name
# character so ``--flag`` and ``-e`` aren't captured.
_LOCAL_PATH_RE = re.compile(
    r"\bpip3?\s+install\s+(?:-e\s+)?(?:\./[^\s;&|]+|/[A-Za-z][^\s;&|]*|file://\S+)"
    r"|\b(?:npm\s+install|yarn\s+add)\s+(?:\./[^\s;&|]+|/[A-Za-z][^\s;&|]*|file:[^\s;&|]+)",
)

# Direct tarball URL installs.
_TARBALL_URL_RE = re.compile(
    r"\bpip3?\s+install\s+https?://\S+\.(?:tar\.gz|tgz|whl|zip)"
    r"|\b(?:npm\s+install|yarn\s+add)\s+https?://\S+\.(?:tgz|tar\.gz)",
)


@dataclass(frozen=True)
class LockfileIssue:
    """A single integrity-bypassing install command."""

    kind: str    # "git", "path", "tarball"
    snippet: str  # the matched install fragment


def scan(text: str) -> list[LockfileIssue]:
    """Return one entry per integrity-bypassing install in *text*.

    Git deps with a resolvable 40-char SHA in the URL are treated
    as pinned and not reported. Everything else in the three
    categories is reported.
    """
    out: list[LockfileIssue] = []

    for rex in (_PIP_GIT_RE, _NPM_GIT_RE):
        for m in rex.finditer(text):
            match = m.group(0)
            if _SHA_RE.search(match):
                continue
            out.append(LockfileIssue("git", _trim(match)))

    for m in _CARGO_GIT_RE.finditer(text):
        match = m.group(0)
        if "--rev" in match and _SHA_RE.search(match):
            continue
        out.append(LockfileIssue("git", _trim(match)))

    for m in _LOCAL_PATH_RE.finditer(text):
        out.append(LockfileIssue("path", _trim(m.group(0))))

    for m in _TARBALL_URL_RE.finditer(text):
        out.append(LockfileIssue("tarball", _trim(m.group(0))))

    return out


def _trim(s: str, limit: int = 80) -> str:
    s = " ".join(s.split())
    return s if len(s) <= limit else s[: limit - 1] + "…"
