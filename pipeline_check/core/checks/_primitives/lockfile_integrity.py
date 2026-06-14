"""Detect package-install commands that bypass registry integrity.

``PKG_NO_LOCKFILE_RE`` in :mod:`pipeline_check.core.checks.base`
already catches the most common integrity miss, running
``npm install`` or ``pip install <bare>`` without a lockfile flag.
This primitive covers the adjacent class: install commands that do
use a resolver but aim it at a source the lockfile doesn't protect.

Three vectors:

1. **Git URL deps**, ``pip install git+https://…``,
   ``npm install git+ssh://…``, ``cargo install --git …``. The
   lockfile only records the repo URL, not an immutable commit;
   HEAD moving on the remote silently changes what CI installs.
   Safe only when the URL pins a commit SHA: ``@<sha>`` for pip
   (``git+https://…/repo.git@<40-hex>``), ``#<sha>`` for npm
   (``git+https://…/repo.git#<40-hex>``), ``--rev <sha>`` for
   cargo. The SHA check is a simple "40-hex anywhere in the match"
   test, weaker than parsing each ecosystem's pin syntax but
   equivalent in practice since nothing else in a typical install
   command shape matches that pattern.
2. **Local path deps**, ``pip install ./dir`` / ``file:…`` /
   ``npm install /abs/path``. Depends on whatever is present at
   that path at build time, often a sibling checkout whose commit
   isn't captured by the primary lockfile.
3. **Direct tarball URL**, ``pip install https://…/x.tar.gz``,
   ``npm install https://…/x.tgz``. Registry authentication and
   mirror policies don't apply; the download is trust-on-first-use.

This primitive is intentionally conservative: it requires an
explicit install verb (``pip install``, ``npm install``, …) before
scanning arguments, so a curl-pipe to a tarball URL that happens
to live in the same line won't false-positive on
``_primitives.remote_script_exec``'s territory.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# 40-char lowercase hex, a git commit SHA. Re-used across the three
# git-URL ecosystems to decide whether a git dep is pinned.
_SHA_RE = re.compile(r"\b[0-9a-f]{40}\b")

# pip / npm / yarn install verbs. Git dependencies are evaluated per
# token (in ``scan``) rather than per command line, so a pinned dep
# early on a line can't mask an unpinned sibling later on the same line.
_PIP_INSTALL_RE = re.compile(r"\bpip3?\s+install\b")
_NPM_INSTALL_RE = re.compile(r"\b(?:npm\s+install|yarn\s+add)\b")

# A single ``git+<scheme>://…`` dependency token. Without a 40-hex
# commit somewhere in the token the install follows the remote HEAD.
_GIT_URL_RE = re.compile(r"\bgit\+[^\s;&|]+")

# npm ``<user>/<repo>`` shorthand as a bare install argument. Must start
# with a non-path char (not ``/`` or ``.``) and hold exactly one slash
# so ``/opt/shared/pkg`` falls through to the local-path matcher.
# Shorthand resolves to the GitHub default branch, the same TOFU risk
# as an un-pinned git URL.
_NPM_SHORTHAND_RE = re.compile(
    r"(?:^|\s)([a-zA-Z0-9_-][a-zA-Z0-9_-]*/[a-zA-Z0-9_.-]+)(?=\s|$)"
)

# Shell statement boundary, so each git dep is scoped to its own
# install command.
_STMT_SPLIT_RE = re.compile(r"[;\n]|&&|\|\|")

# cargo: ``cargo install --git <url>``, accepted as pinned only
# when ``--rev <40-hex>`` follows on the same statement. ``--tag``
# is explicitly treated as unpinned: tags on crates-registry-less
# repos are mutable by the upstream maintainer. Greedy capture up
# to a newline or statement separator so a trailing ``--rev <sha>``
# is included in the match for the SHA check to see.
_CARGO_GIT_RE = re.compile(
    r"\bcargo\s+install\s+[^\n;&|]*--git\s+[^\n;&|]+",
)

# Local-path installs:
# ``pip install ./thing`` / ``pip install -e ./thing`` /
# ``pip install file:///…`` / ``npm install /abs/path`` /
# ``npm install ./dir``. Excludes the bare ``.`` (current package
# build, legitimate) by requiring at least one path separator.
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


@dataclass(frozen=True, slots=True)
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

    # Git deps: scan each install statement and evaluate every git+ token
    # (and npm shorthand) on its own, so a pinned dep doesn't suppress an
    # unpinned one earlier or later in the same command.
    for stmt in _STMT_SPLIT_RE.split(text):
        npm_match = _NPM_INSTALL_RE.search(stmt)
        if not (_PIP_INSTALL_RE.search(stmt) or npm_match):
            continue
        for m in _GIT_URL_RE.finditer(stmt):
            if not _SHA_RE.search(m.group(0)):
                out.append(LockfileIssue("git", _trim(m.group(0))))
        if npm_match:
            for m in _NPM_SHORTHAND_RE.finditer(stmt[npm_match.end():]):
                out.append(LockfileIssue("git", _trim(m.group(1))))

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
