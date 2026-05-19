"""Detect dependency-install commands that bypass registry-side verification.

Two adjacent vectors live here, both about *what's verified at install
time* rather than the per-package lockfile metadata that's PYPI-* /
NPM-*'s territory:

1. **npm install without ``npm audit signatures``**. Lockfile pinning
   guarantees the bytes match what the lockfile recorded, not that
   the bytes were signed by the registry's trusted publisher for the
   package. Maintainer-account compromises (Shai-Hulud npm worm,
   TanStack / axios patch-release compromises) ride this gap.

2. **pip install without ``--require-hashes``**. Hash-pinned install
   refuses to install any tarball whose SHA-256 doesn't match a
   recorded entry; without it, a registry that swaps the tarball
   mid-flight ships arbitrary code under the same version pin.

This primitive classifies a single command-line / script body
according to which side of these vectors it's on. Provider rules
(GHA-059/060, GL-034/035, BB-030/031) iterate their own job-step
structure, call these classifiers per script body, and build
findings using the offender labels + locations they collected.

The pip-tooling allowlist is the trickiest piece. A real-world step
might run ``pip install --upgrade pip`` (tooling-only, exempt) on
one line and ``pip install -r requirements.txt`` (real, must be
hash-pinned) on another. :func:`has_real_pip_install` walks the
body line-by-line so the second still fires. A single-line install
that mixes tooling and runtime tokens (``pip install pip
some-runtime-dep``) correctly fires too because not every package
token is on the tooling allowlist; the earlier per-rule regex-only
implementation matched on first-token-only and silently exempted
the runtime dep.
"""
from __future__ import annotations

import re

# ── npm install primitives ────────────────────────────────────────────

#: Any npm / pnpm verb that installs from package.json. ``\bi\b`` for
#: ``npm i`` doesn't match ``install`` because ``i`` is mid-word.
_NPM_INSTALL_RE = re.compile(
    r"\b(?:npm|pnpm)\s+(?:ci|install|i)\b",
    re.IGNORECASE,
)

#: The verification primitive. ``npm audit signatures`` is the
#: canonical form (npm 8.13+); ``pnpm audit signatures`` is the pnpm
#: 8.7+ port against the same registry endpoint.
_NPM_AUDIT_SIGNATURES_RE = re.compile(
    r"\b(?:npm|pnpm)\s+audit\s+signatures\b",
    re.IGNORECASE,
)


def has_npm_install(body: str) -> bool:
    """``True`` if *body* runs an npm / pnpm install verb anywhere."""
    return bool(_NPM_INSTALL_RE.search(body))


def has_npm_audit_signatures(body: str) -> bool:
    """``True`` if *body* runs ``npm audit signatures`` / ``pnpm audit signatures``."""
    return bool(_NPM_AUDIT_SIGNATURES_RE.search(body))


# ── pip install primitives ────────────────────────────────────────────

#: Real pip install invocations, anchored on the verb so ``pip list``
#: / ``pip show`` / ``pip wheel`` don't fire.
_PIP_INSTALL_RE = re.compile(
    r"\b(?:pip3?|python3?\s+-m\s+pip)\s+install\b",
    re.IGNORECASE,
)

_REQUIRE_HASHES_RE = re.compile(r"--require-hashes\b", re.IGNORECASE)

#: Managers that hash-pin by default. Any invocation of these silences
#: the pip-require-hashes rule because the manager itself enforces
#: hash verification at install time. Limited to commands that
#: unconditionally consume a lockfile (``uv sync`` / ``uv pip sync``
#: read ``uv.lock``; ``poetry install`` reads ``poetry.lock``;
#: ``pipenv install --deploy`` / ``pipenv sync`` read
#: ``Pipfile.lock``). Commands that resolve from the index rather
#: than the lockfile (``uv run`` without ``--frozen``/``--locked``,
#: ``uv tool install``, ``hatch env create``) are deliberately
#: excluded; they don't guarantee hash enforcement by default.
_HASH_PINNING_MANAGER_RE = re.compile(
    r"\b(?:"
    r"uv\s+(?:sync|pip\s+sync)"
    r"|poetry\s+install"
    r"|pipenv\s+install\s+--deploy"
    r"|pipenv\s+sync"
    r")\b",
    re.IGNORECASE,
)

#: Packages whose install is tooling-bootstrap rather than runtime.
#: A pip install whose package tokens are ALL drawn from this set is
#: exempt from the require-hashes rule. This is the union of the
#: ``_DEP_UPDATE_TOOL_EXEMPT_RE`` allowlist in
#: :mod:`pipeline_check.core.checks.base` (which gates the
#: npm/yarn/pip dep-update rule) and the extra entries the
#: per-provider rule pack added (``pipx``, ``hatch``, ``build``,
#: ``twine``, ``poetry``, ``uv``, ``pipenv``). Keeping both rule
#: groups answer the same "is this install tooling-only?" question
#: against the same allowlist prevents the two from drifting.
PIP_TOOLING_PACKAGES: frozenset[str] = frozenset({
    # Build-system tools, produce or install the artifact, don't
    # ship inside it.
    "pip", "setuptools", "wheel", "virtualenv",
    "build", "twine",
    "pip-tools", "pipx",
    # CI scanners and linters, output never lands in the wheel.
    "pip-audit", "cyclonedx-bom", "cyclonedx-py",
    "safety", "bandit", "semgrep", "ruff", "mypy",
    # Higher-level package managers, usually the entry point for a
    # hash-pinning workflow rather than the gap.
    "poetry", "uv", "pipenv", "hatch",
})

#: Option flags after ``pip install`` that don't consume a value.
_PIP_VALUELESS_OPTIONS: frozenset[str] = frozenset({
    "--upgrade", "-U", "--user", "-q", "--quiet",
    "--no-deps", "--no-cache-dir", "--no-cache",
    "--break-system-packages", "--pre", "--prefer-binary",
    "--no-build-isolation", "--ignore-installed",
    "--use-pep517",
})

#: Option flags after ``pip install`` that consume the next token as
#: their value. ``-r`` / ``--requirement`` / ``-c`` / ``--constraint``
#: are deliberately omitted, they DO indicate a real install because
#: the referenced file carries runtime deps that the allowlist can't
#: enumerate.
_PIP_OPTIONS_WITH_VALUE: frozenset[str] = frozenset({
    "--index-url", "-i",
    "--extra-index-url",
    "--find-links", "-f",
    "--trusted-host",
    "--target", "-t",
    "--platform",
    "--python-version",
    "--implementation",
    "--abi",
    "--root", "--prefix",
})

#: Strip version specifiers and extras off a package token so
#: ``pip-tools==6.0`` / ``pip-tools[doc]`` match the allowlist.
_PKG_NAME_SPLIT_RE = re.compile(r"[=<>!~\[]")


def has_require_hashes(body: str) -> bool:
    """``True`` if *body* passes ``--require-hashes`` to pip."""
    return bool(_REQUIRE_HASHES_RE.search(body))


def has_hash_pinning_manager(body: str) -> bool:
    """``True`` if *body* invokes a manager that hash-pins by default."""
    return bool(_HASH_PINNING_MANAGER_RE.search(body))


def has_pip_hash_verification(body: str) -> bool:
    """``True`` if *body* enables pip hash verification by any mechanism."""
    return has_require_hashes(body) or has_hash_pinning_manager(body)


def is_real_pip_install_line(line: str) -> bool:
    """``True`` if *line* runs a non-tooling-only pip install.

    Walks every package-naming token after ``pip install``; the install
    is tooling-only when every such token is on
    :data:`PIP_TOOLING_PACKAGES`. A ``-r <reqs>`` /
    ``--requirement <reqs>`` flag forces a real-install verdict on
    its own because the referenced file carries runtime deps the
    allowlist doesn't enumerate.
    """
    m = _PIP_INSTALL_RE.search(line)
    if not m:
        return False
    tail = line[m.end():].strip()
    if not tail:
        return False
    tokens = tail.split()
    pkg_tokens: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        # ``--flag=value`` shape, one token, no following value to skip.
        if tok.startswith("--") and "=" in tok:
            i += 1
            continue
        if tok in _PIP_VALUELESS_OPTIONS:
            i += 1
            continue
        # ``-r <reqs>`` / ``-c <constraints>`` indicate a real install
        # because the referenced file carries runtime deps.
        if tok in ("-r", "--requirement", "-c", "--constraint"):
            return True
        if tok in _PIP_OPTIONS_WITH_VALUE:
            i += 2  # skip flag + its value
            continue
        # Unrecognized flags, skip just the flag itself; if a value
        # follows, the next loop will treat it as a package token,
        # which over-reports rather than under-reports.
        if tok.startswith("-"):
            i += 1
            continue
        pkg_tokens.append(tok)
        i += 1
    if not pkg_tokens:
        return False
    for pkg in pkg_tokens:
        bare = _PKG_NAME_SPLIT_RE.split(pkg, maxsplit=1)[0]
        if bare not in PIP_TOOLING_PACKAGES:
            return True
    return False


def has_real_pip_install(body: str) -> bool:
    """``True`` if *body* contains any line with a non-tooling pip install.

    Walks line-by-line so a body that mixes a tooling-only install
    (``pip install --upgrade pip``) with a real install
    (``pip install -r requirements.txt``) still fires on the latter.
    Returns ``False`` fast when no ``pip install`` shape appears
    anywhere so single-step short-circuit costs nothing on the
    common case (a step that does ``npm ci`` and nothing else).
    """
    if not _PIP_INSTALL_RE.search(body):
        return False
    for line in body.splitlines():
        if is_real_pip_install_line(line):
            return True
    return False
