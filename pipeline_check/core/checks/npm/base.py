"""npm context and base check.

Loads ``package.json`` / ``package-lock.json`` from disk and exposes
them to per-rule modules as :class:`NpmManifest` / :class:`NpmLock`
dataclasses. Rules subclass-free: each rule module is a function the
orchestrator invokes once per loaded file (manifest rules see every
``package.json``; lock rules see every ``package-lock.json`` /
``npm-shrinkwrap.json``).

The parser is intentionally tolerant. A malformed JSON file is
captured as a warning on the context rather than raised; the goal is
best-effort static analysis over a repo tree, not a strict validator.

Inputs the loader recognizes
----------------------------
- ``package.json`` (top-level manifest, ``dependencies`` / ``devDependencies`` /
  ``optionalDependencies`` / ``peerDependencies`` / ``scripts``)
- ``package-lock.json`` (npm 7+ format, ``packages`` keyed by install
  path; also handles the legacy npm 6 ``dependencies`` shape)
- ``npm-shrinkwrap.json`` (same shape as ``package-lock.json``)

``yarn.lock`` and ``pnpm-lock.yaml`` are out of scope for v1; their
formats are distinct enough to warrant their own parsers.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..base import BaseCheck

#: Filenames the npm loader picks up. ``package.json`` is the manifest;
#: ``package-lock.json`` / ``npm-shrinkwrap.json`` are lockfiles.
MANIFEST_NAMES: frozenset[str] = frozenset({"package.json"})
LOCKFILE_NAMES: frozenset[str] = frozenset({
    "package-lock.json", "npm-shrinkwrap.json",
})
#: ``.npmrc`` is npm's INI-style config file. Per-project ``.npmrc``
#: lives alongside ``package.json``; we scan any ``.npmrc`` in the
#: tree (excluding ``node_modules``) so monorepos with per-package
#: configs are covered.
NPMRC_NAMES: frozenset[str] = frozenset({".npmrc"})


@dataclass(frozen=True, slots=True)
class NpmManifest:
    """A parsed ``package.json``."""

    path: str
    text: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class NpmLock:
    """A parsed ``package-lock.json`` / ``npm-shrinkwrap.json``."""

    path: str
    text: str
    data: dict[str, Any] = field(default_factory=dict)
    #: Lockfile schema version. npm 7+ writes ``lockfileVersion: 2`` or
    #: ``3``; npm 6 writes ``1``. Rules that walk packages branch on
    #: this so the v1-vs-v2 shape difference stays out of every rule.
    lockfile_version: int = 1


@dataclass(frozen=True, slots=True)
class NpmRc:
    """A parsed ``.npmrc`` config file.

    ``.npmrc`` uses an INI-style flat key/value format (no sections in
    the common case; ``@scope:registry`` keys are flat scoped names).
    The parser is intentionally tolerant: comments (``#`` or ``;``),
    blank lines, and quoted values are handled; lines that don't fit
    ``key=value`` are dropped silently.
    """

    path: str
    text: str
    #: Parsed ``key -> value`` map. Keys are lower-cased; values keep
    #: their original case (URLs, auth tokens) and have surrounding
    #: quotes stripped.
    settings: dict[str, str] = field(default_factory=dict)


class NpmContext:
    """Loaded set of npm manifest, lockfile, and config documents."""

    def __init__(
        self,
        manifests: list[NpmManifest],
        locks: list[NpmLock],
        rcs: list[NpmRc] | None = None,
    ) -> None:
        self.manifests = manifests
        self.locks = locks
        self.rcs: list[NpmRc] = rcs or []
        self.files_scanned: int = (
            len(manifests) + len(locks) + len(self.rcs)
        )
        self.files_skipped: int = 0
        self.warnings: list[str] = []

    @classmethod
    def from_path(cls, path: str | Path) -> NpmContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--npm-path {root} does not exist. Pass a "
                "package.json / package-lock.json file or a directory "
                "containing one."
            )
        all_names = MANIFEST_NAMES | LOCKFILE_NAMES | NPMRC_NAMES
        if root.is_file():
            files = [root]
        else:
            files = sorted(
                p for p in root.rglob("*")
                if p.is_file()
                and p.name in all_names
                # Skip vendored copies under node_modules to avoid
                # flagging every transitive dependency's own manifest.
                and "node_modules" not in p.parts
            )
        manifests: list[NpmManifest] = []
        locks: list[NpmLock] = []
        rcs: list[NpmRc] = []
        warnings: list[str] = []
        skipped = 0
        for f in files:
            try:
                text = f.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                warnings.append(f"{f}: read error: {exc}")
                skipped += 1
                continue
            if f.name in NPMRC_NAMES:
                # ``.npmrc`` is INI-style, not JSON. Parse separately.
                settings = parse_npmrc(text)
                rcs.append(NpmRc(path=str(f), text=text, settings=settings))
                continue
            try:
                data = json.loads(text)
            except json.JSONDecodeError as exc:
                warnings.append(f"{f}: JSON decode error: {exc}")
                skipped += 1
                continue
            if not isinstance(data, dict):
                warnings.append(f"{f}: top-level JSON is not an object")
                skipped += 1
                continue
            if f.name in MANIFEST_NAMES:
                manifests.append(NpmManifest(path=str(f), text=text, data=data))
            else:
                version = data.get("lockfileVersion")
                lockfile_version = version if isinstance(version, int) else 1
                locks.append(NpmLock(
                    path=str(f), text=text, data=data,
                    lockfile_version=lockfile_version,
                ))
        ctx = cls(manifests, locks, rcs)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


class NpmBaseCheck(BaseCheck):
    """Base class for npm rule modules."""

    PROVIDER = "npm"

    def __init__(self, ctx: NpmContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: NpmContext = ctx


# ── Helpers shared by multiple rule modules ────────────────────────────


def iter_manifest_dependencies(
    manifest: NpmManifest,
) -> list[tuple[str, str, str]]:
    """Return ``[(section, name, spec), ...]`` for every declared dep.

    Covers ``dependencies`` / ``devDependencies`` / ``optionalDependencies``
    / ``peerDependencies``. ``bundledDependencies`` is an array of names
    only (no specs) and is intentionally skipped.
    """
    out: list[tuple[str, str, str]] = []
    for section in (
        "dependencies", "devDependencies",
        "optionalDependencies", "peerDependencies",
    ):
        block = manifest.data.get(section)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            if isinstance(name, str) and isinstance(spec, str):
                out.append((section, name, spec))
    return out


def iter_lock_packages(lock: NpmLock) -> list[tuple[str, dict[str, Any]]]:
    """Return ``[(install_path, package_record), ...]`` for every entry
    in a lockfile.

    Normalizes across the two shapes:

    * npm 7+ (``lockfileVersion: 2`` / ``3``): ``packages`` keyed by an
      install path like ``"node_modules/lodash"``; the root manifest is
      keyed by ``""``.
    * npm 6 (``lockfileVersion: 1``): ``dependencies`` keyed by package
      name, with nested ``dependencies`` for transitives.

    The root manifest entry (``""`` key) is skipped, it carries no
    ``resolved`` / ``integrity`` field and isn't an installed dep.
    """
    out: list[tuple[str, dict[str, Any]]] = []
    if lock.lockfile_version >= 2:
        packages = lock.data.get("packages")
        if isinstance(packages, dict):
            for install_path, record in packages.items():
                if install_path == "" or not isinstance(record, dict):
                    # Root manifest entry or malformed record.
                    continue
                out.append((install_path, record))
    else:
        # Legacy v1: walk ``dependencies`` recursively.
        def walk(prefix: str, deps: dict[str, Any]) -> None:
            for name, record in deps.items():
                if not isinstance(record, dict):
                    continue
                path = f"{prefix}/{name}" if prefix else name
                out.append((path, record))
                sub = record.get("dependencies")
                if isinstance(sub, dict):
                    walk(path, sub)

        deps = lock.data.get("dependencies")
        if isinstance(deps, dict):
            walk("", deps)
    return out


def parse_npmrc(text: str) -> dict[str, str]:
    """Parse the INI-style body of an ``.npmrc`` config file.

    Returns ``{key_lowercase: value}``. Keys are lower-cased so
    ``IGNORE-SCRIPTS=true`` and ``ignore-scripts=true`` collide;
    values keep their original case (URLs, tokens, scope names).

    Tolerated forms:

    * ``key=value`` and ``key = value`` (spaces around ``=``)
    * ``"quoted value"`` / ``'quoted value'`` — surrounding quotes
      stripped
    * Comments starting with ``#`` or ``;`` (whole line or trailing)
    * Blank lines

    Dropped silently: ``[section]`` headers (npm doesn't use them in
    the common case; advanced ``@scope:registry`` keys are flat),
    lines without ``=``.
    """
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";", "[")):
            continue
        # Strip trailing comment after a whitespace-prefixed ``#``.
        for marker in ("#", ";"):
            idx = line.find(marker)
            if idx > 0 and line[idx - 1].isspace():
                line = line[:idx].rstrip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key:
            out[key] = value
    return out


def _line_of(text: str, needle: str) -> int:
    """Return the 1-based line number of *needle* in *text*, or 1.

    Used by rules that want a location pointing at the offending JSON
    key in the original file. The needle is the bare key (``"name"``
    with quotes); the search is best-effort and returns ``1`` if the
    needle isn't present.
    """
    idx = text.find(needle)
    if idx < 0:
        return 1
    return text[:idx].count("\n") + 1


__all__ = [
    "LOCKFILE_NAMES", "MANIFEST_NAMES", "NPMRC_NAMES", "NpmBaseCheck",
    "NpmContext", "NpmLock", "NpmManifest", "NpmRc",
    "iter_lock_packages", "iter_manifest_dependencies", "parse_npmrc",
]
