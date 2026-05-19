"""npm context and base check.

Loads ``package.json`` / ``package-lock.json`` / ``pnpm-lock.yaml``
from disk and exposes them to per-rule modules as
:class:`NpmManifest` / :class:`NpmLock` dataclasses. Rules
subclass-free: each rule module is a function the orchestrator
invokes once per loaded file (manifest rules see every
``package.json``; lock rules see every ``package-lock.json`` /
``npm-shrinkwrap.json`` / ``pnpm-lock.yaml``).

The parser is intentionally tolerant. A malformed JSON / YAML file
is captured as a warning on the context rather than raised; the goal
is best-effort static analysis over a repo tree, not a strict
validator.

Inputs the loader recognizes
----------------------------
- ``package.json`` (top-level manifest, ``dependencies`` / ``devDependencies`` /
  ``optionalDependencies`` / ``peerDependencies`` / ``scripts``)
- ``package-lock.json`` (npm 7+ format, ``packages`` keyed by install
  path; also handles the legacy npm 6 ``dependencies`` shape)
- ``npm-shrinkwrap.json`` (same shape as ``package-lock.json``)
- ``pnpm-lock.yaml`` (pnpm v5+ schema; the loader synthesizes an
  npm-7+-shaped ``packages`` map from pnpm's ``packages:`` /
  ``snapshots:`` blocks so the existing NPM-002 / NPM-003 / NPM-006
  rules apply without per-rule changes — see
  :func:`_synthesize_pnpm_lock`)

``yarn.lock`` remains out of scope; its custom YAML-ish format
warrants its own parser, deferred.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..base import BaseCheck, safe_load_yaml

#: Filenames the npm loader picks up. ``package.json`` is the manifest;
#: ``package-lock.json`` / ``npm-shrinkwrap.json`` / ``pnpm-lock.yaml``
#: are lockfiles.
MANIFEST_NAMES: frozenset[str] = frozenset({"package.json"})
LOCKFILE_NAMES: frozenset[str] = frozenset({
    "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml",
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
            if f.name == "pnpm-lock.yaml":
                # pnpm-lock.yaml: parse the YAML, synthesize an npm-7+
                # lock-shape ``data`` dict so existing lockfile rules
                # (NPM-002 / NPM-003 / NPM-006) apply unchanged.
                try:
                    raw = safe_load_yaml(text)
                except Exception as exc:  # noqa: BLE001
                    warnings.append(f"{f}: YAML decode error: {exc}")
                    skipped += 1
                    continue
                if not isinstance(raw, dict):
                    warnings.append(f"{f}: top-level YAML is not a mapping")
                    skipped += 1
                    continue
                synthesized = _synthesize_pnpm_lock(raw)
                locks.append(NpmLock(
                    path=str(f), text=text, data=synthesized,
                    # Treat as npm 7+ shape so iter_lock_packages
                    # reads the synthesized ``packages`` map.
                    lockfile_version=3,
                ))
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


def _split_pnpm_key(key: str) -> tuple[str, str] | None:
    """Parse a pnpm ``packages:`` key into ``(name, version)``.

    pnpm-lock.yaml writes package keys in a couple of shapes that
    have shifted across schema versions:

    * v5  ``/foo/1.2.3``                    (slash separator)
    * v5  ``/@scope/foo/1.2.3``             (scoped)
    * v6  ``/foo@1.2.3``                    (``@`` separator, leading slash)
    * v9  ``foo@1.2.3``                     (no leading slash)
    * any ``foo@1.2.3(peer@2.0.0)``         (peer-dep disambiguator)

    Returns ``None`` when the key doesn't look like a package
    coordinate; the synthesizer drops those entries silently rather
    than ingest a half-parsed record.
    """
    if not isinstance(key, str) or not key:
        return None
    coord = key
    # Strip the peer-dep disambiguator first; an entry like
    # ``foo@1.2.3(react@18.0.0)`` is the same package as ``foo@1.2.3``
    # from the rule layer's perspective.
    paren = coord.find("(")
    if paren > 0:
        coord = coord[:paren]
    # Drop the leading ``/`` if present.
    if coord.startswith("/"):
        coord = coord[1:]
    # v6+ uses ``@`` separator (the LAST one, since scoped names
    # also begin with ``@``).
    if "@" in coord[1:]:
        # Look for the last ``@`` that isn't at position 0
        # (scope marker).
        idx = coord.rfind("@")
        if idx > 0:
            name = coord[:idx]
            version = coord[idx + 1:]
            if name and version:
                return name, version
    # v5 slash separator: ``foo/1.2.3`` or ``@scope/foo/1.2.3``.
    parts = coord.rsplit("/", 1)
    if len(parts) == 2 and parts[1]:
        return parts[0], parts[1]
    return None


def _pnpm_registry_tarball_url(name: str, version: str) -> str:
    """Return the canonical npm-registry tarball URL for a package.

    pnpm omits ``resolved`` for registry-sourced packages because the
    URL is implicit from the coordinate. The npm rules expect a
    populated ``resolved`` field (NPM-003 classifies it; NPM-002
    needs it present before flagging missing integrity), so we
    synthesize the same URL npm itself would write into a
    ``package-lock.json`` for the same package.

    For scoped packages, npm tarball URLs use the unscoped name in
    the filename: ``https://registry.npmjs.org/@scope/foo/-/foo-1.0.0.tgz``.
    """
    unscoped = name.split("/", 1)[-1] if name.startswith("@") else name
    return (
        f"https://registry.npmjs.org/{name}/-/{unscoped}-{version}.tgz"
    )


def _synthesize_pnpm_record(
    name: str,
    version: str,
    pkg_entry: dict[str, Any],
) -> dict[str, Any]:
    """Project a pnpm package entry to an npm-7+ lockfile record.

    pnpm's ``resolution`` block carries integrity / tarball / git
    coordinates in a few shapes. We normalize to the npm-side field
    names so existing lockfile rules don't branch on lock format:

    * ``resolution: {integrity: 'sha512-...'}`` (registry tarball)
      → ``integrity`` set, ``resolved`` synthesized to the implicit
      npm registry URL.
    * ``resolution: {tarball: 'https://example.com/foo.tgz'}``
      (non-registry tarball) → ``resolved`` set to the tarball URL
      (NPM-003 classifies the host).
    * ``resolution: {type: 'git', repo, commit}`` (git source) →
      ``resolved`` synthesized as
      ``git+<repo>#<commit>`` so NPM-003 sees the same shape it
      sees in a real npm lockfile.

    Linked workspace packages (``link:..`` specs that pnpm records
    as ``packages: {<key>: {dependencies: {...}}}`` without a
    ``resolution``) get ``link: True`` so NPM-002 skips them.
    """
    record: dict[str, Any] = {"name": name, "version": version}
    resolution = pkg_entry.get("resolution")
    if not isinstance(resolution, dict):
        # No resolution block: treat as a workspace link entry.
        record["link"] = True
        return record
    integrity = resolution.get("integrity")
    if isinstance(integrity, str) and integrity:
        record["integrity"] = integrity
    tarball = resolution.get("tarball")
    if isinstance(tarball, str) and tarball:
        record["resolved"] = tarball
    elif resolution.get("type") == "git":
        repo = resolution.get("repo")
        commit = resolution.get("commit")
        if isinstance(repo, str) and isinstance(commit, str):
            sep = "#" if "#" not in repo else "&"
            record["resolved"] = f"git+{repo}{sep}{commit}"
        elif isinstance(repo, str):
            record["resolved"] = f"git+{repo}"
    else:
        # Registry-sourced: synthesize the canonical npm tarball URL.
        record["resolved"] = _pnpm_registry_tarball_url(name, version)
    return record


def _synthesize_pnpm_lock(raw: dict[str, Any]) -> dict[str, Any]:
    """Return an npm-7+-shaped lockfile dict from a pnpm-lock.yaml.

    The output's ``packages`` map is keyed by ``node_modules/<name>``
    so :func:`iter_lock_packages` reads it as-is and
    :func:`_package_name_from_install_path` in NPM-006 recovers the
    right package name. Entries with the same name but different
    versions get one record each, keyed by appending the version
    to the install path (``node_modules/foo`` for the first match,
    ``node_modules/foo+1.2.3`` for subsequent versions) so they're
    visible to NPM-006 without colliding.

    pnpm v9 split the per-version package metadata into a top-level
    ``snapshots:`` block keyed the same way as ``packages:`` while
    keeping name-and-version coordinates in ``packages:`` with the
    integrity hash. The synthesizer reads ``packages:`` first (the
    canonical source for ``resolution`` / ``integrity``); when an
    entry is empty it falls back to the matching ``snapshots:``
    entry so v9 locks still produce records.
    """
    packages = raw.get("packages")
    snapshots = raw.get("snapshots")
    synthesized: dict[str, Any] = {}
    if not isinstance(packages, dict):
        # Older pnpm v5 schemas sometimes only ship snapshots-like
        # blocks; treat that as empty rather than raising.
        return {"packages": synthesized, "lockfileVersion": 3}
    seen_paths: set[str] = set()
    for key, entry in packages.items():
        parsed = _split_pnpm_key(key)
        if parsed is None:
            continue
        name, version = parsed
        pkg_entry = entry if isinstance(entry, dict) else {}
        if not pkg_entry and isinstance(snapshots, dict):
            snap = snapshots.get(key)
            if isinstance(snap, dict):
                pkg_entry = snap
        record = _synthesize_pnpm_record(name, version, pkg_entry)
        # Build install path; disambiguate same-name-different-version
        # entries by appending the version after a ``+`` sigil. ``+`` is
        # not a legal npm package-name character so this never collides
        # with a real ``node_modules/<name>`` path.
        install_path = f"node_modules/{name}"
        if install_path in seen_paths:
            install_path = f"node_modules/{name}+{version}"
            # Last-write-wins for the rare double-collision (same
            # name + same version twice). Synthesizing more aggressive
            # disambiguation here would mask a real lockfile bug.
        seen_paths.add(install_path)
        synthesized[install_path] = record
    return {"packages": synthesized, "lockfileVersion": 3}


__all__ = [
    "LOCKFILE_NAMES", "MANIFEST_NAMES", "NPMRC_NAMES", "NpmBaseCheck",
    "NpmContext", "NpmLock", "NpmManifest", "NpmRc",
    "iter_lock_packages", "iter_manifest_dependencies", "parse_npmrc",
]
