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
- ``yarn.lock`` (both yarn 1 / Classic and yarn 2+ / Berry; the
  loader sniffs the ``__metadata:`` header to pick a parser. Classic
  goes through :func:`_parse_yarn_lock` + :func:`_synthesize_yarn_lock`;
  Berry goes through :func:`_parse_yarn_berry_lock` +
  :func:`_synthesize_yarn_berry_lock`. Both project to an npm-7+
  ``packages`` map so the NPM-* rules consume one shape regardless
  of the source lockfile.)
"""
from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ...diff import git_show, git_top
from ..base import BaseCheck, safe_load_yaml

#: Filenames the npm loader picks up. ``package.json`` is the manifest;
#: ``package-lock.json`` / ``npm-shrinkwrap.json`` / ``pnpm-lock.yaml``
#: are lockfiles.
MANIFEST_NAMES: frozenset[str] = frozenset({"package.json"})
LOCKFILE_NAMES: frozenset[str] = frozenset({
    "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml",
    "yarn.lock",
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
        #: ``{package_name: {version: utc_timestamp}}`` populated
        #: by the npm provider's ``post_filter`` when
        #: ``--resolve-remote`` is on. Empty by default; rules like
        #: NPM-008 (cooldown gate) read it and pass silently when
        #: the dict is empty so the rule's absence isn't a CI
        #: failure for users on the default no-network path.
        self.publish_times: dict[str, dict[str, _dt.datetime]] = {}
        #: Base-ref counterparts of ``locks``, populated by the npm
        #: provider's ``post_filter`` when ``--npm-base-ref`` is set.
        #: Each base lock carries the same repo-relative path (under
        #: ``path``) as its current-ref sibling so NPM-009 can pair
        #: them. Empty by default; NPM-009 (new-transitive-dep diff
        #: gate) reads it and passes silently when the list is empty.
        self.base_locks: list[NpmLock] = []

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
            if f.name in LOCKFILE_NAMES:
                lock, warn = _parse_lock_text(f.name, text, str(f))
                if lock is None:
                    warnings.append(f"{f}: {warn}")
                    skipped += 1
                    continue
                locks.append(lock)
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
        ctx = cls(manifests, locks, rcs)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


def _parse_lock_text(
    filename: str, text: str, path: str,
) -> tuple[NpmLock | None, str | None]:
    """Dispatch *text* to the right lockfile parser by *filename*.

    Returns ``(NpmLock, None)`` on success or ``(None, reason)`` on
    failure so the caller can decide how to surface the warning.
    Used by both the on-disk loader (:meth:`NpmContext.from_path`)
    and the base-ref loader (:func:`load_base_locks_via_git`) so
    the per-format parse logic lives in exactly one place.
    """
    if filename == "yarn.lock":
        is_berry = _is_yarn_berry(text)
        try:
            if is_berry:
                berry_entries = _parse_yarn_berry_lock(text)
            else:
                entries = _parse_yarn_lock(text)
        except Exception as exc:  # noqa: BLE001
            flavor = "yarn berry" if is_berry else "yarn.lock"
            return None, f"{flavor} parse error: {exc}"
        if is_berry:
            synthesized = _synthesize_yarn_berry_lock(berry_entries)
        else:
            synthesized = _synthesize_yarn_lock(entries)
        return NpmLock(
            path=path, text=text, data=synthesized, lockfile_version=3,
        ), None
    if filename == "pnpm-lock.yaml":
        try:
            raw = safe_load_yaml(text)
        except Exception as exc:  # noqa: BLE001
            return None, f"YAML decode error: {exc}"
        if not isinstance(raw, dict):
            return None, "top-level YAML is not a mapping"
        synthesized = _synthesize_pnpm_lock(raw)
        return NpmLock(
            path=path, text=text, data=synthesized, lockfile_version=3,
        ), None
    # package-lock.json / npm-shrinkwrap.json (JSON variants)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, f"JSON decode error: {exc}"
    if not isinstance(data, dict):
        return None, "top-level JSON is not an object"
    version = data.get("lockfileVersion")
    lockfile_version = version if isinstance(version, int) else 1
    return NpmLock(
        path=path, text=text, data=data, lockfile_version=lockfile_version,
    ), None


def load_base_locks_via_git(
    ctx: NpmContext, base_ref: str, scan_root: str | Path,
) -> None:
    """Populate ``ctx.base_locks`` from each current lock's contents at ``base_ref``.

    Uses :func:`pipeline_check.core.diff.git_show` to fetch each
    tracked lockfile at the base ref, then routes the body through
    :func:`_parse_lock_text` so the same dispatcher that handles
    on-disk loads also handles base-ref loads.

    Failure modes (no git on PATH, ref doesn't exist, file didn't
    exist at the base ref, body fails to parse) land in
    ``ctx.warnings`` rather than raising. NPM-009 silent-passes on
    a lock whose base counterpart didn't load, so a brand-new
    lockfile in this branch (no base sibling) doesn't fail CI.
    """
    root = Path(scan_root)
    if root.is_file():
        root = root.parent
    # ``git show <ref>:<path>`` interprets ``<path>`` as repo-top-
    # relative, not cwd-relative. Resolve the repo top so a scan
    # rooted in a subdirectory (``--npm-path apps/web``) still hands
    # git the right path. Fall back to ``root`` when git is
    # unavailable or the scan root isn't inside a repo (test
    # fixtures, ad-hoc directories) — in that case the loader
    # degrades to the pre-fix behavior, which is correct as long as
    # the scan root happens to be the repo top.
    repo_top = git_top(root) or root
    for lock in ctx.locks:
        lock_path = Path(lock.path)
        try:
            rel = lock_path.resolve().relative_to(repo_top.resolve())
        except (ValueError, OSError):
            ctx.warnings.append(
                f"{lock.path}: lockfile is outside the git repo "
                f"top {str(repo_top)!r}; skipped for base-ref "
                f"comparison",
            )
            continue
        body = git_show(base_ref, rel.as_posix(), cwd=repo_top)
        if body is None:
            ctx.warnings.append(
                f"{lock.path}: base ref {base_ref!r} could not be "
                f"resolved for {rel.as_posix()!r} (new file or git "
                f"unavailable)",
            )
            continue
        base_lock, warn = _parse_lock_text(lock_path.name, body, lock.path)
        if base_lock is None:
            ctx.warnings.append(
                f"{lock.path}: base-ref parse failed: {warn}",
            )
            continue
        ctx.base_locks.append(base_lock)


class NpmBaseCheck(BaseCheck[NpmContext]):
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


def _split_yarn_pattern(pattern: str) -> str | None:
    """Return the package name from a yarn 1 lock pattern like
    ``"@babel/code-frame@^7.0.0"`` or ``lodash@^4.17.21``.

    Strips surrounding quotes if present. Yarn 2+ Berry patterns
    embed a protocol (``lodash@npm:^4.17.21``) — those are split
    on the same trailing ``@`` and the resulting name comes back
    clean even when this parser is fed a Berry lockfile that
    slipped past the dispatcher (defensive, not a supported path).

    Returns ``None`` when the pattern is empty or has no ``@``
    separator that could carry a range.
    """
    if not isinstance(pattern, str):
        return None
    p = pattern.strip()
    if (len(p) >= 2) and p[0] == '"' and p[-1] == '"':
        p = p[1:-1]
    p = p.strip()
    if not p:
        return None
    # Find the LAST ``@`` that isn't at position 0 (scope marker on
    # ``@scope/name`` keeps its leading ``@``).
    idx = p.rfind("@")
    if idx <= 0:
        # No range separator — accept as a bare name. Real yarn.lock
        # entries always have one, but be tolerant.
        return p
    return p[:idx]


# Quoted ``key value`` shapes ("version", "resolved", etc.) we read
# from each yarn 1 entry's indented property lines. Sub-blocks
# (``dependencies:`` / ``optionalDependencies:``) are skipped — the
# existing NPM-* rules don't need transitive metadata.
_YARN_VALUE_KEYS: frozenset[str] = frozenset({
    "version", "resolved", "integrity",
})


def _strip_yarn_value(value: str) -> str:
    """Strip surrounding quotes and trailing comment from a yarn
    property value.

    Yarn 1 writes values like ``"4.17.21"`` (quoted) or
    ``sha512-abc==`` (bare). Trailing comments after ``#`` are
    possible but rare; this strips them defensively.
    """
    v = value.strip()
    # Trailing ``#`` comment (must be space-prefixed to avoid
    # eating ``#`` inside integrity strings).
    idx = v.find(" #")
    if idx >= 0:
        v = v[:idx].rstrip()
    if (len(v) >= 2) and v[0] == '"' and v[-1] == '"':
        v = v[1:-1]
    return v


def _parse_yarn_lock(
    text: str,
) -> list[tuple[list[str], dict[str, str]]]:
    """Parse a yarn 1 / Classic lockfile body into a list of entries.

    Each returned tuple is ``(patterns, props)`` where ``patterns``
    are the raw header pattern strings (one or more
    comma-separated) and ``props`` is a flat string-keyed map of
    the entry's top-level properties (``version`` / ``resolved`` /
    ``integrity``). Nested sub-blocks like ``dependencies:`` are
    walked over without recording — the existing NPM-* rules read
    flat lockfile entries.

    Tolerant of comments (``# ...``), blank lines, mixed indent
    widths (yarn defaults to 2 spaces), and the trailing newline
    quirks editors introduce on Windows. Raises ``ValueError`` only
    for unrecoverable input (binary content, malformed header
    lines that can't be split).
    """
    entries: list[tuple[list[str], dict[str, str]]] = []
    current_patterns: list[str] | None = None
    current_props: dict[str, str] | None = None
    current_indent: int | None = None
    in_subblock = False
    subblock_indent: int | None = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r")
        # Skip full-line comments and blank lines.
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Count leading spaces (yarn uses spaces, not tabs).
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            # New entry header. Close out the previous one.
            if current_patterns is not None and current_props is not None:
                entries.append((current_patterns, current_props))
            # A header line ends in ``:`` (after any trailing comment).
            header = stripped
            if not header.endswith(":"):
                # Defensive: skip unrecognized top-level content
                # (yarn 2+ ``__metadata:`` block falls through here
                # because it ends in ``:`` and just has no real
                # patterns — the synthesizer will drop it).
                current_patterns = None
                current_props = None
                current_indent = None
                continue
            header = header[:-1].strip()
            # Yarn 1 separates multiple match patterns with ``,``;
            # each pattern may be quoted independently.
            patterns = [
                pat.strip()
                for pat in header.split(",")
                if pat.strip()
            ]
            current_patterns = patterns
            current_props = {}
            current_indent = None
            in_subblock = False
            subblock_indent = None
            continue
        # Indented line. Determine if it's a top-level property of
        # the current entry, or part of a sub-block (dependencies:
        # ...).
        if current_patterns is None or current_props is None:
            # Floating indented line with no header — skip.
            continue
        if current_indent is None:
            current_indent = indent
        if in_subblock:
            # Already inside a deeper sub-block. Exit when indent
            # returns to the entry's primary level.
            if subblock_indent is not None and indent <= subblock_indent:
                in_subblock = False
                subblock_indent = None
                # Fall through to handle this line as a primary prop.
            else:
                continue
        if indent > current_indent:
            # Deeper indent without a corresponding sub-block header
            # — treat as a nested value we don't read. Skip.
            continue
        # Primary property line.
        if stripped.endswith(":"):
            # Sub-block header — record so we can skip its body.
            in_subblock = True
            subblock_indent = indent
            continue
        # ``key value`` (with one-or-more spaces between).
        key, _, value = stripped.partition(" ")
        key = key.strip()
        if not key:
            continue
        if key in _YARN_VALUE_KEYS:
            current_props[key] = _strip_yarn_value(value)
    # Flush the last entry.
    if current_patterns is not None and current_props is not None:
        entries.append((current_patterns, current_props))
    return entries


def _synthesize_yarn_lock(
    entries: list[tuple[list[str], dict[str, str]]],
) -> dict[str, Any]:
    """Project parsed yarn 1 entries to an npm-7+ lockfile dict.

    For each entry, pick the first pattern with a recoverable
    package name (``_split_yarn_pattern``) and build a single
    lock record carrying ``name`` / ``version`` / ``resolved`` /
    ``integrity``. Multi-pattern headers (the common case where
    several specifier patterns resolve to the same install) emit
    one record; the install path is ``node_modules/<name>`` with
    a ``+<version>`` suffix appended on the second-and-later
    occurrence of the same name to avoid colliding multiple
    versions in the synthesized output.

    Entries without a ``version`` (yarn 1 always writes one for a
    real install, but the parser is tolerant) get a synthesized
    placeholder rather than being dropped — NPM-006 would otherwise
    miss a name match on the install path, and NPM-002 / NPM-003
    skip records without ``resolved`` regardless. Entries without
    ``resolved`` (rare; yarn 1 records it for every fetched dep)
    are still recorded so name lookups in NPM-006 work.
    """
    packages: dict[str, Any] = {}
    seen_paths: set[str] = set()
    for patterns, props in entries:
        if not patterns:
            continue
        name: str | None = None
        for pat in patterns:
            name = _split_yarn_pattern(pat)
            if name:
                break
        if not name:
            continue
        # Yarn Berry's ``__metadata:`` block is a top-level header
        # that this yarn-1 parser would otherwise accept as a bare
        # package name. The result would synthesize a fake
        # ``node_modules/__metadata`` record and surface it to every
        # NPM-* rule. Berry locks should be routed to a separate
        # parser; this guard keeps yarn-1 parsing of a stray Berry
        # file from materializing a phantom dep.
        if name == "__metadata":
            continue
        version = props.get("version", "")
        resolved = props.get("resolved")
        integrity = props.get("integrity")
        record: dict[str, Any] = {"name": name, "version": version}
        if isinstance(resolved, str) and resolved:
            record["resolved"] = resolved
        if isinstance(integrity, str) and integrity:
            record["integrity"] = integrity
        install_path = f"node_modules/{name}"
        if install_path in seen_paths and version:
            install_path = f"node_modules/{name}+{version}"
        seen_paths.add(install_path)
        packages[install_path] = record
    return {"packages": packages, "lockfileVersion": 3}


# ── Yarn 2+ / Berry ────────────────────────────────────────────────────


def _is_yarn_berry(text: str) -> bool:
    """Return ``True`` when *text* looks like a Yarn Berry lockfile.

    Berry writes a ``__metadata:`` block as the first non-comment,
    non-blank top-level entry. Yarn 1 / Classic has no such block.
    The check scans the first ~50 non-blank lines so a wonky header
    comment doesn't move the marker out of reach; finding
    ``__metadata:`` at column 0 inside that window is sufficient
    evidence to route the body through the Berry parser.
    """
    seen = 0
    for raw in text.splitlines():
        line = raw.rstrip("\r")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if line.startswith("__metadata:"):
            return True
        seen += 1
        if seen > 50:
            break
    return False


# Berry's per-entry value keys. ``resolution`` and ``checksum`` replace
# yarn-1's ``resolved`` and ``integrity`` respectively; ``version`` is
# unchanged.
_YARN_BERRY_VALUE_KEYS: frozenset[str] = frozenset({
    "version", "resolution", "checksum",
})


def _parse_yarn_berry_lock(
    text: str,
) -> list[tuple[list[str], dict[str, str]]]:
    """Parse a Yarn Berry lockfile body into a list of entries.

    Mirrors :func:`_parse_yarn_lock` in shape (header pattern list +
    flat property dict per entry) but reads Berry's key set
    (``version`` / ``resolution`` / ``checksum``) and tolerates the
    ``__metadata:`` block by letting the synthesizer drop it.

    Berry headers use the same comma-separated pattern shape Classic
    uses (``"name@npm:^1.0.0, name@npm:^2.0.0":``); the parser strips
    quotes and splits on commas just like the Classic path.
    """
    entries: list[tuple[list[str], dict[str, str]]] = []
    current_patterns: list[str] | None = None
    current_props: dict[str, str] | None = None
    current_indent: int | None = None
    in_subblock = False
    subblock_indent: int | None = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            if current_patterns is not None and current_props is not None:
                entries.append((current_patterns, current_props))
            header = stripped
            if not header.endswith(":"):
                current_patterns = None
                current_props = None
                current_indent = None
                continue
            header = header[:-1].strip()
            patterns = [
                pat.strip()
                for pat in _split_berry_header_patterns(header)
                if pat.strip()
            ]
            current_patterns = patterns
            current_props = {}
            current_indent = None
            in_subblock = False
            subblock_indent = None
            continue
        if current_patterns is None or current_props is None:
            continue
        if current_indent is None:
            current_indent = indent
        if in_subblock:
            if subblock_indent is not None and indent <= subblock_indent:
                in_subblock = False
                subblock_indent = None
            else:
                continue
        if indent > current_indent:
            continue
        if stripped.endswith(":"):
            in_subblock = True
            subblock_indent = indent
            continue
        # Berry writes ``key: value`` with a colon separator (yarn-1
        # uses a space-separated ``key "value"`` instead).
        if ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key = key.strip()
        if not key:
            continue
        if key in _YARN_BERRY_VALUE_KEYS:
            current_props[key] = _strip_yarn_value(value)
    if current_patterns is not None and current_props is not None:
        entries.append((current_patterns, current_props))
    return entries


def _split_berry_header_patterns(header: str) -> list[str]:
    """Split a Berry header like ``"a@npm:^1, b@npm:^2"`` into the
    list of pattern strings, respecting a surrounding pair of double
    quotes.

    Yarn Berry quotes the whole header when any pattern contains a
    comma; the comma splitter must look at the *unquoted* body, not
    the literal source line.
    """
    h = header.strip()
    if len(h) >= 2 and h[0] == '"' and h[-1] == '"':
        h = h[1:-1]
    return [p.strip() for p in h.split(",")]


def _split_berry_pattern(pattern: str) -> str | None:
    """Return the package name from a Berry pattern.

    Berry patterns embed a protocol after the range separator:

    * ``lodash@npm:^4.17.21``
    * ``"@babel/code-frame@npm:^7.18.6"``
    * ``my-fork@npm:lodash@npm:^4.17.21``      (aliased)
    * ``myrepo@workspace:packages/myrepo``     (workspace)
    * ``lodash@patch:lodash@npm:^4.17.21#~/p.patch::version=...``

    The name is everything up to the protocol-separating ``@``; for
    scoped packages the leading ``@`` is preserved.
    """
    if not isinstance(pattern, str):
        return None
    p = pattern.strip()
    if (len(p) >= 2) and p[0] == '"' and p[-1] == '"':
        p = p[1:-1]
    p = p.strip()
    if not p:
        return None
    # Find the FIRST ``@`` that isn't at position 0; everything before
    # it is the package name. Scoped packages start with ``@`` so the
    # search must skip that leading marker.
    start = 1 if p.startswith("@") else 0
    idx = p.find("@", start)
    if idx <= 0:
        return p
    return p[:idx]


def _classify_berry_resolution(resolution: str) -> tuple[str, str]:
    """Map a Berry ``resolution:`` string to ``(protocol, resolved)``.

    The synthesized ``resolved`` is what the NPM-* rules see in the
    npm-7+ shape. The mapping preserves the verification signal the
    rules care about:

    * ``npm:...``        → ``https://registry.yarnpkg.com/...`` (registry)
    * ``workspace:...``  → ``file:.`` (intra-monorepo, local)
    * ``portal:./x``     → ``file:./x``
    * ``link:./x``       → ``file:./x``
    * ``file:./x``       → ``file:./x`` (kept as-is)
    * ``patch:foo@npm:^1`` → unwrap to the wrapped resolution
    * ``git:...`` / ``git+ssh:...`` / ``http:...`` / ``https:...`` →
      preserved verbatim so NPM-003's prefix classifier flags the
      unsafe transports the same way it would on a package-lock.json

    Returns ``("", "")`` when the resolution is empty or unparseable.
    """
    r = resolution.strip()
    if not r:
        return "", ""
    # ``patch:`` wraps another full resolution
    # (``foo@patch:<name@protocol:version>#<patchfile>::<params>``);
    # unwrap and recurse on the inner ``name@protocol:rest`` so the
    # underlying protocol is what NPM-003 classifies.
    if "@patch:" in r:
        wrapped = r.split("@patch:", 1)[1]
        if "#" in wrapped:
            wrapped = wrapped.split("#", 1)[0]
        # ``wrapped`` is a full ``name@protocol:rest`` string;
        # recurse on it as a fresh resolution.
        if "@" in wrapped:
            return _classify_berry_resolution(wrapped)
    # Resolutions are written as ``name@protocol:rest``; find the
    # protocol separator. Scoped packages start with ``@``.
    start = 1 if r.startswith("@") else 0
    idx = r.find("@", start)
    if idx <= 0:
        return "", ""
    protocol_and_rest = r[idx + 1:]
    if ":" not in protocol_and_rest:
        return "", ""
    protocol, _, rest = protocol_and_rest.partition(":")
    protocol = protocol.lower()
    if protocol == "npm":
        # Synthesize a registry URL the NPM-* rules will accept as a
        # registry source. The rules check prefixes, not the actual
        # tarball — a yarnpkg.com URL is the same signal as
        # registry.npmjs.org for NPM-003.
        name = r[:idx]
        version = rest.split("::", 1)[0]
        return (
            "npm",
            f"https://registry.yarnpkg.com/{name}/-/"
            f"{name.split('/')[-1]}-{version}.tgz",
        )
    if protocol in ("workspace", "link", "portal"):
        return protocol, f"file:{rest or '.'}"
    if protocol in ("file",):
        return protocol, f"file:{rest}"
    if protocol == "git":
        # Berry's ``git:`` shape is ``git:host:owner/repo.git#ref``;
        # forward as a git URL so NPM-003's classifier sees it.
        return protocol, f"git+ssh://git@{rest}"
    return protocol, f"{protocol}:{rest}"


def _synthesize_yarn_berry_lock(
    entries: list[tuple[list[str], dict[str, str]]],
) -> dict[str, Any]:
    """Project parsed Berry entries to an npm-7+ lockfile dict.

    Mirrors :func:`_synthesize_yarn_lock` but reads Berry's
    ``resolution`` / ``checksum`` field names. The ``checksum``
    value (hex SHA-512 in Berry's wire format) maps directly to
    ``integrity`` because the NPM-002 rule cares about *presence*,
    not format: a lockfile entry that records a strong hash, in any
    encoding, satisfies the rule. Entries whose ``resolution:`` maps
    to a workspace / portal / link are emitted with ``link: true``
    so NPM-002's tarball-only branch correctly skips them.
    """
    packages: dict[str, Any] = {}
    seen_paths: set[str] = set()
    for patterns, props in entries:
        if not patterns:
            continue
        name: str | None = None
        for pat in patterns:
            name = _split_berry_pattern(pat)
            if name:
                break
        if not name or name == "__metadata":
            continue
        version = props.get("version", "")
        resolution = props.get("resolution", "")
        checksum = props.get("checksum")
        protocol, resolved = _classify_berry_resolution(resolution)
        record: dict[str, Any] = {"name": name, "version": version}
        if resolved:
            record["resolved"] = resolved
        if isinstance(checksum, str) and checksum:
            # Encode as an SRI-shaped value so downstream regex
            # matchers that look for the ``sha512-`` prefix don't
            # need a Berry-specific branch. The wire format isn't
            # identical (Berry: hex, npm: base64) but the presence
            # signal is what NPM-002 reads.
            record["integrity"] = f"sha512-{checksum}"
        if protocol in ("workspace", "link", "portal"):
            # Linked / workspace deps have no tarball; NPM-002 skips
            # records carrying ``link: true``.
            record["link"] = True
        install_path = f"node_modules/{name}"
        if install_path in seen_paths and version:
            install_path = f"node_modules/{name}+{version}"
        seen_paths.add(install_path)
        packages[install_path] = record
    return {"packages": packages, "lockfileVersion": 3}


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
