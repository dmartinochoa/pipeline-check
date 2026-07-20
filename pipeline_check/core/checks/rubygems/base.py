"""RubyGems / Bundler context and base check.

Parses ``Gemfile`` (Bundler manifest, Ruby DSL) and probes for the
sibling ``Gemfile.lock`` (Bundler's integrity manifest). Mirrors
the npm / PyPI / Maven / NuGet / Go-modules / Cargo / Composer pack
shape: one context per scan, one rule module per check, the
orchestrator runs every rule against every loaded file.

Parser scope
------------
A Gemfile is Ruby code, not a static-format document. The parser
here is a regex-driven extractor for the canonical Bundler idioms:
``source``, ``gem``, ``group`` / ``platforms`` blocks, ``source
"…" do … end`` scoped sources, and the long-form options
(``git: ``, ``github: ``, ``ref: ``, ``branch: ``, ``tag: ``,
``path: ``, ``require: ``). Genuinely dynamic Gemfiles
(``Dir.glob`` over ``gem`` calls, ``eval`` of a generated string)
are treated as opaque — the rule pack reports what it can extract
and otherwise pass-throughs.

Entries audited:

* top-level ``source "https://…"`` declarations
* per-block ``source "https://…" do … end`` scoped sources
* every ``gem "name"`` entry, with version constraints and
  option-hash form (``git: ``, ``github: ``, ``path: ``,
  ``ref: ``, ``branch: ``, ``tag: ``)

Each ``gem`` entry is normalized to a :class:`GemDependency`:

* ``gem "rails", "~> 7.0"`` -> version="~> 7.0"
* ``gem "rails"`` -> version=None  (no version pin)
* ``gem "x", git: "https://...", ref: "abc"`` -> is_git, git_rev
* ``gem "x", github: "owner/repo"`` -> is_git, git_url synthetic
* ``gem "x", path: "../local"`` -> is_path
"""
from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..base import BaseCheck

#: Bundler manifest filename. Always ``Gemfile`` (case-sensitive).
MANIFEST_NAMES: frozenset[str] = frozenset({"Gemfile"})
#: Bundler integrity manifest. GEM-001 fires when the manifest is
#: present but the lockfile is not.
LOCKFILE_NAMES: frozenset[str] = frozenset({"Gemfile.lock"})


# ── Module dataclasses ────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class GemDependency:
    """One declared ``gem`` entry."""

    name: str
    #: Version constraint literal as the manifest declares it. May be
    #: a tilde-arrow (``"~> 7.0"``), exact pin (``"7.0.1"``),
    #: comparison (``">=7,<8"``), or ``None`` when omitted (Bundler
    #: lets ``gem "x"`` mean "any version satisfying the lockfile /
    #: latest").
    version: str | None
    #: ``True`` when the entry has a ``git: "https://..."`` or
    #: ``github: "owner/repo"`` option.
    is_git: bool = False
    #: Git source URL (``https://...`` or synthetic ``github:owner/repo``).
    git_url: str = ""
    #: Pinned ref when ``ref: "<sha>"`` is set. Empty when the entry
    #: only sets ``branch:`` / ``tag:`` / nothing (mutable forms).
    git_ref: str = ""
    #: ``True`` when the git entry pins to a mutable ref (branch / tag
    #: / unspecified). GEM-005's failure signal.
    git_mutable: bool = False
    #: ``True`` when the entry has a ``path: "..."`` option.
    is_path: bool = False
    #: Bundler group(s) the entry was declared under (``:development``,
    #: ``:test``, etc.). Empty tuple when declared at top level.
    groups: tuple[str, ...] = ()
    #: Source URL when declared inside a scoped ``source "..." do … end``
    #: block. Empty when declared at top level.
    scoped_source: str = ""
    #: Per-gem ``source:`` option value (``gem "x", source: "https://…"``).
    #: Empty when the entry sets no inline source. Distinct from
    #: ``scoped_source`` (the block form). GEM-012's signal.
    per_gem_source: str = ""
    line_no: int = 1

    @property
    def coordinate(self) -> str:
        v = self.version or (
            f"git:{self.git_ref or '<mutable>'}" if self.is_git
            else "path" if self.is_path
            else "<unpinned>"
        )
        return f"{self.name} {v}"


@dataclass(frozen=True, slots=True)
class GemSource:
    """One ``source`` declaration."""

    url: str
    line_no: int = 1
    #: ``True`` when this is a top-level (non-block) source.
    is_top_level: bool = True


@dataclass(frozen=True, slots=True)
class GemFile:
    """A parsed ``Gemfile`` document."""

    path: str
    text: str
    sources: tuple[GemSource, ...] = field(default_factory=tuple)
    dependencies: tuple[GemDependency, ...] = field(default_factory=tuple)
    #: ``True`` when parsing did not raise.
    parsed_ok: bool = True
    #: ``True`` when the sibling ``Gemfile.lock`` was found at scan
    #: time.
    has_lockfile: bool = False
    lockfile_path: str | None = None
    #: Path to ``.bundle/config`` when found in the same directory tree
    #: as the Gemfile. Bundler reads this file at install time; its
    #: keys are an ``YAML`` map of ``BUNDLE_<HOSTNAME>``-shaped names.
    bundle_config_path: str | None = None
    #: Raw text of ``.bundle/config`` when found. Empty string when not
    #: present. The bundle-config-side rule (GEM-009) parses the body
    #: per-line so a malformed YAML file doesn't break the scan.
    bundle_config_text: str = ""


class GemContext:
    """Loaded set of ``Gemfile`` documents."""

    def __init__(self, files: list[GemFile]) -> None:
        self.files = files
        self.files_scanned: int = len(files)
        self.files_skipped: int = 0
        self.warnings: list[str] = []
        self.publish_times: dict[str, dict[str, _dt.datetime]] = {}
        self.osv_advisories: dict[tuple[str, str], list[Any]] = {}

    @classmethod
    def from_path(cls, path: str | Path) -> GemContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--rubygems-path {root} does not exist. Pass a "
                "Gemfile or a directory containing one."
            )
        if root.is_file():
            candidates = [root]
        else:
            candidates = sorted(
                p for p in root.rglob("Gemfile")
                if p.is_file()
                and ".git" not in p.parts
                and "vendor" not in p.parts
                and "node_modules" not in p.parts
            )
        files: list[GemFile] = []
        warnings: list[str] = []
        skipped = 0
        for f in candidates:
            try:
                text = f.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                warnings.append(f"{f}: read error: {exc}")
                skipped += 1
                continue
            pf = _parse_gemfile(str(f), text)
            sibling_lock = f.parent / "Gemfile.lock"
            has_lock = sibling_lock.is_file()
            bundle_cfg = f.parent / ".bundle" / "config"
            cfg_path: str | None = None
            cfg_text = ""
            if bundle_cfg.is_file():
                cfg_path = str(bundle_cfg)
                try:
                    cfg_text = bundle_cfg.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    cfg_text = ""
            files.append(GemFile(
                path=pf.path, text=pf.text,
                sources=pf.sources,
                dependencies=pf.dependencies,
                parsed_ok=pf.parsed_ok,
                has_lockfile=has_lock,
                lockfile_path=str(sibling_lock) if has_lock else None,
                bundle_config_path=cfg_path,
                bundle_config_text=cfg_text,
            ))
        ctx = cls(files)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


class RubyGemsBaseCheck(BaseCheck[GemContext]):
    """Base class for rubygems rule modules."""

    PROVIDER = "rubygems"

    def __init__(
        self, ctx: GemContext, target: str | None = None,
    ) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: GemContext = ctx


# ── Parser ────────────────────────────────────────────────────────


# Match a ``source "url"`` or ``source 'url'`` declaration. The url
# group is captured. The optional ``do`` suffix is consumed so the
# parser can tell scoped sources from top-level ones.
_SOURCE_RE = re.compile(
    r"^\s*source\s+['\"](?P<url>[^'\"]+)['\"]"
    r"(?P<do>\s+do\b)?\s*$",
    re.MULTILINE,
)

# Match a ``gem "name"`` line and capture name + the remainder of the
# line up to a comment / EOL. The remainder is later split into the
# version constraint and the options hash.
_GEM_RE = re.compile(
    r"^[\t ]*gem\s+['\"](?P<name>[^'\"]+)['\"]"
    r"(?P<rest>[^\n#]*)",
    re.MULTILINE,
)

# Match each ``key: value`` pair inside the gem options hash. Captures
# string-literal and symbol values. Bare-word values (``true`` /
# ``false`` / ``nil``) are matched and discarded.
_OPTION_RE = re.compile(
    r"(?P<key>[a-z_]+)\s*:\s*"
    r"(?:['\"](?P<sval>[^'\"]+)['\"]"
    r"|:(?P<symval>[a-z_][a-z0-9_]*)"
    r"|(?P<bareval>true|false|nil|\[[^\]]*\]))",
    re.IGNORECASE,
)

# Match a ``group :dev`` block (and ``platforms`` block, same shape).
_GROUP_START_RE = re.compile(
    r"^[\t ]*(?:group|platforms?)\s+(?P<groups>[^\n]+?)\s+do\b",
    re.MULTILINE,
)


def _line_of(text: str, idx: int) -> int:
    """1-based line of a character offset."""
    return text[:idx].count("\n") + 1


def _strip_comments(line: str) -> str:
    """Remove a trailing ``# ...`` comment from a Gemfile line."""
    h = line.find("#")
    if h < 0:
        return line
    return line[:h]


def _join_continuation_lines(text: str, pos: int, rest: str) -> str:
    """Append Ruby continuation lines to *rest*.

    A method-arg list continues onto the next physical line when the
    current line ends with a trailing ``,`` (or an explicit ``\\``).
    *pos* is the offset just past the first line's captured ``rest``;
    each continuation line is comment-stripped and folded in with a
    single space so :func:`_parse_options` sees the whole options hash.
    """
    nl = text.find("\n", pos)
    while nl != -1:
        core = rest.rstrip()
        if not core.endswith((",", "\\")):
            break
        core = core.rstrip("\\").rstrip()
        nxt = text.find("\n", nl + 1)
        line = _strip_comments(text[nl + 1: nxt if nxt != -1 else len(text)])
        if not line.strip():
            break
        rest = f"{core} {line.strip()}"
        nl = nxt
    return rest


def _parse_options(rest: str) -> dict[str, str]:
    """Extract the options hash from a ``gem`` line tail.

    The tail is everything after the gem name; the version
    constraint (if present) is one or more comma-separated string
    literals at the start, followed by zero or more ``key: value``
    options. We don't actually need the version separated here —
    the caller handles that. We only collect ``key: value`` pairs.
    """
    out: dict[str, str] = {}
    for m in _OPTION_RE.finditer(rest):
        key = m.group("key").lower()
        val = (
            m.group("sval") or m.group("symval")
            or m.group("bareval") or ""
        )
        # If the same key appears twice (rare), keep the last value.
        out[key] = val
    return out


def _parse_version(rest: str) -> str | None:
    """Pull the first quoted version literal off the ``gem`` line tail.

    Bundler accepts multiple constraints (``gem "x", ">= 1", "< 2"``);
    we keep the first one for rule purposes and let GEM-002 handle
    floating semantics. Returns ``None`` when no string literal is
    found before the first ``key:`` token.
    """
    # Stop at the first ``key:`` token (one-line option-hash start) so
    # we don't pick up the value side of an option pair.
    head = rest
    # Trim from a ``key:`` introducer if one exists.
    opt = _OPTION_RE.search(rest)
    if opt:
        head = rest[: opt.start()]
    m = re.search(r"['\"]([^'\"]+)['\"]", head)
    if not m:
        return None
    return m.group(1).strip()


def _find_block_ends(text: str) -> list[tuple[int, int, str]]:
    """Return ``(open_offset, close_offset, kind)`` for every ``do``
    / ``end`` block in the file.

    A simple depth-counted scan over ``\\bdo\\b`` and ``\\bend\\b``
    tokens. Good enough for almost every Gemfile in the wild;
    pathological cases (``end`` appearing inside a string literal,
    method-call ``do``-blocks that the parser shouldn't follow) are
    expected to be rare.
    """
    out: list[tuple[int, int, str]] = []
    tokens: list[tuple[int, str]] = []
    for m in re.finditer(
        r"\b(group|platforms?|source|do|end)\b", text,
    ):
        tokens.append((m.start(), m.group(0)))
    # Pair them off depth-first.
    stack: list[tuple[int, str]] = []
    for offset, tok in tokens:
        if tok in {"group", "platforms", "source"}:
            stack.append((offset, tok))
            continue
        if tok == "do":
            # ``do`` confirms the most recent block opener. We only
            # care if the opener was group / platforms / source; bare
            # ``do`` blocks (method calls) push an anonymous opener.
            if stack and stack[-1][1] in {"group", "platforms", "source"}:
                continue
            stack.append((offset, "anon"))
            continue
        if tok == "end":
            if not stack:
                continue
            start, kind = stack.pop()
            if kind != "anon":
                out.append((start, offset, kind))
    return out


def _resolve_source_blocks(
    text: str, blocks: list[tuple[int, int, str]],
) -> list[tuple[int, int, str]]:
    """Return ``(start, end, url)`` for every ``source "..." do`` block.

    Filters the block list down to ``source`` blocks and looks up the
    URL on the same logical line as the block's opening offset.
    """
    out: list[tuple[int, int, str]] = []
    for start, end, kind in blocks:
        if kind != "source":
            continue
        # The ``source`` token sits at ``start``; the URL is the first
        # string literal after that point on the same line.
        line_end = text.find("\n", start)
        if line_end < 0:
            line_end = len(text)
        snippet = text[start:line_end]
        m = re.search(r"['\"]([^'\"]+)['\"]", snippet)
        url = m.group(1) if m else ""
        out.append((start, end, url))
    return out


def _resolve_group_blocks(
    text: str, blocks: list[tuple[int, int, str]],
) -> list[tuple[int, int, tuple[str, ...]]]:
    """Return ``(start, end, groups)`` for every ``group`` block.

    Each group is the symbol literal after ``group`` (with the leading
    ``:`` stripped). Multiple comma-separated groups are split.
    """
    out: list[tuple[int, int, tuple[str, ...]]] = []
    for start, end, kind in blocks:
        if kind not in {"group", "platforms"}:
            continue
        line_end = text.find("\n", start)
        if line_end < 0:
            line_end = len(text)
        snippet = text[start:line_end]
        groups = tuple(
            m.group(1)
            for m in re.finditer(r":([a-z_][a-z0-9_]*)", snippet)
        )
        out.append((start, end, groups))
    return out


def _parse_gemfile(path: str, text: str) -> GemFile:
    """Parse a ``Gemfile`` body into a :class:`GemFile`."""
    sources: list[GemSource] = []
    deps: list[GemDependency] = []

    blocks = _find_block_ends(text)
    source_blocks = _resolve_source_blocks(text, blocks)
    group_blocks = _resolve_group_blocks(text, blocks)

    # Top-level sources: any ``source "..."`` line without a trailing
    # ``do`` keyword.
    for m in _SOURCE_RE.finditer(text):
        if m.group("do"):
            # Scoped source block opener; captured separately below.
            continue
        sources.append(GemSource(
            url=m.group("url"),
            line_no=_line_of(text, m.start()),
            is_top_level=True,
        ))
    # Scoped source blocks: emit one ``GemSource`` per block so the
    # rule pack sees them as declared sources too.
    for start, _end, url in source_blocks:
        sources.append(GemSource(
            url=url, line_no=_line_of(text, start),
            is_top_level=False,
        ))

    # Each ``gem "..."`` entry.
    for m in _GEM_RE.finditer(text):
        offset = m.start()
        name = m.group("name")
        rest = _strip_comments(m.group("rest"))
        # Ruby continues a method-arg list onto the next physical line
        # when the line ends with a trailing ``,`` (or ``\``). The
        # single-line ``_GEM_RE`` stops at the newline, so a gem whose
        # ``git:`` / ``branch:`` / ``ref:`` options sit on continuation
        # lines would parse as a plain, version-less gem. Pull those
        # lines in before parsing. ``offset`` is unchanged, so the
        # reported line number still points at the ``gem`` statement.
        if rest.rstrip().endswith((",", "\\")):
            rest = _join_continuation_lines(text, m.end(), rest)
        version = _parse_version(rest)
        options = _parse_options(rest)

        # Resolve the scoping for this entry.
        scoped_url = ""
        for s_start, s_end, url in source_blocks:
            if s_start <= offset <= s_end:
                scoped_url = url
                break
        groups: tuple[str, ...] = ()
        for g_start, g_end, gs in group_blocks:
            if g_start <= offset <= g_end:
                groups = gs
                break

        is_git = bool(options.get("git") or options.get("github"))
        git_url = options.get("git") or (
            f"github:{options['github']}" if options.get("github") else ""
        )
        git_ref = options.get("ref", "")
        git_mutable = False
        if is_git:
            if git_ref:
                git_mutable = False
            elif options.get("branch") or options.get("tag"):
                git_mutable = True
            else:
                git_mutable = True
        is_path = bool(options.get("path"))
        per_gem_source = options.get("source", "")

        deps.append(GemDependency(
            name=name, version=version,
            is_git=is_git, git_url=git_url, git_ref=git_ref,
            git_mutable=git_mutable, is_path=is_path,
            groups=groups, scoped_source=scoped_url,
            per_gem_source=per_gem_source,
            line_no=_line_of(text, offset),
        ))

    return GemFile(
        path=path, text=text,
        sources=tuple(sources),
        dependencies=tuple(deps),
        parsed_ok=True,
    )


# ── Helpers exposed to rule modules ───────────────────────────────


def is_floating_constraint(spec: str | None) -> bool:
    """Return ``True`` when the Bundler version constraint floats.

    Bundler / RubyGems version semantics:

    * No constraint at all (``gem "x"``) means "any version satisfying
      the lockfile / latest available". That's the most floating form
      and the rule treats ``None`` as floating.
    * Tilde-arrow (``"~> 7.0"`` / ``"~> 7.0.1"``) is a pessimistic
      operator that allows the rightmost component to increment.
      Floating.
    * Comparison operators (``">="``, ``"<="``, ``">"``, ``"<"``,
      ``"!="``) and ranges are floating.
    * An exact pin (no operator, e.g. ``"7.0.1"``, or ``"= 7.0.1"``)
      is the only pinned form.
    """
    if spec is None:
        return True
    s = spec.strip()
    if not s:
        return True
    # ``= 7.0.1`` is an exact pin.
    if s.startswith("="):
        body = s[1:].strip()
        return not _looks_like_pin(body)
    # ``~>``, ``>=``, ``<=``, ``>``, ``<``, ``!=`` all float.
    if s[:2] in {"~>", ">=", "<=", "!="}:
        return True
    if s[:1] in {">", "<"}:
        return True
    if "," in s:
        return True
    # Bare version literal: pinned iff it parses as digits-only-dots.
    return not _looks_like_pin(s)


def _looks_like_pin(s: str) -> bool:
    parts = s.split(".")
    if not parts:
        return False
    for p in parts:
        # Allow ``rc1`` / ``alpha`` suffixes on the last component
        # by matching ``\d+[a-z0-9]*`` per part.
        if not re.fullmatch(r"\d+[a-zA-Z0-9]*", p):
            return False
    return len(parts) >= 2
