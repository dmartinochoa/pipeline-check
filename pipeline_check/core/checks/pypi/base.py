"""pypi context and base check.

Loads pip ``requirements.txt`` / ``requirements*.txt`` / ``*.in``
(pip-tools input), ``poetry.lock``, and ``Pipfile.lock`` files
from disk. Each file becomes a :class:`RequirementsFile` exposing
the original text plus a list of parsed :class:`RequirementLine`
entries: one per logical requirement, with line continuations
joined and comments stripped.

``poetry.lock`` is read by parsing the TOML and synthesizing the
same ``RequirementsFile`` shape (see :func:`_parse_poetry_lock`);
``Pipfile.lock`` is read by parsing the JSON the same way (see
:func:`_parse_pipfile_lock`). Both enforce per-package hashes at
install time, so synthesized files carry ``--require-hashes`` in
their top-level options for PYPI-002's sake; git-sourced
packages get a ``foo @ git+<url>@<sha>`` PEP-508-direct-URL body
so PYPI-004 classifies the ref correctly.

``pyproject.toml`` (PEP 621 / Poetry dependency declarations)
stays out of scope for this pass — it's a manifest, not a
resolved lockfile, and warrants its own parser, deferred.
"""
from __future__ import annotations

import datetime as _dt
import json
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..base import BaseCheck

#: Recognized requirements-file shapes. Both ``requirements.txt`` style
#: (resolved, hash-bearing) and ``*.in`` (pip-tools input, declarative)
#: are scanned, the supply-chain signal is the same in both.
#: ``poetry.lock`` and ``Pipfile.lock`` join the set via TOML / JSON
#: parsing + synthesis (:func:`_parse_poetry_lock`,
#: :func:`_parse_pipfile_lock`).
REQUIREMENTS_GLOBS: tuple[str, ...] = (
    "requirements*.txt", "requirements/*.txt", "*.in",
    "poetry.lock", "Pipfile.lock",
)


@dataclass(frozen=True, slots=True)
class RequirementLine:
    """One logical requirement line.

    Continuation lines (``\\`` at end of physical line) are joined into
    a single ``body``. The original starting line number is preserved
    for finding locations. ``flags`` carries any per-line ``--hash=``
    arguments captured separately from the requirement spec itself.
    """

    line_no: int   #: 1-based line number of the requirement head
    body: str      #: Joined requirement text without trailing ``\``
    flags: tuple[str, ...] = ()  #: Per-line ``--hash=...`` flags


@dataclass(frozen=True, slots=True)
class RequirementsFile:
    """A parsed requirements / pip-tools input file."""

    path: str
    text: str
    lines: tuple[RequirementLine, ...] = field(default_factory=tuple)
    #: Top-level options that apply to the whole file (``--index-url``,
    #: ``--extra-index-url``, ``--trusted-host``, ``--require-hashes``,
    #: ``--no-binary``). Captured separately from per-line flags so
    #: rules can ask "does this file enable require-hashes?" without
    #: walking every line.
    options: tuple[str, ...] = ()


class PypiContext:
    """Loaded set of requirements / pip-tools input files."""

    def __init__(self, files: list[RequirementsFile]) -> None:
        self.files = files
        self.files_scanned: int = len(files)
        self.files_skipped: int = 0
        self.warnings: list[str] = []
        #: ``{package_name: {version: utc_timestamp}}`` populated by
        #: the pypi provider's ``post_filter`` when
        #: ``--resolve-remote`` is on. Empty by default; rules like
        #: PYPI-008 (cooldown gate) read it and pass silently when
        #: the dict is empty so the rule's absence isn't a CI
        #: failure for users on the default no-network path.
        self.publish_times: dict[str, dict[str, _dt.datetime]] = {}

    @classmethod
    def from_path(cls, path: str | Path) -> PypiContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--pypi-path {root} does not exist. Pass a "
                "requirements.txt file or a directory containing one."
            )
        if root.is_file():
            candidates = [root]
        else:
            seen: set[Path] = set()
            candidates = []
            for pattern in REQUIREMENTS_GLOBS:
                for p in sorted(root.rglob(pattern)):
                    if p.is_file() and p not in seen:
                        seen.add(p)
                        candidates.append(p)
        files: list[RequirementsFile] = []
        warnings: list[str] = []
        skipped = 0
        for f in candidates:
            try:
                text = f.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                warnings.append(f"{f}: read error: {exc}")
                skipped += 1
                continue
            if f.name == "poetry.lock":
                try:
                    lines, options = _parse_poetry_lock(text)
                except Exception as exc:  # noqa: BLE001
                    warnings.append(
                        f"{f}: poetry.lock parse error: {exc}"
                    )
                    skipped += 1
                    continue
            elif f.name == "Pipfile.lock":
                try:
                    lines, options = _parse_pipfile_lock(text)
                except Exception as exc:  # noqa: BLE001
                    warnings.append(
                        f"{f}: Pipfile.lock parse error: {exc}"
                    )
                    skipped += 1
                    continue
            else:
                lines, options = _parse_requirements(text)
            files.append(RequirementsFile(
                path=str(f), text=text, lines=lines, options=options,
            ))
        ctx = cls(files)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


class PypiBaseCheck(BaseCheck):
    """Base class for pypi rule modules."""

    PROVIDER = "pypi"

    def __init__(self, ctx: PypiContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: PypiContext = ctx


# ── Parser ────────────────────────────────────────────────────────────


#: Long-form options that pip respects at the top level of a
#: requirements file (PEP 508 + pip-specific). Per-line ``--hash=``
#: is handled separately.
_TOP_LEVEL_OPTIONS: frozenset[str] = frozenset({
    "--index-url", "-i",
    "--extra-index-url",
    "--no-index",
    "--trusted-host",
    "--require-hashes",
    "--no-binary", "--only-binary",
    "--pre",
    "--prefer-binary",
    "--find-links", "-f",
})

#: ``--flag=value`` forms whose head token startswith() one of these.
_OPTION_EQUALS_FORMS: tuple[str, ...] = (
    "--index-url=", "-i=", "--extra-index-url=",
    "--trusted-host=", "--find-links=", "-f=",
)


def _parse_requirements(
    text: str,
) -> tuple[tuple[RequirementLine, ...], tuple[str, ...]]:
    """Return ``(lines, options)`` from a requirements file body.

    Joins ``\\``-continuations, strips ``#`` comments, captures
    top-level options separately, splits each requirement line's
    ``--hash=...`` flags out of the spec into ``RequirementLine.flags``.
    """
    physical = text.splitlines(keepends=False)
    lines: list[RequirementLine] = []
    options: list[str] = []
    i = 0
    while i < len(physical):
        head_line_no = i + 1
        parts: list[str] = []
        while i < len(physical):
            cur = physical[i]
            # Strip ``#`` comments but only when ``#`` is not inside a
            # URL fragment. The rule for pip is: a ``#`` not preceded
            # by an ``egg=`` / URL char starts a comment.
            comment_idx = _comment_start(cur)
            if comment_idx >= 0:
                cur = cur[:comment_idx]
            stripped_cur = cur.rstrip()
            if stripped_cur.endswith("\\"):
                parts.append(stripped_cur[:-1])
                i += 1
                continue
            parts.append(cur)
            i += 1
            break
        joined = " ".join(p.strip() for p in parts if p.strip())
        if not joined:
            continue
        # Top-level options are their own logical entries.
        head = joined.split(maxsplit=1)
        head_tok = head[0]
        if head_tok in _TOP_LEVEL_OPTIONS or head_tok.startswith(_OPTION_EQUALS_FORMS):
            options.append(joined)
            continue
        # Split ``--hash=...`` flags out of the spec body.
        flags: list[str] = []
        tokens = joined.split()
        kept: list[str] = []
        for tok in tokens:
            if tok.startswith("--hash="):
                flags.append(tok)
            else:
                kept.append(tok)
        body = " ".join(kept).strip()
        if not body and not flags:
            continue
        lines.append(RequirementLine(
            line_no=head_line_no, body=body, flags=tuple(flags),
        ))
    return tuple(lines), tuple(options)


def _comment_start(line: str) -> int:
    """Return the index of a ``#`` comment in *line*, or -1.

    A ``#`` is a comment when preceded by whitespace or at column 0;
    a ``#`` inside a URL fragment (``#egg=...``) is not a comment.
    """
    for idx, ch in enumerate(line):
        if ch != "#":
            continue
        if idx == 0:
            return idx
        prev = line[idx - 1]
        if prev.isspace():
            return idx
        # No leading whitespace: ``foo==1.0#egg=...`` keeps the ``#``.
    return -1


# ── poetry.lock synthesis ────────────────────────────────────────────


def _files_for_package(
    pkg: dict[str, Any],
    metadata_files: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Return the list of file records for a single poetry.lock package.

    Lock-version 2.x carries a per-package ``files`` list inside the
    ``[[package]]`` table. Lock-version 1.x keeps file records in a
    top-level ``[metadata.files]`` map keyed by package name. The
    helper hides both shapes from the synthesizer; callers see a
    flat list of ``{file, hash}`` dicts regardless.
    """
    inline = pkg.get("files")
    if isinstance(inline, list):
        return [f for f in inline if isinstance(f, dict)]
    if metadata_files is not None:
        name = pkg.get("name")
        if isinstance(name, str):
            entries = metadata_files.get(name)
            if isinstance(entries, list):
                return [f for f in entries if isinstance(f, dict)]
    return []


def _hash_flag_from_file_entry(entry: dict[str, Any]) -> str | None:
    """Return ``--hash=<algo>:<digest>`` from a poetry file record.

    Poetry's per-file ``hash`` field already carries the ``algo:digest``
    form (typically ``sha256:abc...``), so we just prefix ``--hash=``
    and the resulting flag matches the shape PYPI-002 reads.
    """
    h = entry.get("hash")
    if not isinstance(h, str) or ":" not in h:
        return None
    return f"--hash={h}"


def _synthesize_body_for_package(pkg: dict[str, Any]) -> str | None:
    """Return the requirement body for one ``[[package]]`` table.

    Registry-resolved packages → ``<name>==<version>`` so PYPI-001 /
    PYPI-006 see the exact pin.

    Git-sourced packages (``[package.source]`` ``type = "git"``) →
    ``<name> @ git+<url>@<resolved_reference>`` (PEP 508 direct URL)
    so PYPI-004 classifies the ref. We prefer ``resolved_reference``
    (the lock-time SHA Poetry resolves to) over the human-supplied
    ``reference`` (which may be a branch or tag) so a lockfile that
    pins to a 40-char SHA passes PYPI-004 even when the source block
    asks for ``main``.

    URL-sourced and directory-sourced packages fall through to a
    bare ``<name>==<version>`` body — PYPI-004 only fires on VCS
    schemes, so URL sources don't need the direct-URL shape.

    Returns ``None`` when name or version are missing (defensive;
    Poetry always writes both).
    """
    name = pkg.get("name")
    version = pkg.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        return None
    source = pkg.get("source")
    if isinstance(source, dict) and source.get("type") == "git":
        url = source.get("url")
        ref = source.get("resolved_reference") or source.get("reference")
        if isinstance(url, str) and isinstance(ref, str):
            return f"{name} @ git+{url}@{ref}"
        if isinstance(url, str):
            return f"{name} @ git+{url}"
    return f"{name}=={version}"


def _parse_poetry_lock(
    text: str,
) -> tuple[tuple[RequirementLine, ...], tuple[str, ...]]:
    """Parse a poetry.lock body and project it onto the
    requirements-file shape.

    Each ``[[package]]`` entry becomes one :class:`RequirementLine`
    carrying a ``name==version`` body (or a PEP 508 direct URL for
    git sources) plus one ``--hash=`` flag per file record. The
    returned options always include ``--require-hashes`` because
    Poetry verifies per-package hashes at install time when the lock
    file is present; the per-line ``--hash`` flags carry the
    individual file hashes PYPI-002 expects.

    Line numbers are best-effort: the synthesized RequirementLines
    each report a 1-based index into the ``[[package]]`` block they
    came from (1, 2, 3, ...) rather than a literal byte offset into
    the TOML. PYPI rules use the line number only for finding
    locations, so a monotonic per-package index keeps locations
    distinguishable without a costly TOML-line-tracking pass.
    """
    raw = tomllib.loads(text)
    packages = raw.get("package")
    if not isinstance(packages, list):
        # Empty / malformed lockfile: emit nothing rather than raise.
        return ((), ("--require-hashes",))
    metadata = raw.get("metadata")
    metadata_files = (
        metadata.get("files")
        if isinstance(metadata, dict) and isinstance(metadata.get("files"), dict)
        else None
    )
    lines: list[RequirementLine] = []
    for idx, pkg in enumerate(packages, start=1):
        if not isinstance(pkg, dict):
            continue
        body = _synthesize_body_for_package(pkg)
        if body is None:
            continue
        files = _files_for_package(pkg, metadata_files)
        flags: list[str] = []
        for f in files:
            flag = _hash_flag_from_file_entry(f)
            if flag is not None:
                flags.append(flag)
        lines.append(RequirementLine(
            line_no=idx, body=body, flags=tuple(flags),
        ))
    return tuple(lines), ("--require-hashes",)


# ── Pipfile.lock synthesis ────────────────────────────────────────────


def _hash_flags_from_pipfile_entry(entry: dict[str, Any]) -> list[str]:
    """Return ``--hash=<algo>:<digest>`` flags from a Pipfile.lock entry.

    Pipfile.lock writes ``hashes`` as a flat list of
    ``"<algo>:<digest>"`` strings (always ``sha256``). The helper
    skips empty / malformed entries silently so the synthesizer
    doesn't break on a partially-rendered lockfile.
    """
    hashes = entry.get("hashes")
    if not isinstance(hashes, list):
        return []
    out: list[str] = []
    for h in hashes:
        if isinstance(h, str) and ":" in h:
            out.append(f"--hash={h}")
    return out


def _synthesize_body_for_pipfile_entry(
    name: str,
    entry: dict[str, Any],
) -> str | None:
    """Return the requirement body for one Pipfile.lock entry.

    Registry-resolved entries → ``<name>==<version>`` (Pipfile.lock
    stores ``version`` as ``"==1.2.3"`` so the literal already
    carries the ``==``; we strip it before reattaching to keep the
    body shape unambiguous to PYPI-001 / PYPI-006's parsers).

    Git-sourced entries (``git`` key present) → ``<name> @
    git+<url>@<ref>`` (PEP 508 direct URL) so PYPI-004 classifies
    the ref. ``ref`` carries the resolved commit SHA when Pipenv
    has performed an install; a branch / tag name is possible
    before resolution and falls through verbatim — PYPI-004 then
    flags it because it isn't a 40-char SHA.

    URL- and path-sourced entries (``file``, ``path`` keys) fall
    back to the ``<name>==<version>`` body so PYPI-001 / PYPI-006
    still see a recoverable name. ``editable: true`` is preserved
    on disk but doesn't change the rule layer's interpretation.

    Returns ``None`` when the entry has no recoverable identity
    (no version and no git URL).
    """
    git = entry.get("git")
    if isinstance(git, str) and git:
        ref = entry.get("ref")
        if isinstance(ref, str) and ref:
            return f"{name} @ git+{git}@{ref}"
        return f"{name} @ git+{git}"
    version = entry.get("version")
    if isinstance(version, str) and version:
        # Pipfile.lock stores ``"==1.2.3"``; strip the leading
        # operator(s) before reattaching ``==`` for canonical shape.
        stripped = version.lstrip("=<>~!").strip()
        if stripped:
            return f"{name}=={stripped}"
    return None


def _parse_pipfile_lock(
    text: str,
) -> tuple[tuple[RequirementLine, ...], tuple[str, ...]]:
    """Parse a Pipfile.lock body and project it onto the
    requirements-file shape.

    Pipfile.lock is JSON with two top-level package buckets
    (``default``, ``develop``) each mapping ``name`` to a record
    carrying ``version`` (``"==1.2.3"``), ``hashes`` (list of
    ``sha256:...`` strings), and source coordinates (``git`` /
    ``ref`` / ``file`` / ``path``). The synthesizer walks both
    buckets in order (default first, develop second) and emits one
    :class:`RequirementLine` per entry. Line numbers are best-
    effort: monotonic 1, 2, 3 across the union of buckets, so each
    location stays distinguishable without a per-byte JSON-line
    tracking pass.

    ``--require-hashes`` is set at the file level because
    Pipfile.lock always carries hashes (Pipenv refuses to write a
    lockfile without them), so PYPI-002 sees the same enforcement
    contract Pipenv enforces at ``pipenv install``.
    """
    raw = json.loads(text)
    if not isinstance(raw, dict):
        return ((), ("--require-hashes",))
    lines: list[RequirementLine] = []
    idx = 0
    for bucket_name in ("default", "develop"):
        bucket = raw.get(bucket_name)
        if not isinstance(bucket, dict):
            continue
        for name, entry in bucket.items():
            if not isinstance(name, str) or not isinstance(entry, dict):
                continue
            body = _synthesize_body_for_pipfile_entry(name, entry)
            if body is None:
                continue
            idx += 1
            flags = tuple(_hash_flags_from_pipfile_entry(entry))
            lines.append(RequirementLine(
                line_no=idx, body=body, flags=flags,
            ))
    return tuple(lines), ("--require-hashes",)


# ── Helpers shared by multiple rule modules ────────────────────────────


def iter_specs(rf: RequirementsFile) -> list[RequirementLine]:
    """Return every parsed requirement line (excluding top-level options).

    Trivial wrapper, keeps rule modules from reaching into the
    dataclass field directly so future shape changes stay local.
    """
    return list(rf.lines)


def has_option(rf: RequirementsFile, name: str) -> bool:
    """True if *rf*'s top-level options include *name*.

    Matches both bare-flag form (``--require-hashes``) and ``=value``
    form (``--index-url=https://...``).
    """
    target = name.rstrip("=")
    for opt in rf.options:
        tok = opt.split(maxsplit=1)[0]
        if tok == target or tok.startswith(target + "="):
            return True
    return False


def get_option_values(rf: RequirementsFile, name: str) -> list[str]:
    """Return every value supplied for top-level option *name*.

    Handles both ``--index-url URL`` and ``--index-url=URL`` forms.
    The flag itself isn't included in the returned values.
    """
    target = name.rstrip("=")
    out: list[str] = []
    for opt in rf.options:
        head, _, rest = opt.partition(" ")
        if head == target and rest:
            out.append(rest.strip())
        elif head.startswith(target + "="):
            out.append(head[len(target) + 1:])
            if rest:
                out.append(rest.strip())
    return out


__all__ = [
    "PypiBaseCheck", "PypiContext", "REQUIREMENTS_GLOBS",
    "RequirementLine", "RequirementsFile", "get_option_values",
    "has_option", "iter_specs",
]
