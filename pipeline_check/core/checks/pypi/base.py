"""pypi context and base check.

Loads pip ``requirements.txt`` / ``requirements*.txt`` / ``*.in``
(pip-tools input) files from disk. Each file becomes a
:class:`RequirementsFile` exposing the original text plus a list of
parsed :class:`RequirementLine` entries: one per logical requirement,
with line continuations joined and comments stripped.

pyproject.toml / Pipfile.lock / poetry.lock support is out of scope
for the initial pack; the requirements.txt format covers the
overwhelming majority of pip-installable build/install steps and
captures the strongest supply-chain signals (pinning, hashing,
``--extra-index-url`` dependency confusion).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..base import BaseCheck

#: Recognized requirements-file shapes. Both ``requirements.txt`` style
#: (resolved, hash-bearing) and ``*.in`` (pip-tools input, declarative)
#: are scanned, the supply-chain signal is the same in both.
REQUIREMENTS_GLOBS: tuple[str, ...] = (
    "requirements*.txt", "requirements/*.txt", "*.in",
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
