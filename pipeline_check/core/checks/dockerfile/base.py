"""Dockerfile context and base check.

Parses ``Dockerfile`` / ``Containerfile`` documents from disk. Each
file becomes a :class:`Dockerfile` carrying the original text plus a
list of structured :class:`Instruction` records. Checks subclass
:class:`DockerfileBaseCheck` and iterate ``self.ctx.dockerfiles``.

The parser is deliberately small. It does NOT execute build args, it
does NOT resolve ``FROM <stage>`` references, and it does NOT
validate semantics. Its job is to surface the directive shape so
per-rule regexes don't each reimplement comment-stripping, line-
continuation handling, and tokenization.

Behavior notes:

- Line continuations (``\\`` at end of line) are joined into a single
  logical line. The parser preserves the *first* line number so
  findings point at the directive head.
- Comments (``#``) at the start of a line (after stripping leading
  whitespace) are dropped. Inline ``#`` is NOT a comment in
  Dockerfile syntax (it's part of the value), so it's preserved.
- Directive case is normalized to upper-case (``FROM``, ``RUN``).
- Multi-stage builds are flattened, every ``FROM`` opens a new
  stage but rules see the linear instruction stream and decide for
  themselves whether to scope by stage.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from ..base import BaseCheck

# Every documented Dockerfile directive (Docker + OCI Containerfile).
_DIRECTIVES: frozenset[str] = frozenset({
    "FROM", "RUN", "CMD", "LABEL", "MAINTAINER", "EXPOSE", "ENV",
    "ADD", "COPY", "ENTRYPOINT", "VOLUME", "USER", "WORKDIR", "ARG",
    "ONBUILD", "STOPSIGNAL", "HEALTHCHECK", "SHELL",
})


@dataclass(frozen=True, slots=True)
class Instruction:
    """One parsed directive.

    ``args`` is the raw post-directive text, with line continuations
    joined into a single string. Rules that need a structured view
    (e.g. ``ENV KEY=VALUE`` pairs, ``RUN --mount=...`` flags) parse
    further from ``args``.
    """

    line_no: int       #: 1-based line number of the directive head
    directive: str     #: Upper-case name (``FROM``, ``RUN``, …)
    args: str          #: Joined arguments, line-continuations resolved
    raw: str           #: Original source text, including continuations


@dataclass(frozen=True, slots=True)
class Dockerfile:
    """A parsed Dockerfile / Containerfile document."""

    path: str
    text: str
    instructions: tuple[Instruction, ...] = field(default_factory=tuple)


# Matches a directive name at the start of a logical line. Dockerfile
# directives are case-insensitive in practice; this captures any
# alphabetic token followed by whitespace.
_DIRECTIVE_HEAD_RE = re.compile(r"^\s*([A-Za-z]+)\s+(.*)$")


def parse_dockerfile(text: str) -> tuple[Instruction, ...]:
    """Return the list of directives in *text*.

    Joins line continuations (``\\`` at end of physical line),
    discards full-line comments, and normalises directive names to
    upper case. Lines that don't match a known directive are silently
    skipped, the goal is best-effort detection, not strict parsing.
    """
    out: list[Instruction] = []
    physical_lines = text.splitlines(keepends=False)
    i = 0
    while i < len(physical_lines):
        # Skip blank lines and comments at the *physical* level so the
        # logical-line offset stays accurate. Inline ``#`` is part of
        # the value once we're inside a directive, but a leading ``#``
        # is a Dockerfile comment.
        line = physical_lines[i]
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        head_line_no = i + 1  # 1-based
        # Join continuations until a line doesn't end with ``\``.
        parts: list[str] = []
        while i < len(physical_lines):
            cur = physical_lines[i]
            stripped_cur = cur.rstrip()
            if stripped_cur.endswith("\\"):
                parts.append(stripped_cur[:-1])
                i += 1
                continue
            parts.append(cur)
            i += 1
            break
        joined = "\n".join(parts)
        # Collapse interior whitespace runs that span continuations
        # for the ``args`` field; preserve the original in ``raw``.
        m = _DIRECTIVE_HEAD_RE.match(joined.replace("\n", " "))
        if not m:
            continue
        directive_name = m.group(1).upper()
        if directive_name not in _DIRECTIVES:
            continue
        out.append(Instruction(
            line_no=head_line_no,
            directive=directive_name,
            args=m.group(2).strip(),
            raw=joined,
        ))
    return tuple(out)


class DockerfileContext:
    """Loaded set of Dockerfile / Containerfile documents."""

    def __init__(self, dockerfiles: list[Dockerfile]) -> None:
        self.dockerfiles = dockerfiles
        self.files_scanned: int = len(dockerfiles)
        self.files_skipped: int = 0
        self.warnings: list[str] = []

    @classmethod
    def from_path(cls, path: str | Path) -> DockerfileContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--dockerfile-path {root} does not exist. Pass a "
                "Dockerfile / Containerfile or a directory containing one."
            )
        if root.is_file():
            files = [root]
        else:
            # Match the canonical filenames first, most repos have
            # exactly one Dockerfile at root or under a service dir.
            # ``*.Dockerfile`` (e.g. ``api.Dockerfile``) is also picked
            # up; arbitrary suffixes like ``Dockerfile.dev`` work too.
            files = sorted(
                p for p in root.rglob("*")
                if p.is_file() and (
                    p.name.lower() in {"dockerfile", "containerfile"}
                    or p.name.lower().startswith("dockerfile.")
                    or p.name.lower().endswith(".dockerfile")
                    or p.name.lower().startswith("containerfile.")
                )
            )
        dockerfiles: list[Dockerfile] = []
        warnings: list[str] = []
        skipped = 0
        for f in files:
            try:
                text = f.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                warnings.append(f"{f}: read error: {exc}")
                skipped += 1
                continue
            instructions = parse_dockerfile(text)
            # An empty parse result usually means the file isn't a
            # Dockerfile (e.g. a stray text file in a recursive scan).
            # Skip rather than emit zero findings so users don't get
            # confused output.
            if not instructions:
                skipped += 1
                continue
            dockerfiles.append(Dockerfile(
                path=str(f), text=text, instructions=instructions,
            ))
        ctx = cls(dockerfiles)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


class DockerfileBaseCheck(BaseCheck[DockerfileContext]):
    """Base class for Dockerfile rule modules."""

    PROVIDER = "dockerfile"

    def __init__(self, ctx: DockerfileContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: DockerfileContext = ctx


# ── Helpers shared by multiple rule modules ────────────────────────────

def iter_instructions(
    df: Dockerfile, *, directive: str | None = None,
) -> Iterator[Instruction]:
    """Yield instructions, optionally filtered to one directive."""
    target = directive.upper() if directive else None
    for ins in df.instructions:
        if target is None or ins.directive == target:
            yield ins


def has_directive(df: Dockerfile, name: str) -> bool:
    """Return True if *df* contains at least one instance of *name*."""
    upper = name.upper()
    return any(ins.directive == upper for ins in df.instructions)


def from_refs(df: Dockerfile) -> list[tuple[int, str]]:
    """Return ``[(line_no, image_ref), ...]`` for every ``FROM`` directive.

    The ``args`` of a ``FROM`` is ``[--flag=value ...] <image>[:tag][@digest]
    [AS <stage>]``. Leading flags (``--platform=``) are stripped and only
    the image reference is returned.
    """
    out: list[tuple[int, str]] = []
    for ins in iter_instructions(df, directive="FROM"):
        _, ref = from_args_with_flags(ins)
        if ref:
            out.append((ins.line_no, ref))
    return out


def run_bodies(df: Dockerfile) -> list[tuple[int, str]]:
    """Return ``[(line_no, body), ...]`` for every ``RUN`` directive.

    The body is the raw post-``RUN`` text, with line continuations
    already joined by the parser. Rules that scan for shell idioms
    pass each body to the matching primitive (``shell_eval.scan``,
    ``remote_script_exec.scan``, …).
    """
    return [(ins.line_no, ins.args) for ins in iter_instructions(df, directive="RUN")]


def env_pairs(df: Dockerfile) -> list[tuple[int, str, str]]:
    """Return ``[(line_no, key, value), ...]`` for every ``ENV`` / ``ARG`` pair.

    Both ``ENV KEY=VALUE`` and the legacy ``ENV KEY VALUE`` forms are
    parsed. ``ARG NAME=DEFAULT`` is included since a literal default
    that holds a credential-shaped value is the same risk shape.
    """
    out: list[tuple[int, str, str]] = []
    for ins in df.instructions:
        if ins.directive not in ("ENV", "ARG"):
            continue
        body = ins.args
        if "=" in body:
            # ENV KEY=VAL [KEY=VAL ...], multiple pairs allowed on one line.
            for token in _split_env_kv(body):
                if "=" in token:
                    k, _, v = token.partition("=")
                    out.append((ins.line_no, k.strip(), v.strip().strip('"').strip("'")))
        else:
            # Legacy ENV KEY VALUE, first whitespace-separated token
            # is the key, remainder is the value.
            tokens = body.split(maxsplit=1)
            if tokens:
                k = tokens[0]
                v = tokens[1] if len(tokens) > 1 else ""
                out.append((ins.line_no, k, v.strip().strip('"').strip("'")))
    return out


def _split_env_kv(body: str) -> list[str]:
    """Split an ``ENV`` body into ``KEY=VAL`` tokens, respecting quotes."""
    tokens: list[str] = []
    cur: list[str] = []
    in_quote: str | None = None
    for ch in body:
        if in_quote:
            cur.append(ch)
            if ch == in_quote:
                in_quote = None
            continue
        if ch in ('"', "'"):
            in_quote = ch
            cur.append(ch)
            continue
        if ch.isspace():
            if cur:
                tokens.append("".join(cur))
                cur = []
            continue
        cur.append(ch)
    if cur:
        tokens.append("".join(cur))
    return tokens


def from_args_with_flags(ins: Instruction) -> tuple[list[str], str]:
    """Split a ``FROM`` instruction's args into (flags, image_ref).

    Handles ``--platform=...`` and similar leading flags so the
    image reference can be classified without flag noise.
    """
    tokens = ins.args.split()
    flags: list[str] = []
    while tokens and tokens[0].startswith("--"):
        flags.append(tokens.pop(0))
    ref = tokens[0] if tokens else ""
    return flags, ref


__all__ = [
    "Dockerfile", "DockerfileBaseCheck", "DockerfileContext",
    "Instruction", "env_pairs", "from_args_with_flags", "from_refs",
    "has_directive", "iter_instructions", "parse_dockerfile",
    "run_bodies",
]
