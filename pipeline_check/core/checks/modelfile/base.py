"""Modelfile context and base check.

Parses Ollama ``Modelfile`` declarations from disk. A Modelfile is the
declarative recipe that pins a model into the local registry: a ``FROM``
base model (an Ollama-library name, a ``hf.co`` / ``huggingface.co`` pull,
or a local weights file), optional ``ADAPTER`` LoRA layers, plus prompt
``TEMPLATE`` / ``SYSTEM`` / ``PARAMETER`` blocks. It is the "Dockerfile of
models", so this provider mirrors the Dockerfile provider's shape: a small
best-effort directive parser, text-only, no model pull, no Ollama daemon.

    pipeline_check --pipeline modelfile --modelfile-path path/to/Modelfile

The model supply-chain rules (MODEL-*) reason over the ``FROM`` / ``ADAPTER``
references this parser surfaces, the static complement to the CI-side AI
rules (GHA-120/121/122, GL-045..049) that catch model pulls in build
scripts.

Parser notes:

- Directives are matched at the start of a logical line; case is
  normalized to upper-case (``FROM``, ``ADAPTER``).
- Triple-quoted values (the ``SYSTEM`` / ``TEMPLATE`` / ``LICENSE``
  blocks delimited by three double-quotes) are tracked so a prompt line
  that happens to start with a directive word (a ``SYSTEM`` block whose
  text begins ``FROM now on ...``) is not mis-read as a ``FROM``.
- ``#`` at the start of a line is a comment.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from ..base import BaseCheck

# Documented Ollama Modelfile directives.
# https://github.com/ollama/ollama/blob/main/docs/modelfile.md
_DIRECTIVES: frozenset[str] = frozenset({
    "FROM", "PARAMETER", "TEMPLATE", "SYSTEM", "ADAPTER", "LICENSE", "MESSAGE",
})

# A directive head: a leading word plus the rest of the line.
_DIRECTIVE_HEAD_RE = re.compile(r"^\s*([A-Za-z]+)\b\s*(.*)$")


@dataclass(frozen=True, slots=True)
class Directive:
    """One parsed Modelfile directive."""

    line_no: int       #: 1-based line number of the directive head
    directive: str     #: Upper-case name (``FROM``, ``ADAPTER``, …)
    args: str          #: Post-directive text (first line, stripped)


@dataclass(frozen=True, slots=True)
class Modelfile:
    """A parsed Ollama Modelfile document."""

    path: str
    text: str
    directives: tuple[Directive, ...] = field(default_factory=tuple)


def parse_modelfile(text: str) -> tuple[Directive, ...]:
    """Return the directives in *text*, best-effort.

    Skips blank lines, ``#`` comments, and the interior of triple-quoted
    blocks; normalizes directive names to upper case; ignores lines that
    don't open a known directive.
    """
    out: list[Directive] = []
    in_block = False
    for idx, line in enumerate(text.splitlines()):
        if in_block:
            # Inside a triple-quoted value; a line that closes the quote
            # ends the block. (An odd count of ``"""`` toggles state.)
            if line.count('"""') % 2 == 1:
                in_block = False
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _DIRECTIVE_HEAD_RE.match(stripped)
        if not m:
            continue
        name = m.group(1).upper()
        if name not in _DIRECTIVES:
            continue
        args = m.group(2).strip()
        # A directive that opens (but doesn't close) a triple-quoted value
        # starts a block whose interior lines must not be parsed.
        if args.count('"""') % 2 == 1:
            in_block = True
        out.append(Directive(line_no=idx + 1, directive=name, args=args))
    return tuple(out)


class ModelfileContext:
    """Loaded set of Ollama Modelfile documents."""

    def __init__(self, modelfiles: list[Modelfile]) -> None:
        self.modelfiles = modelfiles
        self.files_scanned: int = len(modelfiles)
        self.files_skipped: int = 0
        self.warnings: list[str] = []

    @classmethod
    def from_path(cls, path: str | Path) -> ModelfileContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--modelfile-path {root} does not exist. Pass a Modelfile "
                "or a directory containing one."
            )
        if root.is_file():
            files = [root]
        else:
            # Canonical name is ``Modelfile``; ``*.Modelfile`` (e.g.
            # ``chat.Modelfile``) and ``Modelfile.*`` variants are also
            # picked up.
            files = sorted(
                p for p in root.rglob("*")
                if p.is_file() and (
                    p.name.lower() == "modelfile"
                    or p.name.lower().endswith(".modelfile")
                    or p.name.lower().startswith("modelfile.")
                )
            )
        modelfiles: list[Modelfile] = []
        warnings: list[str] = []
        skipped = 0
        for f in files:
            try:
                text = f.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                warnings.append(f"{f}: read error: {exc}")
                skipped += 1
                continue
            directives = parse_modelfile(text)
            # No directives usually means the file isn't a Modelfile (a
            # stray match in a recursive scan); skip rather than emit a
            # confusing zero-finding result.
            if not directives:
                skipped += 1
                continue
            modelfiles.append(
                Modelfile(path=str(f), text=text, directives=directives)
            )
        ctx = cls(modelfiles)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


class ModelfileBaseCheck(BaseCheck[ModelfileContext]):
    """Base class for Modelfile rule orchestration."""

    PROVIDER = "modelfile"

    def __init__(self, ctx: ModelfileContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: ModelfileContext = ctx


# ── Helpers shared by the MODEL-* rule modules ─────────────────────────

def iter_directives(
    mf: Modelfile, name: str,
) -> Iterator[Directive]:
    """Yield directives of *mf* matching *name* (case-insensitive)."""
    upper = name.upper()
    for d in mf.directives:
        if d.directive == upper:
            yield d


def from_refs(mf: Modelfile) -> list[tuple[int, str]]:
    """Return ``[(line_no, ref), ...]`` for every ``FROM`` directive.

    The ref is the first whitespace-separated token of the directive's
    args (an Ollama ``FROM`` takes a single model reference or path).
    """
    out: list[tuple[int, str]] = []
    for d in iter_directives(mf, "FROM"):
        ref = d.args.split()[0] if d.args.split() else ""
        if ref:
            out.append((d.line_no, ref))
    return out


def adapter_refs(mf: Modelfile) -> list[tuple[int, str]]:
    """Return ``[(line_no, ref), ...]`` for every ``ADAPTER`` directive."""
    out: list[tuple[int, str]] = []
    for d in iter_directives(mf, "ADAPTER"):
        ref = d.args.split()[0] if d.args.split() else ""
        if ref:
            out.append((d.line_no, ref))
    return out


# Local weights file: a path (``./x``, ``/x``, ``~/x``, ``../x``) or a
# bare filename ending in a weights extension.
_LOCAL_PATH_RE = re.compile(r"^(?:\.{1,2}/|/|~/|[A-Za-z]:[\\/])")
_WEIGHTS_EXT_RE = re.compile(r"\.(?:gguf|bin|safetensors|pt|pth)$", re.IGNORECASE)

# A third-party model hub the Ollama loader can pull from directly.
_HUB_PREFIX_RE = re.compile(r"^(?:hf\.co|huggingface\.co)/", re.IGNORECASE)


def ref_is_local(ref: str) -> bool:
    """True when *ref* names a local weights file rather than a registry pull."""
    return bool(_LOCAL_PATH_RE.match(ref) or _WEIGHTS_EXT_RE.search(ref))


def ref_is_hub(ref: str) -> bool:
    """True when *ref* pulls from a third-party hub (``hf.co`` / ``huggingface.co``)."""
    return bool(_HUB_PREFIX_RE.match(ref))


def ref_tag(ref: str) -> str | None:
    """Return the ``:tag`` of a registry ref, or ``None`` when untagged.

    A ``@sha256:...`` digest is treated as pinned (returns the digest).
    The hub-path host segment is ignored so a leading ``hf.co/`` doesn't
    confuse the ``:`` split.
    """
    if "@" in ref:
        return ref.split("@", 1)[1]
    # Drop any host/path segments; the tag attaches to the last segment.
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        return last.split(":", 1)[1]
    return None


__all__ = [
    "Directive", "Modelfile", "ModelfileBaseCheck", "ModelfileContext",
    "adapter_refs", "from_refs", "iter_directives", "parse_modelfile",
    "ref_is_hub", "ref_is_local", "ref_tag",
]
