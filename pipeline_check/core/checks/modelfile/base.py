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

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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


@dataclass(frozen=True, slots=True)
class ModelConfig:
    """A vendored Hugging Face model ``config.json`` document.

    Only configs that look like a transformers model config (they carry
    one of the HF marker keys) are loaded, so a generic ``config.json``
    in an unrelated tool's directory isn't treated as a model.
    """

    path: str
    data: dict[str, Any]


@dataclass(frozen=True, slots=True)
class WeightBlob:
    """A committed model-weight file in a code-executing serialization format.

    Recorded by path and (lower-case) extension only; the file's bytes
    are never read. MODEL-006 reasons over the format, not the content.
    """

    path: str
    ext: str


#: HF transformers ``config.json`` marker keys: presence of any one means
#: the file is a model config rather than some other ``config.json``.
_HF_CONFIG_MARKERS: frozenset[str] = frozenset({
    "auto_map", "architectures", "model_type",
})

#: Weight-file extensions that deserialize arbitrary code at load and are
#: unambiguous enough to flag on the extension alone: Python pickle
#: (``.pkl`` / ``.pickle`` / ``.joblib`` / ``.dill``), pickle-backed torch
#: (``.pt`` / ``.pth`` / ``.ckpt``), and Keras (``.keras``, whose Lambda
#: layers carry code).
_TIER1_UNSAFE_EXTS: frozenset[str] = frozenset({
    ".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".joblib", ".dill", ".keras",
})

#: Extensions that are pickle- / code-carrying when they hold a model but
#: are widely used for unrelated data too (a firmware ``.bin``, a generic
#: HDF5 dataset). Flagged only with model context (a model-ish filename or
#: a model directory) so the rule stays precise.
_TIER2_AMBIGUOUS_EXTS: frozenset[str] = frozenset({".bin", ".h5", ".hdf5"})

#: The safe formats the recommendation points at. Never flagged.
_SAFE_WEIGHT_EXTS: frozenset[str] = frozenset({
    ".safetensors", ".gguf", ".onnx",
})

#: A filename that reads like model weights, used to qualify a Tier-2
#: extension without a sibling config (``pytorch_model.bin``, ``model.h5``,
#: ``weights.bin``, ``checkpoint.bin``).
_MODELISH_NAME_RE = re.compile(
    r"model|weights|ckpt|checkpoint|pytorch", re.IGNORECASE,
)


def unsafe_weight_ext(name: str, *, in_model_dir: bool) -> str | None:
    """Return the flagged extension of *name*, or ``None``.

    A Tier-1 extension (:data:`_TIER1_UNSAFE_EXTS`) is flagged on its own.
    A Tier-2 extension (:data:`_TIER2_AMBIGUOUS_EXTS`) is flagged only with
    model context: a model-ish filename or a file that sits in a directory
    holding a model config / Modelfile (*in_model_dir*).
    """
    dot = name.rfind(".")
    if dot < 0:
        return None
    ext = name[dot:].lower()
    if ext in _TIER1_UNSAFE_EXTS:
        return ext
    if ext in _TIER2_AMBIGUOUS_EXTS and (
        in_model_dir or _MODELISH_NAME_RE.search(name)
    ):
        return ext
    return None

#: Directories never worth walking for a vendored model config.
_SKIP_DIRS: frozenset[str] = frozenset({
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    "dist", "build", ".tox", "site-packages", ".mypy_cache",
})


def is_hf_model_config(data: Any) -> bool:
    """True when *data* looks like a transformers model ``config.json``."""
    return isinstance(data, dict) and any(
        k in data for k in _HF_CONFIG_MARKERS
    )


def config_custom_code(data: dict[str, Any]) -> list[str]:
    """Return the custom-code class references in a config's ``auto_map``.

    ``auto_map`` maps transformers auto-classes to ``module.ClassName``
    entries that live in the *model repo's own* Python (``modeling_*.py``,
    ``configuration_*.py``). Loading the model with ``trust_remote_code=
    True`` imports and runs that code. Returns the referenced targets
    (the module-qualified names), or ``[]`` when there is no ``auto_map``.
    """
    auto_map = data.get("auto_map")
    if not isinstance(auto_map, dict):
        return []
    out: list[str] = []
    for value in auto_map.values():
        # A value is either ``"module.Class"`` or a list of such.
        if isinstance(value, str) and value.strip():
            out.append(value)
        elif isinstance(value, list):
            out.extend(v for v in value if isinstance(v, str) and v.strip())
    return out


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


def _is_modelfile_name(name: str) -> bool:
    low = name.lower()
    return (
        low == "modelfile"
        or low.endswith(".modelfile")
        or low.startswith("modelfile.")
    )


def _skipped_dir(p: Path) -> bool:
    """True when *p* lives under a directory not worth scanning."""
    return any(part in _SKIP_DIRS for part in p.parts)


class ModelfileContext:
    """Loaded model declarations: Ollama Modelfiles + vendored HF configs."""

    def __init__(
        self,
        modelfiles: list[Modelfile],
        model_configs: list[ModelConfig] | None = None,
        weight_blobs: list[WeightBlob] | None = None,
        root: str = ".",
    ) -> None:
        self.modelfiles = modelfiles
        self.model_configs = model_configs or []
        self.weight_blobs = weight_blobs or []
        #: The scanned path, used as the resource for tree-wide findings
        #: (MODEL-006) that aren't tied to a single parsed document.
        self.root = root
        self.files_scanned: int = len(modelfiles) + len(self.model_configs)
        self.files_skipped: int = 0
        self.warnings: list[str] = []

    @classmethod
    def from_path(cls, path: str | Path) -> ModelfileContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--modelfile-path {root} does not exist. Pass a Modelfile, "
                "a model config.json, or a directory containing one."
            )
        if root.is_file():
            modelfile_paths = [root] if _is_modelfile_name(root.name) else []
            config_paths = [root] if root.name.lower() == "config.json" else []
            # A single file passed that is neither name is still treated as a
            # Modelfile (the explicit-path escape hatch).
            if not modelfile_paths and not config_paths:
                modelfile_paths = [root]
        else:
            modelfile_paths = sorted(
                p for p in root.rglob("*")
                if p.is_file() and _is_modelfile_name(p.name)
                and not _skipped_dir(p)
            )
            config_paths = sorted(
                p for p in root.rglob("config.json")
                if p.is_file() and not _skipped_dir(p)
            )
        modelfiles: list[Modelfile] = []
        model_configs: list[ModelConfig] = []
        warnings: list[str] = []
        skipped = 0
        for f in modelfile_paths:
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
        for f in config_paths:
            try:
                text = f.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                warnings.append(f"{f}: read error: {exc}")
                skipped += 1
                continue
            try:
                data = json.loads(text)
            except (json.JSONDecodeError, RecursionError, MemoryError):
                skipped += 1
                continue
            # Only keep configs that look like a transformers model config,
            # so an unrelated ``config.json`` isn't treated as a model.
            if not is_hf_model_config(data):
                skipped += 1
                continue
            model_configs.append(ModelConfig(path=str(f), data=data))
        # Third pass: committed weight blobs in a code-executing format,
        # anywhere in the tree, independent of any Modelfile reference.
        # A Tier-2 (ambiguous) extension qualifies when it sits in a
        # directory that also holds a model config or Modelfile.
        model_dirs = (
            {Path(mc.path).parent for mc in model_configs}
            | {Path(mf.path).parent for mf in modelfiles}
        )
        if root.is_file():
            weight_candidates = [root]
        else:
            weight_candidates = [
                p for p in root.rglob("*")
                if p.is_file() and not _skipped_dir(p)
            ]
        weight_blobs: list[WeightBlob] = []
        for p in sorted(weight_candidates):
            ext = unsafe_weight_ext(p.name, in_model_dir=p.parent in model_dirs)
            if ext is not None:
                weight_blobs.append(WeightBlob(path=str(p), ext=ext))
        ctx = cls(modelfiles, model_configs, weight_blobs, root=str(root))
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
    # A hub pull (``hf.co/org/model.gguf``) carries a weights extension too,
    # so the hub classification has to win or the ext match misreads a remote
    # pull as a local file (suppressing MODEL-001, false-firing MODEL-003).
    if ref_is_hub(ref):
        return False
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
    "Directive", "ModelConfig", "Modelfile", "ModelfileBaseCheck",
    "ModelfileContext", "WeightBlob", "adapter_refs", "config_custom_code",
    "from_refs", "is_hf_model_config", "iter_directives", "parse_modelfile",
    "ref_is_hub", "ref_is_local", "ref_tag", "unsafe_weight_ext",
]
