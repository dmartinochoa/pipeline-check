"""Go modules context and base check.

Parses ``go.mod`` (Go module manifest) and ``go.sum`` (Go module
integrity manifest) documents on disk and exposes typed views to
per-rule modules. Mirrors the npm / Maven / PyPI / NuGet context
shape: one context per scan, one rule module per check, the
orchestrator runs every rule against every loaded file.

Parser scope
------------
``go.mod`` is a structured text format defined at
https://go.dev/ref/mod#go-mod-file. The parser handles:

* ``module <module-path>``         (required, exactly one)
* ``go <version>``                 (toolchain minimum, optional)
* ``toolchain <name>``             (explicit toolchain pin, optional)
* ``require <path> <version>``    (single-line + block form)
* ``require ( <path> <version> ... )``  (block form)
* ``replace <orig> => <new> <ver>``     (single + block form)
* ``replace <orig> <ver> => <new> <ver>``
* ``exclude <path> <version>``
* ``// indirect`` markers on require lines

``go.sum`` is a flat line list of
``<module> <version> <h1:hash=>`` triples plus matching
``/go.mod`` hash lines. The presence / absence of the file is the
load-bearing signal for GOMOD-001 (integrity manifest missing);
the hash payloads themselves aren't audited (the consumer's
``go mod verify`` does that).

Comments (``// ...``) are stripped during parsing; blank lines
are ignored.
"""
from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..base import BaseCheck

#: Manifest filename. ``go.mod`` is the canonical Go module
#: descriptor.
MANIFEST_NAMES: frozenset[str] = frozenset({"go.mod"})
#: Integrity manifest filename. Required for reproducible builds;
#: GOMOD-001 fires when ``go.mod`` is present but ``go.sum`` is not.
SUMFILE_NAMES: frozenset[str] = frozenset({"go.sum"})


# ── Module dataclasses ────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class GoRequire:
    """One ``require`` directive entry."""

    path: str
    version: str
    indirect: bool = False
    line_no: int = 1


@dataclass(frozen=True, slots=True)
class GoReplace:
    """One ``replace`` directive entry.

    ``orig_version`` is set when the source side carries an explicit
    version (``replace foo v1.2.3 => bar v1.2.4``); ``None`` when
    the replacement applies to every version of ``orig_path``.

    ``new_version`` is set when the target side is another module
    coordinate; ``None`` when ``new_path`` resolves to a local
    filesystem path (``=> ../local/copy`` / ``=> ./vendor``).
    """

    orig_path: str
    orig_version: str | None
    new_path: str
    new_version: str | None
    line_no: int = 1

    @property
    def is_local(self) -> bool:
        """``True`` when the replacement is a local filesystem path."""
        # ``go mod`` treats anything starting with ``./``, ``../``, ``/``
        # or a Windows drive letter as a directory replacement;
        # everything else is interpreted as a module path.
        if not self.new_path:
            return False
        if self.new_version is not None:
            return False
        if self.new_path.startswith(("./", "../", "/")):
            return True
        # Windows absolute path. ``go`` itself supports these.
        if (
            len(self.new_path) >= 3
            and self.new_path[1:3] == ":\\"
            and self.new_path[0].isalpha()
        ):
            return True
        return False

    @property
    def substitutes_different_module(self) -> bool:
        """``True`` when the replacement points at a different module
        coordinate. Same-module replacements (version pin overrides,
        toolchain workarounds) are a legitimate posture; cross-module
        replacements substitute a different upstream, which is the
        supply-chain concern."""
        if self.is_local:
            return False
        if not self.new_path:
            return False
        return self.new_path != self.orig_path


@dataclass(frozen=True, slots=True)
class GoExclude:
    """One ``exclude`` directive entry."""

    path: str
    version: str
    line_no: int = 1


@dataclass(frozen=True, slots=True)
class GoModFile:
    """A parsed ``go.mod`` document."""

    path: str
    text: str
    module_path: str
    #: ``go`` directive value, e.g. ``"1.21"`` or ``"1.22.4"``. Empty
    #: string when the directive is absent.
    go_version: str
    #: ``toolchain`` directive value, e.g. ``"go1.22.4"``. Empty when
    #: absent.
    toolchain: str
    requires: tuple[GoRequire, ...] = field(default_factory=tuple)
    replaces: tuple[GoReplace, ...] = field(default_factory=tuple)
    excludes: tuple[GoExclude, ...] = field(default_factory=tuple)
    #: ``True`` when the document parsed without raising. ``False`` on
    #: unrecoverable malformed input.
    parsed_ok: bool = True
    #: ``True`` when a sibling ``go.sum`` was found in the same
    #: directory. GOMOD-001 reads this flag.
    has_sumfile: bool = False
    #: Path of the sibling ``go.sum`` when present, else ``None``.
    sumfile_path: str | None = None


class GoModContext:
    """Loaded set of ``go.mod`` documents."""

    def __init__(self, files: list[GoModFile]) -> None:
        self.files = files
        self.files_scanned: int = len(files)
        self.files_skipped: int = 0
        self.warnings: list[str] = []
        #: Reserved for future ``--resolve-remote`` extensions
        #: (publish-time table for cooldown / OSV results). Default
        #: empty so rules can compile without touching it.
        self.publish_times: dict[str, dict[str, _dt.datetime]] = {}
        self.osv_advisories: dict[tuple[str, str], list[Any]] = {}

    @classmethod
    def from_path(cls, path: str | Path) -> GoModContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--gomod-path {root} does not exist. Pass a go.mod "
                "file or a directory containing one."
            )
        if root.is_file():
            candidates = [root]
        else:
            candidates = sorted(
                p for p in root.rglob("go.mod")
                if p.is_file()
                # Skip vendored copies / build outputs.
                and "vendor" not in p.parts
                and ".git" not in p.parts
            )
        files: list[GoModFile] = []
        warnings: list[str] = []
        skipped = 0
        for f in candidates:
            try:
                text = f.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                warnings.append(f"{f}: read error: {exc}")
                skipped += 1
                continue
            pf = _parse_gomod(str(f), text)
            if not pf.parsed_ok:
                warnings.append(f"{f}: go.mod parse error")
                skipped += 1
                continue
            # Probe for the sibling go.sum so GOMOD-001 can flag the
            # missing-integrity-manifest case without a second pass.
            sibling_sum = f.parent / "go.sum"
            has_sum = sibling_sum.is_file()
            files.append(GoModFile(
                path=pf.path, text=pf.text,
                module_path=pf.module_path,
                go_version=pf.go_version,
                toolchain=pf.toolchain,
                requires=pf.requires,
                replaces=pf.replaces,
                excludes=pf.excludes,
                parsed_ok=pf.parsed_ok,
                has_sumfile=has_sum,
                sumfile_path=str(sibling_sum) if has_sum else None,
            ))
        ctx = cls(files)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


class GoModBaseCheck(BaseCheck[GoModContext]):
    """Base class for Go modules rule modules."""

    PROVIDER = "gomod"

    def __init__(
        self, ctx: GoModContext, target: str | None = None,
    ) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: GoModContext = ctx


# ── Parser ────────────────────────────────────────────────────────


#: Tokens that terminate the simple identifier in a ``require`` /
#: ``replace`` line. The Go grammar uses whitespace.
_COMMENT_RE = re.compile(r"//.*$", re.MULTILINE)
#: Block-open: ``require (`` / ``replace (`` / ``exclude (``.
_BLOCK_OPEN_RE = re.compile(
    r"^(require|replace|exclude)\s*\(\s*$"
)
#: Block-close: ``)`` on its own line.
_BLOCK_CLOSE_RE = re.compile(r"^\s*\)\s*$")


def _parse_gomod(path: str, text: str) -> GoModFile:
    """Parse a ``go.mod`` body into a :class:`GoModFile`.

    The parser is intentionally tolerant: malformed lines are
    skipped without raising so a single typo doesn't drop the
    whole file. The ``parsed_ok`` flag turns ``False`` only when the
    required ``module`` directive is missing or unparseable.
    """
    module_path = ""
    go_version = ""
    toolchain = ""
    requires: list[GoRequire] = []
    replaces: list[GoReplace] = []
    excludes: list[GoExclude] = []

    in_block: str | None = None
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = _COMMENT_RE.sub("", raw_line).rstrip()
        # Preserve the original raw_line for indirect-detection (the
        # ``// indirect`` marker lives in the comment we just
        # stripped); detect it on the raw form.
        is_indirect = "// indirect" in raw_line
        stripped = line.strip()
        if not stripped:
            continue

        if in_block is None:
            if m := _BLOCK_OPEN_RE.match(stripped):
                in_block = m.group(1)
                continue
            # Single-line directive forms.
            if stripped.startswith("module "):
                module_path = stripped[len("module "):].strip().strip('"')
                continue
            if stripped.startswith("go "):
                go_version = stripped[len("go "):].strip()
                continue
            if stripped.startswith("toolchain "):
                toolchain = stripped[len("toolchain "):].strip()
                continue
            if stripped.startswith("require "):
                if entry := _parse_require_line(
                    stripped[len("require "):], line_no, is_indirect,
                ):
                    requires.append(entry)
                continue
            if stripped.startswith("replace "):
                if entry_r := _parse_replace_line(
                    stripped[len("replace "):], line_no,
                ):
                    replaces.append(entry_r)
                continue
            if stripped.startswith("exclude "):
                if entry_e := _parse_exclude_line(
                    stripped[len("exclude "):], line_no,
                ):
                    excludes.append(entry_e)
                continue
        else:
            if _BLOCK_CLOSE_RE.match(stripped):
                in_block = None
                continue
            if in_block == "require":
                if entry := _parse_require_line(
                    stripped, line_no, is_indirect,
                ):
                    requires.append(entry)
            elif in_block == "replace":
                if entry_r := _parse_replace_line(stripped, line_no):
                    replaces.append(entry_r)
            elif in_block == "exclude":
                if entry_e := _parse_exclude_line(stripped, line_no):
                    excludes.append(entry_e)

    parsed_ok = bool(module_path)
    return GoModFile(
        path=path, text=text, module_path=module_path,
        go_version=go_version, toolchain=toolchain,
        requires=tuple(requires),
        replaces=tuple(replaces),
        excludes=tuple(excludes),
        parsed_ok=parsed_ok,
    )


def _parse_require_line(
    body: str, line_no: int, indirect: bool,
) -> GoRequire | None:
    tokens = body.split()
    if len(tokens) < 2:
        return None
    return GoRequire(
        path=tokens[0], version=tokens[1],
        indirect=indirect, line_no=line_no,
    )


def _parse_replace_line(
    body: str, line_no: int,
) -> GoReplace | None:
    if "=>" not in body:
        return None
    left, right = body.split("=>", 1)
    left_tokens = left.strip().split()
    right_tokens = right.strip().split()
    if not left_tokens or not right_tokens:
        return None
    orig_path = left_tokens[0]
    orig_version = left_tokens[1] if len(left_tokens) >= 2 else None
    new_path = right_tokens[0]
    new_version = right_tokens[1] if len(right_tokens) >= 2 else None
    return GoReplace(
        orig_path=orig_path,
        orig_version=orig_version,
        new_path=new_path,
        new_version=new_version,
        line_no=line_no,
    )


def _parse_exclude_line(
    body: str, line_no: int,
) -> GoExclude | None:
    tokens = body.split()
    if len(tokens) < 2:
        return None
    return GoExclude(
        path=tokens[0], version=tokens[1], line_no=line_no,
    )


# ── Helpers exposed to rule modules ───────────────────────────────


_INCOMPATIBLE_SUFFIX = "+incompatible"


def is_incompatible_version(version: str) -> bool:
    """Return ``True`` when ``version`` carries the ``+incompatible``
    suffix used by Go for pre-modules-adoption tags.

    The suffix signals that the module was published with a
    ``v2+`` tag without the corresponding ``/v2`` import path
    suffix. Go modules accept these for backward compatibility but
    they bypass several module-system guarantees (no semantic
    import versioning, no major-version isolation), which is the
    posture risk GOMOD-004 flags.
    """
    return version.endswith(_INCOMPATIBLE_SUFFIX)


def iter_direct_requires(pom: GoModFile) -> "list[GoRequire]":
    """Return only direct requires (``// indirect`` filtered out).

    Indirect requires are transitive deps the Go tool added to the
    manifest for reproducibility; auditing them as part of the
    direct-dep posture (cooldowns, advisories) double-counts
    transitive paths and is a known FP class.
    """
    return [r for r in pom.requires if not r.indirect]
