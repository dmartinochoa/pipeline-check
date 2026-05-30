"""Cargo (Rust) modules context and base check.

Parses ``Cargo.toml`` (Cargo manifest) and probes for the sibling
``Cargo.lock`` (Cargo's integrity manifest). Mirrors the Maven / npm /
PyPI / NuGet / Go-modules pack shape: one context per scan, one rule
module per check, the orchestrator runs every rule against every
loaded file.

Parser scope
------------
The TOML stdlib parser handles the manifest format directly. The rule
pack only consumes the dependency tables; workspace-only manifests
(``[workspace]`` parents with no per-crate ``[package]``) load with
empty dep lists, which is the correct behavior since rules iterating
``dependencies`` short-circuit.

Dependency tables audited:

* ``[dependencies]``
* ``[dev-dependencies]``
* ``[build-dependencies]``
* ``[target.<target>.dependencies]`` (target-specific entries)

Each entry shape is normalized to a :class:`CargoDependency`:

* short form: ``name = "1.2.3"`` -> ``version="1.2.3"``
* long form: ``name = { version = "1.2", features = [...] }``
* git form:  ``name = { git = "https://...", rev = "abc" }``
* path form: ``name = { path = "../local" }``
* registry form: ``name = { registry = "myregistry", version = "1.0" }``

Variables / workspace inheritance (``workspace = true``) are surfaced
on the dataclass but not resolved against the parent manifest, the
rule pack treats workspace-inherited entries as opaque and the
operator audits the workspace root separately.
"""
from __future__ import annotations

import datetime as _dt
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..base import BaseCheck

#: Cargo manifest filename. ``Cargo.toml`` is the canonical descriptor.
MANIFEST_NAMES: frozenset[str] = frozenset({"Cargo.toml"})
#: Cargo integrity manifest filename. Required for reproducible builds;
#: CARGO-003 fires when the manifest is present but the lockfile is not
#: (and the crate is an executable / library that should ship one).
LOCKFILE_NAMES: frozenset[str] = frozenset({"Cargo.lock"})


# ── Module dataclasses ────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class CargoDependency:
    """One declared dependency entry."""

    name: str
    #: Section the dependency was declared under (``dependencies`` /
    #: ``dev-dependencies`` / ``build-dependencies`` / ``target.<...>``).
    section: str
    #: Version specifier when present. May be a caret-prefixed range
    #: (``"1.2"`` is shorthand for ``"^1.2"``), an exact pin
    #: (``"=1.2.3"``), a wildcard (``"*"`` / ``"1.*"``), or a comparison
    #: (``">=1.2, <2"``). ``None`` when the entry omits the version
    #: (git / path forms).
    version: str | None
    #: ``True`` when the entry sets ``git = "https://..."``.
    is_git: bool = False
    #: ``True`` when the entry sets ``path = "..."``.
    is_path: bool = False
    #: Git ref pin (``rev``) when the dep is git-sourced. Empty when
    #: the entry uses ``branch`` / ``tag`` / no spec (mutable refs).
    git_rev: str = ""
    #: ``True`` when the git entry pins to a mutable ref
    #: (``branch`` / ``tag`` / unspecified). CARGO-002's failure
    #: signal.
    git_mutable: bool = False
    #: Non-default registry name when ``registry = "..."`` is set.
    #: Empty string for the default registry (crates.io).
    registry: str = ""
    #: ``True`` when the entry was inherited from the workspace root
    #: via ``workspace = true``. Surfaced for documentation; not
    #: audited directly.
    from_workspace: bool = False
    line_no: int = 1

    @property
    def coordinate(self) -> str:
        v = self.version or (
            f"git:{self.git_rev or '<mutable>'}" if self.is_git
            else "path" if self.is_path
            else "<unspecified>"
        )
        return f"{self.name} {v}"


@dataclass(frozen=True, slots=True)
class CargoFile:
    """A parsed ``Cargo.toml`` document."""

    path: str
    text: str
    #: ``[package].name``, empty for workspace-only manifests.
    crate_name: str
    dependencies: tuple[CargoDependency, ...] = field(default_factory=tuple)
    #: ``True`` when the document parsed without raising.
    parsed_ok: bool = True
    #: ``True`` when the sibling ``Cargo.lock`` was found at scan time.
    has_lockfile: bool = False
    lockfile_path: str | None = None
    #: ``True`` for workspace-root manifests (have ``[workspace]``,
    #: lack ``[package]``). Rules that audit per-crate posture
    #: (CARGO-003 missing-lockfile) skip workspace roots since the
    #: lockfile lives at the workspace root, not the per-crate
    #: manifest.
    is_workspace_root: bool = False
    #: Raw ``Cargo.lock`` body when present (CARGO-013 reads the
    #: ``[[package]]`` ``source`` entries). Empty when absent.
    lockfile_text: str = ""
    #: Sibling ``build.rs`` path + body when present (CARGO-011 reads
    #: the compile-time egress / exec idioms).
    build_rs_path: str | None = None
    build_rs_text: str = ""
    #: Nearest ``.cargo/config.toml`` path + parsed body, discovered by
    #: walking up to the scan root (CARGO-012 audits the
    #: source-replacement + build-flag keys). Empty when absent.
    cargo_config_path: str | None = None
    cargo_config: dict[str, Any] = field(default_factory=dict)


class CargoContext:
    """Loaded set of ``Cargo.toml`` documents."""

    def __init__(self, files: list[CargoFile]) -> None:
        self.files = files
        self.files_scanned: int = len(files)
        self.files_skipped: int = 0
        self.warnings: list[str] = []
        #: Reserved for future ``--resolve-remote`` extensions.
        self.publish_times: dict[str, dict[str, _dt.datetime]] = {}
        self.osv_advisories: dict[tuple[str, str], list[Any]] = {}

    @classmethod
    def from_path(cls, path: str | Path) -> CargoContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--cargo-path {root} does not exist. Pass a Cargo.toml "
                "file or a directory containing one."
            )
        if root.is_file():
            candidates = [root]
        else:
            candidates = sorted(
                p for p in root.rglob("Cargo.toml")
                if p.is_file()
                and "target" not in p.parts
                and ".git" not in p.parts
            )
        scan_root = root if root.is_dir() else root.parent
        files: list[CargoFile] = []
        warnings: list[str] = []
        skipped = 0
        for f in candidates:
            try:
                text = f.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                warnings.append(f"{f}: read error: {exc}")
                skipped += 1
                continue
            pf = _parse_cargo(str(f), text)
            if not pf.parsed_ok:
                warnings.append(f"{f}: Cargo.toml parse error")
                skipped += 1
                continue
            # Probe for the sibling Cargo.lock so CARGO-003 can flag
            # missing-lockfile without a second pass. The lockfile may
            # also live at the workspace root one level up.
            sibling_lock = f.parent / "Cargo.lock"
            has_lock = sibling_lock.is_file()
            if not has_lock and f.parent != f.parent.parent:
                workspace_lock = f.parent.parent / "Cargo.lock"
                if workspace_lock.is_file():
                    has_lock = True
                    sibling_lock = workspace_lock
            lockfile_text = ""
            if has_lock:
                try:
                    lockfile_text = sibling_lock.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    pass
            build_rs_path: str | None = None
            build_rs_text = ""
            build_rs = f.parent / "build.rs"
            if build_rs.is_file():
                try:
                    build_rs_text = build_rs.read_text(encoding="utf-8")
                    build_rs_path = str(build_rs)
                except (OSError, UnicodeDecodeError):
                    pass
            cfg_path, cfg_data = _discover_cargo_config(f.parent, scan_root)
            files.append(CargoFile(
                path=pf.path, text=pf.text,
                crate_name=pf.crate_name,
                dependencies=pf.dependencies,
                parsed_ok=pf.parsed_ok,
                has_lockfile=has_lock,
                lockfile_path=str(sibling_lock) if has_lock else None,
                is_workspace_root=pf.is_workspace_root,
                lockfile_text=lockfile_text,
                build_rs_path=build_rs_path,
                build_rs_text=build_rs_text,
                cargo_config_path=cfg_path,
                cargo_config=cfg_data,
            ))
        ctx = cls(files)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


class CargoBaseCheck(BaseCheck[CargoContext]):
    """Base class for cargo rule modules."""

    PROVIDER = "cargo"

    def __init__(
        self, ctx: CargoContext, target: str | None = None,
    ) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: CargoContext = ctx


# ── Parser ────────────────────────────────────────────────────────


_SECTION_NAMES = (
    "dependencies",
    "dev-dependencies",
    "build-dependencies",
)


def _line_of(text: str, needle: str) -> int:
    """1-based line of the first occurrence of ``needle`` in ``text``.
    Returns 1 when not found so dataclass init succeeds even on a
    no-match (the parser still wires the entry; locations just point
    at the file header)."""
    idx = text.find(needle)
    if idx < 0:
        return 1
    return text[:idx].count("\n") + 1


def _normalize_dep(
    name: str, raw: Any, section: str, text: str,
) -> CargoDependency:
    """Translate one ``name = <value>`` entry into a
    :class:`CargoDependency`. ``raw`` may be:

    * a string (``"1.2.3"``) — short form, version-only.
    * a table (dict) — long form, may carry ``version`` / ``git`` /
      ``rev`` / ``path`` / ``registry`` / ``workspace`` keys.
    """
    line_no = _line_of(text, f"{name} ")
    if isinstance(raw, str):
        return CargoDependency(
            name=name, section=section, version=raw, line_no=line_no,
        )
    if not isinstance(raw, dict):
        return CargoDependency(
            name=name, section=section, version=None, line_no=line_no,
        )
    version = raw.get("version") if isinstance(raw.get("version"), str) else None
    is_git = bool(raw.get("git"))
    is_path = bool(raw.get("path"))
    git_rev = ""
    git_mutable = False
    if is_git:
        rev = raw.get("rev")
        branch = raw.get("branch")
        tag = raw.get("tag")
        if isinstance(rev, str) and rev:
            git_rev = rev
            git_mutable = False
        elif isinstance(branch, str) or isinstance(tag, str):
            git_mutable = True
        else:
            # No rev / branch / tag means "default branch HEAD", the
            # most mutable form.
            git_mutable = True
    registry = ""
    raw_reg = raw.get("registry")
    if isinstance(raw_reg, str) and raw_reg:
        registry = raw_reg
    from_workspace = bool(raw.get("workspace"))
    return CargoDependency(
        name=name, section=section, version=version,
        is_git=is_git, is_path=is_path,
        git_rev=git_rev, git_mutable=git_mutable,
        registry=registry, from_workspace=from_workspace,
        line_no=line_no,
    )


def _walk_dependency_sections(
    data: dict[str, Any], text: str,
) -> list[CargoDependency]:
    """Pull every dependency entry from a parsed Cargo.toml dict.

    Handles the three top-level sections plus the
    ``target.<target>.dependencies`` nested form. Workspace
    inheritance (``workspace.dependencies``) is captured under its
    own pseudo-section name for the surface but the rules consume it
    the same way (an audit on the workspace root manifest catches
    inherited deps).
    """
    out: list[CargoDependency] = []
    for section in _SECTION_NAMES:
        entries = data.get(section)
        if isinstance(entries, dict):
            for name, raw in entries.items():
                if isinstance(name, str):
                    out.append(_normalize_dep(name, raw, section, text))
    # Target-specific deps:
    #   [target.'cfg(unix)'.dependencies]
    targets = data.get("target")
    if isinstance(targets, dict):
        for target_name, body in targets.items():
            if not isinstance(body, dict):
                continue
            for section in _SECTION_NAMES:
                entries = body.get(section)
                if isinstance(entries, dict):
                    for name, raw in entries.items():
                        if isinstance(name, str):
                            out.append(_normalize_dep(
                                name, raw,
                                f"target.{target_name}.{section}",
                                text,
                            ))
    # Workspace root dependencies (``[workspace.dependencies]``):
    workspace = data.get("workspace")
    if isinstance(workspace, dict):
        for section in _SECTION_NAMES:
            entries = workspace.get(section)
            if isinstance(entries, dict):
                for name, raw in entries.items():
                    if isinstance(name, str):
                        out.append(_normalize_dep(
                            name, raw,
                            f"workspace.{section}", text,
                        ))
    return out


def _parse_cargo(path: str, text: str) -> CargoFile:
    """Parse a ``Cargo.toml`` body into a :class:`CargoFile`."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return CargoFile(
            path=path, text=text, crate_name="",
            parsed_ok=False,
        )
    crate_name = ""
    package = data.get("package")
    if isinstance(package, dict):
        name = package.get("name")
        if isinstance(name, str):
            crate_name = name
    is_workspace_root = (
        isinstance(data.get("workspace"), dict)
        and not isinstance(data.get("package"), dict)
    )
    deps = _walk_dependency_sections(data, text)
    return CargoFile(
        path=path, text=text, crate_name=crate_name,
        dependencies=tuple(deps), parsed_ok=True,
        is_workspace_root=is_workspace_root,
    )


def _discover_cargo_config(
    manifest_dir: Path, scan_root: Path,
) -> tuple[str | None, dict[str, Any]]:
    """Find and parse the nearest ``.cargo/config.toml`` (or the legacy
    ``.cargo/config``) at or above *manifest_dir*, bounded by
    *scan_root* so the walk never reads outside the scanned tree.

    Cargo searches the manifest directory and its ancestors for a
    ``.cargo/config.toml``; this replicates that walk but stops at the
    scan root (it never reads ``~/.cargo/config.toml`` or other
    out-of-tree ancestors, keeping the scanner hermetic). Returns
    ``(path, parsed_table)`` for the nearest config found, or
    ``(None, {})`` when none exists.
    """
    try:
        scan_resolved = scan_root.resolve()
        cur = manifest_dir.resolve()
    except OSError:
        return None, {}
    chain: list[Path] = []
    while True:
        chain.append(cur)
        if cur == scan_resolved:
            break
        parent = cur.parent
        if parent == cur:
            break
        try:
            parent.relative_to(scan_resolved)
        except ValueError:
            break
        cur = parent
    for d in chain:  # nearest-first
        for name in ("config.toml", "config"):
            cfg = d / ".cargo" / name
            if not cfg.is_file():
                continue
            try:
                data = tomllib.loads(cfg.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
                return str(cfg), {}
            return str(cfg), data if isinstance(data, dict) else {}
    return None, {}


# ── Helpers exposed to rule modules ───────────────────────────────


_EXACT_PIN_PREFIXES: frozenset[str] = frozenset({"=", "==v", "=v"})


def is_floating_version(spec: str) -> bool:
    """Return ``True`` when the version spec is floating per Cargo's
    semver model.

    Cargo's default behavior is "caret-equivalent": a bare ``"1.2.3"``
    is read as ``"^1.2.3"`` (any version >= 1.2.3 and < 2.0.0). The
    only specifiers that pin to an exact release are ``"=1.2.3"`` and
    explicit ``"=N.M.P"`` forms; everything else (caret, tilde,
    wildcard, comparison) is a floating range.

    This is the post-incident detection complement to a vendoring
    setup; the right operator response to a CARGO-001 hit is either
    to commit the Cargo.lock (CARGO-003) so the floating spec is
    pinned at build time, or to tighten the manifest to ``=X.Y.Z``.
    """
    s = spec.strip()
    if not s:
        return False
    # Exact pin: ``=1.2.3`` (or ``=v1.2.3``).
    if s.startswith("="):
        return False
    # Caret / tilde / comparison / wildcard / range all float.
    if s[0] in "^~><*":
        return True
    if "*" in s or "," in s or ">" in s or "<" in s:
        return True
    # Bare ``"1.2.3"`` is caret-equivalent => floating.
    return True
