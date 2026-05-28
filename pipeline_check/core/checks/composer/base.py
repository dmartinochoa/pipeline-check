"""Composer (PHP) modules context and base check.

Parses ``composer.json`` (Composer manifest) and probes for the
sibling ``composer.lock`` (Composer's integrity manifest). Mirrors
the npm / PyPI / Maven / NuGet / Go-modules / Cargo pack shape: one
context per scan, one rule module per check, the orchestrator runs
every rule against every loaded file.

Parser scope
------------
The JSON stdlib parser handles the manifest format directly. The
rule pack consumes the manifest top-level keys (``require``,
``require-dev``, ``scripts``, ``repositories``, ``minimum-stability``,
``config``) plus the lockfile presence probe. No registry pulls, no
``composer install``, no PHP runtime required.

Tables audited:

* ``require``      runtime dependencies
* ``require-dev``  test / build-time dependencies
* ``repositories`` extra package sources (Composer, VCS, path, etc.)
* ``scripts``      install / update lifecycle hooks
* ``config``       Composer behavior switches (``allow-plugins``,
                   ``secure-http``, ``minimum-stability``)

Each ``require`` entry shape is normalized to a
:class:`ComposerDependency`:

* ``"vendor/package": "^1.2"``
* ``"vendor/package": "~1.2"``
* ``"vendor/package": "1.2.*"``
* ``"vendor/package": "1.2.3"``
* ``"vendor/package": "dev-master"``
"""
from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..base import BaseCheck

#: Composer manifest filename. ``composer.json`` is the canonical
#: descriptor.
MANIFEST_NAMES: frozenset[str] = frozenset({"composer.json"})
#: Composer integrity manifest filename. Required for reproducible
#: install; COMPOSER-001 fires when the manifest is present but the
#: lockfile is not.
LOCKFILE_NAMES: frozenset[str] = frozenset({"composer.lock"})


# ── Module dataclasses ────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ComposerDependency:
    """One declared dependency entry."""

    name: str
    #: Section the dependency was declared under (``require`` /
    #: ``require-dev``).
    section: str
    #: Version constraint literal as it appears in the manifest. May
    #: be a caret-prefix range (``"^1.2"``), a tilde-prefix range
    #: (``"~1.2"``), an exact pin (``"1.2.3"``), a wildcard
    #: (``"1.2.*"`` / ``"*"``), or a dev branch alias
    #: (``"dev-master"`` / ``"dev-main"``).
    constraint: str
    line_no: int = 1

    @property
    def coordinate(self) -> str:
        return f"{self.name} {self.constraint}"


@dataclass(frozen=True, slots=True)
class ComposerRepository:
    """One ``repositories`` entry."""

    #: Repository type. Common values: ``composer``, ``vcs``,
    #: ``package``, ``path``, ``artifact``.
    type: str
    #: Repository URL. Empty for ``path`` / ``package`` types that
    #: have no URL.
    url: str = ""
    #: Raw entry preserved so rules that probe extra fields (e.g.
    #: ``reference`` on VCS entries) can read them.
    raw: dict[str, Any] = field(default_factory=dict)
    line_no: int = 1


@dataclass(frozen=True, slots=True)
class ComposerScript:
    """One ``scripts`` entry (one lifecycle hook)."""

    #: Hook name (``post-install-cmd``, ``pre-update-cmd``, custom).
    event: str
    #: Each command line as a separate string (Composer accepts a
    #: single string or an array of strings).
    commands: tuple[str, ...]
    line_no: int = 1


@dataclass(frozen=True, slots=True)
class ComposerFile:
    """A parsed ``composer.json`` document."""

    path: str
    text: str
    #: ``name`` field, empty when omitted.
    package_name: str
    dependencies: tuple[ComposerDependency, ...] = field(
        default_factory=tuple,
    )
    repositories: tuple[ComposerRepository, ...] = field(
        default_factory=tuple,
    )
    scripts: tuple[ComposerScript, ...] = field(default_factory=tuple)
    #: ``minimum-stability`` value, defaults to ``"stable"`` per
    #: Composer.
    minimum_stability: str = "stable"
    #: ``config`` table — opaque dict so rules can probe its keys
    #: directly.
    config: dict[str, Any] = field(default_factory=dict)
    #: ``True`` when the document parsed without raising.
    parsed_ok: bool = True
    #: ``True`` when the sibling ``composer.lock`` was found at scan
    #: time.
    has_lockfile: bool = False
    lockfile_path: str | None = None


class ComposerContext:
    """Loaded set of ``composer.json`` documents."""

    def __init__(self, files: list[ComposerFile]) -> None:
        self.files = files
        self.files_scanned: int = len(files)
        self.files_skipped: int = 0
        self.warnings: list[str] = []
        #: Reserved for future ``--resolve-remote`` extensions.
        self.publish_times: dict[str, dict[str, _dt.datetime]] = {}
        self.osv_advisories: dict[tuple[str, str], list[Any]] = {}

    @classmethod
    def from_path(cls, path: str | Path) -> ComposerContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--composer-path {root} does not exist. Pass a "
                "composer.json file or a directory containing one."
            )
        if root.is_file():
            candidates = [root]
        else:
            candidates = sorted(
                p for p in root.rglob("composer.json")
                if p.is_file()
                and "vendor" not in p.parts
                and ".git" not in p.parts
                and "node_modules" not in p.parts
            )
        files: list[ComposerFile] = []
        warnings: list[str] = []
        skipped = 0
        for f in candidates:
            try:
                text = f.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                warnings.append(f"{f}: read error: {exc}")
                skipped += 1
                continue
            pf = _parse_composer(str(f), text)
            if not pf.parsed_ok:
                warnings.append(f"{f}: composer.json parse error")
                skipped += 1
                continue
            sibling_lock = f.parent / "composer.lock"
            has_lock = sibling_lock.is_file()
            files.append(ComposerFile(
                path=pf.path, text=pf.text,
                package_name=pf.package_name,
                dependencies=pf.dependencies,
                repositories=pf.repositories,
                scripts=pf.scripts,
                minimum_stability=pf.minimum_stability,
                config=pf.config,
                parsed_ok=pf.parsed_ok,
                has_lockfile=has_lock,
                lockfile_path=str(sibling_lock) if has_lock else None,
            ))
        ctx = cls(files)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


class ComposerBaseCheck(BaseCheck[ComposerContext]):
    """Base class for composer rule modules."""

    PROVIDER = "composer"

    def __init__(
        self, ctx: ComposerContext, target: str | None = None,
    ) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: ComposerContext = ctx


# ── Parser ────────────────────────────────────────────────────────


def _line_of(text: str, needle: str) -> int:
    """1-based line of the first occurrence of ``needle`` in ``text``.
    Returns 1 when not found so dataclass init succeeds even on a
    no-match."""
    idx = text.find(needle)
    if idx < 0:
        return 1
    return text[:idx].count("\n") + 1


def _walk_dependencies(
    data: dict[str, Any], text: str,
) -> list[ComposerDependency]:
    out: list[ComposerDependency] = []
    for section in ("require", "require-dev"):
        entries = data.get(section)
        if not isinstance(entries, dict):
            continue
        for name, raw in entries.items():
            if not isinstance(name, str):
                continue
            if not isinstance(raw, str):
                continue
            out.append(ComposerDependency(
                name=name, section=section, constraint=raw,
                line_no=_line_of(text, f'"{name}"'),
            ))
    return out


def _walk_repositories(
    data: dict[str, Any], text: str,
) -> list[ComposerRepository]:
    out: list[ComposerRepository] = []
    repos = data.get("repositories")
    # Composer accepts either a list of repo objects or a dict
    # keyed by friendly name. Normalize both forms.
    if isinstance(repos, list):
        items: list[Any] = list(repos)
    elif isinstance(repos, dict):
        items = list(repos.values())
    else:
        return out
    for entry in items:
        if not isinstance(entry, dict):
            continue
        rtype = entry.get("type")
        if not isinstance(rtype, str):
            continue
        url = entry.get("url")
        url_s = url if isinstance(url, str) else ""
        needle = url_s or rtype
        out.append(ComposerRepository(
            type=rtype, url=url_s, raw=dict(entry),
            line_no=_line_of(text, f'"{needle}"') if needle else 1,
        ))
    return out


def _walk_scripts(
    data: dict[str, Any], text: str,
) -> list[ComposerScript]:
    out: list[ComposerScript] = []
    scripts = data.get("scripts")
    if not isinstance(scripts, dict):
        return out
    for event, body in scripts.items():
        if not isinstance(event, str):
            continue
        cmds: tuple[str, ...]
        if isinstance(body, str):
            cmds = (body,)
        elif isinstance(body, list):
            cmds = tuple(c for c in body if isinstance(c, str))
        else:
            cmds = ()
        if not cmds:
            continue
        out.append(ComposerScript(
            event=event, commands=cmds,
            line_no=_line_of(text, f'"{event}"'),
        ))
    return out


def _parse_composer(path: str, text: str) -> ComposerFile:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return ComposerFile(
            path=path, text=text, package_name="",
            parsed_ok=False,
        )
    if not isinstance(data, dict):
        return ComposerFile(
            path=path, text=text, package_name="",
            parsed_ok=False,
        )
    package_name = ""
    name = data.get("name")
    if isinstance(name, str):
        package_name = name
    min_stability = "stable"
    raw_ms = data.get("minimum-stability")
    if isinstance(raw_ms, str):
        min_stability = raw_ms
    config = data.get("config")
    config_d = config if isinstance(config, dict) else {}
    deps = _walk_dependencies(data, text)
    repos = _walk_repositories(data, text)
    scripts = _walk_scripts(data, text)
    return ComposerFile(
        path=path, text=text, package_name=package_name,
        dependencies=tuple(deps), repositories=tuple(repos),
        scripts=tuple(scripts), minimum_stability=min_stability,
        config=config_d, parsed_ok=True,
    )


# ── Helpers exposed to rule modules ───────────────────────────────


def is_floating_constraint(spec: str) -> bool:
    """Return ``True`` when the Composer version constraint floats.

    Composer constraints that resolve to a *range* of versions
    rather than a single release are floating. The exact-pin shapes
    are: a bare ``X.Y.Z`` semver triple with no operators, an
    explicit ``=X.Y.Z`` form, and a 40-char git commit hash. The
    floating shapes include the caret (``^1.2``), tilde (``~1.2``),
    wildcard (``1.2.*`` / ``*``), comparison operators
    (``>=1.2,<2``), and dev-branch aliases (``dev-master``,
    ``X.Y.x-dev``).

    The post-incident detection complement is to commit the
    composer.lock (COMPOSER-001) so the floating spec is pinned at
    install time.
    """
    s = spec.strip()
    if not s:
        return False
    if s.startswith("dev-") or s.endswith("-dev"):
        return True
    if s[0] in "^~><":
        return True
    if "*" in s or "," in s or "||" in s or " - " in s:
        return True
    # Allow leading ``=`` (rare, but explicit pin) or ``v`` prefix.
    body = s
    if body.startswith("="):
        body = body[1:].strip()
    if body[:1] in ("v", "V"):
        body = body[1:]
    # 40-char hex commit hash is an exact pin (rare via composer
    # but supported on VCS-backed entries with a ``#<sha>`` suffix
    # handled at the URL level).
    parts = body.split(".")
    if not parts:
        return True
    # An exact semver triple (or pair) with no operators counts as
    # pinned. Anything else (single number, range fragments) is
    # floating.
    for p in parts:
        if not p.isdigit():
            return True
    if len(parts) < 2:
        return True
    return False
