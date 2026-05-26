"""NuGet context and base check.

Loads ``*.csproj``, ``Directory.Packages.props``, ``packages.config``,
``NuGet.config``, and ``packages.lock.json`` from disk and exposes
parsed objects to per-rule modules. XML parsing uses
``xml.etree.ElementTree`` (same as the Maven provider) and is
intentionally tolerant: malformed files become warnings, not exceptions.
"""
from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..base import BaseCheck

_SKIP_DIRS = frozenset({"bin", "obj", ".nuget", "node_modules", ".git"})

_MSBUILD_NS = re.compile(r"^\{[^}]+\}")

_MAX_XML_BYTES = 10 * 1024 * 1024  # 10 MB — reject oversized files


def _strip_ns(tag: str) -> str:
    return _MSBUILD_NS.sub("", tag)


def _safe_parse_xml(path: Path) -> ET.ElementTree:
    """Parse XML with a size guard against oversized files."""
    if path.stat().st_size > _MAX_XML_BYTES:
        raise ValueError(f"file exceeds {_MAX_XML_BYTES} byte limit")
    return ET.parse(path)  # noqa: S314


# ── Dataclasses ─────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class NuGetPackageRef:
    name: str
    version: str | None
    line_no: int = 1


@dataclass(frozen=True, slots=True)
class NuGetProject:
    path: str
    package_refs: tuple[NuGetPackageRef, ...] = ()
    is_central_managed: bool = False


@dataclass(frozen=True, slots=True)
class NuGetSource:
    name: str
    url: str


@dataclass(frozen=True, slots=True)
class NuGetSourceMapping:
    source: str
    patterns: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NuGetConfig:
    path: str
    sources: tuple[NuGetSource, ...] = ()
    source_mappings: tuple[NuGetSourceMapping, ...] = ()


@dataclass(frozen=True, slots=True)
class NuGetLock:
    path: str
    packages: dict[str, str] = field(default_factory=dict)


# ── Context ─────────────────────────────────────────────────────────────


class NuGetContext:
    """Parsed view of NuGet project files in a directory tree."""

    def __init__(
        self,
        projects: list[NuGetProject],
        configs: list[NuGetConfig],
        locks: list[NuGetLock],
        *,
        files_scanned: int = 0,
        files_skipped: int = 0,
        warnings: list[str] | None = None,
    ) -> None:
        self.projects = projects
        self.configs = configs
        self.locks = locks
        self.files_scanned = files_scanned
        self.files_skipped = files_skipped
        self.warnings: list[str] = warnings or []
        self.publish_times: dict[str, dict[str, Any]] = {}
        self.osv_advisories: dict[tuple[str, str], list[Any]] = {}

    @classmethod
    def from_path(cls, path: str | Path) -> NuGetContext:
        root = Path(path)
        projects: list[NuGetProject] = []
        configs: list[NuGetConfig] = []
        locks: list[NuGetLock] = []
        warnings: list[str] = []
        scanned = 0
        skipped = 0

        central_props = _find_central_props(root)
        central_versions: dict[str, str] = {}
        if central_props is not None:
            try:
                central_versions = _parse_central_props(central_props)
                scanned += 1
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"{central_props}: XML parse error: {exc}")
                skipped += 1

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            rel_dir = Path(dirpath)
            for fname in filenames:
                fpath = rel_dir / fname
                try:
                    rel = os.path.relpath(fpath, root).replace("\\", "/")
                except ValueError:
                    rel = str(fpath).replace("\\", "/")
                flow = fname.lower()
                try:
                    if flow.endswith(".csproj"):
                        projects.append(_parse_csproj(
                            fpath, rel, central_versions,
                        ))
                        scanned += 1
                    elif flow == "packages.config":
                        projects.append(_parse_packages_config(fpath, rel))
                        scanned += 1
                    elif flow in ("nuget.config",):
                        configs.append(_parse_nuget_config(fpath, rel))
                        scanned += 1
                    elif flow == "packages.lock.json":
                        locks.append(_parse_lock_json(fpath, rel))
                        scanned += 1
                except Exception as exc:  # noqa: BLE001
                    warnings.append(f"{rel}: parse error: {exc}")
                    skipped += 1

        return cls(
            projects, configs, locks,
            files_scanned=scanned, files_skipped=skipped,
            warnings=warnings,
        )


# ── XML parsers ─────────────────────────────────────────────────────────


def _find_central_props(root: Path) -> Path | None:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            if fname == "Directory.Packages.props":
                return Path(dirpath) / fname
    return None


def _parse_central_props(path: Path) -> dict[str, str]:
    tree = _safe_parse_xml(path)
    versions: dict[str, str] = {}
    for elem in tree.iter():
        tag = _strip_ns(elem.tag)
        if tag == "PackageVersion":
            name = elem.get("Include") or elem.get("include") or ""
            version = elem.get("Version") or elem.get("version")
            if name and version:
                versions[name.lower()] = version
    return versions


def _parse_csproj(
    path: Path, rel: str, central_versions: dict[str, str],
) -> NuGetProject:
    tree = _safe_parse_xml(path)
    refs: list[NuGetPackageRef] = []
    for elem in tree.iter():
        tag = _strip_ns(elem.tag)
        if tag == "PackageReference":
            name = elem.get("Include") or elem.get("include") or ""
            version = elem.get("Version") or elem.get("version")
            if not version:
                version = central_versions.get(name.lower())
            if name:
                refs.append(NuGetPackageRef(name=name, version=version))
    return NuGetProject(
        path=rel,
        package_refs=tuple(refs),
        is_central_managed=bool(central_versions),
    )


def _parse_packages_config(path: Path, rel: str) -> NuGetProject:
    tree = _safe_parse_xml(path)
    refs: list[NuGetPackageRef] = []
    for elem in tree.iter():
        tag = _strip_ns(elem.tag)
        if tag == "package":
            name = elem.get("id") or ""
            version = elem.get("version")
            if name:
                refs.append(NuGetPackageRef(name=name, version=version))
    return NuGetProject(path=rel, package_refs=tuple(refs))


def _parse_nuget_config(path: Path, rel: str) -> NuGetConfig:
    tree = _safe_parse_xml(path)
    sources: list[NuGetSource] = []
    mappings: list[NuGetSourceMapping] = []
    for elem in tree.iter():
        tag = _strip_ns(elem.tag)
        if tag == "packageSources":
            for child in elem:
                if _strip_ns(child.tag) == "add":
                    key = child.get("key") or ""
                    value = child.get("value") or ""
                    if key and value:
                        sources.append(NuGetSource(name=key, url=value))
        elif tag == "packageSourceMapping":
            for src_elem in elem:
                if _strip_ns(src_elem.tag) == "packageSource":
                    src_key = src_elem.get("key") or ""
                    patterns: list[str] = []
                    for pkg in src_elem:
                        if _strip_ns(pkg.tag) == "package":
                            pat = pkg.get("pattern") or ""
                            if pat:
                                patterns.append(pat)
                    if src_key and patterns:
                        mappings.append(NuGetSourceMapping(
                            source=src_key,
                            patterns=tuple(patterns),
                        ))
    return NuGetConfig(
        path=rel, sources=tuple(sources),
        source_mappings=tuple(mappings),
    )


def _parse_lock_json(path: Path, rel: str) -> NuGetLock:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        return NuGetLock(path=rel, packages={})
    packages: dict[str, str] = {}
    deps = data.get("dependencies", {})
    for _framework, framework_deps in deps.items():
        if not isinstance(framework_deps, dict):
            continue
        for pkg_name, pkg_info in framework_deps.items():
            if isinstance(pkg_info, dict):
                resolved = pkg_info.get("resolved")
                if isinstance(resolved, str):
                    packages[pkg_name] = resolved
    return NuGetLock(path=rel, packages=packages)


# ── Base check ──────────────────────────────────────────────────────────


class NuGetBaseCheck(BaseCheck[NuGetContext]):
    PROVIDER = "nuget"

    def __init__(self, ctx: NuGetContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: NuGetContext = ctx
