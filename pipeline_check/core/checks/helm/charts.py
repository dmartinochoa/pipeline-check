"""Per-chart metadata loaded straight from disk (not via ``helm template``).

The render pipeline at :mod:`pipeline_check.core.checks.helm.render` runs
``helm template`` and feeds the resulting Kubernetes YAML into the
existing K8s rule pack. That is the right shape for "do my workloads
follow K8s posture rules" but it discards the chart's own supply-chain
surface, ``Chart.yaml`` (apiVersion, dependencies, repositories) and
``Chart.lock`` (per-dependency digests) never appear in the rendered
output. Helm-native rules need the raw chart files.

This module reads ``Chart.yaml`` and ``Chart.lock`` from each chart
directory and attaches them to the :class:`HelmContext` as
:class:`Chart` records, alongside the rendered manifests. ``.tgz``
charts are unpacked transparently by Helm at render time, but for the
purposes of HELM-* rules we read their ``Chart.yaml`` straight from
the archive, same metadata, no shell-out required.

The parser is deliberately lenient: a chart whose ``Chart.yaml`` won't
parse lands in ``ctx.warnings`` and is skipped, so a single broken
chart in a multi-chart parent dir doesn't sink the whole scan.
"""
from __future__ import annotations

import io
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True, slots=True)
class Chart:
    """One Helm chart's on-disk metadata.

    ``chart_yaml`` is the parsed ``Chart.yaml`` (always present —
    a chart without one wouldn't have been picked up in the first
    place). ``chart_lock`` is the parsed ``Chart.lock`` if present,
    or ``None`` for charts that don't declare dependencies (and so
    don't need a lock file). ``path`` is the on-disk location of the
    chart directory or ``.tgz``; ``chart_yaml_path`` is the specific
    ``Chart.yaml`` file used for the parse, which reporters can quote
    in finding locations.
    """

    path: str
    chart_yaml_path: str
    chart_yaml: dict[str, Any]
    chart_lock_path: str | None = None
    chart_lock: dict[str, Any] | None = None
    #: Parsed ``values.yaml`` (chart defaults) + its path, read for
    #: HELM-016 (a default secret baked into shipped values). Empty
    #: dict / ``None`` when the chart ships no ``values.yaml``.
    values: dict[str, Any] = field(default_factory=dict)
    values_path: str | None = None
    #: Chart ``templates/`` files as ``(display_path, text)`` pairs,
    #: read for HELM-017 (``tpl`` of an untrusted value). Empty when the
    #: chart has no readable ``templates/``.
    templates: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    #: Free-form per-chart warnings captured during parse (e.g. a
    #: ``Chart.lock`` that exists but won't parse). Surfaced through
    #: the scanner's warning channel without aborting the scan.
    parse_warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def name(self) -> str:
        n = self.chart_yaml.get("name")
        return n if isinstance(n, str) and n.strip() else Path(self.path).name

    @property
    def api_version(self) -> str | None:
        v = self.chart_yaml.get("apiVersion")
        return v if isinstance(v, str) else None

    @property
    def dependencies(self) -> list[dict[str, Any]]:
        """Parsed ``dependencies:`` list, or empty.

        Helm 3 charts (``apiVersion: v2``) declare deps in
        ``Chart.yaml`` directly. Helm 2 charts (``apiVersion: v1``)
        used a sibling ``requirements.yaml``. We only read v2 deps
        here. HELM-001 catches the v1 shape outright, so its
        dependencies are intentionally not walked.
        """
        deps = self.chart_yaml.get("dependencies")
        if not isinstance(deps, list):
            return []
        return [d for d in deps if isinstance(d, dict)]


def parse_chart(path: str | Path) -> Chart | None:
    """Read ``Chart.yaml`` (+ optional ``Chart.lock``) at *path*.

    *path* is either a directory containing ``Chart.yaml`` or a
    packaged ``.tgz``. Returns ``None`` (not a raise) for inputs
    without a parseable ``Chart.yaml``, caller decides whether to
    warn or silently skip.
    """
    p = Path(path)
    if p.is_file() and p.suffix.lower() == ".tgz":
        return _parse_tgz(p)
    if p.is_dir():
        return _parse_dir(p)
    return None


def _parse_dir(chart_dir: Path) -> Chart | None:
    chart_yaml_path = chart_dir / "Chart.yaml"
    if not chart_yaml_path.is_file():
        return None
    warnings: list[str] = []
    chart_yaml = _read_yaml(chart_yaml_path, warnings)
    if chart_yaml is None:
        return None

    lock_path = chart_dir / "Chart.lock"
    chart_lock: dict[str, Any] | None = None
    chart_lock_path: str | None = None
    if lock_path.is_file():
        parsed = _read_yaml(lock_path, warnings)
        if parsed is not None:
            chart_lock = parsed
            chart_lock_path = str(lock_path)

    values: dict[str, Any] = {}
    values_path: str | None = None
    values_file = chart_dir / "values.yaml"
    if values_file.is_file():
        parsed_v = _read_yaml(values_file, warnings)
        if parsed_v is not None:
            values = parsed_v
            values_path = str(values_file)

    return Chart(
        path=str(chart_dir),
        chart_yaml_path=str(chart_yaml_path),
        chart_yaml=chart_yaml,
        chart_lock_path=chart_lock_path,
        chart_lock=chart_lock,
        values=values,
        values_path=values_path,
        templates=_read_dir_templates(chart_dir / "templates"),
        parse_warnings=tuple(warnings),
    )


def _parse_tgz(tgz_path: Path) -> Chart | None:
    """Read ``Chart.yaml`` / ``Chart.lock`` from a packaged chart.

    ``helm package`` lays the archive out as
    ``<chart-name>/Chart.yaml`` etc., exactly one top-level directory.
    We read only those two files; subchart archives nested under
    ``<chart-name>/charts/`` are intentionally not walked here (their
    metadata follows them when the parent is rendered, and HELM-*
    rules score the parent chart's posture, not bundled subcharts).
    """
    warnings: list[str] = []
    try:
        with tarfile.open(tgz_path, mode="r:gz") as tar:
            chart_yaml_member = _find_top_level(tar, "Chart.yaml")
            if chart_yaml_member is None:
                return None
            chart_yaml = _yaml_from_tar(tar, chart_yaml_member, warnings)
            if chart_yaml is None:
                return None
            lock_member = _find_top_level(tar, "Chart.lock")
            chart_lock: dict[str, Any] | None = None
            chart_lock_path: str | None = None
            if lock_member is not None:
                parsed = _yaml_from_tar(tar, lock_member, warnings)
                if parsed is not None:
                    chart_lock = parsed
                    chart_lock_path = (
                        f"{tgz_path}!{lock_member.name}"
                    )
            values: dict[str, Any] = {}
            values_path: str | None = None
            values_member = _find_top_level(tar, "values.yaml")
            if values_member is not None:
                parsed_v = _yaml_from_tar(tar, values_member, warnings)
                if parsed_v is not None:
                    values = parsed_v
                    values_path = f"{tgz_path}!{values_member.name}"
            templates = _read_tgz_templates(tar, str(tgz_path), warnings)
    except (tarfile.TarError, OSError) as exc:
        warnings.append(f"{tgz_path}: tar read error: {exc}")
        return None

    return Chart(
        path=str(tgz_path),
        chart_yaml_path=f"{tgz_path}!{chart_yaml_member.name}",
        chart_yaml=chart_yaml,
        chart_lock_path=chart_lock_path,
        chart_lock=chart_lock,
        values=values,
        values_path=values_path,
        templates=templates,
        parse_warnings=tuple(warnings),
    )


def _find_top_level(
    tar: tarfile.TarFile, leaf: str,
) -> tarfile.TarInfo | None:
    """Return ``<top-dir>/<leaf>`` from the archive, if present.

    A packaged chart's archive has exactly one top-level directory.
    We don't enforce that, just return the first match for
    ``*/<leaf>`` whose path has exactly two components.
    """
    for member in tar.getmembers():
        if not member.isfile():
            continue
        parts = member.name.split("/")
        if len(parts) == 2 and parts[1] == leaf:
            return member
    return None


_MAX_TAR_MEMBER_BYTES = 10 * 1024 * 1024  # 10 MB decompression-bomb guard


def _yaml_from_tar(
    tar: tarfile.TarFile,
    member: tarfile.TarInfo,
    warnings: list[str],
) -> dict[str, Any] | None:
    if member.size > _MAX_TAR_MEMBER_BYTES:
        warnings.append(
            f"{member.name}: skipped (uncompressed size "
            f"{member.size:,} exceeds {_MAX_TAR_MEMBER_BYTES:,} byte limit)"
        )
        return None
    try:
        fobj = tar.extractfile(member)
        if fobj is None:
            return None
        raw = fobj.read(_MAX_TAR_MEMBER_BYTES + 1)
        if len(raw) > _MAX_TAR_MEMBER_BYTES:
            warnings.append(f"{member.name}: decompressed size exceeds limit")
            return None
    except (KeyError, OSError) as exc:
        warnings.append(f"{member.name}: read error: {exc}")
        return None
    return _parse_yaml_text(member.name, raw, warnings)


def _read_yaml(
    path: Path, warnings: list[str],
) -> dict[str, Any] | None:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        warnings.append(f"{path}: read error: {exc}")
        return None
    return _parse_yaml_text(str(path), raw, warnings)


def _parse_yaml_text(
    label: str, raw: bytes | str, warnings: list[str],
) -> dict[str, Any] | None:
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
    try:
        doc = yaml.safe_load(io.StringIO(text))
    except yaml.YAMLError as exc:
        first = str(exc).split("\n", 1)[0]
        warnings.append(f"{label}: YAML parse error: {first}")
        return None
    if doc is None:
        # Empty Chart.lock or Chart.yaml, treat as parseable-but-empty.
        return {}
    if not isinstance(doc, dict):
        warnings.append(
            f"{label}: expected a YAML mapping at the top level, "
            f"got {type(doc).__name__}"
        )
        return None
    return doc


#: Template file suffixes Helm renders. ``.tpl`` (helper partials) and
#: ``.txt`` (NOTES.txt) are included since both can carry a ``tpl`` call.
_TEMPLATE_SUFFIXES: tuple[str, ...] = (".yaml", ".yml", ".tpl", ".txt")


def _read_dir_templates(tdir: Path) -> tuple[tuple[str, str], ...]:
    """Read every rendered template file under *tdir* as
    ``(display_path, text)``. Binary / unknown files and read errors
    are skipped per-file rather than failing the chart load."""
    if not tdir.is_dir():
        return ()
    out: list[tuple[str, str]] = []
    for p in sorted(tdir.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in _TEMPLATE_SUFFIXES:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        out.append((str(p), text))
    return tuple(out)


def _read_tgz_templates(
    tar: tarfile.TarFile, tgz_path: str, warnings: list[str],
) -> tuple[tuple[str, str], ...]:
    """Read ``<top>/templates/...`` text members from a packaged chart
    as ``(display_path, text)``, bounded by the per-member size cap."""
    out: list[tuple[str, str]] = []
    for member in tar.getmembers():
        if not member.isfile():
            continue
        parts = member.name.split("/")
        if len(parts) < 3 or parts[1] != "templates":
            continue
        if Path(member.name).suffix.lower() not in _TEMPLATE_SUFFIXES:
            continue
        if member.size > _MAX_TAR_MEMBER_BYTES:
            warnings.append(f"{member.name}: skipped (exceeds size limit)")
            continue
        try:
            fobj = tar.extractfile(member)
            if fobj is None:
                continue
            raw = fobj.read(_MAX_TAR_MEMBER_BYTES + 1)
        except (KeyError, OSError):
            continue
        out.append((
            f"{tgz_path}!{member.name}",
            raw.decode("utf-8", errors="replace"),
        ))
    return tuple(out)


__all__ = ["Chart", "parse_chart"]
