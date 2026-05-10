"""GitLab CI context and base check.

The context loads one or more ``.gitlab-ci.yml`` documents from disk and
exposes them as parsed dicts. Checks subclass :class:`GitLabBaseCheck`
and iterate ``self.ctx.pipelines``.

Local ``include:`` directives are resolved at load time so cross-job
rules (TAINT-008 ``extends:`` taint, GL-002 script injection across
hidden template jobs) see jobs and variables defined in included
files. Resolution is local-only (no network); ``include: { remote:
}`` / ``project:`` / ``template:`` directives are surfaced as
warnings so the operator knows their scan was incomplete.
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .._yaml_lines import safe_load_yaml_lines
from ..base import BaseCheck

#: Maximum ``include:`` resolution depth. GitLab itself caps at 100
#: but in practice CI repos rarely exceed 3-4 levels; keeping the cap
#: tight protects against runaway recursion when a bug or pathological
#: repo creates effectively-cyclic include graphs that visited-set
#: detection misses (e.g. via symlinked siblings).
_INCLUDE_MAX_DEPTH = 10

# Top-level keys that are *not* jobs. Anything else at the root is a job.
# https://docs.gitlab.com/ee/ci/yaml/
_TOPLEVEL_KEYWORDS: set[str] = {
    "default", "include", "stages", "variables", "workflow",
    "image", "services", "cache", "before_script", "after_script",
    "pages",
}


@dataclass(frozen=True, slots=True)
class Pipeline:
    """A parsed GitLab CI document."""

    path: str
    data: dict[str, Any]


class GitLabContext:
    """Loaded set of GitLab CI YAML documents."""

    def __init__(self, pipelines: list[Pipeline]) -> None:
        self.pipelines = pipelines
        self.files_scanned: int = len(pipelines)
        self.files_skipped: int = 0
        self.warnings: list[str] = []

    @classmethod
    def from_path(cls, path: str | Path) -> GitLabContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--gitlab-path {root} does not exist. Pass a .gitlab-ci.yml "
                f"file or a directory containing one."
            )
        if root.is_file():
            files = [root]
        else:
            files = sorted(
                p for p in root.rglob("*")
                if p.is_file() and p.name in {".gitlab-ci.yml", ".gitlab-ci.yaml"}
            )
            if not files:
                # fall back to any yaml under the directory (e.g. included files)
                files = sorted(
                    p for p in root.rglob("*")
                    if p.is_file() and p.suffix.lower() in {".yml", ".yaml"}
                )
        pipelines: list[Pipeline] = []
        warnings: list[str] = []
        skipped = 0
        for f in files:
            try:
                text = f.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                warnings.append(f"{f}: read error: {exc}")
                skipped += 1
                continue
            try:
                data = safe_load_yaml_lines(text)
            except yaml.YAMLError as exc:
                first_line = str(exc).split("\n", 1)[0]
                warnings.append(f"{f}: YAML parse error: {first_line}")
                skipped += 1
                continue
            if not isinstance(data, dict):
                continue
            # Resolve local ``include:`` directives so cross-job rules
            # see jobs / variables defined in included files. The
            # ``include:`` block itself is preserved in the merged data
            # so include-pinning rules (GL-005, GL-011, GL-030) still
            # see the original directive.
            data, include_warnings = _resolve_local_includes(
                data, base_dir=f.resolve().parent,
            )
            warnings.extend(f"{f}: {w}" for w in include_warnings)
            pipelines.append(Pipeline(path=str(f), data=data))
        ctx = cls(pipelines)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


class GitLabBaseCheck(BaseCheck):
    """Base class for GitLab CI checks."""

    PROVIDER = "gitlab"

    def __init__(self, ctx: GitLabContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: GitLabContext = ctx


def _resolve_local_includes(
    data: dict[str, Any],
    *,
    base_dir: Path,
    visited: frozenset[Path] = frozenset(),
    depth: int = 0,
) -> tuple[dict[str, Any], list[str]]:
    """Recursively merge local ``include:`` files into *data*.

    Returns ``(merged_data, warnings)``. The returned dict is a shallow
    copy of *data* augmented with top-level keys from every transitively-
    included file. Parent keys win on conflict (matches GitLab's
    "the consumer overrides the include" semantics for jobs).

    Supported include forms:

    - ``include: foo.yml``            (bare string, local path)
    - ``include: [a.yml, b.yml]``     (list of bare strings)
    - ``include: { local: foo.yml }`` (dict with ``local:`` key)
    - ``include: [{local: a}, ...]``  (list of dicts)

    Other forms (``remote:``, ``project:``, ``template:``,
    ``component:``) are surfaced as warnings so the operator knows
    the scan ignored a directive. Network resolution is deliberately
    out of scope, the scanner is a no-token, no-network tool.

    Cycle detection: a *visited* set of resolved file paths is
    threaded through the recursion. Re-entering a path emits a
    warning and stops the descent at that branch.

    Depth cap: :data:`_INCLUDE_MAX_DEPTH` (10). Pathological repos
    that survive the visited check (e.g. via symlinks the resolve
    can't normalize) still terminate.
    """
    warnings: list[str] = []
    if depth > _INCLUDE_MAX_DEPTH:
        warnings.append(
            f"include depth limit {_INCLUDE_MAX_DEPTH} exceeded; further "
            f"includes were not resolved"
        )
        return data, warnings

    include_block = data.get("include")
    if include_block is None:
        return data, warnings

    items = (
        include_block if isinstance(include_block, list) else [include_block]
    )
    # Mutate *data* in place rather than copying, so the line-aware
    # ``LineDict`` subclass and its per-key source-position metadata
    # (used by every ``Location``-emitting GitLab rule) are preserved.
    # Copying via ``dict(data)`` would yield a plain dict and silently
    # break line precision for every cross-file rule.
    for item in items:
        ref: str | None = None
        if isinstance(item, str):
            ref = item
        elif isinstance(item, dict):
            local_ref = item.get("local")
            if local_ref is None:
                kind = next(
                    (k for k in ("remote", "project", "template", "component")
                     if k in item),
                    "?",
                )
                warnings.append(
                    f"include type {kind!r} not supported (only 'local:' is "
                    f"resolved offline); the included content was not merged"
                )
                continue
            if isinstance(local_ref, str):
                ref = local_ref
        if ref is None:
            continue

        # GitLab paths starting with '/' are repo-root-relative. Without
        # a known repo root, treat them as relative to base_dir; that
        # preserves prior behavior where the scanner can't always
        # locate the git root from --gitlab-path.
        ref_path = (base_dir / ref.lstrip("/")).resolve()

        if ref_path in visited:
            warnings.append(f"include cycle detected at {ref_path}")
            continue
        if not ref_path.is_file():
            warnings.append(f"include not found: {ref_path}")
            continue

        try:
            text = ref_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            warnings.append(f"include read error: {ref_path}: {exc}")
            continue
        try:
            included = safe_load_yaml_lines(text)
        except yaml.YAMLError as exc:
            first_line = str(exc).split("\n", 1)[0]
            warnings.append(f"include parse error: {ref_path}: {first_line}")
            continue
        if not isinstance(included, dict):
            continue

        # Recurse into the included file's own includes before merging
        # so transitively-included keys also flow up.
        included, sub_warnings = _resolve_local_includes(
            included,
            base_dir=ref_path.parent,
            visited=visited | {ref_path},
            depth=depth + 1,
        )
        warnings.extend(sub_warnings)

        # Parent wins on conflict; only pull in keys the parent doesn't
        # already define. Keeps the parent's ``include:`` block intact
        # so include-pinning rules (GL-005, GL-011, GL-030) still see
        # the original directive.
        for key, value in included.items():
            if key == "include":
                # Don't merge the included file's own include block
                # into the parent; we already followed its references
                # via the recursive call above.
                continue
            if key not in data:
                data[key] = value

    return data, warnings


def iter_jobs(pipeline: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield ``(job_name, job_dict)`` for every job in a GitLab CI doc."""
    for name, value in pipeline.items():
        if not isinstance(name, str):
            continue
        if name in _TOPLEVEL_KEYWORDS:
            continue
        if name.startswith("."):  # hidden / template job
            continue
        if isinstance(value, dict):
            yield name, value


def job_scripts(job: dict[str, Any]) -> list[str]:
    """Return a flat list of every script line across before_script / script / after_script."""
    lines: list[str] = []
    for key in ("before_script", "script", "after_script"):
        v = job.get(key)
        if isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    lines.append(item)
        elif isinstance(v, str):
            lines.append(v)
    return lines
