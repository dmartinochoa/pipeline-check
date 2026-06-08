"""GitLab CI context and base check.

The context loads one or more ``.gitlab-ci.yml`` documents from disk and
exposes them as parsed dicts. Checks subclass :class:`GitLabBaseCheck`
and iterate ``self.ctx.pipelines``.

Local ``include:`` directives are resolved at load time so cross-job
rules (TAINT-008 ``extends:`` taint, GL-002 script injection across
hidden template jobs) see jobs and variables defined in included
files. When ``--resolve-remote`` is on, the provider's ``post_filter``
also fetches ``remote:`` / ``project:`` / ``template:`` /
``component:`` includes via the GitLab API and merges them into the
pipeline document. When off, those directives are surfaced as
warnings so the operator knows their scan was incomplete.
"""
from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from .._yaml_files import load_yaml_files
from .._yaml_lines import safe_load_yaml_lines  # still used by the include resolver
from ..base import BaseCheck

if TYPE_CHECKING:
    from .resolver import GitLabIncludeFetcher

logger = logging.getLogger(__name__)

#: Maximum ``include:`` resolution depth. GitLab itself caps at 100
#: but in practice CI repos rarely exceed 3-4 levels; keeping the cap
#: tight protects against runaway recursion when a bug or pathological
#: repo creates effectively-cyclic include graphs that visited-set
#: detection misses (e.g. via symlinked siblings).
_INCLUDE_MAX_DEPTH = 10

# Top-level keys that are *not* jobs. Anything else at the root is a job.
# https://docs.gitlab.com/ee/ci/yaml/
TOPLEVEL_KEYWORDS: set[str] = {
    "default", "include", "stages", "variables", "workflow",
    "image", "services", "cache", "before_script", "after_script",
    "pages",
}


@dataclass(frozen=True, slots=True)
class Pipeline:
    """A parsed GitLab CI document."""

    path: str
    data: dict[str, Any]
    resolved_includes: tuple[str, ...] = ()


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
        # The "scan root" is the user-supplied ``--gitlab-path`` (or its
        # parent if a single file was passed). Used for two purposes by
        # the include resolver:
        #   1. anchor leading-`/` paths to it (matching GitLab's
        #      "full path relative to the repository root" semantics),
        #   2. reject any resolved include path outside it
        #      (path-traversal protection: a malicious
        #      ``.gitlab-ci.yml`` in an untrusted repo can't make the
        #      scanner read ``../../../etc/passwd``).
        scan_root = (root if root.is_dir() else root.parent).resolve()
        loaded, warnings, skipped = load_yaml_files(files)
        pipelines: list[Pipeline] = []
        for entry in loaded:
            data = entry.docs[0]
            if not isinstance(data, dict):
                continue
            # Resolve local ``include:`` directives so cross-job rules
            # see jobs / variables defined in included files. The
            # ``include:`` block itself is preserved in the merged data
            # so include-pinning rules (GL-005, GL-011, GL-030) still
            # see the original directive.
            data, include_warnings = _resolve_local_includes(
                data,
                base_dir=entry.path.resolve().parent,
                scan_root=scan_root,
            )
            warnings.extend(f"{entry.path}: {w}" for w in include_warnings)
            pipelines.append(Pipeline(path=str(entry.path), data=data))
        ctx = cls(pipelines)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


class GitLabBaseCheck(BaseCheck[GitLabContext]):
    """Base class for GitLab CI checks."""

    PROVIDER = "gitlab"

    def __init__(self, ctx: GitLabContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: GitLabContext = ctx


def _resolve_local_includes(
    data: dict[str, Any],
    *,
    base_dir: Path,
    scan_root: Path,
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

    Path resolution rules:

    - Paths starting with ``/`` are anchored to *scan_root* (the
      ``--gitlab-path`` value passed by the user, or its parent when
      a single file was passed). Matches GitLab's "full path relative
      to the repository root" semantics.
    - Other paths resolve relative to the file currently being merged
      (*base_dir*).
    - After resolution, every include path must be a descendant of
      *scan_root*. Includes that escape via ``..`` traversal are
      rejected with a warning rather than read, so a malicious
      ``.gitlab-ci.yml`` in an untrusted repo can't make the scanner
      read arbitrary host files.

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

        # Anchor leading-`/` paths to the fixed scan root (GitLab's
        # repo-root-relative semantics); other paths resolve against
        # the current file's directory. ``scan_root`` is fixed across
        # the recursion so a deep include can still address a sibling
        # of the entry file via a `/`-prefixed reference, matching
        # what GitLab itself does.
        if ref.startswith("/"):
            anchor = scan_root
        else:
            anchor = base_dir
        ref_path = (anchor / ref.lstrip("/")).resolve()

        # Path-traversal guard: a malicious ``.gitlab-ci.yml`` in an
        # untrusted repo could try ``include: '../../../etc/passwd'``
        # to make the scanner read arbitrary host files. Reject any
        # resolved path that escapes the scan root before opening it.
        try:
            ref_path.relative_to(scan_root)
        except ValueError:
            warnings.append(
                f"include path escapes scan root, refused: {ref_path} "
                f"(scan root: {scan_root})"
            )
            continue

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
        except (yaml.YAMLError, RecursionError, MemoryError) as exc:
            first_line = str(exc).split("\n", 1)[0]
            warnings.append(f"include parse error: {ref_path}: {first_line}")
            continue
        if not isinstance(included, dict):
            continue

        # Recurse into the included file's own includes before merging
        # so transitively-included keys also flow up. ``scan_root``
        # stays fixed across the recursion; ``base_dir`` updates so
        # relative refs in the included file resolve against its own
        # directory.
        included, sub_warnings = _resolve_local_includes(
            included,
            base_dir=ref_path.parent,
            scan_root=scan_root,
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


def _resolve_remote_includes(
    data: dict[str, Any],
    *,
    fetcher: GitLabIncludeFetcher,
    scan_root: Path | None = None,
    visited_remote: frozenset[str] = frozenset(),
    depth: int = 0,
) -> tuple[dict[str, Any], list[str]]:
    """Fetch and merge remote ``include:`` directives into *data*.

    Called from ``GitLabProvider.post_filter()`` when
    ``--resolve-remote`` is on. Handles ``project:``, ``remote:``,
    ``template:``, and ``component:`` include types. Local includes are
    already resolved at this point so they are skipped.

    Merge semantics match ``_resolve_local_includes()``: parent keys win
    on conflict, the ``include:`` block is preserved for pinning rules.

    Fetched documents are recursively resolved for their own remote
    includes (up to :data:`_INCLUDE_MAX_DEPTH`) and for local includes
    when *scan_root* is provided.
    """
    warnings: list[str] = []
    if depth > _INCLUDE_MAX_DEPTH:
        warnings.append(
            f"remote include depth limit {_INCLUDE_MAX_DEPTH} exceeded"
        )
        return data, warnings

    include_block = data.get("include")
    if include_block is None:
        return data, warnings

    items = (
        include_block if isinstance(include_block, list) else [include_block]
    )
    resolved_keys: list[str] = []

    for item in items:
        if isinstance(item, str):
            continue
        if not isinstance(item, dict):
            continue
        if item.get("local") is not None:
            continue

        kind = next(
            (k for k in ("project", "remote", "template", "component")
             if k in item),
            None,
        )
        if kind is None:
            continue

        canonical = _canonical_include_id(kind, item)
        if canonical in visited_remote:
            warnings.append(f"remote include cycle detected: {canonical}")
            continue

        raw = fetcher.fetch(kind, item)
        if raw is None:
            warnings.append(
                f"remote include fetch failed: {kind}:"
                f"{item.get(kind, '?')}"
            )
            continue

        if isinstance(raw, bytes):
            text = raw.decode("utf-8", errors="replace")
        else:
            text = str(raw)

        try:
            included = safe_load_yaml_lines(text)
        except (yaml.YAMLError, RecursionError, MemoryError) as exc:
            first_line = str(exc).split("\n", 1)[0]
            warnings.append(
                f"remote include parse error ({kind}:"
                f"{item.get(kind, '?')}): {first_line}"
            )
            continue
        if not isinstance(included, dict):
            continue

        next_visited = visited_remote | {canonical}

        # Recurse: the fetched document may itself have remote includes.
        included, sub_warnings = _resolve_remote_includes(
            included,
            fetcher=fetcher,
            scan_root=scan_root,
            visited_remote=next_visited,
            depth=depth + 1,
        )
        warnings.extend(sub_warnings)

        # If the fetched doc has local includes and we have a scan root,
        # resolve those too.
        if scan_root is not None and included.get("include"):
            included, local_warnings = _resolve_local_includes(
                included,
                base_dir=scan_root,
                scan_root=scan_root,
                depth=depth + 1,
            )
            warnings.extend(local_warnings)

        resolved_keys.append(canonical)

        for key, value in included.items():
            if key == "include":
                continue
            if key not in data:
                data[key] = value

    return data, warnings


def _canonical_include_id(kind: str, spec: dict[str, Any]) -> str:
    """Stable identifier for cycle detection across remote includes."""
    if kind == "project":
        return (
            f"project:{spec.get('project', '')}:"
            f"{spec.get('file', '')}@{spec.get('ref', 'HEAD')}"
        )
    if kind == "remote":
        return f"remote:{spec.get('remote', '')}"
    if kind == "template":
        return f"template:{spec.get('template', '')}"
    if kind == "component":
        return f"component:{spec.get('component', '')}"
    return f"{kind}:{spec}"


def iter_jobs(pipeline: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield ``(job_name, job_dict)`` for every job in a GitLab CI doc."""
    for name, value in pipeline.items():
        if not isinstance(name, str):
            continue
        if name in TOPLEVEL_KEYWORDS:
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
