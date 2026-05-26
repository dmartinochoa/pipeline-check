"""GitHub Actions context and base check.

The context loads every ``*.yml`` / ``*.yaml`` document under a
``.github/workflows/`` directory and exposes them as parsed dicts. Checks
subclass :class:`GitHubBaseCheck` and iterate ``self.ctx.workflows``.
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .._yaml_files import load_yaml_files
from .._yaml_lines import line_of as _line_of
from ..base import BaseCheck, Location

if TYPE_CHECKING:
    from ._action_reputation import ActionRepoMetadata


@dataclass(frozen=True, slots=True)
class Workflow:
    """A parsed GitHub Actions workflow document.

    The default-empty fields below populate when the document was
    pulled in by the remote-ref resolver. ``caller_path`` points at
    the on-disk caller; ``source_ref`` carries the
    ``owner/repo/path.yml@ref`` that produced this body. Rules that
    care about the call context read these.

    ``inherited_permissions`` and ``inherited_secret_names`` capture
    what the caller was willing to share with the callee. They mirror
    runtime semantics: a reusable workflow without its own
    ``permissions:`` block runs with the caller's; ``secrets: inherit``
    on the call site exposes every caller-visible secret.
    """

    path: str   # relative path, used as the finding's resource handle
    data: dict[str, Any]
    #: For workflows pulled in by the resolver, the canonical
    #: ``owner/repo/path.yml@ref`` that produced this body. ``None``
    #: for workflows loaded directly from disk.
    source_ref: str | None = None
    #: For resolved callees, the path of the caller workflow that
    #: triggered the resolution. Lets rules attribute findings back
    #: to the file under review rather than to a remote URL.
    caller_path: str | None = None
    #: Permissions block the caller declared. Either ``read-all`` /
    #: ``write-all`` (string) or a token-keyed dict. ``None`` means
    #: "caller didn't declare; runtime defaults apply."
    inherited_permissions: dict[str, Any] | str | None = None
    #: Secrets visible to this workflow because the caller passed
    #: ``secrets: inherit``. The set is the explicit names declared on
    #: the call site or in the caller's ``env``; an empty frozenset
    #: combined with ``inherits_secrets=True`` means "unknown universe
    #: of secrets" (org-level secrets aren't in the YAML).
    inherited_secret_names: frozenset[str] = frozenset()
    #: Whether the caller passed ``secrets: inherit`` (vs. an explicit
    #: secret-by-secret map). Distinct from
    #: ``inherited_secret_names`` being empty: an explicit empty map
    #: means no secrets crossed the boundary.
    inherits_secrets: bool = False
    #: Raw on-disk text of the workflow file, populated by
    #: :meth:`GitHubContext.from_path` so rules that need to read the
    #: pre-parse layer (YAML comments, line whitespace) can do so
    #: without re-opening the file. ``None`` for resolver-synthesized
    #: workflows (composite-action bodies, remote callees) whose
    #: source isn't a single on-disk file. Consumed by GHA-095
    #: (ref-version-mismatch) for the ``uses: o/r@<sha>  # vX.Y.Z``
    #: comment shape PyYAML strips during parsing.
    raw_text: str | None = None


class GitHubContext:
    """Loaded set of workflows from a ``.github/workflows`` directory."""

    def __init__(self, workflows: list[Workflow]) -> None:
        self.workflows = workflows
        self.files_scanned: int = len(workflows)
        self.files_skipped: int = 0
        self.warnings: list[str] = []
        #: Per-action GitHub-API metadata, populated lazily by the
        #: ``--resolve-remote`` path so the GHA-04x reputation rules
        #: (GHA-041 single-maintainer / GHA-042 very-young /
        #: GHA-043 low-star + sensitive-permission) have a dict to
        #: consume. Keyed by ``"owner/repo"`` (both lower-cased) to
        #: match :func:`collect_referenced_actions`. Empty when the
        #: opt-in flag isn't set; the reputation rules pass silently
        #: in that case rather than firing on missing data.
        self.action_metadata: dict[str, ActionRepoMetadata] = {}
        #: Action ``owner/repo`` slugs (lower-cased) whose repo-
        #: metadata fetch ran and came back empty. Most commonly a
        #: 404, the repojacking signal GHA-091 fires on. Populated by
        #: the same ``--resolve-remote`` path that fills
        #: :attr:`action_metadata`; an empty set means either the
        #: flag is off or every referenced action's fetch succeeded.
        self.action_fetch_failures: set[str] = set()

    @classmethod
    def from_path(cls, path: str | Path) -> GitHubContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--gha-path {root} does not exist. Pass the workflows "
                f"directory (typically .github/workflows)."
            )
        if root.is_file():
            files = [root]
        else:
            files = sorted(
                p for p in root.rglob("*")
                if p.is_file() and p.suffix.lower() in {".yml", ".yaml"}
            )
        loaded, warnings, skipped = load_yaml_files(files)
        workflows: list[Workflow] = []
        for entry in loaded:
            data = entry.docs[0]
            if not isinstance(data, dict):
                continue
            # Re-read the raw file text so rules that need to inspect
            # the pre-parse layer (YAML comments, the literal line
            # whitespace PyYAML strips on its way to a dict) have it
            # without re-opening per-rule. The file is still in OS
            # cache from ``load_yaml_files``; failures fall back to
            # ``None`` and the consuming rule treats that as
            # "raw layer unavailable" rather than raising.
            try:
                raw_text: str | None = entry.path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                raw_text = None
            workflows.append(
                Workflow(path=str(entry.path), data=data, raw_text=raw_text),
            )
        # Discover local composite actions referenced via
        # ``uses: ./path`` and synthesize them as ``__composite__``
        # job workflows so the rule pack runs against their bodies.
        # On by default (no network needed); inference falls back to
        # the directory's parent for ad-hoc test layouts.
        from .local_actions import (
            discover_local_composite_actions,
            infer_repo_root,
        )
        repo_root = infer_repo_root(root)
        if repo_root is not None:
            synthesized, action_warnings = discover_local_composite_actions(
                workflows, repo_root,
            )
            workflows.extend(synthesized)
            warnings.extend(action_warnings)
        ctx = cls(workflows)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


class GitHubBaseCheck(BaseCheck[GitHubContext]):
    """Base class for GitHub Actions workflow checks."""

    PROVIDER = "github"

    def __init__(self, ctx: GitHubContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: GitHubContext = ctx


def iter_jobs(workflow: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield ``(job_id, job_dict)`` for every job in a workflow."""
    jobs = workflow.get("jobs") or {}
    if isinstance(jobs, dict):
        for job_id, job in jobs.items():
            if isinstance(job, dict):
                yield job_id, job


def iter_steps(job: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield every step dict from a job."""
    steps = job.get("steps") or []
    if isinstance(steps, list):
        for step in steps:
            if isinstance(step, dict):
                yield step


def step_location(path: str, step: dict[str, Any]) -> Location:
    """Build a :class:`Location` for *step* in *path*.

    Falls back to a path-only location when the loader didn't preserve
    line markers (defensive for non-line-aware test loaders).
    """
    line = _line_of(step)
    return Location(path=path, start_line=line, end_line=line)


def job_location(path: str, job: dict[str, Any]) -> Location:
    """Build a :class:`Location` for *job* in *path*."""
    line = _line_of(job)
    return Location(path=path, start_line=line, end_line=line)


def effective_permissions(
    workflow: dict[str, Any],
    inherited: dict[str, Any] | str | None = None,
) -> dict[str, Any] | str | None:
    """Return the permissions block that *runtime* sees for this workflow.

    A workflow's own ``permissions:`` always wins; only when it's
    absent does the caller's block apply (this matches GitHub's
    runtime semantics for reusable workflows). For top-level scans
    this is just the workflow's own ``permissions:``.
    """
    own = workflow.get("permissions")
    if own is not None:
        return own  # type: ignore[no-any-return]
    return inherited


def workflow_triggers(workflow: dict[str, Any]) -> list[str]:
    """Return the list of event names this workflow is triggered by.

    GitHub's ``on:`` field can be a string, a list, or a mapping. Any boolean
    ``True`` yielded by ``safe_load`` for a bareword ``on`` key (which YAML
    1.1 parses as a boolean) is also normalized here, ``workflow["on"]``
    becomes ``workflow[True]`` under YAML 1.1 semantics.
    """
    on = workflow.get("on")
    if on is None:
        # YAML 1.1 parses bare ``on:`` as the boolean ``True``. The
        # ``workflow`` dict is typed ``dict[str, Any]``, but PyYAML may
        # populate it with a ``True`` key in this corner case.
        # ``cast`` widens the key type just for this lookup so mypy
        # accepts it.
        from typing import cast
        wf_any: dict[Any, Any] = cast("dict[Any, Any]", workflow)
        on = wf_any.get(True)
    if on is None:
        return []
    if isinstance(on, str):
        return [on]
    if isinstance(on, list):
        return [str(v) for v in on]
    if isinstance(on, dict):
        return [str(k) for k in on.keys()]
    return []
