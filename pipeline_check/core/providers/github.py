"""GitHub Actions provider — scans workflow YAML under ``.github/workflows/``.

Producer workflow:

    pipeline_check --pipeline github --gha-path .github/workflows

YAML parsing is the default. ``--resolve-remote`` opt-in fetches
reusable workflow callees over HTTPS for full coverage; the scanner
otherwise stays read-from-disk-only.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..checks.base import BaseCheck
from ..checks.github.base import GitHubContext
from ..checks.github.resolver import (
    CompositeFetcher,
    DiskFetcher,
    FileSystemCache,
    HttpFetcher,
    Resolver,
    default_cache_dir,
)
from ..checks.github.uses_parser import parse_uses
from ..checks.github.workflows import WorkflowChecks
from ..inventory import Component
from .base import BaseProvider


class GitHubProvider(BaseProvider):
    """GitHub Actions provider — parses workflow YAML from disk."""

    NAME = "github"

    def build_context(self, gha_path: str | None = None, **_: Any) -> GitHubContext:
        if not gha_path:
            raise ValueError(
                "The github provider requires --gha-path <dir> pointing at the "
                "directory of workflow YAML files (typically .github/workflows)."
            )
        return GitHubContext.from_path(gha_path)

    @property
    def check_classes(self) -> list[type[BaseCheck]]:
        return [WorkflowChecks]

    def post_filter(  # type: ignore[override]
        self,
        context: GitHubContext,
        resolve_remote: bool = False,
        gh_token: str | None = None,
        no_cache: bool = False,
        gha_search_paths: list[str] | tuple[str, ...] = (),
        gha_resolve_depth: int = 3,
        **_: Any,
    ) -> None:
        """Optionally pull in remote reusable-workflow callees.

        Off by default. When ``resolve_remote`` is true, walks every
        loaded caller for ``jobs.<id>.uses: owner/repo/.../foo.yml@<sha>``
        and appends the fetched bodies to ``context.workflows``.
        Failures land in ``context.warnings`` rather than raising.

        When ``resolve_remote`` is *false*, the method still inspects
        the loaded workflows for unresolved remote refs and writes a
        one-line nudge to ``context.warnings`` so users discover the
        opt-in flag.
        """
        if not resolve_remote:
            self._warn_unresolved(context)
            return

        fetchers: list[Any] = []
        search_paths = [Path(p) for p in gha_search_paths]
        if search_paths:
            fetchers.append(DiskFetcher(search_paths))
        fetchers.append(HttpFetcher(token=gh_token))
        fetcher = (
            CompositeFetcher(fetchers) if len(fetchers) > 1 else fetchers[0]
        )
        cache = FileSystemCache(
            default_cache_dir(),
            enabled=not no_cache,
        )
        resolver = Resolver(
            fetcher=fetcher,
            cache=cache,
            max_depth=gha_resolve_depth,
        )
        resolver.resolve(context)

    @staticmethod
    def _warn_unresolved(context: GitHubContext) -> None:
        """Surface a one-line stderr nudge if remote refs are skipped."""
        skipped = 0
        for wf in context.workflows:
            jobs = wf.data.get("jobs")
            if not isinstance(jobs, dict):
                continue
            for job in jobs.values():
                if not isinstance(job, dict):
                    continue
                ref = parse_uses(job.get("uses"))
                if ref is not None and ref.kind == "remote-workflow":
                    skipped += 1
        if skipped:
            context.warnings.append(
                f"[gha] {skipped} reusable workflow(s) reference remote "
                f"refs; rerun with --resolve-remote to scan them."
            )

    def inventory(self, context: GitHubContext) -> list[Component]:
        out: list[Component] = []
        for wf in context.workflows:
            data = wf.data if isinstance(wf.data, dict) else {}
            out.append(Component(
                provider=self.NAME,
                type="workflow",
                identifier=str(data.get("name") or wf.path),
                source=wf.path,
                metadata=_gha_metadata(data),
            ))
        return out


def _gha_metadata(data: dict[str, Any]) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    jobs = data.get("jobs")
    if isinstance(jobs, dict):
        meta["jobs"] = sorted(jobs.keys())
        # Runner labels tell you where the workflow physically runs;
        # environment names tell you whether protection rules apply.
        runners: set[str] = set()
        environments: set[str] = set()
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            ro = job.get("runs-on")
            if isinstance(ro, str):
                runners.add(ro)
            elif isinstance(ro, list):
                runners.update(x for x in ro if isinstance(x, str))
            env = job.get("environment")
            if isinstance(env, str):
                environments.add(env)
            elif isinstance(env, dict) and isinstance(env.get("name"), str):
                environments.add(env["name"])
        if runners:
            meta["runners"] = sorted(runners)
        if environments:
            meta["environments"] = sorted(environments)
    # Trigger events — ``pull_request_target`` is the one that grants
    # write tokens on fork PRs, so surfacing triggers is load-bearing
    # for any "which workflows are reachable from untrusted input"
    # audit.
    # PyYAML parses bare ``on:`` as the Python ``True`` key (YAML 1.1
    # boolean coercion), so probe both.
    on = data.get("on")
    if on is None:
        # PyYAML 1.1 parses bare ``on:`` as the Python ``True`` key.
        # The dict is typed ``dict[str, Any]``, so widen via cast for
        # this one lookup. ``cast`` widens at type-check time only.
        from typing import cast
        on = cast("dict[Any, Any]", data).get(True)
    if isinstance(on, dict):
        meta["triggers"] = sorted(on.keys())
    elif isinstance(on, list):
        meta["triggers"] = sorted(x for x in on if isinstance(x, str))
    elif isinstance(on, str):
        meta["triggers"] = [on]
    # Top-level ``permissions:``  — tightened token scopes worth recording.
    perms = data.get("permissions")
    if isinstance(perms, str):
        meta["permissions"] = perms
    elif isinstance(perms, dict):
        meta["permissions"] = "scoped"
    return meta
