"""GitLab CI provider, scans ``.gitlab-ci.yml`` from disk.

    pipeline_check --pipeline gitlab --gitlab-path path/to/.gitlab-ci.yml

YAML parsing requires no network calls. When ``--resolve-remote`` is on,
the provider fetches ``include: { project/remote/template/component }``
directives via the GitLab API and merges them into the pipeline document
before rules run.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ..checks._primitives.registry_fetcher import (
    FileSystemCache,
    HttpGetFetcher,
    default_cache_dir,
)
from ..checks.base import BaseCheck
from ..checks.gitlab.base import (
    GitLabContext,
    Pipeline,
    _resolve_remote_includes,
    iter_jobs,
)
from ..checks.gitlab.pipelines import GitLabPipelineChecks
from ..checks.gitlab.resolver import (
    GitLabIncludeFetcher,
    count_unresolved_remote_includes,
)
from ..inventory import Component
from ..sbom import BuildDependency, make_docker_purl, parse_docker_ref
from .base import BaseProvider


def _image_ref(value: Any) -> str | None:
    """A GitLab ``image:`` / ``services:`` entry is a string or a dict
    with a ``name:`` key."""
    if isinstance(value, str):
        return value.strip() or None
    if isinstance(value, dict):
        name = value.get("name")
        return name.strip() if isinstance(name, str) and name.strip() else None
    return None

_GITLAB_TOPLEVEL_KEYWORDS = {
    "default", "include", "stages", "variables", "workflow",
    "image", "services", "cache", "before_script", "after_script", "pages",
}


class GitLabProvider(BaseProvider):
    """GitLab CI provider, parses pipeline YAML from disk."""

    NAME = "gitlab"

    def build_context(self, gitlab_path: str | None = None, **_: Any) -> GitLabContext:
        if not gitlab_path:
            raise ValueError(
                "The gitlab provider requires --gitlab-path <file-or-dir> "
                "pointing at a .gitlab-ci.yml file or a directory containing one."
            )
        return GitLabContext.from_path(gitlab_path)

    @property
    def check_classes(self) -> list[type[BaseCheck[Any]]]:
        return [GitLabPipelineChecks]

    def build_dependencies(
        self, context: GitLabContext,
    ) -> list[BuildDependency]:
        """Emit each ``image:`` / ``services:`` reference as a container
        dependency, the runner images a GitLab pipeline executes in."""
        deps: list[BuildDependency] = []
        for pipe in context.pipelines:
            doc = pipe.data
            if not isinstance(doc, dict):
                continue
            # The top-level default plus every job inherits the same
            # ``image:`` / ``services:`` schema.
            scopes: list[dict[str, Any]] = [doc]
            scopes.extend(job for _name, job in iter_jobs(doc))
            for scope in scopes:
                refs = [_image_ref(scope.get("image"))]
                services = scope.get("services")
                if isinstance(services, list):
                    refs.extend(_image_ref(s) for s in services)
                for ref in refs:
                    if not ref:
                        continue
                    img, tag, digest = parse_docker_ref(ref)
                    deps.append(BuildDependency(
                        name=img,
                        version=tag or digest or "latest",
                        dep_type="container",
                        purl=make_docker_purl(img, tag, digest),
                        provider=self.NAME,
                        source=pipe.path,
                        pinned=bool(digest),
                        digest=digest,
                    ))
        return deps

    def post_filter(self, context: Any, **kwargs: Any) -> None:
        resolve_remote: bool = kwargs.get("resolve_remote", False)
        ctx: GitLabContext = context
        if not resolve_remote:
            _warn_unresolved(ctx)
            return

        token = kwargs.get("gitlab_token") or os.environ.get("GITLAB_TOKEN")
        gitlab_url: str = kwargs.get("gitlab_url", "") or "https://gitlab.com"
        no_cache: bool = kwargs.get("no_cache", False)

        cache = FileSystemCache(
            default_cache_dir("gitlab-resolver"),
            enabled=not no_cache,
        )
        http = HttpGetFetcher(
            user_agent="pipeline-check-gitlab-resolver",
        )
        fetcher = GitLabIncludeFetcher(
            gitlab_url=gitlab_url,
            token=token,
            cache=cache,
            http=http,
        )

        for i, pipeline in enumerate(ctx.pipelines):
            scan_root: Path | None = None
            if pipeline.path:
                p = Path(pipeline.path).resolve()
                scan_root = p.parent if p.is_file() else p

            merged, warnings = _resolve_remote_includes(
                pipeline.data,
                fetcher=fetcher,
                scan_root=scan_root,
            )
            ctx.warnings.extend(
                f"{pipeline.path}: {w}" for w in warnings
            )

            resolved = _collect_resolved_ids(pipeline.data, fetcher)
            ctx.pipelines[i] = Pipeline(
                path=pipeline.path,
                data=merged,
                resolved_includes=tuple(resolved),
            )

        stats = fetcher.stats
        if stats.fetched or stats.cached:
            ctx.warnings.append(
                f"GitLab include resolver: {stats.fetched} fetched, "
                f"{stats.cached} cached, {stats.failed} failed"
            )
        if stats.failed_details:
            shown = stats.failed_details[:5]
            ctx.warnings.extend(
                f"  failed: {d}" for d in shown
            )
            if len(stats.failed_details) > 5:
                ctx.warnings.append(
                    f"  ... and {len(stats.failed_details) - 5} more"
                )

    def inventory(self, context: GitLabContext) -> list[Component]:
        out: list[Component] = []
        for pipe in context.pipelines:
            data = pipe.data if isinstance(pipe.data, dict) else {}
            jobs = sorted(
                k for k in data
                if isinstance(k, str) and k not in _GITLAB_TOPLEVEL_KEYWORDS
            )
            out.append(Component(
                provider=self.NAME,
                type="pipeline",
                identifier=pipe.path,
                source=pipe.path,
                metadata={"jobs": jobs} if jobs else {},
            ))
        return out


def _warn_unresolved(ctx: GitLabContext) -> None:
    """Emit a nudge when remote includes exist but aren't resolved."""
    n = count_unresolved_remote_includes(ctx.pipelines)
    if n > 0:
        ctx.warnings.append(
            f"{n} remote include directive(s) were not resolved "
            f"(project/remote/template/component). Pass --resolve-remote "
            f"to fetch and merge them."
        )


def _collect_resolved_ids(
    data: dict[str, Any],
    fetcher: GitLabIncludeFetcher,
) -> list[str]:
    """Return canonical IDs for remote includes in *data*."""
    include_block = data.get("include")
    if include_block is None:
        return []
    items = (
        include_block if isinstance(include_block, list) else [include_block]
    )
    ids: list[str] = []
    for item in items:
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
        key = fetcher._cache_key(kind, item)
        if key:
            ids.append(key)
    return ids
