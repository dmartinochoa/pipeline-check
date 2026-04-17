"""GitLab CI provider — scans ``.gitlab-ci.yml`` from disk.

    pipeline_check --pipeline gitlab --gitlab-path path/to/.gitlab-ci.yml

Only YAML parsing is required — no network calls, no GitLab API token.
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.gitlab.base import GitLabContext
from ..checks.gitlab.pipelines import GitLabPipelineChecks
from ..inventory import Component
from .base import BaseProvider


_GITLAB_TOPLEVEL_KEYWORDS = {
    "default", "include", "stages", "variables", "workflow",
    "image", "services", "cache", "before_script", "after_script", "pages",
}


class GitLabProvider(BaseProvider):
    """GitLab CI provider — parses pipeline YAML from disk."""

    NAME = "gitlab"

    def build_context(self, gitlab_path: str | None = None, **_: Any) -> GitLabContext:
        if not gitlab_path:
            raise ValueError(
                "The gitlab provider requires --gitlab-path <file-or-dir> "
                "pointing at a .gitlab-ci.yml file or a directory containing one."
            )
        return GitLabContext.from_path(gitlab_path)

    @property
    def check_classes(self) -> list[type[BaseCheck]]:
        return [GitLabPipelineChecks]

    def inventory(self, context: GitLabContext) -> list[Component]:
        out: list[Component] = []
        for pipe in context.pipelines:
            data = pipe.data if isinstance(pipe.data, dict) else {}
            jobs = sorted(
                k for k in data.keys()
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
