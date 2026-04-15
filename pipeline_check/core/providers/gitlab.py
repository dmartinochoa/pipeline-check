"""GitLab CI provider — scans ``.gitlab-ci.yml`` from disk.

    pipeline_check --pipeline gitlab --gitlab-path path/to/.gitlab-ci.yml

Only YAML parsing is required — no network calls, no GitLab API token.
"""
from __future__ import annotations

from typing import Any

from .base import BaseProvider
from ..checks.base import BaseCheck
from ..checks.gitlab.base import GitLabContext
from ..checks.gitlab.pipelines import GitLabPipelineChecks


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
