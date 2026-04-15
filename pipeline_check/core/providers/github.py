"""GitHub Actions provider — scans workflow YAML under ``.github/workflows/``.

Producer workflow:

    pipeline_check --pipeline github --gha-path .github/workflows

Only YAML parsing is required — no network calls, no GitHub API token.
"""
from __future__ import annotations

from typing import Any

from .base import BaseProvider
from ..checks.base import BaseCheck
from ..checks.github.base import GitHubContext
from ..checks.github.workflows import WorkflowChecks


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
