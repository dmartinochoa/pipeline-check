"""Gitea / Forgejo Actions provider.

Gitea Actions and Forgejo Actions use the same workflow YAML syntax
as GitHub Actions, stored under ``.gitea/workflows/`` or
``.forgejo/workflows/``. This provider reuses :class:`GitHubContext`
and the full GHA rule pack.

Rules fire under their original ``GHA-NNN`` IDs because the
underlying engine is the same. GitHub-specific reputation rules
(GHA-041..043, GHA-089..091, GHA-096) that depend on ``--resolve-remote``
and GitHub API metadata pass silently when that data is absent.
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.github.base import GitHubContext
from ..checks.github.workflows import WorkflowChecks
from .base import BaseProvider


class GiteaProvider(BaseProvider):
    """Gitea / Forgejo Actions provider."""

    NAME = "gitea"

    def build_context(
        self, gitea_path: str | None = None, **_: Any,
    ) -> GitHubContext:
        if not gitea_path:
            raise ValueError(
                "The gitea provider requires --gitea-path <dir> pointing "
                "at the workflow directory (typically .gitea/workflows "
                "or .forgejo/workflows)."
            )
        return GitHubContext.from_path(gitea_path)

    @property
    def check_classes(self) -> list[type[BaseCheck[Any]]]:
        return [WorkflowChecks]
