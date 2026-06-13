"""GitLab pipeline run-history forensics provider.

Pulls recent pipelines via the GitLab REST API and flags what actually
executed (merge-request pipelines that fired), complementing the static
``gitlab`` provider's "what could run" analysis. Authenticated with
``--gitlab-token`` / ``$GITLAB_TOKEN``; ``--gitlab-url`` points it at a
self-managed instance.

    pipeline_check --pipeline gitlab_runs --scm-repo group/project
"""
from __future__ import annotations

import os
from typing import Any

from ..checks.base import BaseCheck
from ..checks.gitlab_runs.base import GitLabRunsContext, HttpGitLabFetcher
from ..checks.gitlab_runs.checks import GitLabRunsChecks
from ..inventory import Component
from .base import BaseProvider


class GitLabRunsProvider(BaseProvider):
    """GitLab run-history forensics provider (live GitLab API)."""

    NAME = "gitlab_runs"

    def build_context(
        self,
        scm_repo: str | None = None,
        gitlab_token: str | None = None,
        gitlab_url: str | None = None,
        audit_runs_logs: bool = False,
        **_: Any,
    ) -> GitLabRunsContext:
        if not scm_repo:
            raise ValueError(
                "The gitlab-runs provider audits a GitLab project's "
                "pipeline history and requires --scm-repo group/project, "
                "e.g. --pipeline gitlab_runs --scm-repo gitlab-org/gitlab."
            )
        token = gitlab_token or os.environ.get("GITLAB_TOKEN")
        fetcher = HttpGitLabFetcher(
            token=token, gitlab_url=gitlab_url or "https://gitlab.com",
        )
        # ``--audit-runs-logs`` is the deep run-forensics pass: for GitLab it
        # resolves which merge-request pipelines came from a fork (GLRUN-002),
        # which needs extra MR-API fetches beyond the one pipeline-list call.
        return GitLabRunsContext.for_project(
            scm_repo, fetcher, resolve_forks=audit_runs_logs,
        )

    @property
    def check_classes(self) -> list[type[BaseCheck[Any]]]:
        return [GitLabRunsChecks]

    def inventory(self, context: GitLabRunsContext) -> list[Component]:
        return [Component(
            provider=self.NAME,
            type="pipeline_run_history",
            identifier=context.slug,
            source=f"gitlab:{context.slug}/pipelines",
            metadata={"pipelines_audited": len(context.pipelines)},
        )]
