"""GitLab group-level governance provider.

Audits group-wide controls that govern every project in a GitLab group at
once (2FA requirement, project-forking policy, ...), the GitLab analog of
the GitHub-only ``scm_org`` provider. Authenticated with ``--gitlab-token``
/ ``$GITLAB_TOKEN``; the group-owner settings need a token with
``read_api`` and Owner access to the group.

    pipeline_check --pipeline gitlab_group --scm-org my-group
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.gitlab_group.base import GitLabGroupContext
from ..checks.gitlab_group.checks import GitLabGroupChecks
from ..checks.scm._platforms import HttpGitLabSCMFetcher
from ..inventory import Component
from .base import BaseProvider


class GitLabGroupProvider(BaseProvider):
    """GitLab group-governance provider (live GitLab REST v4 API)."""

    NAME = "gitlab_group"

    def build_context(
        self,
        scm_org: str | None = None,
        gitlab_token: str | None = None,
        gitlab_url: str | None = None,
        **_: Any,
    ) -> GitLabGroupContext:
        if not scm_org:
            raise ValueError(
                "The gitlab_group provider audits a GitLab group's settings "
                "and requires --scm-org GROUP, e.g. "
                "--pipeline gitlab_group --scm-org my-group (a group path; "
                "subgroups like my-group/platform are allowed)."
            )
        # ``HttpGitLabSCMFetcher`` wants a bare host; ``--gitlab-url`` is a
        # full URL (default https://gitlab.com), so strip the scheme.
        raw_host = gitlab_url or "gitlab.com"
        host = raw_host.split("://", 1)[-1].rstrip("/") or "gitlab.com"
        fetcher = HttpGitLabSCMFetcher(token=gitlab_token, host=host)
        return GitLabGroupContext.for_group(scm_org, fetcher)

    @property
    def check_classes(self) -> list[type[BaseCheck[Any]]]:
        return [GitLabGroupChecks]

    def inventory(self, context: GitLabGroupContext) -> list[Component]:
        return [Component(
            provider=self.NAME,
            type="gitlab_group",
            identifier=context.slug,
            source=f"gitlab:group/{context.slug}",
            metadata={"group_fetched": context.group_meta is not None},
        )]
