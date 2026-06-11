"""GitHub organization-level governance provider.

Audits org-wide controls that govern every repository at once (2FA
requirement, default member permission, ...), complementing the per-repo
``scm`` provider. Authenticated with ``--gh-token`` / ``$GITHUB_TOKEN``;
the org-admin settings need a token with ``admin:org`` / ``read:org``.

    pipeline_check --pipeline scm_org --scm-org acme
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..checks.base import BaseCheck
from ..checks.scm.base import DiskSCMFetcher, HttpSCMFetcher, SCMFetcher
from ..checks.scm_org.base import SCMOrgContext
from ..checks.scm_org.checks import SCMOrgChecks
from ..inventory import Component
from .base import BaseProvider


class SCMOrgProvider(BaseProvider):
    """GitHub organization-governance provider (live GitHub API)."""

    NAME = "scm_org"

    def build_context(
        self,
        scm_org: str | None = None,
        scm_fixture_dir: str | None = None,
        gh_token: str | None = None,
        **_: Any,
    ) -> SCMOrgContext:
        if not scm_org:
            raise ValueError(
                "The scm_org provider audits a GitHub organization's "
                "settings and requires --scm-org ORG, e.g. "
                "--pipeline scm_org --scm-org my-org."
            )
        if "/" in scm_org:
            raise ValueError(
                f"Invalid --scm-org {scm_org!r}; expected a bare "
                "organization login (no '/'). For a single repo use "
                "--pipeline scm --scm-repo owner/name."
            )
        fetcher: SCMFetcher
        if scm_fixture_dir:
            fetcher = DiskSCMFetcher([Path(scm_fixture_dir)])
        else:
            fetcher = HttpSCMFetcher(token=gh_token)
        return SCMOrgContext.for_org(scm_org, fetcher)

    @property
    def check_classes(self) -> list[type[BaseCheck[Any]]]:
        return [SCMOrgChecks]

    def inventory(self, context: SCMOrgContext) -> list[Component]:
        return [Component(
            provider=self.NAME,
            type="scm_organization",
            identifier=context.slug,
            source=f"github:org/{context.slug}",
            metadata={"org_fetched": context.org_meta is not None},
        )]
