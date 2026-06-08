"""GitHub Actions run-history forensics provider.

Pulls recent workflow runs via the Actions REST API and flags what
actually executed (privileged triggers that fired, fork-originated
runs), complementing the static ``github`` provider's "what could run"
analysis. Reuses the SCM provider's GitHub fetcher, so ``--gh-token`` /
``$GITHUB_TOKEN`` authenticate it and ``--scm-fixture-dir`` drives the
offline test path.

    pipeline_check --pipeline runs --scm-repo owner/name [--gh-token <t>]
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..checks.base import BaseCheck
from ..checks.runs.base import RunsContext
from ..checks.runs.checks import RunsChecks
from ..checks.scm.base import DiskSCMFetcher, HttpSCMFetcher, SCMFetcher
from ..inventory import Component
from .base import BaseProvider


class RunsProvider(BaseProvider):
    """Run-history forensics provider (live GitHub Actions API)."""

    NAME = "runs"

    def build_context(
        self,
        scm_repo: str | None = None,
        scm_fixture_dir: str | None = None,
        gh_token: str | None = None,
        **_: Any,
    ) -> RunsContext:
        if not scm_repo or "/" not in scm_repo:
            raise ValueError(
                "The runs provider audits a GitHub repository's Actions "
                "run history and requires --scm-repo owner/name, e.g. "
                "--pipeline runs --scm-repo octocat/hello-world."
            )
        owner, name = scm_repo.split("/", 1)
        if not owner or not name:
            raise ValueError(
                f"Invalid --scm-repo {scm_repo!r}; expected owner/name."
            )
        fetcher: SCMFetcher
        if scm_fixture_dir:
            fetcher = DiskSCMFetcher([Path(scm_fixture_dir)])
        else:
            fetcher = HttpSCMFetcher(token=gh_token)
        return RunsContext.for_repo(owner, name, fetcher)

    @property
    def check_classes(self) -> list[type[BaseCheck[Any]]]:
        return [RunsChecks]

    def inventory(self, context: RunsContext) -> list[Component]:
        return [Component(
            provider=self.NAME,
            type="actions_run_history",
            identifier=context.slug,
            source=f"github:{context.slug}/actions",
            metadata={"runs_audited": len(context.runs)},
        )]
