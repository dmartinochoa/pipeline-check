"""SCM (source control management) posture provider.

Scans a single repository's governance settings (branch protection,
required reviews, security feature toggles, CODEOWNERS presence)
through the platform's REST API.

    pipeline_check --pipeline scm --scm-platform github \\
                   --scm-repo owner/name [--gh-token <token>]
    pipeline_check --pipeline scm --scm-platform gitlab \\
                   --scm-repo group/project [--gh-token <token>]
    pipeline_check --pipeline scm --scm-platform bitbucket \\
                   --scm-repo workspace/repo_slug [--gh-token <token>]

Tokens default to ``$GITHUB_TOKEN`` / ``$GITLAB_TOKEN`` /
``$BITBUCKET_TOKEN`` for their respective platforms; ``--gh-token``
acts as a platform-agnostic override that flows on to the chosen
platform's fetcher so a single flag plumbs through CI environments. Failed API calls land in
``ctx.warnings`` rather than raising, so a missing token or
restricted repo degrades gracefully (every rule that depends on the
missing payload sees ``None`` and reports accordingly).

Per-platform rule coverage:

  * **GitHub**: full 37-rule pack.
  * **GitLab** / **Bitbucket**: 7-rule universal subset (SCM-001
    branch protection presence, SCM-002 required reviews, SCM-006
    signed commits, SCM-007 force push, SCM-008 required status
    checks, SCM-009 branch deletion, SCM-017 CODEOWNERS file).
    GitHub-only rules pass silently with a "not applicable on
    PLATFORM" note so the operator sees the deliberate skip.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..checks.base import BaseCheck
from ..checks.scm._platforms import (
    HttpBitbucketSCMFetcher,
    HttpGitLabSCMFetcher,
    bitbucket_context_for_repo,
    gitlab_context_for_repo,
)
from ..checks.scm.base import (
    DiskSCMFetcher,
    HttpSCMFetcher,
    SCMContext,
    SCMFetcher,
)
from ..checks.scm.posture import SCMPostureChecks
from ..inventory import Component
from .base import BaseProvider

_SUPPORTED_PLATFORMS = ("github", "gitlab", "bitbucket")


class SCMProvider(BaseProvider):
    """SCM posture provider — pulls governance via the platform API."""

    NAME = "scm"

    def build_context(
        self,
        scm_platform: str | None = None,
        scm_repo: str | None = None,
        scm_fixture_dir: str | None = None,
        gh_token: str | None = None,
        **_: Any,
    ) -> SCMContext:
        if not scm_platform:
            raise ValueError(
                "The scm provider requires --scm-platform "
                "<github|gitlab|bitbucket>."
            )
        platform = scm_platform.lower()
        if platform not in _SUPPORTED_PLATFORMS:
            raise ValueError(
                f"Unsupported --scm-platform {scm_platform!r}. "
                f"Supported: {', '.join(_SUPPORTED_PLATFORMS)}."
            )
        if not scm_repo or "/" not in scm_repo:
            raise ValueError(
                "The scm provider requires --scm-repo. For GitHub: "
                "owner/name (``octocat/hello-world``). For GitLab: "
                "group/project (nested subgroups allowed). For "
                "Bitbucket Cloud: workspace/repo_slug."
            )
        if platform == "github":
            return self._build_github(scm_repo, scm_fixture_dir, gh_token)
        if platform == "gitlab":
            return self._build_gitlab(scm_repo, scm_fixture_dir, gh_token)
        return self._build_bitbucket(scm_repo, scm_fixture_dir, gh_token)

    @staticmethod
    def _build_github(
        scm_repo: str,
        scm_fixture_dir: str | None,
        gh_token: str | None,
    ) -> SCMContext:
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
        return SCMContext.for_repo(owner, name, fetcher)

    @staticmethod
    def _build_gitlab(
        scm_repo: str,
        scm_fixture_dir: str | None,
        gh_token: str | None,
    ) -> SCMContext:
        fetcher: SCMFetcher
        if scm_fixture_dir:
            fetcher = DiskSCMFetcher([Path(scm_fixture_dir)])
        else:
            # ``--gh-token`` plumbs through as the platform token
            # regardless of which platform is selected so CI configs
            # don't need to special-case env-var names.
            fetcher = HttpGitLabSCMFetcher(token=gh_token)
        return gitlab_context_for_repo(scm_repo, fetcher)

    @staticmethod
    def _build_bitbucket(
        scm_repo: str,
        scm_fixture_dir: str | None,
        gh_token: str | None,
    ) -> SCMContext:
        workspace, slug = scm_repo.split("/", 1)
        if not workspace or not slug:
            raise ValueError(
                f"Invalid --scm-repo {scm_repo!r}; expected "
                f"workspace/repo_slug for Bitbucket Cloud."
            )
        fetcher: SCMFetcher
        if scm_fixture_dir:
            fetcher = DiskSCMFetcher([Path(scm_fixture_dir)])
        else:
            fetcher = HttpBitbucketSCMFetcher(token=gh_token)
        return bitbucket_context_for_repo(workspace, slug, fetcher)

    @property
    def check_classes(self) -> list[type[BaseCheck[Any]]]:
        return [SCMPostureChecks]

    def inventory(self, context: SCMContext) -> list[Component]:
        out: list[Component] = []
        for snapshot in context.repos:
            metadata: dict[str, Any] = {"platform": snapshot.platform}
            meta = snapshot.repo_meta or {}
            if isinstance(meta, dict):
                if isinstance(meta.get("default_branch"), str):
                    metadata["default_branch"] = meta["default_branch"]
                if isinstance(meta.get("private"), bool):
                    metadata["private"] = meta["private"]
                if isinstance(meta.get("visibility"), str):
                    metadata["visibility"] = meta["visibility"]
                if isinstance(meta.get("archived"), bool):
                    metadata["archived"] = meta["archived"]
                if isinstance(meta.get("disabled"), bool):
                    metadata["disabled"] = meta["disabled"]
            metadata["branch_protection_enabled"] = (
                snapshot.default_branch_protection is not None
            )
            metadata["code_scanning_default_enabled"] = (
                isinstance(snapshot.code_scanning_default_setup, dict)
                and snapshot.code_scanning_default_setup.get("state")
                == "configured"
            )
            out.append(Component(
                provider=self.NAME,
                type="scm_repository",
                identifier=f"{snapshot.owner}/{snapshot.name}",
                source=(
                    f"{snapshot.platform}:{snapshot.owner}/{snapshot.name}"
                ),
                metadata=metadata,
            ))
        return out
