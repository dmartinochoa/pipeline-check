"""SCM (source control management) posture provider.

Scans a single GitHub repository's governance settings — branch
protection, required reviews, default code scanning — via the
GitHub REST API. Future expansion covers GitLab and Bitbucket
behind the same provider name.

    pipeline_check --pipeline scm --scm-platform github \\
                   --scm-repo owner/name [--gh-token <token>]

Token defaults to ``$GITHUB_TOKEN``. Failed API calls land in
``ctx.warnings`` rather than raising, so a missing token or
restricted repo degrades gracefully (every rule that depends on the
missing payload sees ``None`` and reports accordingly).

Closes the largest competitive gap with Legitify and OpenSSF
Scorecard, neither of which scans pipeline-config files.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..checks.base import BaseCheck
from ..checks.scm.base import (
    DiskSCMFetcher,
    HttpSCMFetcher,
    SCMContext,
    SCMFetcher,
)
from ..checks.scm.posture import SCMPostureChecks
from ..inventory import Component
from .base import BaseProvider


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
                "The scm provider requires --scm-platform <github|...>. "
                "GitHub is the only platform supported today; GitLab "
                "and Bitbucket are tracked on the roadmap."
            )
        if scm_platform.lower() != "github":
            raise ValueError(
                f"Unsupported --scm-platform {scm_platform!r}. Only "
                f"``github`` is supported in this release."
            )
        if not scm_repo or "/" not in scm_repo:
            raise ValueError(
                "The scm provider requires --scm-repo owner/name "
                "(e.g. ``--scm-repo octocat/hello-world``)."
            )
        owner, name = scm_repo.split("/", 1)
        if not owner or not name:
            raise ValueError(
                f"Invalid --scm-repo {scm_repo!r}; expected owner/name."
            )
        fetcher: SCMFetcher
        if scm_fixture_dir:
            # Fixture mode: read responses from disk, never touch the
            # network. CI test environments use this so the rule pack
            # exercises against a known snapshot.
            fetcher = DiskSCMFetcher([Path(scm_fixture_dir)])
        else:
            fetcher = HttpSCMFetcher(token=gh_token)
        return SCMContext.for_repo(owner, name, fetcher)

    @property
    def check_classes(self) -> list[type[BaseCheck]]:
        return [SCMPostureChecks]

    def inventory(self, context: SCMContext) -> list[Component]:
        out: list[Component] = []
        for snapshot in context.repos:
            metadata: dict[str, Any] = {}
            meta = snapshot.repo_meta or {}
            if isinstance(meta, dict):
                if isinstance(meta.get("default_branch"), str):
                    metadata["default_branch"] = meta["default_branch"]
                if isinstance(meta.get("private"), bool):
                    metadata["private"] = meta["private"]
                if isinstance(meta.get("visibility"), str):
                    metadata["visibility"] = meta["visibility"]
                # Archived / disabled state is the dominant context
                # for posture interpretation: the security-feature
                # rules skip these repos because the underlying
                # platform auto-disables the features. Surface the
                # state in inventory so the operator can correlate.
                # Use isinstance to match the other typed-metadata
                # fields above — a malformed payload (e.g. the string
                # ``"false"``) should not be silently coerced to
                # ``True``, and an explicit ``False`` should survive.
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
                source=f"github:{snapshot.owner}/{snapshot.name}",
                metadata=metadata,
            ))
        return out
