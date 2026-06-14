"""GitLab group-level governance context.

Where the ``gitlab`` provider audits one project's ``.gitlab-ci.yml`` and
the ``scm`` provider audits one repository's settings, ``gitlab_group``
audits the group-wide controls that govern every project in a GitLab
group at once: whether two-factor authentication is required of all
members, whether members can fork the group's projects outside the
group, and so on. It issues ``GET /groups/{group}`` over the same GitLab
REST v4 fetcher the ``scm`` provider's GitLab path uses, so a missing
token / 404 / insufficient scope degrades to a warning and every rule
passes with an "unavailable" note rather than crashing.

    pipeline_check --pipeline gitlab_group --scm-org my-group [--gitlab-token <t>]

The GitLab analog of the GitHub-only ``scm_org`` provider (``ORG-*``).
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from ..base import BaseCheck

# A GitLab group endpoint is a plain REST v4 path, so the repo-level
# GitLab fetcher (HTTP + on-disk fixture variants) drives it unchanged.
from ..scm.base import SCMFetcher


@dataclass
class GitLabGroupContext:
    """Loaded group-level posture for one GitLab group."""

    group: str
    #: ``GET /groups/{group}`` body, or ``None`` when the fetch failed. Rules
    #: read this slot; ``None`` means "couldn't ask" (pass with a note),
    #: distinct from a setting that is present but insecure.
    group_meta: dict[str, Any] | None = None
    #: ``GET /groups/{group}/hooks`` body (a list of ``{id, url,
    #: enable_ssl_verification, ...}``), or ``None`` when unavailable.
    #: GLGRP-005.
    group_hooks: list[Any] | None = None
    warnings: list[str] = field(default_factory=list)
    files_scanned: int = 0   # repurposed: 1 when any group endpoint was fetched
    files_skipped: int = 0

    @property
    def slug(self) -> str:
        return self.group

    @classmethod
    def for_group(cls, group: str, fetcher: SCMFetcher) -> GitLabGroupContext:
        """Hydrate the group snapshot from the GitLab API.

        ``group`` is the URL-style group / subgroup path (``my-group``,
        ``my-group/platform``); it is URL-encoded for the API call. On any
        failure the snapshot degrades to ``group_meta = None`` with a
        warning, so a rule whose slot is ``None`` passes with an
        "unavailable" note instead of firing on absence.
        """
        ctx = cls(group=group)
        encoded = urllib.parse.quote(group, safe="")
        raw = fetcher.fetch(f"groups/{encoded}")
        if isinstance(raw, dict):
            ctx.group_meta = raw
        else:
            ctx.warnings.append(
                f"[gitlab-group] could not fetch groups/{group} (missing "
                "token, 404, or insufficient scope; the group-owner settings "
                "need a token with ``read_api`` and Owner access to the group)."
            )
        # The group webhooks endpoint returns a bare JSON array, not an
        # object, and needs Owner access. Fetched independently so a
        # token that can read the group but not its hooks still degrades
        # GLGRP-005 to a pass-with-note rather than crashing the others.
        hooks = fetcher.fetch(f"groups/{encoded}/hooks")
        if isinstance(hooks, list):
            ctx.group_hooks = hooks
        fetched_any = ctx.group_meta is not None or ctx.group_hooks is not None
        ctx.files_scanned = 1 if fetched_any else 0
        ctx.files_skipped = 0 if fetched_any else 1
        return ctx


def group_resource(ctx: GitLabGroupContext) -> str:
    """Stable, human-readable handle for a group-level finding."""
    return f"gitlab:group/{ctx.group}"


class GitLabGroupBaseCheck(BaseCheck["GitLabGroupContext"]):
    """Base class for group-governance rule orchestration."""

    PROVIDER = "gitlab_group"

    def __init__(
        self, ctx: GitLabGroupContext, target: str | None = None,
    ) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: GitLabGroupContext = ctx
