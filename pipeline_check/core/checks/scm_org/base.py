"""GitHub organization-level governance context.

Where the ``scm`` provider audits one repository's settings, ``scm_org``
audits the organization-wide controls that govern every repo at once:
whether two-factor authentication is required of all members, the default
permission members get on org repos, the org Actions allow-list, and so
on. It issues ``GET /orgs/{org}`` (plus sibling endpoints as the rule
pack grows) over the same GitHub REST fetcher the ``scm`` provider uses,
so a missing token / 404 / insufficient scope degrades to a warning and
every rule passes with an "unavailable" note rather than crashing.

    pipeline_check --pipeline scm_org --scm-org acme [--gh-token <t>]
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..base import BaseCheck

# The org endpoints are plain GitHub REST paths, so the repo-level SCM
# fetcher (HTTP + on-disk fixture variants) drives them unchanged.
from ..scm.base import SCMFetcher


@dataclass
class SCMOrgContext:
    """Loaded organization-level posture for one GitHub org."""

    org: str
    #: ``GET /orgs/{org}`` body, or ``None`` when the fetch failed. Rules
    #: read this slot; ``None`` means "couldn't ask" (pass with a note),
    #: distinct from a setting that is present but insecure.
    org_meta: dict[str, Any] | None = None
    warnings: list[str] = field(default_factory=list)
    files_scanned: int = 0   # repurposed: 1 when the org was fetched
    files_skipped: int = 0

    @property
    def slug(self) -> str:
        return self.org

    @classmethod
    def for_org(cls, org: str, fetcher: SCMFetcher) -> SCMOrgContext:
        """Hydrate the org snapshot from the GitHub API.

        A failed fetch lands a warning and leaves ``org_meta`` at
        ``None``; the rule pack then passes each rule with an
        "org settings unavailable" note instead of firing on absence.
        """
        ctx = cls(org=org)
        raw = fetcher.fetch(f"orgs/{org}")
        if not isinstance(raw, dict):
            ctx.warnings.append(
                f"[scm-org] could not fetch orgs/{org} (missing token, "
                "404, or insufficient scope; the org-admin settings need a "
                "token with ``admin:org`` / ``read:org``). No org findings."
            )
            ctx.files_skipped = 1
            return ctx
        ctx.org_meta = raw
        ctx.files_scanned = 1
        return ctx


def org_resource(ctx: SCMOrgContext) -> str:
    """Stable, human-readable handle for an org-level finding."""
    return f"github:org/{ctx.org}"


class SCMOrgBaseCheck(BaseCheck["SCMOrgContext"]):
    """Base class for org-governance rule orchestration."""

    PROVIDER = "scm_org"

    def __init__(
        self, ctx: SCMOrgContext, target: str | None = None,
    ) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: SCMOrgContext = ctx
