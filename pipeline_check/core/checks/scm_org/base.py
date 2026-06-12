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
    #: ``GET /orgs/{org}/actions/permissions`` body (``allowed_actions`` /
    #: ``enabled_repositories``), or ``None`` when unavailable. ORG-003.
    actions_permissions: dict[str, Any] | None = None
    #: ``GET /orgs/{org}/actions/permissions/workflow`` body
    #: (``default_workflow_permissions`` / ``can_approve_pull_request_reviews``),
    #: or ``None`` when unavailable. ORG-004 / ORG-005.
    actions_workflow_permissions: dict[str, Any] | None = None
    #: ``GET /orgs/{org}/actions/secrets`` body (``{total_count, secrets:
    #: [{name, visibility, ...}]}``), or ``None`` when unavailable. ORG-006.
    actions_secrets: dict[str, Any] | None = None
    #: ``GET /orgs/{org}/actions/runner-groups`` body (``{total_count,
    #: runner_groups: [{name, visibility, allows_public_repositories, ...}]}``),
    #: or ``None`` when unavailable. ORG-009.
    actions_runner_groups: dict[str, Any] | None = None
    #: ``GET /orgs/{org}/hooks`` body (a list of ``{id, name, active, config:
    #: {url, insecure_ssl, ...}}``), or ``None`` when unavailable. ORG-011.
    org_hooks: list[Any] | None = None
    #: ``GET /orgs/{org}/rulesets`` body (a list of ``{id, name, target,
    #: enforcement, ...}``), or ``None`` when unavailable. ORG-013.
    org_rulesets: list[Any] | None = None
    warnings: list[str] = field(default_factory=list)
    files_scanned: int = 0   # repurposed: 1 when any org endpoint was fetched
    files_skipped: int = 0

    @property
    def slug(self) -> str:
        return self.org

    @classmethod
    def for_org(cls, org: str, fetcher: SCMFetcher) -> SCMOrgContext:
        """Hydrate the org snapshot from the GitHub API.

        Each endpoint is fetched independently and degrades to ``None`` on
        failure (different settings need different token scopes), so a rule
        whose slot is ``None`` passes with an "unavailable" note instead of
        firing on absence. When the base ``GET /orgs/{org}`` fails a single
        warning is recorded.
        """
        ctx = cls(org=org)
        raw = fetcher.fetch(f"orgs/{org}")
        if isinstance(raw, dict):
            ctx.org_meta = raw
        else:
            ctx.warnings.append(
                f"[scm-org] could not fetch orgs/{org} (missing token, "
                "404, or insufficient scope; the org-admin settings need a "
                "token with ``admin:org`` / ``read:org``)."
            )
        # Actions-governance endpoints. Independent scope (``actions``), so
        # they're attempted even when the base org fetch failed.
        ap = fetcher.fetch(f"orgs/{org}/actions/permissions")
        if isinstance(ap, dict):
            ctx.actions_permissions = ap
        awp = fetcher.fetch(f"orgs/{org}/actions/permissions/workflow")
        if isinstance(awp, dict):
            ctx.actions_workflow_permissions = awp
        sec = fetcher.fetch(f"orgs/{org}/actions/secrets")
        if isinstance(sec, dict):
            ctx.actions_secrets = sec
        rg = fetcher.fetch(f"orgs/{org}/actions/runner-groups")
        if isinstance(rg, dict):
            ctx.actions_runner_groups = rg
        # The hooks endpoint returns a bare JSON array, not an object.
        hk = fetcher.fetch(f"orgs/{org}/hooks")
        if isinstance(hk, list):
            ctx.org_hooks = hk
        # The rulesets endpoint also returns a bare JSON array.
        rs = fetcher.fetch(f"orgs/{org}/rulesets")
        if isinstance(rs, list):
            ctx.org_rulesets = rs
        fetched_any = any((
            ctx.org_meta is not None,
            ctx.actions_permissions is not None,
            ctx.actions_workflow_permissions is not None,
            ctx.actions_secrets is not None,
            ctx.actions_runner_groups is not None,
            ctx.org_hooks is not None,
            ctx.org_rulesets is not None,
        ))
        ctx.files_scanned = 1 if fetched_any else 0
        ctx.files_skipped = 0 if fetched_any else 1
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
