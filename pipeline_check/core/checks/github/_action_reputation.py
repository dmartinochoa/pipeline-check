"""Action reputation: per-action repo metadata fetcher and snapshot.

Foundation for the GHA-04x reputation rule pack (GHA-041 single-
maintainer, GHA-042 very-young repo, GHA-043 low-star + sensitive
permission). Where ``_compromised_actions.py`` is a *static* registry
of known-bad refs, this module is a *dynamic* fetcher: each scan
queries the GitHub REST API for the metadata of every action
referenced by the loaded workflows and surfaces the result on the
context for the reputation rules to consume.

Network access is opt-in via ``--resolve-remote``. The CLI wires the
HTTP fetcher in there; when the flag is off, no metadata is fetched
and the rules pass silently with a "no metadata available" note so
the operator discovers the flag.

The fetcher layer reuses the SCM provider's :class:`HttpSCMFetcher`
and :class:`DiskSCMFetcher` since both target ``api.github.com`` and
the disk shape is identical (endpoint path with ``/`` collapsed to
``_``). A thin :class:`ActionMetadataFetcher` projects the raw JSON
into the typed :class:`ActionRepoMetadata` dataclass the rules
consume.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ..scm.base import SCMFetcher
from .uses_parser import parse_uses

if TYPE_CHECKING:
    from .base import GitHubContext


@dataclass(frozen=True, slots=True)
class ActionRepoMetadata:
    """Per-action GitHub repo snapshot.

    All numeric / temporal fields are ``None`` when the upstream
    response didn't carry them (private repo + no token, deleted
    action, network failure). Rules treat ``None`` as "unknown" and
    pass with a no-data note rather than firing on absence — the
    opposite of SCM's posture rules, where a missing protection
    payload IS the failure signal.
    """

    owner: str
    repo: str
    #: ``"User"`` for personal accounts, ``"Organization"`` for org
    #: accounts. Sourced from ``owner.type``. ``None`` when the
    #: repo-meta fetch failed.
    owner_type: str | None = None
    #: ISO 8601 timestamp from ``created_at``. Parsed lazily by the
    #: GHA-042 rule (the rule does the math, not this loader).
    created_at: str | None = None
    #: Public star count from ``stargazers_count``. ``None`` when the
    #: fetch failed.
    stargazers_count: int | None = None
    #: Number of contributors found on the first page of the
    #: ``/contributors`` endpoint (capped at 2 by the fetcher; rule
    #: only cares about == 1). ``None`` when the contributors fetch
    #: failed; ``0`` for an empty repo with no commits.
    contributor_count: int | None = None
    #: True when ``repo_meta.archived`` is true. Archived actions are
    #: themselves a signal (no maintenance), but the reputation rules
    #: don't fire on this slot alone — it's surfaced for inventory.
    archived: bool = False
    #: True when ``repo_meta.fork`` is true. Forks are usually
    #: throwaway and the GHA-041 / -042 / -043 heuristics apply with
    #: even more weight.
    fork: bool = False


class ActionMetadataFetcher:
    """Projects raw GitHub API JSON into :class:`ActionRepoMetadata`.

    Wraps a generic :class:`SCMFetcher` so swapping HTTP for an
    on-disk fixture set is a one-line change at construction. Failed
    fetches return ``None`` rather than raising; the populate step
    records the failure on ``ctx.warnings`` and continues so a single
    private repo doesn't tank the scan.
    """

    #: First page of ``/contributors`` we request. Two is enough to
    #: distinguish "exactly one contributor" (single-maintainer
    #: signal for GHA-041) from "more than one" without paginating.
    #: Bump if a future rule needs a richer contributor distribution.
    _CONTRIBUTORS_CAP = 2

    def __init__(self, raw: SCMFetcher) -> None:
        self.raw = raw

    def fetch(self, owner: str, repo: str) -> ActionRepoMetadata | None:
        repo_meta = self.raw.fetch(f"repos/{owner}/{repo}")
        if not isinstance(repo_meta, dict):
            return None
        owner_block = repo_meta.get("owner")
        owner_type: str | None = None
        if isinstance(owner_block, dict):
            t = owner_block.get("type")
            if isinstance(t, str):
                owner_type = t
        created_at = repo_meta.get("created_at")
        if not isinstance(created_at, str):
            created_at = None
        stars = repo_meta.get("stargazers_count")
        if not isinstance(stars, int):
            stars = None
        archived = bool(repo_meta.get("archived"))
        fork = bool(repo_meta.get("fork"))
        # Contributors fetch is best-effort: the endpoint may 403 on
        # very large action repos or 204 (no content) on empty repos.
        # ``None`` here means "unknown"; the rules treat it like the
        # other ``None`` slots and pass with a no-data note.
        contributor_count: int | None = None
        contribs = self.raw.fetch(
            f"repos/{owner}/{repo}/contributors"
            f"?per_page={self._CONTRIBUTORS_CAP}&anon=false"
        )
        if isinstance(contribs, list):
            contributor_count = len(contribs)
        return ActionRepoMetadata(
            owner=owner,
            repo=repo,
            owner_type=owner_type,
            created_at=created_at,
            stargazers_count=stars,
            contributor_count=contributor_count,
            archived=archived,
            fork=fork,
        )


def collect_referenced_actions(ctx: GitHubContext) -> set[tuple[str, str]]:
    """Walk every loaded workflow, return the distinct ``(owner, repo)``
    pairs referenced as a step or reusable-workflow ``uses:``.

    Skips local refs (``./``), Docker steps, and refs missing an
    owner / repo component. The populate step iterates this set to
    bound the number of API calls; a workflow that references
    ``actions/checkout`` 20 times produces a single fetch.
    """
    seen: set[tuple[str, str]] = set()
    for wf in ctx.workflows:
        data = wf.data if isinstance(wf.data, dict) else {}
        jobs = data.get("jobs")
        if not isinstance(jobs, dict):
            continue
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            _consume_uses(job.get("uses"), seen)
            steps = job.get("steps")
            if not isinstance(steps, list):
                continue
            for step in steps:
                if not isinstance(step, dict):
                    continue
                _consume_uses(step.get("uses"), seen)
    return seen


def _consume_uses(
    value: Any, sink: set[tuple[str, str]],
) -> None:
    """Parse a ``uses:`` value and add ``(owner, repo)`` to *sink*
    when it names a remote action or workflow with a fully-qualified
    owner / repo pair."""
    ref = parse_uses(value)
    if ref is None:
        return
    if ref.kind not in {"remote-action", "remote-workflow"}:
        return
    if not ref.owner or not ref.repo:
        return
    sink.add((ref.owner.lower(), ref.repo.lower()))


def populate_action_metadata(
    ctx: GitHubContext, fetcher: ActionMetadataFetcher,
) -> None:
    """Fetch metadata for every distinct action referenced by the
    workflows and store the result on ``ctx.action_metadata``.

    Failures land in ``ctx.warnings`` rather than raising — a private
    fork or rate-limit response on one action shouldn't abort the
    scan. The reputation rules read ``ctx.action_metadata`` and pass
    silently on the actions whose metadata fetch failed.
    """
    actions = sorted(collect_referenced_actions(ctx))
    fetched: dict[str, ActionRepoMetadata] = {}
    failed: list[str] = []
    for owner, repo in actions:
        meta = fetcher.fetch(owner, repo)
        if meta is None:
            failed.append(f"{owner}/{repo}")
            continue
        fetched[f"{owner}/{repo}"] = meta
    if failed:
        ctx.warnings.append(
            f"[gha] action reputation: metadata fetch failed for "
            f"{len(failed)} action(s) "
            f"({', '.join(failed[:3])}"
            f"{', ...' if len(failed) > 3 else ''}). The reputation "
            f"rules (GHA-041 / GHA-042 / GHA-043) pass silently on "
            f"those actions; rerun with --gh-token to lift the "
            f"unauthenticated rate-limit ceiling."
        )
    ctx.action_metadata = fetched
