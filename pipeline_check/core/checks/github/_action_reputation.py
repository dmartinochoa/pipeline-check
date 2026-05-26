"""Action reputation: per-action repo metadata fetcher and snapshot.

Foundation for the GHA-04x reputation rule pack (GHA-041 single-
maintainer, GHA-042 very-young repo, GHA-043 low-star + sensitive
permission, GHA-047 fresh referenced tag/SHA). Where
``_compromised_actions.py`` is a *static* registry of known-bad refs,
this module is a *dynamic* fetcher: each scan queries the GitHub REST
API for the metadata of every action referenced by the loaded
workflows and surfaces the result on the context for the reputation
rules to consume.

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

from .._primitives.sha_ref import SHA_RE as _SHA_RE
from ..scm.base import SCMFetcher
from .uses_parser import parse_uses

if TYPE_CHECKING:
    from .base import GitHubContext


@dataclass(frozen=True, slots=True)
class ActionAdvisory:
    """One GitHub Security Advisory (GHSA) entry affecting an action."""

    ghsa_id: str
    cve_id: str | None
    summary: str
    severity: str
    vulnerable_ranges: tuple[str, ...]
    patched_versions: tuple[str | None, ...]


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
    #: Per-ref commit timestamp, keyed by the ``UsesRef.ref`` string
    #: (a tag like ``v4`` or a 40-char commit SHA). Populated by
    #: :meth:`ActionMetadataFetcher.fetch_ref_dates` for each ref the
    #: workflows actually reference. ``None`` for the whole slot when
    #: the rule should treat per-ref freshness as unknown (typical
    #: when the opt-in flag is off or every per-ref fetch failed).
    #: A ``None`` value for a specific key inside the dict (e.g.
    #: ``{"v4": None}``) means the ref was looked up and the API
    #: didn't carry a usable date; the consuming rule passes silently
    #: on that specific ref. Consumed by GHA-047.
    ref_committed_at: dict[str, str | None] | None = None
    #: Per-SHA membership in the upstream repo's commit network. Keyed
    #: by the 40-char SHA referenced in ``uses:``. ``True`` when the
    #: ``/commits/{sha}`` lookup returned 200 (the commit exists in
    #: this repo's reachability set); ``False`` when the lookup ran
    #: but came back empty (most commonly a 404, the impostor-commit
    #: signal GHA-090 fires on). ``None`` for the whole slot means the
    #: rule should treat membership as unknown (typical when the opt-
    #: in flag is off or no SHA-shaped refs were referenced). Only
    #: populated for refs that match a 40-char hex SHA shape; tag /
    #: branch refs don't carry the impostor-commit attack model.
    sha_membership: dict[str, bool] | None = None
    #: Set of 40-char commit SHAs currently at the tip of some branch
    #: in the upstream repo. Populated by a one-shot
    #: ``GET /repos/{o}/{r}/branches?per_page=100`` when any
    #: SHA-shaped ref is referenced for this action. A pinned SHA
    #: that lands in this set is GHA-094 territory, the maintainer
    #: can re-point the branch and the same pin starts fetching
    #: different code. ``None`` for the whole slot means the lookup
    #: didn't run (opt-in off, or no SHA-shaped refs referenced).
    branch_head_shas: frozenset[str] | None = None
    #: Resolved tag -> SHA mapping for tags harvested from
    #: ``uses: o/r@<sha>  # <tag>`` version comments in the workflow
    #: bodies. Populated by
    #: :meth:`ActionMetadataFetcher.fetch_tag_shas` (one
    #: ``/commits/{tag}`` call per tag). ``None`` for the whole slot
    #: means the lookup didn't run (no version comments referenced
    #: this action). A ``None`` value for a specific key inside the
    #: dict (e.g. ``{"v4": None}``) means the tag was looked up and
    #: the API didn't carry a usable SHA. GHA-095 consumes this to
    #: decide whether the SHA pin and the comment tag agree.
    tag_shas: dict[str, str | None] | None = None
    #: GHSA advisories affecting this action, populated by
    #: :meth:`ActionMetadataFetcher.fetch_advisories`. ``None`` when
    #: the lookup didn't run (opt-in off). An empty tuple means the
    #: lookup ran and no advisories were found. Consumed by GHA-096.
    ghsa_advisories: tuple[ActionAdvisory, ...] | None = None


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

    def fetch_branch_heads(
        self, owner: str, repo: str,
    ) -> frozenset[str] | None:
        """Return the set of branch-tip SHAs for ``owner/repo``.

        One call to ``/repos/{o}/{r}/branches?per_page=100``. Repos
        with more than 100 branches are an edge case; the rule
        consuming this accepts the ceiling and skips the bonus
        signal on branches past the first page. Returns ``None``
        when the API call fails so the rule can distinguish
        "lookup ran, repo has no branches" (empty frozenset) from
        "lookup didn't run" (``None``).
        """
        payload = self.raw.fetch(
            f"repos/{owner}/{repo}/branches?per_page=100"
        )
        if not isinstance(payload, list):
            return None
        heads: set[str] = set()
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            commit = entry.get("commit")
            if not isinstance(commit, dict):
                continue
            sha = commit.get("sha")
            if isinstance(sha, str) and len(sha) == 40:
                heads.add(sha.lower())
        return frozenset(heads)

    def fetch_sha_membership(
        self, owner: str, repo: str, sha_refs: set[str],
    ) -> dict[str, bool]:
        """Probe whether each 40-char SHA in *sha_refs* is reachable
        in ``owner/repo``'s commit network.

        Returns ``{sha: True}`` when ``/repos/{o}/{r}/commits/{sha}``
        returned a non-empty payload (the commit is in the repo's
        reachability set) and ``{sha: False}`` when the lookup ran
        but came back empty — typically a 404 from a SHA that exists
        only in a fork's network, the impostor-commit attack shape.

        Empty *sha_refs* returns an empty dict; callers map that to
        ``None`` on :attr:`ActionRepoMetadata.sha_membership` so
        consumers can distinguish "no data" from "every probe ran."
        """
        out: dict[str, bool] = {}
        for sha in sha_refs:
            if not sha:
                continue
            payload = self.raw.fetch(f"repos/{owner}/{repo}/commits/{sha}")
            out[sha] = isinstance(payload, dict)
        return out

    def fetch_tag_shas(
        self, owner: str, repo: str, tags: set[str],
    ) -> dict[str, str | None]:
        """Resolve each tag in *tags* to its commit SHA.

        Uses the same ``/repos/{o}/{r}/commits/{ref}`` endpoint as
        :meth:`fetch_ref_dates`, the response carries both
        ``commit.committer.date`` (date-extractor lives in the
        sibling method) and the canonical ``sha`` (extracted here).
        One API call per distinct tag; empty input set returns the
        empty dict so callers can map that to ``None`` on
        :attr:`ActionRepoMetadata.tag_shas` to distinguish "no tags
        to resolve" from "every resolve ran."

        Returns a mapping ``{tag: sha | None}``. A ``None`` value
        means the lookup completed but the payload didn't carry a
        usable ``sha`` (most commonly a 404 from a tag that doesn't
        exist on the upstream repo, the cue GHA-095 uses to pass
        silently rather than fire on an unverifiable comment).
        """
        out: dict[str, str | None] = {}
        for tag in tags:
            if not tag:
                continue
            payload = self.raw.fetch(f"repos/{owner}/{repo}/commits/{tag}")
            out[tag] = _extract_commit_sha(payload)
        return out

    def fetch_advisories(
        self, owner: str, repo: str,
    ) -> tuple[ActionAdvisory, ...] | None:
        """Query the GitHub Advisory Database for advisories affecting
        ``owner/repo`` in the ``actions`` ecosystem.

        Returns a tuple of :class:`ActionAdvisory` entries, an empty
        tuple when the query ran but found no advisories, or ``None``
        when the API call failed.
        """
        payload = self.raw.fetch(
            f"advisories?type=reviewed&ecosystem=actions"
            f"&affects={owner}/{repo}&per_page=100"
        )
        if not isinstance(payload, list):
            return None
        out: list[ActionAdvisory] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            ghsa_id = item.get("ghsa_id")
            if not isinstance(ghsa_id, str) or not ghsa_id:
                continue
            cve_id = item.get("cve_id")
            summary = item.get("summary", "")
            severity = item.get("severity", "unknown")
            vulns = item.get("vulnerabilities")
            if not isinstance(vulns, list):
                continue
            ranges: list[str] = []
            patched: list[str | None] = []
            for v in vulns:
                if not isinstance(v, dict):
                    continue
                pkg = v.get("package")
                if not isinstance(pkg, dict):
                    continue
                if pkg.get("ecosystem") != "actions":
                    continue
                vr = v.get("vulnerable_version_range")
                if isinstance(vr, str):
                    ranges.append(vr)
                fv = v.get("first_patched_version")
                if isinstance(fv, dict):
                    patched.append(fv.get("identifier"))
                else:
                    patched.append(None)
            if not ranges:
                continue
            out.append(ActionAdvisory(
                ghsa_id=ghsa_id,
                cve_id=cve_id if isinstance(cve_id, str) else None,
                summary=summary if isinstance(summary, str) else "",
                severity=severity if isinstance(severity, str) else "unknown",
                vulnerable_ranges=tuple(ranges),
                patched_versions=tuple(patched),
            ))
        return tuple(out)

    def fetch_ref_dates(
        self, owner: str, repo: str, refs: set[str],
    ) -> dict[str, str | None]:
        """Resolve per-ref commit timestamps for *refs*.

        Each entry in *refs* is the right-hand side of a ``uses:``
        ``@<ref>`` (a tag like ``v4``, an annotated tag, or a 40-char
        commit SHA). Branch refs are accepted too; they resolve to the
        branch HEAD's commit date, which is the freshness signal
        GHA-047 wants for the unpinned-ref case. The
        ``/repos/{o}/{r}/commits/{ref}`` endpoint handles all three
        ref shapes uniformly, so this method is one API call per
        distinct ref rather than the
        ``/git/refs`` → ``/git/tags`` → ``/commits`` chain a strict
        tag-vs-SHA dispatch would require.

        Returns a mapping ``{ref: iso8601 | None}``. A ``None`` value
        means the lookup completed but the response didn't carry a
        usable ``commit.committer.date``; GHA-047 passes silently on
        those entries. Skipped (empty) input returns an empty dict so
        the caller can distinguish "no refs to look up" from "lookups
        failed."
        """
        out: dict[str, str | None] = {}
        for ref in refs:
            if not ref:
                continue
            payload = self.raw.fetch(f"repos/{owner}/{repo}/commits/{ref}")
            out[ref] = _extract_committer_date(payload)
        return out


def _extract_commit_sha(payload: Any) -> str | None:
    """Pull the canonical ``sha`` out of a ``/commits/{ref}`` body.

    Returns ``None`` when the response is missing or wrong-typed.
    Lower-cases the result so callers can compare against
    ``uses:`` SHA pins without per-side case juggling — every other
    SHA-handling path in the module already normalizes to lower-case.
    """
    if not isinstance(payload, dict):
        return None
    sha = payload.get("sha")
    if not isinstance(sha, str) or len(sha) != 40:
        return None
    return sha.lower()


def _extract_committer_date(payload: Any) -> str | None:
    """Pull ``commit.committer.date`` out of a ``/commits/{ref}`` body.

    Returns ``None`` when any layer is missing or wrong-typed so the
    caller records "lookup ran, no usable date" rather than crashing.
    GitHub also exposes ``commit.author.date`` but the *committer*
    date is what changes when a tag is re-pointed at a new commit —
    that's the signal GHA-047 wants.
    """
    if not isinstance(payload, dict):
        return None
    commit = payload.get("commit")
    if not isinstance(commit, dict):
        return None
    committer = commit.get("committer")
    if not isinstance(committer, dict):
        return None
    date = committer.get("date")
    if not isinstance(date, str):
        return None
    return date


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


def collect_referenced_action_refs(
    ctx: GitHubContext,
) -> dict[tuple[str, str], set[str]]:
    """Like :func:`collect_referenced_actions`, but also captures the
    set of ``@<ref>`` values referenced for each action.

    Returns ``{(owner, repo): {ref, ...}}`` — same lower-cased keys as
    :func:`collect_referenced_actions` so a caller can merge the two
    views. An action referenced as both ``acme/foo@v1`` and
    ``acme/foo@v2`` lands as one entry with two refs. Used by
    :func:`populate_action_metadata` to drive the per-ref date fetch
    in addition to the repo-metadata fetch.
    """
    out: dict[tuple[str, str], set[str]] = {}
    for wf in ctx.workflows:
        data = wf.data if isinstance(wf.data, dict) else {}
        jobs = data.get("jobs")
        if not isinstance(jobs, dict):
            continue
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            _consume_uses_with_ref(job.get("uses"), out)
            steps = job.get("steps")
            if not isinstance(steps, list):
                continue
            for step in steps:
                if not isinstance(step, dict):
                    continue
                _consume_uses_with_ref(step.get("uses"), out)
    return out


def _consume_uses_with_ref(
    value: Any, sink: dict[tuple[str, str], set[str]],
) -> None:
    ref = parse_uses(value)
    if ref is None:
        return
    if ref.kind not in {"remote-action", "remote-workflow"}:
        return
    if not ref.owner or not ref.repo:
        return
    if not ref.ref:
        return
    key = (ref.owner.lower(), ref.repo.lower())
    sink.setdefault(key, set()).add(ref.ref)


def populate_action_metadata(
    ctx: GitHubContext, fetcher: ActionMetadataFetcher,
) -> None:
    """Fetch metadata for every distinct action referenced by the
    workflows and store the result on ``ctx.action_metadata``.

    Two passes per action:

      1. Repo metadata (``/repos/{o}/{r}`` + contributors) for the
         GHA-041 / GHA-042 / GHA-043 reputation rules.
      2. Per-ref commit date (``/repos/{o}/{r}/commits/{ref}``) for
         every distinct ``@<ref>`` the workflows use for that action.
         Drives GHA-047's freshness check.

    Failures land in ``ctx.warnings`` rather than raising — a private
    fork or rate-limit response on one action shouldn't abort the
    scan. The reputation rules read ``ctx.action_metadata`` and pass
    silently on the actions whose metadata fetch failed.
    """
    refs_by_action = collect_referenced_action_refs(ctx)
    from ._version_comments import (
        collect_referenced_action_version_comments,
    )
    tags_by_action = collect_referenced_action_version_comments(ctx)
    actions = sorted(
        refs_by_action.keys()
        | collect_referenced_actions(ctx)
        | tags_by_action.keys()
    )
    fetched: dict[str, ActionRepoMetadata] = {}
    failed: list[str] = []
    for owner, repo in actions:
        meta = fetcher.fetch(owner, repo)
        if meta is None:
            failed.append(f"{owner}/{repo}")
            continue
        refs = refs_by_action.get((owner, repo), set())
        ref_dates = fetcher.fetch_ref_dates(owner, repo, refs) if refs else {}
        # SHA-shaped refs (40-char hex) get an additional membership
        # probe so GHA-090 can fire on impostor-commit. Tag / branch
        # refs are skipped, the impostor-commit attack model is
        # specific to "SHA pin points at a commit absent from the
        # claimed repo." Same /commits/{sha} endpoint as
        # fetch_ref_dates, but we ask a yes/no question rather than
        # a timestamp-extraction one.
        sha_refs = {
            r for r in refs if _SHA_RE.match(r)
        }
        sha_membership = (
            fetcher.fetch_sha_membership(owner, repo, sha_refs)
            if sha_refs else {}
        )
        # Branch-heads probe rides on the SHA-refs presence test;
        # tag/branch-pinned actions don't carry the GHA-094 attack
        # model so we skip the call for them.
        branch_head_shas = (
            fetcher.fetch_branch_heads(owner, repo)
            if sha_refs else None
        )
        # Version-comment tags harvested from raw workflow text feed
        # the GHA-095 (ref-version-mismatch) comparator. Each tag
        # resolves through the same ``/commits/{ref}`` endpoint as
        # the ref-date fetch above, but the projection extracts
        # ``sha`` rather than ``commit.committer.date``. Skipped when
        # the action carries no comment-pinned tags.
        comment_tags = tags_by_action.get((owner, repo), set())
        tag_shas = (
            fetcher.fetch_tag_shas(owner, repo, comment_tags)
            if comment_tags else {}
        )
        # GHSA advisories feed GHA-096 (known-vulnerable action). One
        # call per action against the global advisory database filtered
        # by ``ecosystem=actions&affects=owner/repo``.
        ghsa_advisories = fetcher.fetch_advisories(owner, repo)
        # Re-pack the metadata with the per-ref dates folded in.
        # ``ref_committed_at`` stays ``None`` (rather than ``{}``)
        # when the action had no resolvable refs, so GHA-047 can tell
        # "no data" from "looked up, came back empty."
        meta_with_refs = ActionRepoMetadata(
            owner=meta.owner,
            repo=meta.repo,
            owner_type=meta.owner_type,
            created_at=meta.created_at,
            stargazers_count=meta.stargazers_count,
            contributor_count=meta.contributor_count,
            archived=meta.archived,
            fork=meta.fork,
            ref_committed_at=ref_dates if ref_dates else None,
            sha_membership=sha_membership if sha_membership else None,
            branch_head_shas=branch_head_shas,
            tag_shas=tag_shas if tag_shas else None,
            ghsa_advisories=ghsa_advisories,
        )
        fetched[f"{owner}/{repo}"] = meta_with_refs
    if failed:
        ctx.warnings.append(
            f"[gha] action reputation: metadata fetch failed for "
            f"{len(failed)} action(s) "
            f"({', '.join(failed[:3])}"
            f"{', ...' if len(failed) > 3 else ''}). The reputation "
            f"rules (GHA-041 / GHA-042 / GHA-043 / GHA-047) pass "
            f"silently on those actions; rerun with --gh-token to "
            f"lift the unauthenticated rate-limit ceiling."
        )
    ctx.action_metadata = fetched
    # Surface the failed-fetch set separately so GHA-091 (repojacking)
    # can act on it. The set carries owner/repo slugs, lower-cased
    # to match the action_metadata keying so a rule can do both
    # lookups with one normalized form.
    ctx.action_fetch_failures = {slug.lower() for slug in failed}
