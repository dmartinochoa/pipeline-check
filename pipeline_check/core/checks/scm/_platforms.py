"""Platform-specific fetchers and hydrators for the SCM provider.

The SCM rule pack was written GitHub-first: snapshots carry
GitHub-shaped slots (``security_and_analysis``, ``required_pull_
request_reviews``, ``allow_force_pushes``). To run the same rules
against GitLab and Bitbucket repositories without duplicating
every check module, this layer:

  * Adds a platform-specific HTTP fetcher per platform that knows
    how to hit the platform's REST API.
  * Normalizes each platform's protection / metadata payload into
    the GitHub-shaped slots the universal rules consume.

Universal rules (``SCM-001`` branch protection presence,
``SCM-002`` required reviews, ``SCM-006`` signed commits,
``SCM-007`` force push, ``SCM-008`` required status checks,
``SCM-009`` branch deletion, ``SCM-017`` CODEOWNERS file) read
from the normalized slots. GitHub-only rules (``security_and_
analysis``-driven, GitHub-only review knobs) are skipped at the
orchestrator level when ``snapshot.platform`` is not ``"github"``.

Network access uses stdlib urllib for parity with the existing
HTTP fetcher; failed fetches return ``None`` so a missing token
or rate-limit response degrades to "feature unavailable" without
raising.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .base import (
    SCMContext,
    SCMFetcher,
    SCMRepoSnapshot,
    _build_fan_out_context,
)

_DEFAULT_TIMEOUT = 10.0
_MAX_RESPONSE_BYTES = 5 * 1024 * 1024


# ── GitLab ───────────────────────────────────────────────────────────


class HttpGitLabSCMFetcher:
    """Hit the GitLab REST v4 API at a configurable host. Token is
    taken from the constructor or ``$GITLAB_TOKEN``.

    ``host`` defaults to ``gitlab.com`` but accepts a self-hosted
    URL (``gitlab.example.com``, no scheme) so on-premises
    deployments can plug in without code changes.
    """

    def __init__(
        self,
        token: str | None = None,
        host: str = "gitlab.com",
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        self.token = (
            token if token is not None else os.environ.get("GITLAB_TOKEN")
        )
        self.host = host
        self.timeout = timeout

    @property
    def base_url(self) -> str:
        return f"https://{self.host}/api/v4"

    def fetch(self, path: str) -> dict[str, Any] | list[Any] | None:
        url = f"{self.base_url}/{path.lstrip('/')}"
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", "pipeline-check-scm")
        if self.token:
            req.add_header("PRIVATE-TOKEN", self.token)
        try:
            with urllib.request.urlopen(
                req, timeout=self.timeout,
            ) as resp:
                body = resp.read(_MAX_RESPONSE_BYTES + 1)
                if len(body) > _MAX_RESPONSE_BYTES:
                    return None
                parsed = json.loads(body.decode("utf-8"))
        except urllib.error.HTTPError:
            return None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            return None
        if isinstance(parsed, (dict, list)):
            return parsed
        return None


def gitlab_context_for_repo(
    project_path: str, fetcher: SCMFetcher,
) -> SCMContext:
    """Hydrate an :class:`SCMContext` for a single GitLab project.

    ``project_path`` is the URL-style group / subgroup / project path
    (``gitlab-org/gitlab``, ``group/subgroup/project``). The fetcher
    issues two API calls: project metadata and protected-branches
    list. Each is translated into the GitHub-shaped snapshot slots
    so the universal rules ((SCM-001 / -002 / -006 / -007 / -008 /
    -009 / -017) consume the same shape they always have.
    """
    warnings: list[str] = []
    encoded = urllib.parse.quote(project_path, safe="")
    project = fetcher.fetch(f"projects/{encoded}")
    if not isinstance(project, dict):
        warnings.append(
            f"[scm] could not fetch projects/{project_path} from "
            f"GitLab — check the token (need ``read_api`` scope)."
        )
        snap = SCMRepoSnapshot(
            owner=_split_owner(project_path)[0],
            name=_split_owner(project_path)[1],
            platform="gitlab",
            repo_meta=None,
        )
        ctx = SCMContext(repos=[snap])
        ctx.files_scanned = 1
        ctx.warnings = warnings
        return ctx

    default_branch = project.get("default_branch")
    if not isinstance(default_branch, str) or not default_branch:
        default_branch = "main"

    push_rule_raw = fetcher.fetch(f"projects/{encoded}/push_rule")
    # Merge-request approval settings live on their own endpoint, NOT
    # on the project payload. ``merge_requests_author_approval`` (the
    # field SCM-053 reads) is here, not on ``GET /projects/:id``.
    approvals_raw = fetcher.fetch(f"projects/{encoded}/approvals")

    stats = project.get("statistics")
    raw_size = stats.get("repository_size") if isinstance(stats, dict) else None
    try:
        # A self-hosted / proxied GitLab can return a null or non-numeric
        # ``repository_size``; don't let ``int()`` abort the SCM scan.
        repo_size = int(raw_size)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        repo_size = 1024

    repo_meta: dict[str, Any] = {
        "default_branch": default_branch,
        "size": repo_size,
        "private": project.get("visibility") == "private",
        "visibility": project.get("visibility"),
        "archived": bool(project.get("archived")),
        # Raw payloads so platform-specific rules (SCM-050..053) can
        # read GitLab-shaped fields without re-issuing the API call.
        # Keys are underscore-prefixed so they don't collide with the
        # normalized GitHub-shaped slots above.
        "_gitlab_project": project,
        "_gitlab_push_rule": (
            push_rule_raw if isinstance(push_rule_raw, dict) else None
        ),
        "_gitlab_approvals": (
            approvals_raw if isinstance(approvals_raw, dict) else None
        ),
    }

    protection = _gitlab_protected_branch(
        fetcher, encoded, default_branch,
        project=project,
        push_rules=(
            push_rule_raw if isinstance(push_rule_raw, dict) else None
        ),
    )

    codeowners_path = _gitlab_codeowners_path(
        fetcher, encoded, default_branch,
    )

    owner, name = _split_owner(project_path)
    snap = SCMRepoSnapshot(
        owner=owner,
        name=name,
        platform="gitlab",
        repo_meta=repo_meta,
        default_branch_protection=protection,
        codeowners_path=codeowners_path,
    )
    ctx = SCMContext(repos=[snap])
    ctx.files_scanned = 1
    ctx.warnings = warnings
    return ctx


def gitlab_context_for_org(
    group: str,
    fetcher: SCMFetcher,
    include: tuple[str, ...] = (),
    exclude: tuple[str, ...] = (),
    max_repos: int = 0,
) -> SCMContext:
    """Fan the universal SCM pack out across a whole GitLab group.

    Paginates ``GET /groups/{group}/projects`` (subgroups included) to
    enumerate the group's projects, then builds a per-project snapshot for
    each via :func:`gitlab_context_for_repo`. ``include`` / ``exclude``
    globs match the short project name; ``max_repos`` caps the count. The
    GitLab analog of :meth:`SCMContext.for_org`; only the 7-rule universal
    subset runs (the GitHub-only rules pass with a "not applicable" note).
    """
    encoded = urllib.parse.quote(group, safe="")
    pairs: list[tuple[str, str]] = []
    page = 1
    while True:
        result = fetcher.fetch(
            f"groups/{encoded}/projects"
            f"?per_page=100&page={page}&include_subgroups=true"
        )
        if not isinstance(result, list) or not result:
            break
        for r in result:
            if not isinstance(r, dict) or r.get("archived"):
                continue
            path_ns = r.get("path_with_namespace")
            if not isinstance(path_ns, str) or "/" not in path_ns:
                continue
            pairs.append((path_ns.rsplit("/", 1)[1], path_ns))
        if len(result) < 100:
            break
        page += 1
    return _build_fan_out_context(
        pairs,
        lambda path: gitlab_context_for_repo(path, fetcher),
        org_label=group,
        enumerate_empty_warning=(
            f"[scm] enumerated no projects for GitLab group {group} — check "
            "the token's ``read_api`` scope, or the group has no "
            "(non-archived) projects."
        ),
        include=include,
        exclude=exclude,
        max_repos=max_repos,
    )


def _split_owner(project_path: str) -> tuple[str, str]:
    """Split a GitLab project path into ``(owner_or_group, name)``.

    GitLab supports nested subgroups (``a/b/c/repo``); the rule pack
    treats everything before the last ``/`` as the owner so the
    resource label still reads cleanly.
    """
    if "/" not in project_path:
        return ("", project_path)
    parts = project_path.rsplit("/", 1)
    return (parts[0], parts[1])


def _gitlab_protected_branch(
    fetcher: SCMFetcher,
    encoded_path: str,
    default_branch: str,
    *,
    project: dict[str, Any] | None = None,
    push_rules: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Fetch the protection rule for the default branch (if any) and
    translate into GitHub-shaped slots.

    Returns ``None`` when the branch is not protected (the SCM-001
    failure signal). Returns a normalized dict otherwise:

      * ``required_pull_request_reviews.required_approving_review_count``
        from ``code_owner_approval_required`` / project-level
        ``approvals_before_merge`` (best-effort).
      * ``required_signatures.enabled`` from the project's
        ``push_rules.reject_unsigned_commits`` setting.
      * ``allow_force_pushes.enabled`` from
        ``allow_force_push``.
      * ``allow_deletions.enabled`` mirrors GitLab's lack of a
        per-branch delete-protection toggle (defaults to False —
        protected branches in GitLab can't be deleted without
        admin intervention).
      * ``required_status_checks.contexts`` from the project's
        ``only_allow_merge_if_pipeline_succeeds`` flag (presence
        signals required checks).
    """
    branches = fetcher.fetch(
        f"projects/{encoded_path}/protected_branches",
    )
    target: dict[str, Any] | None = None
    if isinstance(branches, list):
        for entry in branches:
            if not isinstance(entry, dict):
                continue
            if entry.get("name") == default_branch:
                target = entry
                break
    if target is None:
        return None

    # ``push_access_levels`` of ``[]`` means nobody can push (which
    # is GitLab's strongest protection); a non-empty list with
    # access levels above 0 (NoAccess) means push is allowed.
    # We surface the access levels as ``restrictions.users`` for
    # SCM-019 compatibility (kept GitHub-only at the rule layer).
    allow_force = bool(target.get("allow_force_push"))

    # Project-level metadata for the cross-cutting knobs. Caller
    # (``gitlab_context_for_repo``) passes already-fetched payloads;
    # falling back to a fresh fetch keeps the helper callable from
    # any future code path that doesn't pre-fetch.
    proj = project
    if proj is None:
        raw_proj = fetcher.fetch(f"projects/{encoded_path}")
        proj = raw_proj if isinstance(raw_proj, dict) else None
    if push_rules is None and proj is not None:
        raw_pr = fetcher.fetch(f"projects/{encoded_path}/push_rule")
        push_rules = raw_pr if isinstance(raw_pr, dict) else None

    approvals: int = 0
    if isinstance(proj, dict):
        raw = proj.get("approvals_before_merge", 0)
        if isinstance(raw, int):
            approvals = raw

    pipeline_required = False
    if isinstance(proj, dict):
        pipeline_required = bool(
            proj.get("only_allow_merge_if_pipeline_succeeds"),
        )

    require_signed = False
    if isinstance(push_rules, dict):
        require_signed = bool(push_rules.get("reject_unsigned_commits"))

    return {
        "required_pull_request_reviews": {
            "required_approving_review_count": approvals,
        },
        "required_signatures": {"enabled": require_signed},
        "allow_force_pushes": {"enabled": allow_force},
        "allow_deletions": {"enabled": False},
        "required_status_checks": (
            {"strict": True, "contexts": ["pipeline"]}
            if pipeline_required else {}
        ),
    }


def _gitlab_codeowners_path(
    fetcher: SCMFetcher, encoded_path: str, default_branch: str,
) -> str | None:
    """Probe the three canonical CODEOWNERS locations on a GitLab
    project. GitLab follows GitHub's convention (``.gitlab/CODE
    OWNERS`` is the platform-preferred alternative, also tried)."""
    candidates = (
        ".gitlab/CODEOWNERS",
        ".github/CODEOWNERS",
        "CODEOWNERS",
        "docs/CODEOWNERS",
    )
    for path in candidates:
        encoded_file = urllib.parse.quote(path, safe="")
        raw = fetcher.fetch(
            f"projects/{encoded_path}/repository/files/{encoded_file}"
            f"?ref={default_branch}",
        )
        if isinstance(raw, dict) and raw.get("file_path"):
            return path
    return None


# ── Bitbucket Cloud ──────────────────────────────────────────────────


class HttpBitbucketSCMFetcher:
    """Hit the Bitbucket Cloud REST 2.0 API. Authentication is via
    HTTP Basic with an app password; ``token`` is treated as the
    ``user:app_password`` pair (passed verbatim into the
    ``Authorization`` header). Falls back to ``$BITBUCKET_TOKEN``.

    Bitbucket Cloud only; Bitbucket Server is a different surface
    and out of scope here.
    """

    BASE_URL = "https://api.bitbucket.org/2.0"

    def __init__(
        self,
        token: str | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        self.token = (
            token if token is not None else
            os.environ.get("BITBUCKET_TOKEN")
        )
        self.timeout = timeout

    def fetch(self, path: str) -> dict[str, Any] | list[Any] | None:
        url = f"{self.BASE_URL}/{path.lstrip('/')}"
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", "pipeline-check-scm")
        if self.token:
            # The user/app-password value is passed verbatim into a
            # Basic header so callers can also pass an existing
            # ``Basic <b64>`` string.
            if self.token.startswith("Basic "):
                req.add_header("Authorization", self.token)
            else:
                import base64
                encoded = base64.b64encode(
                    self.token.encode("utf-8"),
                ).decode("ascii")
                req.add_header("Authorization", f"Basic {encoded}")
        try:
            with urllib.request.urlopen(
                req, timeout=self.timeout,
            ) as resp:
                body = resp.read(_MAX_RESPONSE_BYTES + 1)
                if len(body) > _MAX_RESPONSE_BYTES:
                    return None
                parsed = json.loads(body.decode("utf-8"))
        except urllib.error.HTTPError:
            return None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            return None
        if isinstance(parsed, (dict, list)):
            return parsed
        return None


def bitbucket_context_for_repo(
    workspace: str, repo_slug: str, fetcher: SCMFetcher,
) -> SCMContext:
    """Hydrate an :class:`SCMContext` for a single Bitbucket Cloud
    repo. The fetcher issues two calls: repo metadata and
    branch-restrictions list. Branch restrictions are translated
    into the GitHub-shaped protection slot so the universal rules
    consume the same shape.
    """
    warnings: list[str] = []
    repo = fetcher.fetch(f"repositories/{workspace}/{repo_slug}")
    if not isinstance(repo, dict):
        warnings.append(
            f"[scm] could not fetch repositories/{workspace}/"
            f"{repo_slug} from Bitbucket Cloud — check the app "
            f"password (need ``repositories:read``)."
        )
        snap = SCMRepoSnapshot(
            owner=workspace,
            name=repo_slug,
            platform="bitbucket",
            repo_meta=None,
        )
        ctx = SCMContext(repos=[snap])
        ctx.files_scanned = 1
        ctx.warnings = warnings
        return ctx

    default_branch = (
        repo.get("mainbranch", {}).get("name")
        if isinstance(repo.get("mainbranch"), dict) else None
    )
    if not isinstance(default_branch, str) or not default_branch:
        default_branch = "main"

    repo_meta: dict[str, Any] = {
        "default_branch": default_branch,
        "size": int(repo.get("size", 1024))
        if isinstance(repo.get("size"), int) else 1024,
        "private": bool(repo.get("is_private")),
        # Bitbucket Cloud doesn't expose an explicit ``archived``
        # field via 2.0; treat unset as False.
        "archived": False,
        # Raw payload so platform-specific rules (SCM-054..055) can
        # read Bitbucket-shaped fields (``fork_policy``,
        # ``project.is_private``, ``has_issues``) without re-issuing
        # the API call. Underscore-prefixed to avoid colliding with
        # the normalized GitHub-shaped slots above.
        "_bitbucket_repo": repo,
    }

    protection = _bitbucket_protection(
        fetcher, workspace, repo_slug, default_branch,
    )

    codeowners_path = _bitbucket_codeowners_path(
        fetcher, workspace, repo_slug, default_branch,
    )

    snap = SCMRepoSnapshot(
        owner=workspace,
        name=repo_slug,
        platform="bitbucket",
        repo_meta=repo_meta,
        default_branch_protection=protection,
        codeowners_path=codeowners_path,
    )
    ctx = SCMContext(repos=[snap])
    ctx.files_scanned = 1
    ctx.warnings = warnings
    return ctx


def _bitbucket_protection(
    fetcher: SCMFetcher,
    workspace: str,
    repo_slug: str,
    default_branch: str,
) -> dict[str, Any] | None:
    """Translate Bitbucket branch restrictions into GitHub-shaped
    slots.

    Bitbucket's ``branch-restrictions`` returns a list of typed
    restriction entries:

      * ``kind == "push"``  → can write to branch (restriction means
        only listed users / groups can push).
      * ``kind == "force"`` → force-push allowed iff restriction is
        absent.
      * ``kind == "delete"`` → branch deletion allowed iff
        restriction is absent.
      * ``kind == "require_approvals_to_merge"`` → integer value
        maps onto required PR reviews.
      * ``kind == "require_passing_builds_to_merge"`` → presence
        signals required status checks.

    Returns ``None`` when no restrictions exist on the default
    branch (SCM-001 failure signal).
    """
    raw = fetcher.fetch(
        f"repositories/{workspace}/{repo_slug}/branch-restrictions",
    )
    if not isinstance(raw, dict):
        return None
    values = raw.get("values")
    if not isinstance(values, list) or not values:
        return None

    # Bitbucket's ``pattern`` field carries the glob the restriction
    # applies to; only restrictions matching the default branch (or
    # a glob covering it) participate in the SCM-001 evaluation.
    on_default: list[dict[str, Any]] = []
    for entry in values:
        if not isinstance(entry, dict):
            continue
        pattern = entry.get("pattern")
        if not isinstance(pattern, str):
            continue
        if (
            pattern == default_branch
            or pattern == "*"
            or pattern == "master"
            and default_branch == "master"
        ):
            on_default.append(entry)
    if not on_default:
        return None

    by_kind = {e.get("kind"): e for e in on_default if isinstance(e, dict)}

    approvals = 0
    appr_entry = by_kind.get("require_approvals_to_merge")
    if isinstance(appr_entry, dict):
        raw_val = appr_entry.get("value", 0)
        if isinstance(raw_val, int):
            approvals = raw_val

    allow_force = "force" not in by_kind
    allow_delete = "delete" not in by_kind

    pipeline_required = "require_passing_builds_to_merge" in by_kind

    return {
        "required_pull_request_reviews": {
            "required_approving_review_count": approvals,
        },
        "allow_force_pushes": {"enabled": allow_force},
        "allow_deletions": {"enabled": allow_delete},
        # The ``push`` kind (Bitbucket's "Prevent push" / Write-access
        # restriction) has no GitHub-shaped slot, but it's the primary
        # write-side control. Surface the raw restriction kinds present
        # on the default branch so SCM-055 can count it.
        "_bitbucket_restriction_kinds": [
            k for k in by_kind if isinstance(k, str)
        ],
        "required_status_checks": (
            {"strict": True, "contexts": ["pipeline"]}
            if pipeline_required else {}
        ),
        # Bitbucket Cloud has no per-branch signed-commit enforcement
        # (it has GPG signing as a personal-account setting, not a
        # protection rule), so SCM-006 always fires unless the user
        # suppresses; we still surface the slot for shape parity.
        "required_signatures": {"enabled": False},
    }


def _bitbucket_codeowners_path(
    fetcher: SCMFetcher,
    workspace: str,
    repo_slug: str,
    default_branch: str,
) -> str | None:
    """Probe the canonical CODEOWNERS locations on a Bitbucket repo
    via the ``src`` endpoint.

    The ``?format=meta`` query string is load-bearing: without it
    Bitbucket Cloud returns the raw file body (which trips
    ``isinstance(raw, dict)`` and silently fails the probe). With
    it the endpoint returns a JSON object carrying ``path`` /
    ``type`` so the existing dict-shape check can distinguish "file
    exists" from "404".

    Reference: https://developer.atlassian.com/cloud/bitbucket/rest/
    api-group-source/#format-meta-parameter
    """
    candidates = (
        ".bitbucket/CODEOWNERS",
        "CODEOWNERS",
        "docs/CODEOWNERS",
    )
    encoded_ref = urllib.parse.quote(default_branch, safe="")
    for path in candidates:
        encoded_path = urllib.parse.quote(path, safe="/")
        raw = fetcher.fetch(
            f"repositories/{workspace}/{repo_slug}/src/"
            f"{encoded_ref}/{encoded_path}?format=meta",
        )
        if isinstance(raw, dict) and raw.get("path") == path:
            return path
    return None


def bitbucket_context_for_org(
    workspace: str,
    fetcher: SCMFetcher,
    include: tuple[str, ...] = (),
    exclude: tuple[str, ...] = (),
    max_repos: int = 0,
) -> SCMContext:
    """Fan the universal SCM pack out across a whole Bitbucket workspace.

    Paginates ``GET /repositories/{workspace}`` (cursor-based ``next``) to
    enumerate the workspace's repos, then builds a per-repo snapshot for
    each via :func:`bitbucket_context_for_repo`. ``include`` / ``exclude``
    globs match the repo slug; ``max_repos`` caps the count. The Bitbucket
    analog of :meth:`SCMContext.for_org`; only the 7-rule universal subset
    runs.
    """
    pairs: list[tuple[str, str]] = []
    path = f"repositories/{workspace}?pagelen=100"
    while path:
        result = fetcher.fetch(path)
        if not isinstance(result, dict):
            break
        values = result.get("values")
        if not isinstance(values, list) or not values:
            break
        for r in values:
            if not isinstance(r, dict):
                continue
            full_name = r.get("full_name")
            if not isinstance(full_name, str) or "/" not in full_name:
                continue
            pairs.append((full_name.split("/", 1)[1],
                          full_name.split("/", 1)[1]))
        next_url = result.get("next")
        if isinstance(next_url, str) and next_url:
            base = "https://api.bitbucket.org/2.0/"
            path = (
                next_url[len(base):]
                if next_url.startswith(base)
                else next_url
            )
        else:
            path = ""
    return _build_fan_out_context(
        pairs,
        lambda slug: bitbucket_context_for_repo(workspace, slug, fetcher),
        org_label=workspace,
        enumerate_empty_warning=(
            f"[scm] enumerated no repositories for Bitbucket workspace "
            f"{workspace} — check the token, or the workspace has no repos."
        ),
        include=include,
        exclude=exclude,
        max_repos=max_repos,
    )
