"""GitLab pipeline run-history forensics context.

Pulls recent pipelines via the GitLab REST API
(``GET /projects/:id/pipelines``) and exposes them as
:class:`GitLabPipelineRecord` snapshots so rules can reason about what
*actually executed*: which pipelines ran on a merge-request event (code a
contributor proposed), and on what ref. The live fetcher hits
``{gitlab_url}/api/v4`` over HTTPS with an optional ``PRIVATE-TOKEN``
(reusing the same ``safe_http`` guard the GitLab include-resolver uses), so
a missing token / 404 / network error degrades to a warning rather than a
crash (every rule then sees an empty pipeline list and passes).

    pipeline_check --pipeline gitlab_runs --scm-repo group/project \\
        [--gitlab-token <t>] [--gitlab-url https://gitlab.example.com]
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol

from .._primitives.safe_http import urlopen_https_only
from ..base import BaseCheck

#: How many recent pipelines to audit. The GitLab API caps ``per_page`` at
#: 100; one page is ample forensic signal without paginating all history.
DEFAULT_PIPELINE_LIMIT = 100

_TIMEOUT = 10.0
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024

#: Pipeline ``source`` values that mean a merge request's code was the
#: trigger, the GitLab surface where a contributor (and, when "run
#: pipelines for fork merge requests" is enabled, a fork) gets code to
#: execute in CI. The untrusted-trigger analog of the GitHub runs
#: provider's ``PRIVILEGED_TRIGGERS``.
MR_SOURCES: frozenset[str] = frozenset({
    "merge_request_event", "external_pull_request_event",
})


def _str(value: Any) -> str:
    return value if isinstance(value, str) else ""


class GitLabFetcher(Protocol):
    """Minimal fetch interface: a GitLab API path -> parsed JSON or None."""

    def fetch(self, path: str) -> dict[str, Any] | list[Any] | None: ...


class HttpGitLabFetcher:
    """Hit the GitLab REST API at ``{gitlab_url}/api/v4`` over HTTPS.

    Mirrors the GitHub ``HttpSCMFetcher`` shape (``fetch(path) -> json``)
    so the context code is fetcher-agnostic. ``path`` is an API path
    relative to ``/api/v4`` (e.g. ``projects/42/pipelines?per_page=100``).
    """

    def __init__(
        self, token: str | None = None,
        gitlab_url: str = "https://gitlab.com",
    ) -> None:
        self.token = token
        self.gitlab_url = gitlab_url.rstrip("/")

    def fetch(self, path: str) -> dict[str, Any] | list[Any] | None:
        url = f"{self.gitlab_url}/api/v4/{path.lstrip('/')}"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "pipeline-check-gitlab-runs")
        if self.token:
            req.add_header("PRIVATE-TOKEN", self.token)
        try:
            with urlopen_https_only(req, timeout=_TIMEOUT) as resp:
                body: bytes = resp.read(_MAX_RESPONSE_BYTES + 1)
        except Exception:
            return None
        if len(body) > _MAX_RESPONSE_BYTES:
            return None
        try:
            parsed = json.loads(body.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, ValueError):
            return None
        if isinstance(parsed, (dict, list)):
            return parsed
        return None


@dataclass(frozen=True, slots=True)
class GitLabPipelineRecord:
    """Forensic metadata for one GitLab pipeline."""

    pipeline_id: int
    status: str
    ref: str
    sha: str
    source: str   # push / merge_request_event / schedule / trigger / api / ...
    web_url: str
    created_at: str
    username: str  # user.username when the payload carries it ("" otherwise)

    @property
    def from_merge_request(self) -> bool:
        """True when a merge request's code was the trigger."""
        return self.source in MR_SOURCES


@dataclass
class GitLabRunsContext:
    """Recent pipelines for one GitLab project."""

    project: str   # the group/project path or numeric id, as supplied
    pipelines: list[GitLabPipelineRecord] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    files_scanned: int = 0   # repurposed: number of pipelines audited
    files_skipped: int = 0

    @property
    def slug(self) -> str:
        return self.project

    @classmethod
    def for_project(
        cls,
        project: str,
        fetcher: GitLabFetcher,
        limit: int = DEFAULT_PIPELINE_LIMIT,
    ) -> GitLabRunsContext:
        ctx = cls(project=project)
        per_page = max(1, min(limit, 100))
        encoded = urllib.parse.quote(project, safe="")
        raw = fetcher.fetch(f"projects/{encoded}/pipelines?per_page={per_page}")
        if not isinstance(raw, list):
            ctx.warnings.append(
                f"[gitlab-runs] could not fetch pipeline history for "
                f"{project} (missing token, 404, or network error); "
                "run forensics produced no findings."
            )
            return ctx
        for entry in raw[:limit]:
            rec = _to_record(entry)
            if rec is not None:
                ctx.pipelines.append(rec)
        ctx.files_scanned = len(ctx.pipelines)
        return ctx


def _to_record(entry: Any) -> GitLabPipelineRecord | None:
    if not isinstance(entry, dict):
        return None
    pid = entry.get("id")
    if not isinstance(pid, int):
        return None
    user = entry.get("user")
    user = user if isinstance(user, dict) else {}
    return GitLabPipelineRecord(
        pipeline_id=pid,
        status=_str(entry.get("status")),
        ref=_str(entry.get("ref")),
        sha=_str(entry.get("sha")),
        source=_str(entry.get("source")),
        web_url=_str(entry.get("web_url")),
        created_at=_str(entry.get("created_at")),
        username=_str(user.get("username")),
    )


def project_resource(ctx: GitLabRunsContext) -> str:
    """Resource handle for a project-level (aggregate) pipeline finding."""
    return f"gitlab:{ctx.project}/pipelines"


def pipeline_resource(ctx: GitLabRunsContext, rec: GitLabPipelineRecord) -> str:
    """Stable, human-readable handle for a single-pipeline finding."""
    return f"gitlab:{ctx.project}#pipeline/{rec.pipeline_id}"


class GitLabRunsBaseCheck(BaseCheck["GitLabRunsContext"]):
    """Base class for GitLab run-forensics rule orchestration."""

    PROVIDER = "gitlab_runs"

    def __init__(
        self, ctx: GitLabRunsContext, target: str | None = None,
    ) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: GitLabRunsContext = ctx
