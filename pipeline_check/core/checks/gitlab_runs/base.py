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
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol

from .._primitives.safe_http import urlopen_https_only
from ..base import BaseCheck

#: How many recent pipelines to audit. The GitLab API caps ``per_page`` at
#: 100; one page is ample forensic signal without paginating all history.
DEFAULT_PIPELINE_LIMIT = 100

#: Fork-origin resolution (the deep pass, GLRUN-002) fetches one
#: ``/merge_requests/:iid/pipelines`` page per fork merge request, so it is
#: bounded to this many fork MRs.
DEFAULT_MR_FETCH_LIMIT = 25

#: Job-trace scanning (GLRUN-003 / GLRUN-004) downloads each job's trace,
#: so it is bounded to this many fork pipelines (one ``/jobs`` page each,
#: then one ``/trace`` per job).
DEFAULT_TRACE_FETCH_LIMIT = 10

_TIMEOUT = 10.0
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024
_MAX_TRACE_BYTES = 5 * 1024 * 1024

#: Markers that a job trace exercised cloud OIDC token minting. Tight by
#: design (near-zero false positive): these strings essentially only occur
#: in an OIDC federation exchange -- the AWS STS web-identity call and GCP
#: workload-identity federation. GitLab CI mints the token via
#: ``id_tokens:`` and the cloud-side call is the high-signal evidence,
#: regardless of issuer. Recall is best-effort (trace content varies and
#: masked variables are redacted), matching run-log forensics.
_GITLAB_OIDC_MARKERS_RE = re.compile(
    r"AssumeRoleWithWebIdentity|workloadIdentityPools",
)

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

    def fetch_text(self, path: str) -> str | None:
        """Fetch a plain-text endpoint (a job ``/trace``); not JSON."""
        url = f"{self.gitlab_url}/api/v4/{path.lstrip('/')}"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "pipeline-check-gitlab-runs")
        if self.token:
            req.add_header("PRIVATE-TOKEN", self.token)
        try:
            with urlopen_https_only(req, timeout=_TIMEOUT) as resp:
                body: bytes = resp.read(_MAX_TRACE_BYTES + 1)
        except Exception:
            return None
        if len(body) > _MAX_TRACE_BYTES:
            body = body[:_MAX_TRACE_BYTES]
        return body.decode("utf-8", errors="replace")


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
    #: Pipelines confirmed to belong to a *fork* merge request (the MR's
    #: source project differs from the target project), so untrusted fork
    #: code executed in this project's CI. Only populated when fork
    #: resolution was requested (the deep pass behind ``--audit-runs-logs``);
    #: GLRUN-002 reports it.
    fork_pipelines: list[GitLabPipelineRecord] = field(default_factory=list)
    #: True once the fork-resolution pass ran, so GLRUN-002 can tell
    #: "no fork pipelines" from "never resolved".
    forks_resolved: bool = False
    #: pipeline_id -> sorted "detector:redacted" labels for secrets found in
    #: that fork pipeline's job traces (only populated when the deep pass ran
    #: and the fetcher can download traces); GLRUN-003 reports it.
    trace_leaks: dict[int, list[str]] = field(default_factory=dict)
    #: fork pipeline_ids whose job traces show a cloud OIDC token was minted
    #: (only populated under the deep pass); GLRUN-004 reports it.
    oidc_mint_pipelines: set[int] = field(default_factory=set)

    @property
    def slug(self) -> str:
        return self.project

    @classmethod
    def for_project(
        cls,
        project: str,
        fetcher: GitLabFetcher,
        limit: int = DEFAULT_PIPELINE_LIMIT,
        *,
        resolve_forks: bool = False,
        mr_fetch_limit: int = DEFAULT_MR_FETCH_LIMIT,
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
        if resolve_forks:
            ctx.forks_resolved = True
            ctx._resolve_forks(fetcher, encoded, mr_fetch_limit)
            ctx._scan_fork_traces(fetcher, encoded, DEFAULT_TRACE_FETCH_LIMIT)
        return ctx

    def _resolve_forks(
        self, fetcher: GitLabFetcher, encoded: str, fetch_limit: int,
    ) -> None:
        """Find pipelines that ran for a *fork* merge request.

        GitLab's pipeline list doesn't carry the source/target project, so
        fork-origin is resolved via the MR API: list recent merge requests,
        keep the ones whose ``source_project_id`` differs from the
        ``target_project_id`` (a fork), then pull each such MR's pipelines
        (``/merge_requests/:iid/pipelines``). Those pipelines executed
        untrusted fork code in this project's CI. Bounded to *fetch_limit*
        fork MRs; a 404 / network error degrades to a skip.
        """
        raw = fetcher.fetch(
            f"projects/{encoded}/merge_requests"
            f"?per_page=100&order_by=updated_at&scope=all"
        )
        if not isinstance(raw, list):
            return
        fork_iids: list[int] = []
        for mr in raw:
            if not isinstance(mr, dict):
                continue
            src, tgt, iid = (
                mr.get("source_project_id"),
                mr.get("target_project_id"),
                mr.get("iid"),
            )
            if (
                isinstance(src, int) and isinstance(tgt, int)
                and isinstance(iid, int) and src != tgt
            ):
                fork_iids.append(iid)
        seen: set[int] = set()
        for iid in fork_iids[:fetch_limit]:
            praw = fetcher.fetch(
                f"projects/{encoded}/merge_requests/{iid}/pipelines"
            )
            if not isinstance(praw, list):
                continue
            for entry in praw:
                rec = _to_record(entry)
                if rec is not None and rec.pipeline_id not in seen:
                    seen.add(rec.pipeline_id)
                    self.fork_pipelines.append(rec)
        if len(fork_iids) > fetch_limit:
            self.warnings.append(
                f"[gitlab-runs] {self.project}: resolved the {fetch_limit} "
                f"most recent fork merge request(s) of {len(fork_iids)}; "
                "older fork MRs were not fetched."
            )

    def _scan_fork_traces(
        self, fetcher: GitLabFetcher, encoded: str, fetch_limit: int,
    ) -> None:
        """Download + scan fork pipelines' job traces for leaked secrets and
        cloud OIDC token minting (GLRUN-003 / GLRUN-004).

        Scoped to the fork pipelines resolved above (the untrusted-code
        surface) and bounded to *fetch_limit* of them. For each, lists its
        jobs and reads each job's ``/trace`` (plain text), scanning for
        secret-shaped strings that leaked past GitLab's variable masking and
        for cloud-federation OIDC markers. Needs a fetcher exposing
        ``fetch_text`` (the live one does; an offline fixture fetcher may
        not). ``find_secret_values`` is imported lazily so a metadata-only
        scan never pays for the detector catalog.
        """
        fetch_text = getattr(fetcher, "fetch_text", None)
        if not callable(fetch_text):
            if self.fork_pipelines:
                self.warnings.append(
                    "[gitlab-runs] job-trace scanning needs a fetcher that "
                    "can download traces; the configured fetcher cannot, so "
                    "GLRUN-003 / GLRUN-004 were skipped."
                )
            return
        from .._secrets import find_secret_values
        for rec in self.fork_pipelines[:fetch_limit]:
            jobs = fetcher.fetch(
                f"projects/{encoded}/pipelines/{rec.pipeline_id}/jobs?per_page=100"
            )
            if not isinstance(jobs, list):
                continue
            leaks: set[str] = set()
            oidc = False
            for job in jobs:
                if not isinstance(job, dict):
                    continue
                jid = job.get("id")
                if not isinstance(jid, int):
                    continue
                text = fetch_text(f"projects/{encoded}/jobs/{jid}/trace")
                if not text:
                    continue
                leaks.update(find_secret_values([text]))
                if not oidc and _GITLAB_OIDC_MARKERS_RE.search(text):
                    oidc = True
            if leaks:
                self.trace_leaks[rec.pipeline_id] = sorted(leaks)
            if oidc:
                self.oidc_mint_pipelines.add(rec.pipeline_id)
        if len(self.fork_pipelines) > fetch_limit:
            self.warnings.append(
                f"[gitlab-runs] {self.project}: scanned the {fetch_limit} "
                f"most recent fork pipeline(s) of {len(self.fork_pipelines)} "
                "for trace leaks; older fork pipelines were not fetched."
            )


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
