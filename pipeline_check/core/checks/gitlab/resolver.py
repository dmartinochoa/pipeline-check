"""GitLab CI remote ``include:`` fetcher.

Handles four include types that the local-only resolver skips:

- ``include: { project: 'group/proj', file: '/path.yml', ref: 'sha' }``
- ``include: { remote: 'https://...' }``
- ``include: { template: 'Auto-DevOps.gitlab-ci.yml' }``
- ``include: { component: 'gitlab.com/group/proj/name@1.0' }``

Gated on ``--resolve-remote``. When off, the scanner stays network-free
and emits a nudge warning so the operator knows the scan was incomplete.
"""
from __future__ import annotations

import logging
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from .._primitives.registry_fetcher import (
    FileSystemCache,
    HttpGetFetcher,
    default_cache_dir,
)

logger = logging.getLogger(__name__)

_MAX_RESPONSE_BYTES = 10 * 1024 * 1024
_TIMEOUT = 10.0


@dataclass(slots=True)
class ResolverStats:
    """Counters surfaced in the post-scan summary."""

    fetched: int = 0
    cached: int = 0
    failed: int = 0
    skipped: int = 0
    failed_details: list[str] = field(default_factory=list)


class GitLabIncludeFetcher:
    """Fetches remote GitLab CI ``include:`` content.

    All methods return ``bytes | None``. ``None`` means the fetch
    failed; the caller appends to warnings rather than raising.
    """

    def __init__(
        self,
        *,
        gitlab_url: str = "https://gitlab.com",
        token: str | None = None,
        cache: FileSystemCache | None = None,
        http: HttpGetFetcher | None = None,
    ) -> None:
        self.gitlab_url = gitlab_url.rstrip("/")
        self.token = token
        self.cache = cache
        self.http = http or HttpGetFetcher(
            user_agent="pipeline-check-gitlab-resolver",
            timeout=_TIMEOUT,
            max_response_bytes=_MAX_RESPONSE_BYTES,
        )
        self.stats = ResolverStats()

    def fetch(self, kind: str, spec: dict[str, Any]) -> bytes | None:
        """Dispatch to the appropriate fetcher for *kind*.

        Returns raw YAML bytes on success, ``None`` on failure.
        """
        handler = {
            "project": self._fetch_project,
            "remote": self._fetch_remote,
            "template": self._fetch_template,
            "component": self._fetch_component,
        }.get(kind)
        if handler is None:
            self.stats.skipped += 1
            return None
        cache_key = self._cache_key(kind, spec)
        if self.cache and cache_key:
            hit = self.cache.get(cache_key)
            if hit is not None:
                self.stats.cached += 1
                return hit
        data = handler(spec)
        if data is None:
            self.stats.failed += 1
            detail = _describe_include(kind, spec)
            self.stats.failed_details.append(detail)
            return None
        self.stats.fetched += 1
        if self.cache and cache_key:
            self.cache.put(cache_key, data)
        return data

    def _fetch_project(self, spec: dict[str, Any]) -> bytes | None:
        project = spec.get("project", "")
        file_path = spec.get("file", "")
        ref = spec.get("ref", "HEAD")
        if not project or not file_path:
            return None
        encoded_project = urllib.parse.quote(str(project), safe="")
        encoded_file = urllib.parse.quote(str(file_path).lstrip("/"), safe="")
        url = (
            f"{self.gitlab_url}/api/v4/projects/{encoded_project}"
            f"/repository/files/{encoded_file}/raw"
            f"?ref={urllib.parse.quote(str(ref), safe='')}"
        )
        return self._api_get(url)

    def _fetch_remote(self, spec: dict[str, Any]) -> bytes | None:
        url = str(spec.get("remote", ""))
        if not url:
            return None
        if not url.startswith("https://"):
            return None
        return self._http_get(url)

    def _fetch_template(self, spec: dict[str, Any]) -> bytes | None:
        name = str(spec.get("template", ""))
        if not name:
            return None
        encoded = urllib.parse.quote(name, safe="")
        url = f"{self.gitlab_url}/api/v4/templates/gitlab_ci_ymls/{encoded}"
        raw = self._api_get(url)
        if raw is None:
            return None
        # The templates API returns JSON with a "content" field; extract
        # the raw YAML from it.
        import json

        try:
            body = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return raw
        if isinstance(body, dict) and "content" in body:
            content = body["content"]
            if isinstance(content, str):
                return content.encode("utf-8")
        return raw

    def _fetch_component(self, spec: dict[str, Any]) -> bytes | None:
        uri = str(spec.get("component", ""))
        if not uri:
            return None
        # Component URI format: <host>/<project-path>/<component-name>@<version>
        # Split off the version first.
        if "@" not in uri:
            return None
        path_part, version = uri.rsplit("@", 1)
        # Remove the host prefix if it matches our gitlab_url.
        segments = path_part.split("/")
        if len(segments) < 3:
            return None
        # First segment is host (e.g. "gitlab.com"), skip it.
        project_path = "/".join(segments[1:-1])
        component_name = segments[-1]
        file_path = f"templates/{component_name}/template.yml"
        return self._fetch_project({
            "project": project_path,
            "file": file_path,
            "ref": version,
        })

    def _api_get(self, url: str) -> bytes | None:
        """HTTP GET with optional ``PRIVATE-TOKEN`` header."""
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "pipeline-check-gitlab-resolver")
        if self.token:
            req.add_header("PRIVATE-TOKEN", self.token)
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                body: bytes = resp.read(_MAX_RESPONSE_BYTES + 1)
                if len(body) > _MAX_RESPONSE_BYTES:
                    return None
                return body
        except (urllib.error.HTTPError, urllib.error.URLError,
                TimeoutError, OSError):
            return None

    def _http_get(self, url: str) -> bytes | None:
        """Plain HTTP GET (no auth) for ``remote:`` URLs."""
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "pipeline-check-gitlab-resolver")
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                body: bytes = resp.read(_MAX_RESPONSE_BYTES + 1)
                if len(body) > _MAX_RESPONSE_BYTES:
                    return None
                return body
        except (urllib.error.HTTPError, urllib.error.URLError,
                TimeoutError, OSError):
            return None

    @staticmethod
    def _cache_key(kind: str, spec: dict[str, Any]) -> str | None:
        if kind == "project":
            project = spec.get("project", "")
            file_path = spec.get("file", "")
            ref = spec.get("ref", "HEAD")
            return f"gitlab:project:{project}:{file_path}@{ref}"
        if kind == "remote":
            return f"gitlab:remote:{spec.get('remote', '')}"
        if kind == "template":
            return f"gitlab:template:{spec.get('template', '')}"
        if kind == "component":
            return f"gitlab:component:{spec.get('component', '')}"
        return None


def _describe_include(kind: str, spec: dict[str, Any]) -> str:
    """One-line summary of a failed include for warning output."""
    if kind == "project":
        return f"project:{spec.get('project', '?')} file:{spec.get('file', '?')}"
    if kind == "remote":
        return f"remote:{spec.get('remote', '?')}"
    if kind == "template":
        return f"template:{spec.get('template', '?')}"
    if kind == "component":
        return f"component:{spec.get('component', '?')}"
    return f"{kind}:{spec}"


def count_unresolved_remote_includes(
    pipelines: list[Any],
) -> int:
    """Count remote include directives that were not resolved."""
    n = 0
    for pipe in pipelines:
        data = pipe.data if isinstance(pipe.data, dict) else {}
        include_block = data.get("include")
        if include_block is None:
            continue
        items = (
            include_block if isinstance(include_block, list) else [include_block]
        )
        for item in items:
            if isinstance(item, dict) and not item.get("local"):
                if any(k in item for k in ("remote", "project", "template", "component")):
                    n += 1
    return n
