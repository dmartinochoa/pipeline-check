"""SCM posture context and base check.

Loads governance metadata for a single repository from a SCM
platform's REST API (GitHub today; GitLab + Bitbucket are future
work). Each high-value endpoint maps to one slot on the
:class:`SCMRepoSnapshot` dataclass so rule modules consume a
typed view rather than chasing JSON dictionaries.

The fetcher is a Protocol so tests swap in an in-memory map without
touching the network. The HTTP implementation only knows how to GET
public REST endpoints; it never PUTs / POSTs / DELETEs (the scanner
is a posture-reporter, not a remediation tool).
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from ..base import BaseCheck

_DEFAULT_TIMEOUT = 10.0
#: Hard cap on response body size. Real GitHub responses for the
#: endpoints we hit top out at low hundreds of kilobytes; anything
#: larger is either a misrouted endpoint or attacker-controlled and
#: we'd rather treat the fetch as a failure than blow scanner memory.
_MAX_RESPONSE_BYTES = 5 * 1024 * 1024


# ── Fetcher protocol + implementations ────────────────────────────────


class SCMFetcher(Protocol):
    """Fetch a JSON response for an API path. Returns ``None`` on any
    error (network failure, 404, 401, malformed JSON, body too large)
    so the caller surfaces a warning rather than crashing the scan."""

    def fetch(self, path: str) -> dict[str, Any] | list[Any] | None:
        ...


class HttpSCMFetcher:
    """Hit the GitHub REST API at ``api.github.com`` over stdlib
    urllib. ``token`` enables private-repo access and bumps the
    rate-limit ceiling; defaults to ``$GITHUB_TOKEN`` when not given.
    """

    BASE_URL = "https://api.github.com"

    def __init__(
        self,
        token: str | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        self.token = (
            token if token is not None else os.environ.get("GITHUB_TOKEN")
        )
        self.timeout = timeout

    def fetch(self, path: str) -> dict[str, Any] | list[Any] | None:
        url = f"{self.BASE_URL}/{path.lstrip('/')}"
        req = urllib.request.Request(url)  # noqa: S310, fixed scheme + host
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        req.add_header("User-Agent", "pipeline-check-scm")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(  # noqa: S310, fixed scheme + host
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


class DiskSCMFetcher:
    """Look up a JSON file under one or more on-disk roots. The path
    component of the API endpoint becomes the relative filename, with
    ``/`` collapsed to ``_`` so deeply nested endpoint paths fit a
    single directory.

    Useful for offline tests and CI runs that exercise the rule pack
    against a known fixture set without holding an API token. Mirrors
    :class:`pipeline_check.core.checks.github.resolver.DiskFetcher`.
    """

    def __init__(self, search_paths: list[Path]) -> None:
        self.search_paths = [Path(p) for p in search_paths]

    def fetch(self, path: str) -> dict[str, Any] | list[Any] | None:
        # Path-component validation: an attacker-controlled fixture
        # path containing ``..`` segments could escape the search root.
        # Reject parts containing literal ``..`` before resolving.
        flat = path.lstrip("/").replace("/", "_") + ".json"
        if ".." in Path(flat).parts:
            return None
        for root in self.search_paths:
            try:
                root_resolved = root.resolve()
            except OSError:
                continue
            candidate = (root / flat)
            try:
                candidate_resolved = candidate.resolve()
            except OSError:
                continue
            if root_resolved not in candidate_resolved.parents \
                    and candidate_resolved != root_resolved:
                continue
            if candidate_resolved.is_file():
                try:
                    text = candidate_resolved.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    continue
                try:
                    parsed = json.loads(text)
                except ValueError:
                    continue
                if isinstance(parsed, (dict, list)):
                    return parsed
        return None


# ── Snapshot dataclass ────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class SCMRepoSnapshot:
    """Per-repository governance snapshot.

    Each field maps 1:1 to a GitHub REST endpoint. Empty / ``None``
    fields mean either "the API call failed (see ``warnings``)" or
    "the feature isn't enabled and the endpoint returned 404 / 403".
    Rule modules check both shapes — a missing branch protection
    response is itself the failure signal for ``SCM-001``.
    """

    owner: str
    name: str
    #: ``GET /repos/{owner}/{repo}``. Carries ``default_branch``,
    #: ``private`` flag, ``security_and_analysis`` settings (when the
    #: token has admin scope), and the ``allow_*`` PR-merge knobs.
    repo_meta: dict[str, Any] | None = None
    #: ``GET /repos/{owner}/{repo}/branches/{branch}/protection``.
    #: 404 means the default branch has no protection rule at all
    #: (a SCM-001 hit). When present, ``required_pull_request_reviews``,
    #: ``required_status_checks``, and ``required_signatures`` are the
    #: keys SCM-002 / SCM-003-derivatives consult.
    default_branch_protection: dict[str, Any] | None = None
    #: ``GET /repos/{owner}/{repo}/code-scanning/default-setup``.
    #: 404 / not-enabled means default code scanning is off; any other
    #: code-scanning state requires the workflow-uploaded path which
    #: this snapshot doesn't try to enumerate.
    code_scanning_default_setup: dict[str, Any] | None = None


@dataclass(slots=True)
class SCMContext:
    """Loaded posture for one or more repositories.

    Rules iterate :attr:`repos` and emit one :class:`Finding` per
    repo per rule. The single-repo scan path the CLI exposes today
    populates a single-element list; future expansion to org-wide
    scans (``--scm-org``) keeps the same shape.
    """

    repos: list[SCMRepoSnapshot]
    files_scanned: int = 0
    files_skipped: int = 0
    warnings: list[str] = field(default_factory=list)

    @classmethod
    def for_repo(
        cls,
        owner: str,
        name: str,
        fetcher: SCMFetcher,
    ) -> SCMContext:
        """Hydrate a snapshot for a single repo by issuing the API
        calls one slot at a time. Failures land in ``warnings`` and
        leave the corresponding field at ``None`` so rules can
        distinguish "didn't ask" from "asked, got 404".
        """
        warnings: list[str] = []
        repo_meta = fetcher.fetch(f"repos/{owner}/{name}")
        if repo_meta is None:
            warnings.append(
                f"[scm] could not fetch repos/{owner}/{name} — check "
                f"the token (need ``repo`` scope for private repos)."
            )
        elif not isinstance(repo_meta, dict):
            warnings.append(
                f"[scm] repos/{owner}/{name} returned non-object body."
            )
            repo_meta = None
        default_branch = "main"
        if isinstance(repo_meta, dict):
            db = repo_meta.get("default_branch")
            if isinstance(db, str) and db:
                default_branch = db
        protection = fetcher.fetch(
            f"repos/{owner}/{name}/branches/{default_branch}/protection"
        )
        if protection is not None and not isinstance(protection, dict):
            protection = None
        code_scanning = fetcher.fetch(
            f"repos/{owner}/{name}/code-scanning/default-setup"
        )
        if code_scanning is not None and not isinstance(code_scanning, dict):
            code_scanning = None
        snapshot = SCMRepoSnapshot(
            owner=owner,
            name=name,
            repo_meta=repo_meta if isinstance(repo_meta, dict) else None,
            default_branch_protection=protection,
            code_scanning_default_setup=code_scanning,
        )
        ctx = cls(repos=[snapshot])
        ctx.files_scanned = 1
        ctx.warnings = warnings
        return ctx


class SCMBaseCheck(BaseCheck):
    """Base class for SCM posture checks. Mirrors the per-provider
    base classes (``OCIBaseCheck``, ``GitHubBaseCheck``)."""

    PROVIDER = "scm"

    def __init__(self, ctx: SCMContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: SCMContext = ctx


# ── Helpers exposed to rule modules ───────────────────────────────────


def repo_resource(snapshot: SCMRepoSnapshot) -> str:
    """Stable resource handle for SCM findings. Reporters group by
    ``resource`` for the heatmap so the value should be deterministic
    and human-readable: ``github:owner/repo``."""
    return f"github:{snapshot.owner}/{snapshot.name}"


def default_branch_name(snapshot: SCMRepoSnapshot) -> str:
    """Read the repo's default branch name from the meta payload, or
    fall back to ``main`` (the GitHub-side default since 2020)."""
    if not isinstance(snapshot.repo_meta, dict):
        return "main"
    name = snapshot.repo_meta.get("default_branch")
    if isinstance(name, str) and name:
        return name
    return "main"
