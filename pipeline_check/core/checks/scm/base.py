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
    #: Platform this snapshot was hydrated from. ``"github"`` is the
    #: default (covered by every rule); ``"gitlab"`` / ``"bitbucket"``
    #: subset the rule pack to the universal rules (SCM-001, -002,
    #: -006, -007, -008, -009, -017). Platform-specific rules
    #: (``security_and_analysis``-driven, GitHub-only review knobs)
    #: pass silently with a "not applicable on PLATFORM" note when
    #: the snapshot platform is not GitHub.
    platform: str = "github"
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
    #: The canonical CODEOWNERS path that actually exists in the repo
    #: (``.github/CODEOWNERS``, ``CODEOWNERS``, or ``docs/CODEOWNERS``),
    #: or ``None`` when no CODEOWNERS file is present at any of the
    #: three GitHub-recognized locations. ``SCM-017`` reads this slot.
    #: Populated via ``GET /repos/{owner}/{repo}/contents/<path>`` —
    #: the first 200 response wins.
    codeowners_path: str | None = None


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
        # When repo_meta failed we don't know the default branch
        # name; probing ``branches/main/protection`` would FP for
        # any repo whose default branch is not literally ``main``.
        # Skip downstream probes entirely; the rules detect
        # ``repo_meta is None`` and pass with an unavailable note.
        protection: dict[str, Any] | None = None
        code_scanning: dict[str, Any] | None = None
        codeowners_path: str | None = None
        if isinstance(repo_meta, dict):
            db = repo_meta.get("default_branch")
            default_branch = db if isinstance(db, str) and db else "main"
            raw_protection = fetcher.fetch(
                f"repos/{owner}/{name}/branches/{default_branch}/protection"
            )
            if isinstance(raw_protection, dict):
                protection = raw_protection
            raw_cs = fetcher.fetch(
                f"repos/{owner}/{name}/code-scanning/default-setup"
            )
            if isinstance(raw_cs, dict):
                code_scanning = raw_cs
            # GitHub recognizes CODEOWNERS in three canonical locations;
            # the first one that responds 200 wins. The contents endpoint
            # returns a dict with ``type: "file"`` for an existing file
            # and 404 (→ ``None`` here) when absent.
            for candidate in (
                ".github/CODEOWNERS",
                "CODEOWNERS",
                "docs/CODEOWNERS",
            ):
                raw_co = fetcher.fetch(
                    f"repos/{owner}/{name}/contents/{candidate}"
                )
                if isinstance(raw_co, dict) and raw_co.get("type") == "file":
                    codeowners_path = candidate
                    break
        snapshot = SCMRepoSnapshot(
            owner=owner,
            name=name,
            repo_meta=repo_meta if isinstance(repo_meta, dict) else None,
            default_branch_protection=protection,
            code_scanning_default_setup=code_scanning,
            codeowners_path=codeowners_path,
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
    and human-readable: ``<platform>:owner/repo``."""
    return f"{snapshot.platform}:{snapshot.owner}/{snapshot.name}"


def default_branch_name(snapshot: SCMRepoSnapshot) -> str:
    """Read the repo's default branch name from the meta payload, or
    fall back to ``main`` (the GitHub-side default since 2020)."""
    if not isinstance(snapshot.repo_meta, dict):
        return "main"
    name = snapshot.repo_meta.get("default_branch")
    if isinstance(name, str) and name:
        return name
    return "main"


def is_archived(snapshot: SCMRepoSnapshot) -> bool:
    """Whether the repo is archived (read-only).

    GitHub auto-disables Dependabot, secret scanning, secret-scanning
    push protection, and code scanning on archived repos. Without
    this guard, every ``security_and_analysis``-driven rule would
    misfire on every archived repo regardless of historical posture.

    The signal is ``repo_meta.archived: true``. Returns ``False``
    when ``repo_meta`` is missing — failed-fetch shouldn't be
    treated as archived.
    """
    meta = snapshot.repo_meta
    if not isinstance(meta, dict):
        return False
    return bool(meta.get("archived"))


def is_disabled(snapshot: SCMRepoSnapshot) -> bool:
    """Whether the repo is administratively disabled.

    GitHub disables a repo (TOS, billing, abuse) by setting
    ``repo_meta.disabled: true``. Reads against a disabled repo
    are partial; we treat them the same as archived for guard
    purposes.
    """
    meta = snapshot.repo_meta
    if not isinstance(meta, dict):
        return False
    return bool(meta.get("disabled"))


def is_empty_repo(snapshot: SCMRepoSnapshot) -> bool:
    """Whether the repo has no commits / no default branch yet.

    Two production signals concur:

      * ``repo_meta.size == 0`` (disk usage in KB; a brand-new repo
        with no commits has size 0).
      * The branch-protection endpoint returned 404 — caught by
        ``snapshot.default_branch_protection is None``. We don't
        rely on this alone because a non-empty repo with no
        protection rule produces the same shape; the size signal
        disambiguates.

    Returns ``True`` only when both hold. Without this guard,
    ``SCM-001`` (default branch unprotected) misfires on every
    fresh repo with the "no protection rule" message even though
    there is no commit to protect.
    """
    meta = snapshot.repo_meta
    if not isinstance(meta, dict):
        return False
    size = meta.get("size")
    if not isinstance(size, int) or size != 0:
        return False
    return snapshot.default_branch_protection is None


def archived_state_label(snapshot: SCMRepoSnapshot) -> str | None:
    """Return ``"archived"`` / ``"disabled"`` if applicable, else ``None``.

    Single read-only helper that rules call to decide whether a
    GitHub-auto-disabled feature should suppress their failure
    signal. Returns ``None`` when neither flag is set so callers
    use ``if label := archived_state_label(snap): ...`` for the
    early-skip pattern.
    """
    if is_archived(snapshot):
        return "archived"
    if is_disabled(snapshot):
        return "disabled"
    return None


def github_only_skip(
    snapshot: SCMRepoSnapshot,
) -> str | None:
    """Return a "not applicable on PLATFORM" note when the snapshot
    came from a non-GitHub platform, else ``None``.

    Platform-specific rules call this at the top of their ``check``
    function and pass silently when the response is non-``None``.
    The string content goes into the Finding description so the
    operator sees the rule was deliberately skipped rather than
    silently passing.
    """
    if snapshot.platform == "github":
        return None
    return (
        f"Rule is GitHub-specific (relies on the "
        f"``security_and_analysis`` block or a GitHub-only "
        f"protection knob); skipped on the {snapshot.platform} "
        f"snapshot."
    )


def security_feature_state(
    snapshot: SCMRepoSnapshot, feature: str,
) -> str | None:
    """Read ``security_and_analysis.<feature>.status`` from repo meta.

    Returns the status string (``"enabled"`` / ``"disabled"``) or
    ``None`` when the data is unavailable. Three production cases
    produce ``None``:

      * The token lacks ``admin`` scope on the repo — GitHub omits
        the entire ``security_and_analysis`` block.
      * The repo is on a plan that doesn't expose the feature
        (e.g. private-repo Dependabot on a free org).
      * The repo metadata fetch itself failed.

    Rules that map to these features should add a ``known_fp`` note
    explaining the scope-omission case so the user can distinguish
    "really disabled" from "I lacked visibility."
    """
    meta = snapshot.repo_meta
    if not isinstance(meta, dict):
        return None
    sa = meta.get("security_and_analysis")
    if not isinstance(sa, dict):
        return None
    feat = sa.get(feature)
    if not isinstance(feat, dict):
        return None
    status = feat.get("status")
    if isinstance(status, str):
        return status
    return None
