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

import fnmatch
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
#: Larger cap for binary endpoints (the Actions run-logs ZIP, fetched by
#: ``fetch_bytes``). Run logs are bigger than JSON metadata but still
#: bounded so a pathological response can't exhaust memory.
_MAX_BINARY_RESPONSE_BYTES = 25 * 1024 * 1024


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
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        req.add_header("User-Agent", "pipeline-check-scm")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
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

    def fetch_bytes(
        self, path: str, *, max_bytes: int = _MAX_BINARY_RESPONSE_BYTES,
    ) -> bytes | None:
        """Fetch a raw binary response (the Actions run-logs ZIP).

        urllib follows the logs endpoint's 302 redirect to the signed
        blob URL automatically. Returns ``None`` on any error or when the
        body exceeds *max_bytes*, mirroring :meth:`fetch`'s
        degrade-don't-raise contract.
        """
        url = f"{self.BASE_URL}/{path.lstrip('/')}"
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        req.add_header("User-Agent", "pipeline-check-scm")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body: bytes = resp.read(max_bytes + 1)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            return None
        if len(body) > max_bytes:
            return None
        return body


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
    #: ``GET /repos/{owner}/{repo}/actions/permissions``. Carries the
    #: ``enabled`` master switch and ``allowed_actions`` allowlist
    #: mode (``all`` / ``local_only`` / ``selected``). ``SCM-022``
    #: reads this slot. ``None`` when the token lacks admin scope or
    #: actions are disabled on the plan.
    actions_permissions: dict[str, Any] | None = None
    #: ``GET /repos/{owner}/{repo}/actions/permissions/workflow``.
    #: Carries ``default_workflow_permissions`` (``read`` /
    #: ``write``) — the default GITHUB_TOKEN scope new workflows
    #: get — and ``can_approve_pull_request_reviews`` (whether
    #: GitHub Actions can submit PR reviews). ``SCM-020`` / ``SCM-
    #: 021`` read this slot.
    actions_workflow_permissions: dict[str, Any] | None = None
    #: ``GET /repos/{owner}/{repo}/environments``. List of deploy
    #: environments with their ``protection_rules`` (required
    #: reviewers, wait timers) and ``deployment_branch_policy``
    #: (branch / tag allowlist). ``SCM-023`` / ``SCM-024`` walk this
    #: slot. ``None`` when the endpoint failed; empty ``environments``
    #: list (``{"total_count": 0}``) when no environments configured.
    environments: dict[str, Any] | None = None
    #: ``GET /repos/{owner}/{repo}/keys``. List of deploy keys, each
    #: ``{"id", "title", "key", "read_only", ...}``. ``SCM-025`` reads
    #: this slot to flag write-enabled keys (``read_only: false``).
    #: ``None`` when the endpoint failed or the token lacks admin
    #: scope; empty list ``[]`` when no deploy keys are configured.
    deploy_keys: list[dict[str, Any]] | None = None
    #: ``GET /repos/{owner}/{repo}/hooks``. List of webhooks, each
    #: ``{"id", "name", "active", "events", "config": {"url",
    #: "content_type", "secret", "insecure_ssl"}, ...}``. ``SCM-026``
    #: reads this slot to flag plain-HTTP URLs, ``insecure_ssl: "1"``,
    #: and missing webhook secrets. ``None`` when the endpoint failed
    #: or the token lacks admin scope.
    webhooks: list[dict[str, Any]] | None = None
    #: ``GET /repos/{owner}/{repo}/collaborators?affiliation=outside&
    #: per_page=100``. List of outside collaborators, each
    #: ``{"login", "permissions": {"admin", "maintain", "push",
    #: "triage", "pull"}, ...}``. ``SCM-027`` reads this slot to
    #: flag elevated-permission outside collaborators. ``None``
    #: when the endpoint failed or the token lacks admin scope;
    #: empty list when no outside collaborators are configured. The
    #: hydrator fetches only the first page (per_page=100) to keep
    #: scan cost bounded; rules note the truncation when a list of
    #: exactly 100 entries comes back.
    outside_collaborators: list[dict[str, Any]] | None = None
    #: ``GET /repos/{owner}/{repo}/rulesets``. List of repository
    #: rulesets (the newer alternative / supplement to legacy branch
    #: protection), each ``{"id", "name", "target", "source_type",
    #: "enforcement", ...}``. ``SCM-029`` reads this slot to flag
    #: rulesets in non-enforcing modes (``evaluate`` / ``disabled``).
    #: ``None`` when the endpoint failed; empty list ``[]`` when no
    #: rulesets are configured (in which case the SCM-001..010
    #: legacy branch-protection rules carry the governance load).
    rulesets: list[dict[str, Any]] | None = None
    #: ``GET /repos/{owner}/{repo}/languages``. Mapping of language
    #: name (GitHub's linguist label, e.g. ``"Python"``, ``"Go"``,
    #: ``"JavaScript"``) to byte count. SCM-047 cross-checks this
    #: against ``code_scanning_default_setup.languages`` to flag
    #: CodeQL-supported languages present in the repo but excluded
    #: from default scanning. ``None`` when the endpoint failed;
    #: empty dict when the repo has no detectable source.
    repo_languages: dict[str, int] | None = None
    #: ``GET /orgs/{owner}/codespaces/secrets``. List of org-level
    #: codespace secrets, each ``{"name", "visibility",
    #: "selected_repositories_url", ...}``. SCM-048 flags secrets
    #: whose ``visibility`` is ``"all"`` (exposed to every repo in
    #: the org). ``None`` when the endpoint failed (token lacks
    #: ``admin:org`` scope, owner is a user not an org, etc.);
    #: empty list ``[]`` when no org codespace secrets are configured.
    codespace_secrets: list[dict[str, Any]] | None = None
    #: Token type used for API authentication, inferred from the
    #: token prefix. ``"classic"`` for ``ghp_`` classic PATs,
    #: ``"fine-grained"`` for ``github_pat_`` fine-grained PATs,
    #: ``"oauth"`` for ``gho_`` OAuth tokens, ``"app"`` for
    #: ``ghs_`` / ``ghr_`` GitHub App tokens, ``"unknown"`` when
    #: the prefix doesn't match a known pattern, ``None`` when no
    #: token was provided. SCM-049 reads this slot.
    token_type: str | None = None


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
        # Actions governance: two endpoints carry the Actions-side
        # supply-chain knobs (token scope, self-approval, allow-list).
        # Both require ``admin`` scope on the repo; without it GitHub
        # returns 403 / 404 and the rule pack passes silently with a
        # "scope unavailable" note.
        actions_permissions: dict[str, Any] | None = None
        actions_workflow_permissions: dict[str, Any] | None = None
        environments: dict[str, Any] | None = None
        deploy_keys: list[dict[str, Any]] | None = None
        webhooks: list[dict[str, Any]] | None = None
        outside_collaborators: list[dict[str, Any]] | None = None
        rulesets: list[dict[str, Any]] | None = None
        repo_languages: dict[str, int] | None = None
        if isinstance(repo_meta, dict):
            raw_ap = fetcher.fetch(f"repos/{owner}/{name}/actions/permissions")
            if isinstance(raw_ap, dict):
                actions_permissions = raw_ap
            raw_awp = fetcher.fetch(
                f"repos/{owner}/{name}/actions/permissions/workflow"
            )
            if isinstance(raw_awp, dict):
                actions_workflow_permissions = raw_awp
            raw_envs = fetcher.fetch(f"repos/{owner}/{name}/environments")
            if isinstance(raw_envs, dict):
                environments = raw_envs
            raw_keys = fetcher.fetch(f"repos/{owner}/{name}/keys")
            if isinstance(raw_keys, list):
                deploy_keys = [k for k in raw_keys if isinstance(k, dict)]
            raw_hooks = fetcher.fetch(f"repos/{owner}/{name}/hooks")
            if isinstance(raw_hooks, list):
                webhooks = [h for h in raw_hooks if isinstance(h, dict)]
            raw_outside = fetcher.fetch(
                f"repos/{owner}/{name}/collaborators"
                "?affiliation=outside&per_page=100"
            )
            if isinstance(raw_outside, list):
                outside_collaborators = [
                    u for u in raw_outside if isinstance(u, dict)
                ]
            # The rulesets list endpoint defaults to ``per_page=30``
            # and paginates; bump to the maximum so a repo with a
            # mid-sized ruleset count fits in a single page. A list
            # at exactly the page cap is potentially truncated; warn
            # so the operator audits manually (mirrors the
            # collaborators pattern above).
            raw_rulesets = fetcher.fetch(
                f"repos/{owner}/{name}/rulesets?per_page=100"
            )
            if isinstance(raw_rulesets, list):
                rulesets = [r for r in raw_rulesets if isinstance(r, dict)]
                if len(rulesets) == 100:
                    warnings.append(
                        f"[scm] repos/{owner}/{name}/rulesets returned "
                        "100 entries; additional pages may exist and "
                        "are not audited by this scan."
                    )
                # Hydrate per-ruleset details for any active entry.
                # The list endpoint returns only ``id`` / ``name`` /
                # ``target`` / ``enforcement``; ``bypass_actors`` and
                # the per-rule body live behind a per-id GET. We only
                # follow up on ``active`` rulesets — non-active ones
                # are already SCM-029's surface and their internals
                # don't affect runtime behavior anyway. Bounded
                # ``ruleset_id`` extraction keeps the fetch list to
                # the small handful of active rulesets a repo
                # typically has.
                for rs in rulesets:
                    if rs.get("enforcement") != "active":
                        continue
                    rs_id = rs.get("id")
                    if not isinstance(rs_id, int):
                        continue
                    raw_detail = fetcher.fetch(
                        f"repos/{owner}/{name}/rulesets/{rs_id}"
                    )
                    if isinstance(raw_detail, dict):
                        # Merge in place; the list entry's basic
                        # fields (id, name, enforcement) round-trip
                        # safely since the detail endpoint returns
                        # the same values.
                        rs.update(raw_detail)
                    else:
                        # Detail fetch failed (403 / 404 / timeout).
                        # Mark the ruleset so SCM-030 can distinguish
                        # "clean bypass list" (no offenders) from
                        # "couldn't fetch the bypass list" (data
                        # unavailable) — the silent-pass mistake.
                        rs["_detail_unavailable"] = True
            # Linguist-detected language byte counts. SCM-047 reads
            # this to flag CodeQL-supported languages present in the
            # repo but excluded from default code scanning. Endpoint
            # is public-readable; a None return means the fetch
            # failed (rule passes with an "unavailable" note).
            raw_languages = fetcher.fetch(f"repos/{owner}/{name}/languages")
            if isinstance(raw_languages, dict):
                repo_languages = {
                    k: v for k, v in raw_languages.items()
                    if isinstance(k, str) and isinstance(v, int)
                }
        # Infer the token type from its prefix so SCM-049 can
        # recommend fine-grained tokens over classic PATs.
        token_type: str | None = None
        token_value: str | None = None
        if isinstance(fetcher, HttpSCMFetcher):
            token_value = fetcher.token
        if token_value:
            if token_value.startswith("ghp_"):
                token_type = "classic"
            elif token_value.startswith("github_pat_"):
                token_type = "fine-grained"
            elif token_value.startswith("gho_"):
                token_type = "oauth"
            elif token_value.startswith(("ghs_", "ghr_")):
                token_type = "app"
            else:
                token_type = "unknown"
        # Org-level codespace secrets. The endpoint is org-scoped
        # (``/orgs/{owner}/...``), not repo-scoped; it returns 404
        # for user-owned repos and 403 without ``admin:org`` scope.
        # Both failures land as ``None`` so the SCM-048 rule passes
        # silently with an "unavailable" note.
        codespace_secrets: list[dict[str, Any]] | None = None
        if isinstance(repo_meta, dict):
            raw_cs_secrets = fetcher.fetch(
                f"orgs/{owner}/codespaces/secrets?per_page=100"
            )
            if isinstance(raw_cs_secrets, dict):
                secrets_list = raw_cs_secrets.get("secrets")
                if isinstance(secrets_list, list):
                    codespace_secrets = [
                        s for s in secrets_list if isinstance(s, dict)
                    ]
            elif isinstance(raw_cs_secrets, list):
                codespace_secrets = [
                    s for s in raw_cs_secrets if isinstance(s, dict)
                ]
        snapshot = SCMRepoSnapshot(
            owner=owner,
            name=name,
            repo_meta=repo_meta if isinstance(repo_meta, dict) else None,
            default_branch_protection=protection,
            code_scanning_default_setup=code_scanning,
            codeowners_path=codeowners_path,
            actions_permissions=actions_permissions,
            actions_workflow_permissions=actions_workflow_permissions,
            environments=environments,
            deploy_keys=deploy_keys,
            webhooks=webhooks,
            outside_collaborators=outside_collaborators,
            rulesets=rulesets,
            repo_languages=repo_languages,
            codespace_secrets=codespace_secrets,
            token_type=token_type,
        )
        ctx = cls(repos=[snapshot])
        ctx.files_scanned = 1
        ctx.warnings = warnings
        return ctx


class SCMBaseCheck(BaseCheck[SCMContext]):
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


def gitlab_only_skip(snapshot: SCMRepoSnapshot) -> str | None:
    """Return a skip note when the snapshot is not from GitLab.

    Mirror of :func:`github_only_skip` for the GitLab-specific
    rule pack (SCM-050..053). Rules read GitLab-shaped payloads
    stashed under ``repo_meta["_gitlab_project"]`` /
    ``repo_meta["_gitlab_push_rule"]`` by the GitLab hydrator.
    """
    if snapshot.platform == "gitlab":
        return None
    return (
        f"Rule is GitLab-specific (reads GitLab push-rule / "
        f"merge-request settings); skipped on the "
        f"{snapshot.platform} snapshot."
    )


def bitbucket_only_skip(snapshot: SCMRepoSnapshot) -> str | None:
    """Return a skip note when the snapshot is not from Bitbucket.

    Mirror of :func:`github_only_skip` for the Bitbucket-specific
    rule pack (SCM-054..055). Rules read Bitbucket-shaped payloads
    stashed under ``repo_meta["_bitbucket_repo"]`` by the
    Bitbucket Cloud hydrator.
    """
    if snapshot.platform == "bitbucket":
        return None
    return (
        f"Rule is Bitbucket-specific (reads Bitbucket Cloud repo "
        f"settings); skipped on the {snapshot.platform} snapshot."
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


# ── Ruleset scoping helpers ───────────────────────────────────────


def _matches_default_branch_ref(pattern: str, default_branch: str) -> bool:
    """True if a GitHub Rulesets ref-name pattern matches the repo's
    default branch.

    Recognized forms:
      * ``"~ALL"``             — wildcard, matches every ref.
      * ``"~DEFAULT_BRANCH"``  — the literal default-branch token.
      * ``"refs/heads/<X>"``   — exact match when ``X == default_branch``.
      * fnmatch globs          — e.g. ``"refs/heads/**"``,
        ``"refs/heads/release/**"`` matched against
        ``"refs/heads/<default_branch>"`` with ``fnmatchcase``.

    Globs are matched literally (no Bash-style brace expansion); the
    rulesets API only emits fnmatch shapes today.
    """
    if pattern == "~ALL" or pattern == "~DEFAULT_BRANCH":
        return True
    ref = f"refs/heads/{default_branch}"
    if pattern == ref:
        return True
    return fnmatch.fnmatchcase(ref, pattern)


def ruleset_targets_default_branch(
    ruleset: dict[str, Any], default_branch: str,
) -> bool:
    """True if a ruleset's branch-target conditions include the
    default branch and don't exclude it.

    Tag-only rulesets (``target: "tag"``), push-only rulesets, and
    rulesets whose ``conditions.ref_name.include`` never matches the
    default branch return ``False``. A missing ``target`` field is
    treated as ``"branch"`` — GitHub's UI defaults the field and
    some legacy / minimal fixtures omit it.

    Rulesets without a populated ``conditions.ref_name.include``
    can't be evaluated; this returns ``False`` so the caller's
    "scoped away from default" branch fires rather than a silent
    pass.
    """
    target = ruleset.get("target")
    if target not in (None, "branch"):
        return False
    conditions = ruleset.get("conditions")
    if not isinstance(conditions, dict):
        return False
    ref_name = conditions.get("ref_name")
    if not isinstance(ref_name, dict):
        return False
    include = ref_name.get("include")
    if not isinstance(include, list) or not include:
        return False
    exclude = ref_name.get("exclude")
    if not isinstance(exclude, list):
        exclude = []
    if any(
        isinstance(p, str)
        and _matches_default_branch_ref(p, default_branch)
        for p in exclude
    ):
        return False
    return any(
        isinstance(p, str)
        and _matches_default_branch_ref(p, default_branch)
        for p in include
    )


def active_rulesets_targeting_default(
    snapshot: SCMRepoSnapshot,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    """Partition active rulesets into three buckets:

      1. ``targeting``    — active + detail available + the
                            ``conditions.ref_name`` filter includes
                            (and doesn't exclude) the default
                            branch. These are the rulesets that
                            actually enforce on the default branch
                            and are what per-rule-type checks
                            (SCM-032..040) should iterate.
      2. ``unavailable``  — active but the per-ruleset detail fetch
                            failed (``_detail_unavailable: True``);
                            target can't be determined. Surface as
                            "not fully evaluated".
      3. ``scoped_away``  — active + detail available + branch-
                            targeted but the ``conditions.ref_name``
                            filter doesn't include the default
                            branch (tag-only, feature-branch-only,
                            exclude list shadows the default). These
                            are the false-pass shape: a ruleset that
                            exists but doesn't protect ``main``.

    Non-active rulesets (``evaluate`` / ``disabled``) are filtered
    out — they're SCM-029's surface. Push-targeted rulesets are also
    filtered out: they fire on every push but use a different rule
    shape (file size / path / extension filters) that can't carry
    the SCM-032..040 rule types, so classifying them as scoped-away
    would emit a confusing "doesn't target the default branch"
    failure for a ruleset that does. Tag-targeted rulesets stay in
    scope of the branch-rule checks only when their ref_name filter
    matches the default branch, which it generally won't; they
    surface as scoped_away. Returns three empty lists when
    ``snapshot.rulesets`` is ``None``.
    """
    if snapshot.rulesets is None:
        return [], [], []
    default = default_branch_name(snapshot)
    targeting: list[dict[str, Any]] = []
    unavailable: list[dict[str, Any]] = []
    scoped_away: list[dict[str, Any]] = []
    for rs in snapshot.rulesets:
        if rs.get("enforcement") != "active":
            continue
        if rs.get("_detail_unavailable") is True:
            unavailable.append(rs)
            continue
        if rs.get("target") == "push":
            continue
        if ruleset_targets_default_branch(rs, default):
            targeting.append(rs)
        else:
            scoped_away.append(rs)
    return targeting, unavailable, scoped_away


def ruleset_label(ruleset: dict[str, Any]) -> str:
    """Human-readable label for a ruleset finding. Prefers ``name``,
    falls back to ``ruleset:<id>``, finally ``(unnamed)``."""
    name = ruleset.get("name")
    rs_id = ruleset.get("id")
    if isinstance(name, str) and name:
        return name
    if isinstance(rs_id, int):
        return f"ruleset:{rs_id}"
    return "(unnamed)"
