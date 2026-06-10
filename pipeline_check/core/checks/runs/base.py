"""Run-history forensics context.

Pulls recent GitHub Actions runs via the REST API
(``GET /repos/{owner}/{repo}/actions/runs``) and exposes them as
:class:`RunRecord` snapshots so rules can reason about what *actually
executed*: which privileged triggers fired, and whether any ran
untrusted fork code. Reuses the SCM provider's ``SCMFetcher`` (urllib +
``GITHUB_TOKEN``, with a disk-fixture mode for offline tests), so a
missing token / 404 / network error degrades to a warning rather than a
crash (every rule then sees an empty run list and passes).

    pipeline_check --pipeline runs --scm-repo owner/name [--gh-token <t>]
"""
from __future__ import annotations

import io
import re
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..base import BaseCheck

#: How many recent runs to audit. The Actions API caps ``per_page`` at
#: 100; one page is ample forensic signal without paginating all history.
DEFAULT_RUN_LIMIT = 100

#: Log scanning (``--audit-runs-logs``) downloads a ZIP per run, so it is
#: bounded: at most this many privileged-trigger runs are fetched, each
#: log file is read up to ``_MAX_LOG_FILE_BYTES`` and the whole run's
#: decompressed text is capped at ``_MAX_LOG_TOTAL_BYTES`` (a guard
#: against a pathological / zip-bomb log archive).
DEFAULT_LOG_FETCH_LIMIT = 25
_MAX_LOG_FILE_BYTES = 5 * 1024 * 1024
_MAX_LOG_TOTAL_BYTES = 50 * 1024 * 1024

#: Job-metadata fetch (for self-hosted-runner detection) downloads one
#: ``.../jobs`` page per fork run, so it is bounded the same way.
DEFAULT_JOBS_FETCH_LIMIT = 25

#: Known-compromised-action forensics (RUN-006) is not trigger-specific:
#: the tj-actions / Trivy / Checkmarx campaigns ran on ordinary push / PR
#: runs, not just the privileged-trigger subset RUN-003 / RUN-004 scan. So
#: a separate bounded pass downloads logs for the most recent runs of *any*
#: trigger and scans them for the IOC match only (no secret detector). The
#: privileged subset is already covered by the secrets pass, so this pass
#: skips it to avoid re-downloading.
DEFAULT_ACTION_LOG_FETCH_LIMIT = 25

#: Triggers that execute in the *base* repository's privileged context
#: (repo secrets + a write-scoped ``GITHUB_TOKEN``) while potentially
#: handling PR-controlled content. A run that actually fired on one of
#: these is live evidence of the pwn-request attack surface, not just a
#: static "the config allows it".
PRIVILEGED_TRIGGERS: frozenset[str] = frozenset({
    "pull_request_target", "workflow_run",
})

#: Markers that a run's logs exercised cloud OIDC token minting. Tight by
#: design (near-zero false positive): these strings essentially only occur
#: in an OIDC flow -- GitHub's OIDC issuer / token-request env, the AWS STS
#: web-identity call, and GCP workload-identity federation. Recall is
#: best-effort (log content varies and registered secrets are masked),
#: matching the best-effort nature of run-log forensics.
_OIDC_MARKERS_RE = re.compile(
    r"token\.actions\.githubusercontent\.com"
    r"|ACTIONS_ID_TOKEN_REQUEST_(?:URL|TOKEN)"
    r"|AssumeRoleWithWebIdentity"
    r"|workloadIdentityPools",
)

#: GitHub's "Set up job" step prints one line per resolved action,
#: ``Download action repository 'owner/repo@ref' (SHA:<resolved-commit>)``.
#: The line carries both the ref the workflow pinned *and* the commit it
#: actually resolved to, so it is the runtime record that catches a
#: tag-repoint (the workflow says ``@v44`` but the tag now points at a
#: malicious SHA). The optional sub-path (``owner/repo/path@ref``) and a
#: leading log timestamp are tolerated.
_ACTION_DOWNLOAD_RE = re.compile(
    r"Download action repository '"
    r"([^/'@\s]+)/([^/'@\s]+)(?:/[^'@\s]*)?@([^'\s]+)'"
    r"(?:\s*\(SHA:\s*([0-9a-fA-F]+)\))?",
)


def _scan_compromised_actions(text: str) -> dict[str, str]:
    """Return ``{label: advisory}`` for known-compromised actions whose
    download line appears in *text*, or an empty dict.

    Each ``Download action repository`` line is matched against the
    curated GHA-040 IOC registry on both the pinned ref and the resolved
    commit SHA: a workflow pinned to ``@v44`` still trips the rule when
    the log shows ``v44`` resolved to the registry's malicious commit
    (the tag-repoint case). ``lookup`` is imported lazily so a
    metadata-only scan never pays for the GitHub rule package import.
    """
    from ..github._compromised_actions import lookup
    out: dict[str, str] = {}
    for m in _ACTION_DOWNLOAD_RE.finditer(text):
        owner, repo, ref, sha = m.group(1), m.group(2), m.group(3), m.group(4)
        entry = lookup(owner, repo, ref)
        if entry is None and sha:
            entry = lookup(owner, repo, sha)
        if entry is not None:
            label = f"{owner}/{repo}@{ref}"
            if sha and sha.lower() != ref.lower():
                label += f" (resolved SHA {sha[:12]})"
            out[label] = entry.advisory
    return out


#: Action owners treated as first-party and never flagged by RUN-007:
#: GitHub's own namespaces. The scanned repo's own owner is excluded
#: separately (an org pinning its own actions by tag is an internal-trust
#: decision, not a third-party supply-chain exposure).
_FIRST_PARTY_ACTION_OWNERS = frozenset({"actions", "github"})

#: A 40-character hex string is an immutable Git commit SHA. Anything else
#: in the ``@ref`` slot (a tag like ``v4`` / ``v1.2.3``, or a branch) is
#: mutable and can be force-moved, the tj-actions/changed-files repoint
#: vector.
_FULL_SHA_RE = re.compile(r"\A[0-9a-fA-F]{40}\Z")


def _scan_unpinned_actions(text: str, repo_owner: str) -> list[str]:
    """Return sorted ``owner/repo@ref`` labels for third-party actions a run
    resolved from a *mutable* ref (a tag or branch, not a 40-hex commit
    SHA), or an empty list.

    Mirrors :func:`_scan_compromised_actions` over the same
    ``Download action repository`` lines, but instead of an IOC match it
    flags pin hygiene: a third-party action pinned by a ref the upstream can
    force-move (the tj-actions/changed-files repoint vector) that actually
    executed. First-party (``actions`` / ``github``) and the repo's own
    actions are excluded, since they are not a third-party supply-chain
    exposure. Each label carries the resolved commit SHA (when the log
    records one) so the evidence shows what the tag pointed at.
    """
    owner_lc = repo_owner.lower()
    out: set[str] = set()
    for m in _ACTION_DOWNLOAD_RE.finditer(text):
        owner, repo, ref, sha = m.group(1), m.group(2), m.group(3), m.group(4)
        lc = owner.lower()
        if lc in _FIRST_PARTY_ACTION_OWNERS or lc == owner_lc:
            continue
        if _FULL_SHA_RE.match(ref):
            continue  # already pinned by an immutable commit SHA
        label = f"{owner}/{repo}@{ref}"
        if sha:
            label += f" (resolved SHA {sha[:12]})"
        out.add(label)
    return sorted(out)


def _str(value: Any) -> str:
    return value if isinstance(value, str) else ""


@dataclass(frozen=True, slots=True)
class RunRecord:
    """Forensic metadata for one workflow run."""

    run_id: int
    name: str
    event: str
    status: str
    conclusion: str | None
    head_branch: str
    actor: str
    head_repo: str   # head_repository.full_name ("" when absent)
    base_repo: str   # repository.full_name
    is_fork: bool     # head_repository.fork
    run_attempt: int
    html_url: str
    created_at: str

    @property
    def from_fork(self) -> bool:
        """True when the run's head came from a fork (untrusted code).

        Prefer the explicit ``fork`` flag; fall back to comparing the
        head vs base repo full names, since a fork's ``head_repository``
        differs from the base ``repository``.
        """
        if self.is_fork:
            return True
        return bool(
            self.head_repo and self.base_repo
            and self.head_repo != self.base_repo
        )


@dataclass
class RunsContext:
    """Recent Actions runs for one repository."""

    owner: str
    name: str
    runs: list[RunRecord] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    files_scanned: int = 0   # repurposed: number of runs audited
    files_skipped: int = 0
    #: run_id -> sorted, deduped "detector:redacted" labels for secrets
    #: found in that run's logs (only populated when ``scan_logs=True``).
    log_leaks: dict[int, list[str]] = field(default_factory=dict)
    #: run_ids whose logs show a cloud OIDC token was minted (only
    #: populated when ``scan_logs=True``); RUN-004 escalates the fork subset.
    oidc_mint_runs: set[int] = field(default_factory=set)
    #: run_id -> the self-hosted runner's joined labels, for fork runs that
    #: executed on a self-hosted runner (only populated when ``scan_logs=True``).
    self_hosted_runs: dict[int, str] = field(default_factory=dict)
    #: run_id -> {``owner/repo@ref`` label: advisory} for runs whose logs show
    #: a known-compromised action (the GHA-040 IOC registry) actually
    #: executed (only populated when ``scan_logs=True``); RUN-006 reports it.
    compromised_action_runs: dict[int, dict[str, str]] = field(default_factory=dict)
    #: run_id -> sorted ``owner/repo@ref`` labels for third-party actions a
    #: privileged run resolved from a mutable tag/branch (not a commit SHA);
    #: the preventive twin of ``compromised_action_runs`` (only populated when
    #: ``scan_logs=True``, privileged-trigger runs only); RUN-007 reports it.
    unpinned_action_runs: dict[int, list[str]] = field(default_factory=dict)
    #: True once deep auditing (logs + job metadata) was requested + attempted,
    #: so RUN-003 / RUN-004 / RUN-005 can tell "nothing found" from "never run".
    logs_scanned: bool = False

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.name}"

    @classmethod
    def for_repo(
        cls,
        owner: str,
        name: str,
        fetcher: Any,
        limit: int = DEFAULT_RUN_LIMIT,
        *,
        scan_logs: bool = False,
        log_fetch_limit: int = DEFAULT_LOG_FETCH_LIMIT,
    ) -> RunsContext:
        ctx = cls(owner=owner, name=name)
        per_page = max(1, min(limit, 100))
        raw = fetcher.fetch(
            f"repos/{owner}/{name}/actions/runs?per_page={per_page}"
        )
        if not isinstance(raw, dict):
            ctx.warnings.append(
                f"[runs] could not fetch Actions run history for "
                f"{owner}/{name} (missing token, 404, or network error); "
                "run forensics produced no findings."
            )
            return ctx
        run_list = raw.get("workflow_runs")
        if not isinstance(run_list, list):
            ctx.warnings.append(
                f"[runs] {owner}/{name}: unexpected actions/runs payload "
                "(no ``workflow_runs`` array)."
            )
            return ctx
        for entry in run_list[:limit]:
            rec = _to_record(entry)
            if rec is not None:
                ctx.runs.append(rec)
        ctx.files_scanned = len(ctx.runs)
        total = raw.get("total_count")
        if isinstance(total, int) and total > len(ctx.runs):
            ctx.warnings.append(
                f"[runs] {owner}/{name}: audited the {len(ctx.runs)} most "
                f"recent run(s) of {total} total; older runs were not "
                "fetched."
            )
        if scan_logs:
            ctx.logs_scanned = True
            ctx._scan_logs(fetcher, log_fetch_limit)
            ctx._scan_jobs(fetcher, DEFAULT_JOBS_FETCH_LIMIT)
        return ctx

    def _scan_logs(
        self, fetcher: Any, fetch_limit: int,
        action_fetch_limit: int = DEFAULT_ACTION_LOG_FETCH_LIMIT,
    ) -> None:
        """Download + scan logs for the privileged-trigger runs (the risk
        surface), bounded to *fetch_limit* runs. A leaked secret-shaped
        string in CI output is recorded under ``log_leaks[run_id]``.

        After the privileged subset, a second bounded pass
        (``_scan_action_logs``, ``action_fetch_limit`` runs) scans the most
        recent *non-privileged* runs for known-compromised actions only, so
        RUN-006's coverage is not limited to the privileged subset.

        Needs a fetcher exposing ``fetch_bytes`` (the live HTTP fetcher
        does; an offline fixture fetcher may not). Each log fetch can 404
        (logs expire / were deleted), which degrades to a skip.
        """
        fetch_bytes = getattr(fetcher, "fetch_bytes", None)
        if not callable(fetch_bytes):
            self.warnings.append(
                "[runs] --audit-runs-logs needs a fetcher that can download "
                "log archives; the configured fetcher cannot, so log "
                "scanning was skipped."
            )
            return
        targets = [
            r for r in self.runs if r.event in PRIVILEGED_TRIGGERS
        ][:fetch_limit]
        scanned_ids: set[int] = set()
        for run in targets:
            raw = fetch_bytes(
                f"repos/{self.owner}/{self.name}/actions/runs/"
                f"{run.run_id}/logs"
            )
            scanned_ids.add(run.run_id)
            if not raw:
                continue
            leaks, oidc_minted, compromised, unpinned = _scan_log_zip(
                raw, repo_owner=self.owner,
            )
            if leaks:
                self.log_leaks[run.run_id] = leaks
            if oidc_minted:
                self.oidc_mint_runs.add(run.run_id)
            if compromised:
                self.compromised_action_runs[run.run_id] = compromised
            if unpinned:
                self.unpinned_action_runs[run.run_id] = unpinned
        self._scan_action_logs(fetch_bytes, scanned_ids, action_fetch_limit)

    def _scan_action_logs(
        self, fetch_bytes: Any, scanned_ids: set[int], fetch_limit: int,
    ) -> None:
        """Scan recent non-privileged run logs for known-compromised actions.

        RUN-006 (a compromised action confirmed executing) is not
        trigger-specific: the tj-actions / Trivy / Checkmarx campaigns ran
        on ordinary ``push`` / ``pull_request`` runs, which the privileged
        secrets pass above does not download. This pass fills that gap,
        bounded to *fetch_limit* of the most recent runs not already
        scanned, and runs only the cheap IOC-line scan (no secret
        detector). Each 404 / expired-log archive degrades to a skip.
        """
        targets = [
            r for r in self.runs if r.run_id not in scanned_ids
        ]
        for run in targets[:fetch_limit]:
            raw = fetch_bytes(
                f"repos/{self.owner}/{self.name}/actions/runs/"
                f"{run.run_id}/logs"
            )
            if not raw:
                continue
            _, _, compromised, _ = _scan_log_zip(raw, compromised_only=True)
            if compromised:
                self.compromised_action_runs[run.run_id] = compromised
        if len(targets) > fetch_limit:
            self.warnings.append(
                f"[runs] {self.slug}: scanned the {fetch_limit} most recent "
                f"non-privileged run(s) of {len(targets)} for "
                "known-compromised actions; older runs were not fetched."
            )

    def _scan_jobs(self, fetcher: Any, fetch_limit: int) -> None:
        """Fetch job metadata for fork runs to flag self-hosted-runner use.

        A fork PR that ran on a self-hosted runner executed untrusted code
        on infrastructure you own (RCE on the runner host, network pivot,
        persistence) regardless of whether secrets were in scope, which is
        GitHub's most-warned-about self-hosted-runner risk. The runner type
        only appears per job (``.../jobs``), not in the run list, and GitHub
        labels every self-hosted runner's jobs with ``self-hosted``. Bounded
        to *fetch_limit* fork runs; a 404 / network error degrades to a skip.
        """
        targets = [r for r in self.runs if r.from_fork]
        for run in targets[:fetch_limit]:
            raw = fetcher.fetch(
                f"repos/{self.owner}/{self.name}/actions/runs/"
                f"{run.run_id}/jobs"
            )
            labels = _self_hosted_labels(raw)
            if labels:
                self.self_hosted_runs[run.run_id] = labels
        if len(targets) > fetch_limit:
            self.warnings.append(
                f"[runs] {self.slug}: checked the {fetch_limit} most recent "
                f"fork run(s) of {len(targets)} for self-hosted runners; "
                "older fork runs were not fetched."
            )


def _to_record(entry: Any) -> RunRecord | None:
    if not isinstance(entry, dict):
        return None
    run_id = entry.get("id")
    if not isinstance(run_id, int):
        return None
    head_repo = entry.get("head_repository")
    head_repo = head_repo if isinstance(head_repo, dict) else {}
    base_repo = entry.get("repository")
    base_repo = base_repo if isinstance(base_repo, dict) else {}
    actor = entry.get("actor")
    actor = actor if isinstance(actor, dict) else {}
    triggering = entry.get("triggering_actor")
    triggering = triggering if isinstance(triggering, dict) else {}
    attempt = entry.get("run_attempt")
    return RunRecord(
        run_id=run_id,
        name=_str(entry.get("name")) or _str(entry.get("display_title")),
        event=_str(entry.get("event")),
        status=_str(entry.get("status")),
        conclusion=(
            entry.get("conclusion")
            if isinstance(entry.get("conclusion"), str) else None
        ),
        head_branch=_str(entry.get("head_branch")),
        actor=_str(actor.get("login")) or _str(triggering.get("login")),
        head_repo=_str(head_repo.get("full_name")),
        base_repo=_str(base_repo.get("full_name")),
        is_fork=bool(head_repo.get("fork")),
        run_attempt=attempt if isinstance(attempt, int) else 1,
        html_url=_str(entry.get("html_url")),
        created_at=_str(entry.get("created_at")),
    )


def _self_hosted_labels(raw: Any) -> str:
    """Return the joined labels of a self-hosted runner in a ``.../jobs``
    payload, or ``""`` when every job ran on a GitHub-hosted runner.

    GitHub automatically adds the ``self-hosted`` label to every
    self-hosted runner, so a job whose ``labels`` contain it (case
    insensitive) ran on infrastructure the repo owner controls. Defensive
    against a missing / malformed payload (degrades to ``""``).
    """
    if not isinstance(raw, dict):
        return ""
    jobs = raw.get("jobs")
    if not isinstance(jobs, list):
        return ""
    for job in jobs:
        if not isinstance(job, dict):
            continue
        labels = job.get("labels")
        if not isinstance(labels, list):
            continue
        names = [str(label) for label in labels if isinstance(label, str)]
        if any(name.lower() == "self-hosted" for name in names):
            return ", ".join(names)
    return ""


def _scan_log_zip(
    raw: bytes, *, compromised_only: bool = False, repo_owner: str = "",
) -> tuple[list[str], bool, dict[str, str], list[str]]:
    """Scan a run-logs ZIP for secret-shaped strings, OIDC-mint markers,
    known-compromised action executions, and unpinned third-party actions.

    GitHub masks registered secrets in logs, so a secret hit is one that
    leaked *past* masking (a credential a tool printed, a value never
    registered as a secret, a base64/transformed token) -- exactly the
    high-signal case. The OIDC pass flags that the run exercised cloud
    OIDC token minting (the fork subset is RUN-004). The compromised-action
    pass matches each ``Download action repository`` line against the
    GHA-040 IOC registry (the runtime confirmation behind RUN-006). All
    three run on the same single decompress pass. Bounded per-file and in
    total against a pathological archive; ``find_secret_values`` is
    imported lazily so a metadata-only scan never pays for the detector
    catalog.

    With ``compromised_only=True`` the secret, OIDC, and unpinned-action
    passes are skipped (those findings are scoped to privileged-trigger
    runs), so a non-privileged run downloaded purely for RUN-006 pays only
    for the cheap IOC-line scan. The unpinned-action pass needs
    *repo_owner* to exclude the repo's own actions.

    Returns ``(sorted_secret_labels, oidc_minted, compromised_actions,
    unpinned_actions)``, where ``compromised_actions`` maps each offending
    ``owner/repo@ref`` label to its advisory and ``unpinned_actions`` is the
    sorted list of third-party actions resolved from a mutable ref.
    """
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except (zipfile.BadZipFile, OSError, EOFError):
        return [], False, {}, []
    find_secret_values: Callable[[Any], list[str]] | None = None
    if not compromised_only:
        from .._secrets import find_secret_values
    leaks: set[str] = set()
    oidc_minted = False
    compromised: dict[str, str] = {}
    unpinned: set[str] = set()
    consumed = 0
    with archive:
        for info in archive.infolist():
            if info.is_dir() or info.file_size > _MAX_LOG_FILE_BYTES:
                continue
            consumed += info.file_size
            if consumed > _MAX_LOG_TOTAL_BYTES:
                break
            try:
                text = archive.read(info).decode("utf-8", errors="replace")
            except (OSError, RuntimeError, zipfile.BadZipFile):
                continue
            if find_secret_values is not None:
                leaks.update(find_secret_values([text]))
                if not oidc_minted and _OIDC_MARKERS_RE.search(text):
                    oidc_minted = True
                unpinned.update(_scan_unpinned_actions(text, repo_owner))
            compromised.update(_scan_compromised_actions(text))
    return sorted(leaks), oidc_minted, compromised, sorted(unpinned)


def run_resource(ctx: RunsContext, run: RunRecord) -> str:
    """Stable, human-readable resource handle for a single-run finding."""
    return f"github:{ctx.owner}/{ctx.name}#run/{run.run_id}"


def repo_resource(ctx: RunsContext) -> str:
    """Resource handle for a repo-level (aggregate) run finding."""
    return f"github:{ctx.owner}/{ctx.name}/actions"


class RunsBaseCheck(BaseCheck["RunsContext"]):
    """Base class for run-forensics rule orchestration."""

    PROVIDER = "runs"

    def __init__(self, ctx: RunsContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: RunsContext = ctx
