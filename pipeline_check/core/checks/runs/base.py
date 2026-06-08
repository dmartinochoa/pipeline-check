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
import zipfile
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

#: Triggers that execute in the *base* repository's privileged context
#: (repo secrets + a write-scoped ``GITHUB_TOKEN``) while potentially
#: handling PR-controlled content. A run that actually fired on one of
#: these is live evidence of the pwn-request attack surface, not just a
#: static "the config allows it".
PRIVILEGED_TRIGGERS: frozenset[str] = frozenset({
    "pull_request_target", "workflow_run",
})


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
    #: True once log scanning was requested + attempted, so RUN-003 can
    #: tell "no leaks found" from "logs were never scanned".
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
        return ctx

    def _scan_logs(self, fetcher: Any, fetch_limit: int) -> None:
        """Download + scan logs for the privileged-trigger runs (the risk
        surface), bounded to *fetch_limit* runs. A leaked secret-shaped
        string in CI output is recorded under ``log_leaks[run_id]``.

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
        for run in targets:
            raw = fetch_bytes(
                f"repos/{self.owner}/{self.name}/actions/runs/"
                f"{run.run_id}/logs"
            )
            if not raw:
                continue
            leaks = _scan_log_zip(raw)
            if leaks:
                self.log_leaks[run.run_id] = leaks


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


def _scan_log_zip(raw: bytes) -> list[str]:
    """Scan a run-logs ZIP for secret-shaped strings.

    GitHub masks registered secrets in logs, so a hit here is a secret
    that leaked *past* masking (a credential a tool printed, a value
    never registered as a secret, a base64/transformed token) -- exactly
    the high-signal case. Bounded per-file and in total against a
    pathological archive; ``find_secret_values`` is imported lazily so a
    metadata-only scan never pays for the detector catalog.
    """
    from .._secrets import find_secret_values
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except (zipfile.BadZipFile, OSError, EOFError):
        return []
    leaks: set[str] = set()
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
            leaks.update(find_secret_values([text]))
    return sorted(leaks)


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
