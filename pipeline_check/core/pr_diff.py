"""PR-time finding delta between a base git ref and HEAD.

Where :mod:`pipeline_check.core.diff` scopes which files get scanned
on a feature branch (``--diff-base``), and ``--baseline`` /
``--baseline-from-git`` suppress already-failing findings from the
gate, this module re-scans the *full* state of a base ref and the
*full* state of HEAD, then computes which findings the branch
*introduced*, *resolved*, or left *preserved*. The intent is to
produce a structured delta suited to a PR-review comment, where
"this PR added 3 HIGH findings" is the question being asked.

Mechanism
---------

1. The HEAD scan runs in-process via the normal CLI path (the caller
   already has its findings list).
2. The BASE scan runs *out of process* in a throwaway ``git worktree``
   materialized from the base ref. Out-of-process keeps the two scans
   isolated, no shared blob caches, no leaked click context, no
   chdir-and-restore dance.
3. The subprocess emits ``--output json``; we parse the ``findings``
   array and pair the two sides via a multiset-aware fingerprint that
   matches the existing ``--baseline`` convention
   (``(check_id, resource)``, lowercased POSIX path).

Multiset semantics matter because a single workflow file routinely
trips the same rule multiple times: if BASE has one ``GHA-001`` on
``ci.yml`` and HEAD has two, the *count* of new findings is one, not
zero, and not "everything in HEAD that matches a BASE pair gets
silently dropped". Without this, a PR that adds a second offender to
an already-flagged file would show no delta.

Worktree-based, not stash-based: ``git worktree add --detach`` gives
us a fully-checked-out tree at the base ref without touching the
current working tree or index. It works during a dirty rebase, with
uncommitted changes, and on shallow clones (CI-checkout-action's
default depth-1 fetch needs an unshallow when the base ref isn't
already local; we surface that as a recoverable failure).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .diff import _reject_dash_prefix


#: How long the BASE subprocess scan is allowed to run before we kill
#: it. The HEAD scan has no timeout because the caller's main scan
#: path doesn't impose one either; the BASE scan does because a hung
#: subprocess would otherwise wedge the PR-diff flow indefinitely.
_SUBPROCESS_TIMEOUT_SECONDS = 600


@dataclass(frozen=True, slots=True)
class FindingRef:
    """Minimal projection of a Finding kept around for the delta report.

    The delta layer works on JSON-shaped dicts from the subprocess
    side, so we keep things in plain primitives. Only the fields the
    reporter needs are pulled out; the full Finding dataclass lives
    one layer up and isn't needed here.
    """

    check_id: str
    title: str
    severity: str
    confidence: str
    resource: str
    description: str
    recommendation: str
    location_line: int | None


@dataclass(frozen=True, slots=True)
class DeltaReport:
    """The structural answer to "what changed between BASE and HEAD?".

    ``introduced`` is the multiset of findings present in HEAD but
    *not* matched by an equivalent in BASE. ``resolved`` is the
    inverse, findings in BASE that no longer appear in HEAD.
    ``preserved`` is the intersection.

    Each list is sorted: failures only, severity-desc, then
    check_id-asc, then resource-asc. Passed findings are filtered out
    entirely; this is a *delta of failures*, not a delta of every
    scanner emission.
    """

    base_ref: str
    base_commit: str | None
    head_commit: str | None
    introduced: list[FindingRef] = field(default_factory=list)
    resolved: list[FindingRef] = field(default_factory=list)
    preserved: list[FindingRef] = field(default_factory=list)
    #: Warnings collected during the run (worktree creation failed for
    #: a recoverable reason, subprocess emitted unparseable JSON,
    #: etc.). Surfaced to the user; not fatal.
    warnings: list[str] = field(default_factory=list)


# ────────────────────────────────────────────────────────────────────────────
# Fingerprinting + delta computation (pure)
# ────────────────────────────────────────────────────────────────────────────


def _norm_resource(s: str) -> str:
    """POSIX-form, lowercased resource path for fingerprint equality.

    Mirrors :func:`pipeline_check.core.gate._norm_resource` (slash
    direction) and additionally lowercases so a base scan run on
    Linux (lowercase tree) and a HEAD scan run on Windows (uppercase
    drive letter in resolved paths) still fingerprint-match. Resource
    strings that aren't filesystem paths (e.g. AWS ARNs) are also
    lowercased; the case-insensitive comparison is conservative for
    those (an ARN's region/account/name segments are case-sensitive
    in practice, but conflating them across BASE/HEAD is far less
    common than path-case mismatches and the failure mode is "treat
    two findings as the same when they were the same", which is
    correct).
    """
    return s.replace("\\", "/").lower()


def _fingerprint(f: FindingRef) -> tuple[str, str]:
    return (f.check_id.upper(), _norm_resource(f.resource))


def _finding_from_dict(d: dict[str, Any]) -> FindingRef | None:
    """Extract a :class:`FindingRef` from a JSON ``findings[i]`` dict.

    Returns ``None`` for any document shape we don't recognize so the
    caller can skip drift rather than crashing. The subprocess output
    is trusted to be our own format, but defensive parsing here lets
    us evolve the JSON schema without coupling the diff layer to
    every additive field.
    """
    if not isinstance(d, dict):
        return None
    check_id = str(d.get("check_id", "")).strip()
    if not check_id:
        return None
    resource = str(d.get("resource", ""))
    locations = d.get("locations")
    location_line: int | None = None
    if isinstance(locations, list) and locations:
        first = locations[0]
        if isinstance(first, dict):
            start = first.get("start_line")
            if isinstance(start, int):
                location_line = start
    return FindingRef(
        check_id=check_id,
        title=str(d.get("title", "")),
        severity=str(d.get("severity", "INFO")).upper(),
        confidence=str(d.get("confidence", "HIGH")).upper(),
        resource=resource,
        description=str(d.get("description", "")),
        recommendation=str(d.get("recommendation", "")),
        location_line=location_line,
    )


def _projection(raw_findings: list[Any]) -> list[FindingRef]:
    """Project the JSON ``findings`` array to a list of failures.

    Skips passed findings and any entry whose shape we can't parse.
    """
    out: list[FindingRef] = []
    for entry in raw_findings:
        if not isinstance(entry, dict):
            continue
        if entry.get("passed", False):
            continue
        ref = _finding_from_dict(entry)
        if ref is not None:
            out.append(ref)
    return out


_SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0,
}


def _sort_key(f: FindingRef) -> tuple[int, str, str]:
    # Negative severity rank so highest-severity sorts first under
    # ascending sort.
    return (-_SEVERITY_ORDER.get(f.severity, 0), f.check_id, _norm_resource(f.resource))


def compute_delta(
    base: list[FindingRef],
    head: list[FindingRef],
) -> tuple[list[FindingRef], list[FindingRef], list[FindingRef]]:
    """Partition findings into (introduced, resolved, preserved).

    Multiset semantics on the ``(check_id, resource)`` fingerprint: a
    PR that adds a second occurrence of the same rule on the same
    file is *introducing* one finding, not zero. Lines are
    intentionally excluded from the fingerprint to stay immune to
    line-shifts on otherwise-unchanged code (matches the existing
    ``--baseline`` convention).

    Within a fingerprint bucket the partitioning is order-stable: the
    first ``min(|base|, |head|)`` HEAD findings are preserved; the
    remainder of HEAD is introduced; the unmatched tail of BASE is
    resolved. Stability matters so the report shows "the new one" not
    "an arbitrary one" when a file already had findings of that rule.
    """
    bucket_base: dict[tuple[str, str], list[FindingRef]] = {}
    bucket_head: dict[tuple[str, str], list[FindingRef]] = {}
    for f in base:
        bucket_base.setdefault(_fingerprint(f), []).append(f)
    for f in head:
        bucket_head.setdefault(_fingerprint(f), []).append(f)

    introduced: list[FindingRef] = []
    resolved: list[FindingRef] = []
    preserved: list[FindingRef] = []

    keys = set(bucket_base) | set(bucket_head)
    for key in keys:
        b = bucket_base.get(key, [])
        h = bucket_head.get(key, [])
        common = min(len(b), len(h))
        preserved.extend(h[:common])
        if len(h) > common:
            introduced.extend(h[common:])
        if len(b) > common:
            resolved.extend(b[common:])

    introduced.sort(key=_sort_key)
    resolved.sort(key=_sort_key)
    preserved.sort(key=_sort_key)
    return introduced, resolved, preserved


# ────────────────────────────────────────────────────────────────────────────
# Git plumbing (worktree, rev-parse)
# ────────────────────────────────────────────────────────────────────────────


def _resolve_commit(ref: str, cwd: str | Path = ".") -> str | None:
    """Return the 7-char short SHA of ``ref`` or ``None`` on failure.

    Used only to label the report ("Scanned base origin/main (abc1234)
    vs HEAD (def5678)"). Failure is non-fatal; the report degrades
    gracefully.
    """
    _reject_dash_prefix("ref", ref)
    try:
        result = subprocess.run(
            # ``--end-of-options`` must come *after* all the flags
            # ``rev-parse`` itself consumes (``--short``). Older
            # invocations had ``--end-of-options`` before ``--short``
            # and git 2.45 rejected ``--short`` as a "non-option
            # argument" once the boundary marker had passed.
            ["git", "rev-parse", "--short", "--end-of-options", ref],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    sha = result.stdout.strip()
    return sha or None


def _worktree_add(ref: str, dest: Path, cwd: str | Path = ".") -> str | None:
    """Create a detached worktree at ``ref`` under ``dest``.

    Returns ``None`` on success, or an error string the caller surfaces
    as a warning. We use ``--detach`` so the worktree carries no
    branch and won't conflict if the user has the same ref checked
    out elsewhere; ``--force`` is *not* set, so a pre-existing
    worktree at the destination is a hard error (we always create a
    fresh tempdir).
    """
    _reject_dash_prefix("--pr-diff", ref)
    try:
        result = subprocess.run(
            [
                "git", "worktree", "add", "--detach",
                "--end-of-options",
                str(dest), ref,
            ],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except FileNotFoundError:
        return "git not found on PATH"
    except subprocess.TimeoutExpired:
        return "git worktree add timed out after 60s"
    if result.returncode != 0:
        # git's own stderr is the most informative thing we can show.
        stderr = (result.stderr or result.stdout or "").strip().splitlines()
        first = stderr[0] if stderr else "git worktree add failed"
        return f"git worktree add failed: {first}"
    return None


def _worktree_remove(dest: Path, cwd: str | Path = ".") -> None:
    """Best-effort cleanup of a worktree created by :func:`_worktree_add`.

    Never raises. We try ``git worktree remove --force`` first because
    it knows how to detach git-internal state cleanly; if that fails
    (the worktree directory was already deleted, git can't find its
    record), we drop to ``rmtree`` to free disk space.

    The worktree gets its own tempdir under :data:`tempfile.gettempdir`
    so a leak just costs disk, never repository integrity.
    """
    try:
        subprocess.run(
            [
                "git", "worktree", "remove", "--force",
                "--end-of-options", str(dest),
            ],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    if dest.exists():
        import shutil
        shutil.rmtree(dest, ignore_errors=True)


# ────────────────────────────────────────────────────────────────────────────
# Subprocess scan in the base worktree
# ────────────────────────────────────────────────────────────────────────────


def _scan_in_worktree(
    worktree: Path,
    forwarded_argv: list[str],
) -> tuple[list[dict[str, Any]] | None, str | None]:
    """Run ``pipeline_check --output json`` in ``worktree`` and parse it.

    Returns ``(findings_list, error_message)``. On success
    ``error_message`` is ``None`` and ``findings_list`` is the raw
    JSON ``findings`` array (list of dicts). On failure the inverse:
    ``findings_list`` is ``None`` and ``error_message`` carries a
    diagnostic the caller turns into a warning.

    The subprocess re-uses the *same Python interpreter* that's
    running us (``sys.executable -m pipeline_check``) so a venv /
    editable install scans the same code on both sides. ``GHA``
    auto-detection re-runs inside the worktree; path flags from the
    parent get forwarded as-is so a user with a custom ``--gha-path
    ci/workflows`` is honored.
    """
    cmd = [sys.executable, "-m", "pipeline_check", "--output", "json"]
    cmd.extend(forwarded_argv)
    env = os.environ.copy()
    # Force the subprocess to emit UTF-8 JSON regardless of the
    # parent's stdio encoding. Our CLI already does this for non-TTY
    # streams, but PYTHONIOENCODING is the belt-and-suspenders form
    # in case the harness invocation later swaps the entrypoint.
    env.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        result = subprocess.run(
            cmd,
            cwd=str(worktree),
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT_SECONDS,
            check=False,
            env=env,
        )
    except FileNotFoundError:
        return None, f"could not invoke {sys.executable!r}"
    except subprocess.TimeoutExpired:
        return None, (
            f"base scan timed out after {_SUBPROCESS_TIMEOUT_SECONDS}s"
        )
    # The scanner exits 1 when the gate fails; that's a normal,
    # JSON-on-stdout outcome and not a parse failure. Only treat
    # exit code 2 (the documented "scanner error" exit) and 3
    # (usage / lookup errors from eager flag handlers) as fatal.
    if result.returncode in (2, 3):
        stderr_head = (result.stderr or "").strip().splitlines()[:1]
        msg = stderr_head[0] if stderr_head else "(no stderr)"
        return None, f"base scan exited {result.returncode}: {msg}"
    stdout = result.stdout or ""
    if not stdout.strip():
        return None, "base scan produced no JSON output"
    try:
        doc = json.loads(stdout)
    except json.JSONDecodeError as exc:
        # When the subprocess emitted a non-JSON line before JSON
        # (a stderr warning that leaked into stdout under some
        # console reconfiguration), find the first ``{`` and retry.
        # If that still fails the parent surfaces the raw error so
        # the user has something concrete to debug with.
        first_brace = stdout.find("{")
        if first_brace > 0:
            try:
                doc = json.loads(stdout[first_brace:])
            except json.JSONDecodeError:
                return None, f"base scan emitted unparseable JSON: {exc}"
        else:
            return None, f"base scan emitted unparseable JSON: {exc}"
    findings = doc.get("findings") if isinstance(doc, dict) else None
    if not isinstance(findings, list):
        return None, "base scan JSON missing 'findings' array"
    return findings, None


# ────────────────────────────────────────────────────────────────────────────
# Top-level orchestration
# ────────────────────────────────────────────────────────────────────────────


def run_pr_diff(
    base_ref: str,
    head_findings_raw: list[dict[str, Any]],
    forwarded_argv: list[str],
    cwd: str | Path = ".",
) -> DeltaReport:
    """End-to-end: materialize BASE, scan it, compute the delta.

    ``head_findings_raw`` is the dict-form ``findings`` list the parent
    already produced via the in-process scan (passed through
    ``report_json`` or built directly via ``Finding.to_dict``). We
    don't re-scan HEAD here, the parent already has it.

    ``forwarded_argv`` is the curated subset of the parent's argv
    that's safe to replay against the BASE worktree (everything that
    affects what the BASE scan finds: ``--pipeline``, ``--checks``,
    path flags, ``--standard``, ``--severity-threshold``,
    ``--min-confidence``, ``--custom-rules``, ``--no-chains``).
    The CLI layer is responsible for building this list; this module
    treats it as opaque so any future flag becomes a one-line CLI
    edit, not a diff-module concern.

    The function is total: it never raises on git / subprocess
    failures. A worktree-add failure produces an empty BASE side
    (so every HEAD finding shows up as ``introduced``, which is
    visibly wrong but conservative, the PR comment will surface the
    warning so the reviewer knows the diff is degraded). The intent
    is that ``--pr-diff`` should always produce *some* output in a
    PR comment, even when the base ref is unreachable.
    """
    head_findings = _projection(head_findings_raw)
    warnings: list[str] = []

    base_commit = _resolve_commit(base_ref, cwd=cwd)
    if base_commit is None:
        warnings.append(
            f"could not resolve base ref {base_ref!r} "
            f"(fetch it or pass a different ref); "
            f"treating every HEAD finding as new."
        )
        return DeltaReport(
            base_ref=base_ref,
            base_commit=None,
            head_commit=_resolve_commit("HEAD", cwd=cwd),
            introduced=sorted(head_findings, key=_sort_key),
            resolved=[],
            preserved=[],
            warnings=warnings,
        )

    head_commit = _resolve_commit("HEAD", cwd=cwd)

    base_findings: list[FindingRef] = []
    with tempfile.TemporaryDirectory(prefix="pipeline-check-prdiff-") as tmp:
        # mkdtemp's path can land inside the system temp dir, which on
        # macOS is symlinked through ``/private``; that's fine for git
        # worktree as long as we hand it the realpath.
        worktree = Path(tmp).resolve() / "base"
        # ``Path.mkdir`` would create the leaf, but git worktree add
        # wants the destination *not* to exist yet, so we leave it.
        err = _worktree_add(base_ref, worktree, cwd=cwd)
        if err is not None:
            warnings.append(err)
            warnings.append(
                "treating every HEAD finding as new (BASE side is empty)."
            )
            return DeltaReport(
                base_ref=base_ref,
                base_commit=base_commit,
                head_commit=head_commit,
                introduced=sorted(head_findings, key=_sort_key),
                resolved=[],
                preserved=[],
                warnings=warnings,
            )
        try:
            base_raw, scan_err = _scan_in_worktree(worktree, forwarded_argv)
            if scan_err is not None:
                warnings.append(scan_err)
                warnings.append(
                    "treating every HEAD finding as new (BASE scan failed)."
                )
                return DeltaReport(
                    base_ref=base_ref,
                    base_commit=base_commit,
                    head_commit=head_commit,
                    introduced=sorted(head_findings, key=_sort_key),
                    resolved=[],
                    preserved=[],
                    warnings=warnings,
                )
            base_findings = _projection(base_raw or [])
        finally:
            _worktree_remove(worktree, cwd=cwd)

    introduced, resolved, preserved = compute_delta(base_findings, head_findings)
    return DeltaReport(
        base_ref=base_ref,
        base_commit=base_commit,
        head_commit=head_commit,
        introduced=introduced,
        resolved=resolved,
        preserved=preserved,
        warnings=warnings,
    )


# ────────────────────────────────────────────────────────────────────────────
# Severity-driven summary, useful for the gate
# ────────────────────────────────────────────────────────────────────────────


def severity_counts(refs: list[FindingRef]) -> Counter[str]:
    """Return a ``Counter`` of severity → count over *refs*.

    Used by the CLI to wire ``--pr-diff`` into the existing
    ``--fail-on SEV`` semantics: the gate fails when any introduced
    finding meets the threshold. Severities are normalized to the
    canonical upper-case form so callers don't have to.
    """
    c: Counter[str] = Counter()
    for f in refs:
        c[f.severity.upper()] += 1
    return c


def any_at_or_above(refs: list[FindingRef], threshold: str) -> bool:
    """``True`` when at least one finding in *refs* is >= *threshold*.

    *threshold* is the upper-cased severity name; unknown values are
    treated as INFO (no gate) for forward-compatibility with future
    severities.
    """
    min_rank = _SEVERITY_ORDER.get(threshold.upper(), 0)
    return any(
        _SEVERITY_ORDER.get(f.severity.upper(), 0) >= min_rank
        for f in refs
    )
