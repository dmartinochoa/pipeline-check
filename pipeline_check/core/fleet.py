"""Org-wide fleet scanner.

Reads a YAML list of repository coordinates, shallow-clones each
into a per-repo tmpdir, runs the existing ``pipeline_check`` scan
against the clone (subprocess so per-repo state is fully isolated),
and writes a unified output tree:

::

    <output-dir>/
      <owner>/<repo>/findings.json    one per repo
      <owner>/<repo>/scan.stderr      captured warnings/errors
      fleet.json                      aggregate (per-repo grade,
                                      score, severity totals)
      fleet.md                        human-readable digest

A single repo's clone or scan failure becomes a per-repo warning
on the aggregate rather than aborting the whole run — the
operator wants to see the green-and-red breakdown across the org
even when one repo is misconfigured.

Phase 1 scope
-------------
* GitHub-style ``owner/name`` coordinates resolved to
  ``https://github.com/<owner>/<name>.git``.
* Subprocess invocation of ``pipeline_check`` for each repo via
  ``--pipeline auto --output json --output-file ...``.

Out of scope (phase 2 follow-ups):

* ``--from-org`` SCM API enumeration (GitHub / GitLab / Bitbucket).
* ``--include`` / ``--exclude`` glob filtering of the coordinate
  list.
* ``--baseline-dir`` comparison against a prior fleet snapshot.
* Per-repo SARIF / ``threats.md`` outputs (only the JSON shape and
  the markdown digest land in phase 1).
* GitLab ``group/subgroup/project`` and Bitbucket
  ``workspace/repo_slug`` coordinate shapes (the parser just rejects
  anything that isn't ``owner/repo``).
* Forwarding arbitrary ``pipeline_check`` flags through to the
  per-repo subprocess (just ``--output json``; standard / gate /
  resolve-remote knobs come in phase 2).
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_GITHUB_COORD_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")

_SEVERITIES: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

#: Per-repo subprocess timeout. Realistic single-repo scans run in
#: seconds; an unbounded run that hangs on git clone shouldn't block
#: the rest of the fleet.
_DEFAULT_SCAN_TIMEOUT_SEC: int = 600


@dataclass(frozen=True, slots=True)
class RepoCoordinate:
    """One entry from the ``--repos`` YAML."""

    #: The original coordinate string (``"dmartinochoa/pipeline-check"``).
    coord: str
    #: The HTTPS git clone URL we'll fetch from.
    clone_url: str
    #: Used for the on-disk layout key
    #: (``<output-dir>/<owner>/<repo>/findings.json``).
    owner: str
    repo: str


@dataclass(slots=True)
class FleetSnapshot:
    """The aggregated per-repo result for the digest."""

    coord: str
    grade: str
    score: int
    failed_by_severity: dict[str, int] = field(default_factory=dict)
    total_failed: int = 0
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error


@dataclass(slots=True)
class FleetDigest:
    """Top-level aggregate written to ``fleet.json`` + ``fleet.md``."""

    snapshots: list[FleetSnapshot] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshots": [
                {
                    "coord": s.coord,
                    "grade": s.grade,
                    "score": s.score,
                    "failed_by_severity": dict(s.failed_by_severity),
                    "total_failed": s.total_failed,
                    "error": s.error,
                }
                for s in self.snapshots
            ],
            "warnings": list(self.warnings),
        }


def load_repo_list(yaml_path: Path | str) -> list[RepoCoordinate]:
    """Parse a fleet repo-list YAML into typed coordinates.

    Accepted YAML shapes:

    * A flat list:

      .. code-block:: yaml

          - dmartinochoa/pipeline-check
          - greylag-ci/pipeline-check-vscode

    * A mapping with a ``repos:`` key carrying the same list (so
      the file can also hold ``defaults:`` or future per-fleet
      config without breaking the parser).

      .. code-block:: yaml

          repos:
            - dmartinochoa/pipeline-check

    Coordinates that don't match ``owner/repo`` (one slash, only
    word chars / dots / hyphens / underscores) raise ``ValueError``
    with the offending entry — the caller can decide whether to
    catch and surface as a warning or hard-fail. We reject up-front
    rather than emit a warning per-entry because a malformed
    repo-list file is almost always a typo the user wants to see
    immediately.
    """
    path = Path(yaml_path)
    if not path.exists():
        raise ValueError(
            f"--repos {path} does not exist. Pass a YAML file with "
            "a list of 'owner/repo' entries."
        )
    text = path.read_text(encoding="utf-8")
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(
            f"--repos {path}: YAML parse error: {exc}"
        ) from exc
    if isinstance(raw, dict) and "repos" in raw:
        raw = raw["repos"]
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError(
            f"--repos {path}: top-level must be a list of "
            "'owner/repo' entries (or a mapping with a 'repos:' "
            "key holding such a list)."
        )
    out: list[RepoCoordinate] = []
    for entry in raw:
        if not isinstance(entry, str):
            raise ValueError(
                f"--repos {path}: every entry must be a string "
                f"'owner/repo'; got {entry!r}."
            )
        coord = entry.strip()
        if not _GITHUB_COORD_RE.match(coord):
            raise ValueError(
                f"--repos {path}: coordinate {coord!r} is not the "
                "'owner/repo' shape phase 1 accepts. GitLab "
                "'group/sub/project' and Bitbucket "
                "'workspace/slug' coordinates are deferred."
            )
        owner, repo = coord.split("/", 1)
        out.append(RepoCoordinate(
            coord=coord,
            clone_url=f"https://github.com/{coord}.git",
            owner=owner,
            repo=repo,
        ))
    return out


def _clone_repo(
    coord: RepoCoordinate,
    dest: Path,
    *,
    timeout_sec: int = _DEFAULT_SCAN_TIMEOUT_SEC,
) -> str:
    """Shallow-clone *coord* into *dest*. Return '' on success, error
    string on failure (caller folds into the per-repo snapshot)."""
    try:
        subprocess.run(
            [
                "git", "clone", "--depth", "1", "--no-tags",
                coord.clone_url, str(dest),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
    except FileNotFoundError:
        return "git executable not found on PATH"
    except subprocess.TimeoutExpired:
        return f"git clone timed out after {timeout_sec}s"
    except subprocess.CalledProcessError as exc:
        # Truncate stderr — the FleetDigest's warnings should be
        # readable; full logs land on disk under <repo>/scan.stderr.
        msg = (exc.stderr or "").strip().splitlines()[-1:] or ["(no stderr)"]
        return f"git clone exit {exc.returncode}: {msg[0]}"
    return ""


def _scan_repo(
    coord: RepoCoordinate,
    src: Path,
    findings_path: Path,
    stderr_path: Path,
    *,
    timeout_sec: int = _DEFAULT_SCAN_TIMEOUT_SEC,
) -> str:
    """Run ``pipeline_check`` against *src*, writing findings to
    *findings_path* and captured stderr to *stderr_path*.

    Subprocess invocation rather than in-process so per-repo state
    (env vars, cwd, any module-level caches the scanner builds) is
    fully isolated. Returns '' on success, error string on failure.
    """
    try:
        result = subprocess.run(
            [
                sys.executable, "-m", "pipeline_check",
                "--output", "json",
                "--output-file", str(findings_path),
            ],
            cwd=src,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
    except FileNotFoundError:
        return f"{sys.executable} not invokable; can't run pipeline_check"
    except subprocess.TimeoutExpired:
        return f"pipeline_check scan timed out after {timeout_sec}s"
    # Capture stderr regardless of exit code — even passing scans
    # emit warnings worth surfacing.
    if result.stderr:
        stderr_path.write_text(result.stderr, encoding="utf-8")
    # ``pipeline_check`` exits non-zero when the gate trips
    # (intentional fail-on behavior). That isn't an orchestration
    # failure — findings.json should still have landed. Only treat
    # a missing output file as a real error.
    if not findings_path.exists():
        tail = (result.stderr or "").strip().splitlines()[-1:] or [
            f"exit code {result.returncode}",
        ]
        return f"pipeline_check produced no findings.json: {tail[0]}"
    return ""


def _snapshot_from_findings(
    coord: RepoCoordinate, findings_path: Path,
) -> FleetSnapshot:
    """Project a per-repo findings.json onto a :class:`FleetSnapshot`.

    Defensive about missing fields: a corrupt or partial JSON
    produces a snapshot with zeros + an error message rather than
    raising, so one bad file doesn't break the whole digest.
    """
    try:
        doc = json.loads(findings_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return FleetSnapshot(
            coord=coord.coord, grade="?", score=0,
            failed_by_severity={s: 0 for s in _SEVERITIES},
            total_failed=0,
            error=f"findings.json parse error: {exc}",
        )
    if not isinstance(doc, dict):
        return FleetSnapshot(
            coord=coord.coord, grade="?", score=0,
            failed_by_severity={s: 0 for s in _SEVERITIES},
            total_failed=0,
            error="findings.json top-level is not an object",
        )
    score_block = doc.get("score") or {}
    score = score_block.get("score") if isinstance(score_block, dict) else None
    grade = score_block.get("grade") if isinstance(score_block, dict) else None
    summary = score_block.get("summary") if isinstance(score_block, dict) else None
    failed: dict[str, int] = {sev: 0 for sev in _SEVERITIES}
    if isinstance(summary, dict):
        for sev in _SEVERITIES:
            entry = summary.get(sev)
            if isinstance(entry, dict) and isinstance(entry.get("failed"), int):
                failed[sev] = entry["failed"]
    return FleetSnapshot(
        coord=coord.coord,
        grade=grade if isinstance(grade, str) else "?",
        score=score if isinstance(score, int) else 0,
        failed_by_severity=failed,
        total_failed=sum(failed.values()),
    )


def run_fleet(
    repos: list[RepoCoordinate],
    output_dir: Path,
    *,
    timeout_sec: int = _DEFAULT_SCAN_TIMEOUT_SEC,
) -> FleetDigest:
    """Clone each repo, scan it, and write the aggregated digest.

    *output_dir* is created if missing; per-repo trees land under
    ``<output_dir>/<owner>/<repo>/``. The top-level ``fleet.json``
    + ``fleet.md`` are written after every repo has been processed
    so a partial run still produces a coherent (if incomplete)
    digest.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    digest = FleetDigest()
    for coord in repos:
        per_repo_dir = output_dir / coord.owner / coord.repo
        per_repo_dir.mkdir(parents=True, exist_ok=True)
        findings_path = per_repo_dir / "findings.json"
        stderr_path = per_repo_dir / "scan.stderr"
        with tempfile.TemporaryDirectory(prefix="fleet-clone-") as tmpd:
            clone_dest = Path(tmpd) / coord.repo
            err = _clone_repo(coord, clone_dest, timeout_sec=timeout_sec)
            if err:
                digest.warnings.append(f"{coord.coord}: {err}")
                digest.snapshots.append(FleetSnapshot(
                    coord=coord.coord, grade="?", score=0,
                    failed_by_severity={s: 0 for s in _SEVERITIES},
                    total_failed=0,
                    error=err,
                ))
                continue
            err = _scan_repo(
                coord, clone_dest, findings_path, stderr_path,
                timeout_sec=timeout_sec,
            )
            if err:
                digest.warnings.append(f"{coord.coord}: {err}")
                digest.snapshots.append(FleetSnapshot(
                    coord=coord.coord, grade="?", score=0,
                    failed_by_severity={s: 0 for s in _SEVERITIES},
                    total_failed=0,
                    error=err,
                ))
                continue
        digest.snapshots.append(
            _snapshot_from_findings(coord, findings_path),
        )
    _write_digest(output_dir, digest)
    return digest


def _write_digest(output_dir: Path, digest: FleetDigest) -> None:
    """Write fleet.json + fleet.md to *output_dir*."""
    (output_dir / "fleet.json").write_text(
        json.dumps(digest.to_dict(), indent=2),
        encoding="utf-8",
    )
    (output_dir / "fleet.md").write_text(
        render_markdown(digest), encoding="utf-8",
    )


def render_markdown(digest: FleetDigest) -> str:
    """Human-readable digest of a fleet run."""
    lines: list[str] = []
    lines.append("# Fleet scan digest\n")
    ok = [s for s in digest.snapshots if s.ok]
    errored = [s for s in digest.snapshots if not s.ok]
    lines.append(
        f"Scanned **{len(digest.snapshots)}** repo(s) "
        f"({len(ok)} OK, {len(errored)} errored)."
    )
    # Severity totals across the org.
    if ok:
        totals: Counter[str] = Counter()
        for s in ok:
            for sev, n in s.failed_by_severity.items():
                totals[sev] += n
        lines.append("")
        lines.append("## Org-wide failed findings")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|---|---:|")
        for sev in _SEVERITIES:
            lines.append(f"| {sev.lower()} | {totals.get(sev, 0)} |")
    # Per-repo table, ranked by ascending score (worst first).
    lines.append("")
    lines.append("## Per-repo posture (ranked worst -> best)")
    lines.append("")
    lines.append(
        "| Repo | Grade | Score | Failed | Status |"
    )
    lines.append("|---|---:|---:|---:|---|")
    ranked = sorted(digest.snapshots, key=lambda s: (s.score, s.coord))
    for s in ranked:
        if s.ok:
            status = "ok"
        else:
            status = f"error: {s.error[:60]}"
        lines.append(
            f"| {s.coord} | {s.grade} | {s.score} | "
            f"{s.total_failed} | {status} |"
        )
    if digest.warnings:
        lines.append("")
        lines.append("## Warnings")
        lines.append("")
        for w in digest.warnings:
            lines.append(f"- {w}")
    lines.append("")
    return "\n".join(lines)


__all__ = [
    "FleetDigest",
    "FleetSnapshot",
    "RepoCoordinate",
    "load_repo_list",
    "render_markdown",
    "run_fleet",
]
