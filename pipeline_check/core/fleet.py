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
on the aggregate rather than aborting the whole run, so the
operator sees the green-and-red breakdown across the org even when
one repo is misconfigured.

Parallel execution: ``run_fleet(..., jobs=N)`` fans out clone+scan
work across *N* threads. Each thread runs subprocesses (git clone,
python -m pipeline_check) so the GIL is irrelevant. ``jobs=0``
preserves sequential behavior for debugging.
"""
from __future__ import annotations

import concurrent.futures
import fnmatch as _fnmatch
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import threading
import urllib.parse
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

if TYPE_CHECKING:
    from .chains.base import Chain
    from .checks.base import Finding

_log = logging.getLogger(__name__)

_GITHUB_COORD_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
_GITLAB_COORD_RE = re.compile(
    r"^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)+$",
)
_VALID_PLATFORMS = frozenset({"github", "gitlab", "bitbucket"})
_PLATFORM_PREFIXES = ("github:", "gitlab:", "bitbucket:")

_SEVERITIES: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

#: Per-repo subprocess timeout. Realistic single-repo scans run in
#: seconds; an unbounded run that hangs on git clone shouldn't block
#: the rest of the fleet.
_DEFAULT_SCAN_TIMEOUT_SEC: int = 600

#: Upper bound on auto-detected parallelism. Keeps the clone burst
#: inside GitHub's unauthenticated rate-limit window for small orgs
#: and avoids saturating the machine on large ones.
_MAX_DEFAULT_WORKERS: int = 8


def default_worker_count(repo_count: int) -> int:
    """Pick a sensible default parallelism level."""
    cpu = os.cpu_count() or 4
    return min(cpu, repo_count, _MAX_DEFAULT_WORKERS)


@dataclass(frozen=True, slots=True)
class RepoCoordinate:
    """One entry from the ``--repos`` YAML."""

    #: The original coordinate string (``"dmartinochoa/pipeline-check"``).
    coord: str
    #: The HTTPS git clone URL we'll fetch from.
    clone_url: str
    #: Used for the on-disk layout key
    #: (``<output-dir>/<platform>/<owner>/<repo>/findings.json``).
    owner: str
    repo: str
    #: SCM platform. Defaults to ``"github"`` for backward compat.
    platform: str = "github"


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
    cxpc_chains: list[Chain] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
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
        if self.cxpc_chains:
            out["cxpc_chains"] = [c.to_dict() for c in self.cxpc_chains]
        return out


_CLONE_URL_TEMPLATES: dict[str, str] = {
    "github": "https://github.com/{coord}.git",
    "gitlab": "https://gitlab.com/{coord}.git",
    "bitbucket": "https://bitbucket.org/{coord}.git",
}


def _parse_coord_string(s: str) -> tuple[str, str]:
    """Parse ``'platform:coord'`` or bare ``'coord'`` (defaults to github).

    Raises ``ValueError`` if the string has a ``name:`` prefix that
    isn't a recognized platform.
    """
    for prefix in _PLATFORM_PREFIXES:
        if s.startswith(prefix):
            return prefix[:-1], s[len(prefix):]
    if ":" in s:
        candidate = s.split(":", 1)[0]
        if candidate.isalpha():
            raise ValueError(
                f"Unknown platform {candidate!r}. "
                f"Accepted: {', '.join(sorted(_VALID_PLATFORMS))}."
            )
    return "github", s


def _resolve_coord(
    platform: str, coord: str,
) -> tuple[str, str, str]:
    """Validate *coord* for *platform* and return ``(owner, repo, clone_url)``.

    Raises ``ValueError`` on invalid shapes.
    """
    if platform not in _VALID_PLATFORMS:
        raise ValueError(
            f"Unknown platform {platform!r}. "
            f"Accepted: {', '.join(sorted(_VALID_PLATFORMS))}."
        )
    if platform in ("github", "bitbucket"):
        if not _GITHUB_COORD_RE.match(coord):
            raise ValueError(
                f"Coordinate {coord!r} is not a valid "
                f"{platform} 'owner/repo' shape."
            )
        owner, repo = coord.split("/", 1)
    else:
        if not _GITLAB_COORD_RE.match(coord):
            raise ValueError(
                f"Coordinate {coord!r} is not a valid "
                "GitLab 'group/[subgroup/]project' shape."
            )
        owner, repo = coord.rsplit("/", 1)
    clone_url = _CLONE_URL_TEMPLATES[platform].format(coord=coord)
    return owner, repo, clone_url


def load_repo_list(yaml_path: Path | str) -> list[RepoCoordinate]:
    """Parse a fleet repo-list YAML into typed coordinates.

    Accepted YAML shapes:

    * A flat list of strings (bare ``owner/repo`` defaults to GitHub,
      or prefixed like ``gitlab:group/sub/project``):

      .. code-block:: yaml

          - dmartinochoa/pipeline-check
          - gitlab:mygroup/mysubgroup/myproject
          - bitbucket:workspace/slug

    * A flat list of mappings with ``coord`` and ``platform`` keys:

      .. code-block:: yaml

          - coord: mygroup/mysubgroup/myproject
            platform: gitlab

    * A mapping with a ``repos:`` key holding any of the above (so
      the file can also hold ``defaults:`` or future per-fleet
      config without breaking the parser).

    Invalid coordinates raise ``ValueError`` with the offending
    entry so the user sees the problem immediately.
    """
    path = Path(yaml_path)
    if not path.exists():
        raise ValueError(
            f"--repos {path} does not exist. Pass a YAML file with "
            "a list of repo coordinate entries."
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
            "repo coordinate entries (or a mapping with a 'repos:' "
            "key holding such a list)."
        )
    out: list[RepoCoordinate] = []
    for entry in raw:
        if isinstance(entry, str):
            platform, coord_str = _parse_coord_string(entry.strip())
        elif isinstance(entry, dict):
            coord_raw = entry.get("coord")
            if not isinstance(coord_raw, str):
                raise ValueError(
                    f"--repos {path}: mapping entry must have a "
                    f"string 'coord' key; got {entry!r}."
                )
            coord_str = coord_raw.strip()
            platform = str(entry.get("platform", "github"))
        else:
            raise ValueError(
                f"--repos {path}: every entry must be a string or "
                f"mapping; got {entry!r}."
            )
        try:
            owner, repo, clone_url = _resolve_coord(platform, coord_str)
        except ValueError as exc:
            raise ValueError(
                f"--repos {path}: {exc}"
            ) from exc
        out.append(RepoCoordinate(
            coord=coord_str,
            clone_url=clone_url,
            owner=owner,
            repo=repo,
            platform=platform,
        ))
    return out


# ── Org-wide repo enumeration ───────────────────────────────────────


def apply_filters(
    coords: list[RepoCoordinate],
    include: list[str] | None = None,
    exclude: list[str] | None = None,
) -> list[RepoCoordinate]:
    """Filter coordinates by repo name using fnmatch glob patterns."""
    if include:
        coords = [
            c for c in coords
            if any(_fnmatch.fnmatch(c.repo, pat) for pat in include)
        ]
    if exclude:
        coords = [
            c for c in coords
            if not any(_fnmatch.fnmatch(c.repo, pat) for pat in exclude)
        ]
    return coords


def _github_org_repos(
    fetcher: Any, org: str,
) -> list[RepoCoordinate]:
    """Paginate ``GET /orgs/{org}/repos`` and return coordinates."""
    coords: list[RepoCoordinate] = []
    page = 1
    while True:
        result = fetcher.fetch(
            f"orgs/{org}/repos?per_page=100&page={page}&type=all",
        )
        if not isinstance(result, list) or not result:
            break
        for r in result:
            if not isinstance(r, dict):
                continue
            full_name = r.get("full_name")
            if not isinstance(full_name, str) or "/" not in full_name:
                continue
            if r.get("archived"):
                continue
            owner, repo = full_name.split("/", 1)
            gh_clone = r.get("clone_url")
            coords.append(RepoCoordinate(
                coord=full_name,
                clone_url=(
                    gh_clone
                    if isinstance(gh_clone, str) and gh_clone
                    else f"https://github.com/{full_name}.git"
                ),
                owner=owner,
                repo=repo,
                platform="github",
            ))
        if len(result) < 100:
            break
        page += 1
    return coords


def _gitlab_group_projects(
    fetcher: Any, group: str,
) -> list[RepoCoordinate]:
    """Paginate ``GET /groups/{id}/projects`` and return coordinates."""
    encoded = urllib.parse.quote(group, safe="")
    coords: list[RepoCoordinate] = []
    page = 1
    while True:
        result = fetcher.fetch(
            f"groups/{encoded}/projects"
            f"?per_page=100&page={page}&include_subgroups=true",
        )
        if not isinstance(result, list) or not result:
            break
        for r in result:
            if not isinstance(r, dict):
                continue
            path_ns = r.get("path_with_namespace")
            if not isinstance(path_ns, str) or "/" not in path_ns:
                continue
            if r.get("archived"):
                continue
            owner, repo = path_ns.rsplit("/", 1)
            http_url = r.get("http_url_to_repo")
            coords.append(RepoCoordinate(
                coord=path_ns,
                clone_url=(
                    http_url
                    if isinstance(http_url, str) and http_url
                    else f"https://gitlab.com/{path_ns}.git"
                ),
                owner=owner,
                repo=repo,
                platform="gitlab",
            ))
        if len(result) < 100:
            break
        page += 1
    return coords


def _bitbucket_workspace_repos(
    fetcher: Any, workspace: str,
) -> list[RepoCoordinate]:
    """Paginate ``GET /repositories/{workspace}`` and return coordinates."""
    coords: list[RepoCoordinate] = []
    path = f"repositories/{workspace}?pagelen=100"
    while path:
        result = fetcher.fetch(path)
        if not isinstance(result, dict):
            break
        values = result.get("values")
        if not isinstance(values, list):
            break
        for r in values:
            if not isinstance(r, dict):
                continue
            full_name = r.get("full_name")
            if not isinstance(full_name, str) or "/" not in full_name:
                continue
            owner, repo = full_name.split("/", 1)
            clone_links = r.get("links", {}).get("clone", [])
            https_url = ""
            if isinstance(clone_links, list):
                for link in clone_links:
                    if (
                        isinstance(link, dict)
                        and link.get("name") == "https"
                    ):
                        href = link.get("href")
                        if isinstance(href, str):
                            https_url = href
                            break
            coords.append(RepoCoordinate(
                coord=full_name,
                clone_url=(
                    https_url
                    or f"https://bitbucket.org/{full_name}.git"
                ),
                owner=owner,
                repo=repo,
                platform="bitbucket",
            ))
        if not values:
            break
        next_url = result.get("next")
        if isinstance(next_url, str) and next_url:
            # The API returns a full URL; strip the base so
            # fetcher.fetch() doesn't double-prefix it.
            base = "https://api.bitbucket.org/2.0/"
            path = (
                next_url[len(base):]
                if next_url.startswith(base)
                else next_url
            )
        else:
            path = ""
    return coords


def enumerate_org_repos(
    org: str,
    platform: str = "github",
) -> list[RepoCoordinate]:
    """Fetch all repos for an org/group/workspace from the SCM API.

    Requires the corresponding platform token in the environment
    (``GITHUB_TOKEN``, ``GITLAB_TOKEN``, ``BITBUCKET_TOKEN``).

    Returns unfiltered coordinates. Use :func:`apply_filters` to
    narrow the list by glob patterns.
    """
    if platform == "github":
        from .checks.scm.base import HttpSCMFetcher
        return _github_org_repos(HttpSCMFetcher(), org)
    if platform == "gitlab":
        from .checks.scm._platforms import HttpGitLabSCMFetcher
        return _gitlab_group_projects(HttpGitLabSCMFetcher(), org)
    if platform == "bitbucket":
        from .checks.scm._platforms import HttpBitbucketSCMFetcher
        return _bitbucket_workspace_repos(HttpBitbucketSCMFetcher(), org)
    raise ValueError(
        f"Unknown platform {platform!r}. "
        f"Accepted: {', '.join(sorted(_VALID_PLATFORMS))}."
    )


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
    extra_flags: list[str] | None = None,
) -> str:
    """Run ``pipeline_check`` against *src*, writing findings to
    *findings_path* and captured stderr to *stderr_path*.

    Subprocess invocation rather than in-process so per-repo state
    (env vars, cwd, any module-level caches the scanner builds) is
    fully isolated. Returns '' on success, error string on failure.
    """
    cmd = [
        sys.executable, "-m", "pipeline_check",
        "--output", "json",
        "--output-file", str(findings_path),
    ]
    if extra_flags:
        cmd.extend(extra_flags)
    try:
        result = subprocess.run(
            cmd,
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
            failed_by_severity=dict.fromkeys(_SEVERITIES, 0),
            total_failed=0,
            error=f"findings.json parse error: {exc}",
        )
    if not isinstance(doc, dict):
        return FleetSnapshot(
            coord=coord.coord, grade="?", score=0,
            failed_by_severity=dict.fromkeys(_SEVERITIES, 0),
            total_failed=0,
            error="findings.json top-level is not an object",
        )
    score_block = doc.get("score") or {}
    score = score_block.get("score") if isinstance(score_block, dict) else None
    grade = score_block.get("grade") if isinstance(score_block, dict) else None
    summary = score_block.get("summary") if isinstance(score_block, dict) else None
    failed: dict[str, int] = dict.fromkeys(_SEVERITIES, 0)
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


def _error_snapshot(coord: str, error: str) -> FleetSnapshot:
    """Build a snapshot for a repo that failed to clone or scan."""
    return FleetSnapshot(
        coord=coord, grade="?", score=0,
        failed_by_severity=dict.fromkeys(_SEVERITIES, 0),
        total_failed=0,
        error=error,
    )


def _load_repo_findings(
    output_dir: Path,
    repos: list[RepoCoordinate],
) -> dict[str, list[Finding]]:
    """Load per-repo findings from disk after all scans complete.

    Returns ``{repo_coord: [Finding, ...]}`` with minimal Finding
    reconstruction (only the fields chain rules inspect).
    """
    from .checks.base import Confidence, Finding, ResourceAnchor, Severity

    result: dict[str, list[Finding]] = {}
    for coord in repos:
        fpath = (
            output_dir
            / coord.platform
            / coord.owner.lower()
            / coord.repo.lower()
            / "findings.json"
        )
        if not fpath.exists():
            continue
        try:
            doc = json.loads(fpath.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            _log.warning(
                "could not parse %s for cross-repo chain evaluation",
                fpath,
            )
            continue
        if not isinstance(doc, dict):
            continue
        raw_findings = doc.get("findings")
        if not isinstance(raw_findings, list):
            continue

        parsed: list[Finding] = []
        for fd in raw_findings:
            if not isinstance(fd, dict):
                continue
            try:
                sev = Severity(fd.get("severity", "INFO"))
            except ValueError:
                sev = Severity.INFO
            try:
                conf = Confidence(fd.get("confidence", "HIGH"))
            except ValueError:
                conf = Confidence.HIGH
            anchors: tuple[ResourceAnchor, ...] = ()
            raw_anchors = fd.get("resource_anchors")
            if isinstance(raw_anchors, list):
                anchors = tuple(
                    ResourceAnchor(kind=a["kind"], identity=a["identity"])
                    for a in raw_anchors
                    if isinstance(a, dict) and "kind" in a and "identity" in a
                )
            job_anch: tuple[str, ...] = ()
            raw_ja = fd.get("job_anchors")
            if isinstance(raw_ja, list):
                job_anch = tuple(str(j) for j in raw_ja)

            parsed.append(Finding(
                check_id=str(fd.get("check_id", "")),
                passed=bool(fd.get("passed", True)),
                resource=str(fd.get("resource", "")),
                severity=sev,
                confidence=conf,
                title="",
                description="",
                recommendation="",
                job_anchors=job_anch,
                resource_anchors=anchors,
            ))
        result[coord.coord] = parsed
    return result


def _process_one_repo(
    coord: RepoCoordinate,
    output_dir: Path,
    *,
    timeout_sec: int = _DEFAULT_SCAN_TIMEOUT_SEC,
    scan_flags: list[str] | None = None,
) -> tuple[FleetSnapshot, list[str]]:
    """Clone, scan, and snapshot one repo.

    Thread-safe: each call creates its own tmpdir and writes to a
    unique per-repo subdirectory under *output_dir*.

    Returns ``(snapshot, warnings)`` so the caller can aggregate
    results after all workers finish.
    """
    warnings: list[str] = []
    per_repo_dir = output_dir / coord.platform / coord.owner.lower() / coord.repo.lower()
    per_repo_dir.mkdir(parents=True, exist_ok=True)
    findings_path = per_repo_dir / "findings.json"
    stderr_path = per_repo_dir / "scan.stderr"
    with tempfile.TemporaryDirectory(prefix="fleet-clone-") as tmpd:
        clone_dest = Path(tmpd) / coord.repo
        err = _clone_repo(coord, clone_dest, timeout_sec=timeout_sec)
        if err:
            warnings.append(f"{coord.coord}: {err}")
            return _error_snapshot(coord.coord, err), warnings
        err = _scan_repo(
            coord, clone_dest, findings_path, stderr_path,
            timeout_sec=timeout_sec,
            extra_flags=scan_flags,
        )
        if err:
            warnings.append(f"{coord.coord}: {err}")
            return _error_snapshot(coord.coord, err), warnings
    return _snapshot_from_findings(coord, findings_path), warnings


def _progress(
    n: int, total: int, coord: RepoCoordinate, snap: FleetSnapshot,
) -> None:
    """Print a one-line progress update to stderr."""
    suffix = f" ERROR: {snap.error}" if snap.error else ""
    print(
        f"[fleet] [{n}/{total}] {coord.coord}: "
        f"{snap.grade} ({snap.score}){suffix}",
        file=sys.stderr,
        flush=True,
    )


def run_fleet(
    repos: list[RepoCoordinate],
    output_dir: Path,
    *,
    timeout_sec: int = _DEFAULT_SCAN_TIMEOUT_SEC,
    jobs: int = 0,
    scan_flags: list[str] | None = None,
) -> FleetDigest:
    """Clone each repo, scan it, and write the aggregated digest.

    *output_dir* is created if missing; per-repo trees land under
    ``<output_dir>/<owner>/<repo>/``.

    *jobs* controls parallelism: ``0`` runs sequentially (useful for
    debugging), ``>=1`` fans out across that many threads. Each thread
    runs subprocesses (``git clone``, ``python -m pipeline_check``), so
    the GIL is irrelevant.

    *scan_flags* are forwarded verbatim to each per-repo
    ``pipeline_check`` subprocess.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    digest = FleetDigest()

    if jobs == 0:
        for i, coord in enumerate(repos, 1):
            snap, warns = _process_one_repo(
                coord, output_dir,
                timeout_sec=timeout_sec,
                scan_flags=scan_flags,
            )
            digest.snapshots.append(snap)
            digest.warnings.extend(warns)
            _progress(i, len(repos), coord, snap)
    else:
        completed = 0
        lock = threading.Lock()

        def _worker(
            idx: int, coord: RepoCoordinate,
        ) -> tuple[int, RepoCoordinate, FleetSnapshot, list[str]]:
            nonlocal completed
            snap, warns = _process_one_repo(
                coord, output_dir,
                timeout_sec=timeout_sec,
                scan_flags=scan_flags,
            )
            with lock:
                completed += 1
                n = completed
            _progress(n, len(repos), coord, snap)
            return (idx, coord, snap, warns)

        results: list[tuple[int, RepoCoordinate, FleetSnapshot, list[str]]] = []
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=jobs,
        ) as pool:
            futures = {
                pool.submit(_worker, i, coord): i
                for i, coord in enumerate(repos)
            }
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())

        results.sort(key=lambda t: t[0])
        for _, _coord, snap, warns in results:
            digest.snapshots.append(snap)
            digest.warnings.extend(warns)

    try:
        from .chains.engine import evaluate_cross_repo
        fbr = _load_repo_findings(output_dir, repos)
        if fbr:
            digest.cxpc_chains = evaluate_cross_repo(fbr)
    except Exception:
        _log.warning(
            "cross-repo chain evaluation failed; skipping",
            exc_info=True,
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
    if digest.cxpc_chains:
        lines.append("")
        lines.append("## Cross-repo attack chains")
        lines.append("")
        lines.append(
            f"**{len(digest.cxpc_chains)}** cross-repo chain(s) detected."
        )
        lines.append("")
        lines.append("| Chain | Severity | Confidence | Resources |")
        lines.append("|---|---|---|---|")
        for c in digest.cxpc_chains:
            resources = ", ".join(c.resources) if c.resources else "-"
            lines.append(
                f"| {c.chain_id}: {c.title} "
                f"| {c.severity.value} | {c.confidence.value} "
                f"| {resources} |"
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
    "apply_filters",
    "default_worker_count",
    "enumerate_org_repos",
    "load_repo_list",
    "render_markdown",
    "run_fleet",
]
