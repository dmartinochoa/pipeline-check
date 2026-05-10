"""Remote-ref resolver for GitHub Actions reusable workflows AND
composite actions.

When a caller workflow declares
``jobs.build.uses: owner/repo/.github/workflows/release.yml@v1``, the
called workflow's body is what actually runs with the caller's token
and secrets. Same applies to ``steps[].uses: owner/repo@v1`` — when
the referenced action is a composite action, its inner ``runs.steps``
execute inside the calling job's context, with the same secrets and
``GITHUB_TOKEN`` permissions. By default pipeline-check stops at the
call site (it flags an unpinned ref via GHA-001 / GHA-025 and goes
no further). This module adds an opt-in path that fetches both
called workflow bodies AND composite action bodies, then feeds them
back through the GHA rule pack so issues hidden inside a third-party
composite show up exactly as if the caller had written them inline.

Architecture
------------

  - :class:`RemoteRefFetcher` is a Protocol. Any object with a
    ``fetch(owner, repo, ref, path) -> bytes | None`` is acceptable.
  - :class:`HttpFetcher` hits ``raw.githubusercontent.com`` with
    stdlib ``urllib`` (no extra dep). Optional ``GITHUB_TOKEN`` for
    private repos. Returns ``None`` on 404 / 401 / network error so
    the resolver records a warning but the scan keeps going.
  - :class:`DiskFetcher` looks for the same file under one or more
    on-disk search paths. Useful for monorepos where the called repo
    is already checked out alongside the caller.
  - :class:`CompositeFetcher` chains DiskFetcher → HttpFetcher.
  - :class:`FileSystemCache` caches fetched bytes by
    ``(owner, repo, ref, path)`` with a default 7-day TTL.
  - :class:`Resolver` walks the loaded workflows, follows remote
    ``uses:`` refs up to ``max_depth``, detects cycles, parses each
    fetched body into a :class:`Workflow`, and tags it with
    ``source_ref`` / ``caller_path`` / inheritance metadata. Composite
    action bodies are synthesized into a single-job ``Workflow``
    (one fake job named ``__composite__``) so the same rule pack
    runs against them without a second orchestrator.

The resolver never raises on a network error or a malformed body —
it appends to ``GitHubContext.warnings`` and returns. Resolution is
strictly additive: failed fetches don't change the existing scan.

Threat-model note: the resolver issues HTTPS requests to
``raw.githubusercontent.com``. The CLI default is opt-out
(``--resolve-remote`` flips it on); this module never reads the
network unless instructed via :class:`Resolver(fetcher=...)`.
"""
from __future__ import annotations

import hashlib
import os
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import yaml

from ..base import safe_load_yaml
from .base import GitHubContext, Workflow
from .uses_parser import UsesRef, parse_uses

_DEFAULT_TTL_SECONDS = 7 * 24 * 3600
_DEFAULT_MAX_DEPTH = 3
_HARD_DEPTH_CEILING = 10
_DEFAULT_TIMEOUT = 10.0

#: Hard cap on response body size for the HTTP fetcher. A real
#: GitHub workflow file is at most a few hundred KB; a maliciously
#: large response (or a misrouted server) shouldn't be allowed to
#: balloon scanner memory. 10 MiB is generous for a single workflow
#: while bounding the worst case.
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024


# ── Fetcher protocol + implementations ────────────────────────────────


class RemoteRefFetcher(Protocol):
    """Fetch the raw bytes of a workflow file from a callee repo."""

    def fetch(
        self, owner: str, repo: str, ref: str, path: str,
    ) -> bytes | None:
        ...


class DiskFetcher:
    """Look up a workflow file under one or more on-disk roots.

    For each ``root`` in ``search_paths`` the fetcher checks
    ``<root>/<owner>/<repo>/<path>`` and returns the bytes if found.
    The ref is intentionally ignored, the caller is asserting that
    the on-disk checkout matches the ref they want, since enumerating
    git refs across paths is expensive and out of scope.
    """

    def __init__(self, search_paths: list[Path]) -> None:
        self.search_paths = [Path(p) for p in search_paths]

    def fetch(
        self, owner: str, repo: str, ref: str, path: str,
    ) -> bytes | None:
        # Defense against path-traversal in attacker-controlled
        # workflow ``uses:`` refs. A malicious workflow could call
        # ``uses: ../../etc/passwd@<sha>`` which the parser would
        # split into owner / repo / path components carrying ``..``.
        # We validate each component and confirm the resolved
        # candidate stays inside the configured search root before
        # reading.
        for component in (owner, repo, path):
            if ".." in Path(component).parts:
                return None
        for root in self.search_paths:
            try:
                root_resolved = root.resolve()
            except OSError:
                continue
            candidate = root / owner / repo / path
            try:
                candidate_resolved = candidate.resolve()
            except OSError:
                continue
            if root_resolved not in candidate_resolved.parents \
                    and candidate_resolved != root_resolved:
                # Symlink or component combination escaped the root.
                continue
            if candidate_resolved.is_file():
                try:
                    return candidate_resolved.read_bytes()
                except OSError:
                    continue
        return None


class HttpFetcher:
    """Fetch via ``raw.githubusercontent.com``.

    ``token`` enables private-repo access; defaults to the
    ``GITHUB_TOKEN`` env var when not set explicitly. ``None`` means
    unauthenticated (works for public repos within rate limits).
    """

    BASE_URL = "https://raw.githubusercontent.com"

    def __init__(
        self,
        token: str | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        self.token = token if token is not None else os.environ.get("GITHUB_TOKEN")
        self.timeout = timeout

    def fetch(
        self, owner: str, repo: str, ref: str, path: str,
    ) -> bytes | None:
        url = f"{self.BASE_URL}/{owner}/{repo}/{ref}/{path}"
        req = urllib.request.Request(url)  # noqa: S310, fixed scheme, fixed host
        if self.token:
            req.add_header("Authorization", f"token {self.token}")
        # Identify ourselves so a server-side rate-limit log can tell
        # pipeline-check apart from a generic ``urllib`` consumer.
        req.add_header("User-Agent", "pipeline-check-resolver")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                # Cap reads at ``_MAX_RESPONSE_BYTES + 1``; any extra
                # byte indicates the body is over the cap, in which
                # case we treat the fetch as a failure rather than
                # streaming a multi-GB attacker-controlled response
                # into memory.
                body: bytes = resp.read(_MAX_RESPONSE_BYTES + 1)
                if len(body) > _MAX_RESPONSE_BYTES:
                    return None
                return body
        except urllib.error.HTTPError:
            return None
        except (urllib.error.URLError, TimeoutError, OSError):
            return None


class CompositeFetcher:
    """Try each fetcher in order; return the first non-``None`` hit."""

    def __init__(self, fetchers: list[RemoteRefFetcher]) -> None:
        self.fetchers = fetchers

    def fetch(
        self, owner: str, repo: str, ref: str, path: str,
    ) -> bytes | None:
        for f in self.fetchers:
            result = f.fetch(owner, repo, ref, path)
            if result is not None:
                return result
        return None


# ── Cache ────────────────────────────────────────────────────────────


def _cache_filename(owner: str, repo: str, ref: str, path: str) -> str:
    """Filename-safe key for ``(owner, repo, ref, path)``.

    The path component is sha256-truncated so deeply-nested workflow
    paths don't blow Windows' 260-char filename limit.
    """
    path_hash = hashlib.sha256(path.encode("utf-8")).hexdigest()[:16]
    safe_owner = owner.replace("/", "_")
    safe_repo = repo.replace("/", "_")
    safe_ref = ref.replace("/", "_").replace(":", "_")
    return f"{safe_owner}__{safe_repo}__{safe_ref}__{path_hash}.yml"


class FileSystemCache:
    """Disk-backed cache for fetcher output.

    Default TTL is 7 days; tune with ``ttl_seconds=0`` to disable
    write-side caching while still allowing reads of unexpired
    entries. Pass ``enabled=False`` to short-circuit both read and
    write, the caller wires that up to ``--no-cache``.
    """

    def __init__(
        self,
        root: Path,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
        enabled: bool = True,
    ) -> None:
        self.root = Path(root)
        self.ttl_seconds = ttl_seconds
        self.enabled = enabled

    def _path_for(self, owner: str, repo: str, ref: str, path: str) -> Path:
        return self.root / _cache_filename(owner, repo, ref, path)

    def get(
        self, owner: str, repo: str, ref: str, path: str,
    ) -> bytes | None:
        if not self.enabled:
            return None
        cached = self._path_for(owner, repo, ref, path)
        if not cached.is_file():
            return None
        try:
            mtime = cached.stat().st_mtime
        except OSError:
            return None
        if self.ttl_seconds > 0 and time.time() - mtime > self.ttl_seconds:
            return None
        try:
            return cached.read_bytes()
        except OSError:
            return None

    def put(
        self, owner: str, repo: str, ref: str, path: str, data: bytes,
    ) -> None:
        if not self.enabled:
            return
        cached = self._path_for(owner, repo, ref, path)
        try:
            cached.parent.mkdir(parents=True, exist_ok=True)
            cached.write_bytes(data)
        except OSError:
            # Cache failures are never fatal, the next scan will
            # just refetch.
            pass


def default_cache_dir() -> Path:
    """Return the platform-appropriate cache root.

    Falls back to ``~/.cache/pipeline-check/gha-resolver`` when
    ``platformdirs`` is unavailable so we don't take a hard dep just
    for one path.
    """
    try:
        import platformdirs
        base = Path(platformdirs.user_cache_dir("pipeline-check"))
    except ImportError:
        base = Path.home() / ".cache" / "pipeline-check"
    return base / "gha-resolver"


# ── Resolver ─────────────────────────────────────────────────────────


@dataclass(slots=True)
class _Pending:
    """Internal queue item: a ref to fetch, with its provenance.

    ``kind`` discriminates two fetch flavors that share the cache,
    fetcher, dedup, and concurrency machinery:

      - ``"workflow"`` — caller's ``jobs.<id>.uses:`` points at a
        reusable workflow YAML file. Fetched verbatim.
      - ``"action"`` — caller's ``steps[].uses:`` points at an action
        repo. Fetched as ``action.yml`` (or ``action.yaml`` on
        fallback). Only composite actions produce a synthesized
        workflow downstream — JavaScript / Docker actions ship as
        opaque blobs that can't be statically scanned with the
        workflow rule pack.
    """

    ref: UsesRef
    caller_path: str
    inherited_permissions: dict[str, Any] | str | None
    inherited_secret_names: frozenset[str]
    inherits_secrets: bool
    depth: int
    kind: str = "workflow"


@dataclass(slots=True)
class ResolverStats:
    """Counts surfaced through the context's warnings stream."""

    fetched: int = 0
    cache_hits: int = 0
    failures: list[str] = field(default_factory=list)
    skipped_unpinned_warning: list[str] = field(default_factory=list)
    #: Composite-action refs the resolver successfully fetched and
    #: synthesized into scannable workflow bodies. Reported alongside
    #: the workflow stats in the per-scan warnings stream so users see
    #: the composite-action path is doing work.
    composite_actions_resolved: int = 0
    #: Action refs fetched whose ``runs.using`` was not ``composite``
    #: (typically ``node20`` or ``docker``). Counted but not scanned —
    #: their executable surface is outside the workflow YAML rule pack.
    non_composite_actions_skipped: int = 0


class Resolver:
    """Walk a context's workflows and pull in remote callees.

    The resolver mutates the passed :class:`GitHubContext` in place,
    appending newly-fetched workflows to ``ctx.workflows`` so existing
    rules iterate them just like local files. Findings emitted on a
    resolved callee carry the ``Workflow.source_ref`` so the report
    attributes the issue back to the caller.
    """

    def __init__(
        self,
        fetcher: RemoteRefFetcher,
        cache: FileSystemCache | None = None,
        max_depth: int = _DEFAULT_MAX_DEPTH,
        max_workers: int = 4,
    ) -> None:
        self.fetcher = fetcher
        self.cache = cache
        self.max_depth = min(max(1, max_depth), _HARD_DEPTH_CEILING)
        self.max_workers = max_workers
        self.stats = ResolverStats()

    def resolve(self, ctx: GitHubContext) -> None:
        """Mutate *ctx* in place: append every reachable callee.

        Walks two parallel surfaces in lock-step:

          - Reusable workflow callees referenced by ``jobs.<id>.uses:``.
          - Composite action bodies referenced by ``steps[].uses:``
            whose fetched ``action.yml`` declares ``runs.using:
            composite``.

        Both paths share the cache, fetcher, dedup table, and
        depth counter. Composite-of-composite recursion just falls
        out of the wave loop because a synthesized composite
        workflow's ``steps[]`` entries flow back through
        ``_collect_remote_uses`` on the next wave.
        """
        # ``visited`` keys ride the four-tuple identity. Cycle
        # detection uses it so an "a uses b uses a" pair stops at
        # depth 2 with a clear warning. Workflow and action fetches
        # naturally don't collide because action refs have empty
        # ``ref.path`` (or a subdir path) and workflow refs always
        # carry a ``.yml`` / ``.yaml`` path.
        visited: set[tuple[str, str, str, str]] = set()
        # Seed the queue from each loaded caller. Callers are the
        # things originally on disk; resolver-added workflows have
        # ``source_ref`` set and we don't recurse into them as
        # callers (we recurse via the depth counter inside the loop).
        queue: list[_Pending] = []
        for wf in list(ctx.workflows):
            if wf.source_ref is not None:
                continue  # already a resolved callee
            for pending in self._collect_remote_uses(
                wf, depth=1,
            ):
                queue.append(pending)

        # Process the queue in waves so each wave's fetches happen in
        # parallel. Newly-discovered refs append to the next wave.
        while queue:
            current, queue = queue, []
            new_workflows = self._fetch_wave(current, ctx, visited)
            ctx.workflows.extend(new_workflows)
            for wf in new_workflows:
                # Recurse only if we have room for another hop.
                if wf.source_ref is None:
                    continue
                # ``depth`` is 1-indexed: a depth-1 fetch is the
                # caller's direct callee. Inherit depth+1 from the
                # newly-fetched workflow so the cap is meaningful.
                next_depth = self._depth_of(wf) + 1
                if next_depth > self.max_depth:
                    continue
                for pending in self._collect_remote_uses(wf, depth=next_depth):
                    queue.append(pending)

        # Surface stats so users can see what happened.
        if self.stats.skipped_unpinned_warning:
            ctx.warnings.append(
                f"[gha-resolver] skipped {len(self.stats.skipped_unpinned_warning)} "
                f"unpinned remote ref(s); pin to a SHA to enable resolution."
            )
        if self.stats.composite_actions_resolved:
            ctx.warnings.append(
                f"[gha-resolver] resolved "
                f"{self.stats.composite_actions_resolved} composite "
                f"action(s); rule pack ran against their bodies."
            )
        if self.stats.non_composite_actions_skipped:
            ctx.warnings.append(
                f"[gha-resolver] skipped "
                f"{self.stats.non_composite_actions_skipped} non-composite "
                f"action(s) (JavaScript / Docker); their executable "
                f"surface is outside the workflow YAML rule pack."
            )
        for failure in self.stats.failures[:5]:
            ctx.warnings.append(f"[gha-resolver] {failure}")
        if len(self.stats.failures) > 5:
            ctx.warnings.append(
                f"[gha-resolver] {len(self.stats.failures) - 5} more "
                f"fetch failure(s) suppressed."
            )

    def _depth_of(self, wf: Workflow) -> int:
        """Recover the resolution depth from a callee's source_ref.

        We don't carry depth through the dataclass; instead, count
        how many ``->`` separators are in the synthetic
        ``caller_path``. The first callee has 0 separators; a
        callee-of-a-callee has 1; etc. Add 1 because depth is
        1-indexed at the original call site.
        """
        if not wf.caller_path:
            return 1
        return wf.caller_path.count(" -> ") + 1

    def _collect_remote_uses(
        self, wf: Workflow, depth: int,
    ) -> list[_Pending]:
        """Yield one :class:`_Pending` per remote ``uses:`` in *wf*.

        Covers both surfaces:

          - ``jobs.<id>.uses:`` pointing at a remote reusable workflow
            (``kind="workflow"``).
          - ``steps[].uses:`` pointing at a remote action repo
            (``kind="action"``). The fetch reads ``action.yml`` and
            only synthesizes a workflow when ``runs.using == composite``.

        Both surfaces share dedup via the wave's ``visited`` set so a
        workflow that uses the same composite action in N steps fetches
        once.
        """
        out: list[_Pending] = []
        jobs = wf.data.get("jobs")
        if not isinstance(jobs, dict):
            return out
        # Caller-level permissions cascade into callees that don't
        # declare their own. Capture once so each pending entry can
        # carry it forward.
        caller_permissions = wf.data.get("permissions")
        if caller_permissions is None:
            caller_permissions = wf.inherited_permissions
        for _job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            ref = parse_uses(job.get("uses"))
            if ref is not None and ref.kind == "remote-workflow":
                if not ref.is_pinned_to_sha:
                    # We *could* resolve unpinned refs by treating the
                    # tag as a ref token, but doing so silently would
                    # defeat GHA-025's value. Mark it skipped and let
                    # the user opt back in by pinning.
                    self.stats.skipped_unpinned_warning.append(ref.raw)
                else:
                    inherited_secrets, inherits = _secrets_visible_to_callee(
                        job, wf,
                    )
                    out.append(_Pending(
                        ref=ref,
                        caller_path=_synthesized_caller_path(wf),
                        inherited_permissions=caller_permissions,
                        inherited_secret_names=inherited_secrets,
                        inherits_secrets=inherits,
                        depth=depth,
                        kind="workflow",
                    ))
            # Composite-action surface. Composite actions execute in
            # the calling job's process — same secrets, same token,
            # same runner — so the inherited context is the caller's
            # job permissions and the full caller-secret horizon.
            steps = job.get("steps")
            if not isinstance(steps, list):
                continue
            for step in steps:
                if not isinstance(step, dict):
                    continue
                step_ref = parse_uses(step.get("uses"))
                if step_ref is None or step_ref.kind != "remote-action":
                    continue
                if not step_ref.is_pinned_to_sha:
                    # Same logic as workflow refs: don't follow tag
                    # pins silently. GHA-001 already flagged the
                    # unpinned ref at the call site.
                    self.stats.skipped_unpinned_warning.append(step_ref.raw)
                    continue
                # Composite-action callees inherit the caller's full
                # secret horizon (the action runs in-process). We
                # don't enumerate names here; mark "inherits" so the
                # synthesized workflow's rules see the same
                # conservative assumption as ``secrets: inherit``.
                out.append(_Pending(
                    ref=step_ref,
                    caller_path=_synthesized_caller_path(wf),
                    inherited_permissions=caller_permissions,
                    inherited_secret_names=frozenset(),
                    inherits_secrets=True,
                    depth=depth,
                    kind="action",
                ))
        return out

    def _fetch_wave(
        self,
        pendings: list[_Pending],
        ctx: GitHubContext,
        visited: set[tuple[str, str, str, str]],
    ) -> list[Workflow]:
        """Fetch *pendings* concurrently and turn each hit into a Workflow."""
        # Dedup within the wave so two callers referencing the same
        # callee fetch once. ``visited`` carries dedup across waves.
        # Workflow and action keys naturally don't collide (workflow
        # refs always have a ``.yml`` / ``.yaml`` path; action refs
        # have ``""`` or a subdir).
        unique: dict[tuple[str, str, str, str], _Pending] = {}
        for p in pendings:
            key = self._dedup_key(p)
            if key in visited:
                continue
            unique.setdefault(key, p)

        results: list[Workflow] = []
        if not unique:
            return results

        def _do_one(p: _Pending) -> tuple[_Pending, bytes | None]:
            return p, self._fetch_one(p)

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            for p, data in pool.map(_do_one, unique.values()):
                visited.add(self._dedup_key(p))
                if data is None:
                    self.stats.failures.append(
                        f"could not fetch {p.ref.raw} "
                        f"(referenced from {p.caller_path})"
                    )
                    continue
                wf = self._build_workflow(p, data)
                if wf is not None:
                    results.append(wf)
        return results

    @staticmethod
    def _dedup_key(p: _Pending) -> tuple[str, str, str, str]:
        """Cache key incorporates kind so a workflow ``foo.yml@SHA`` and
        an action subpath ``foo`` at the same SHA don't collide."""
        return (p.ref.owner, p.ref.repo, p.ref.ref, f"{p.kind}:{p.ref.path}")

    def _fetch_one(self, p: _Pending) -> bytes | None:
        """Single-pending fetch with cache and per-kind path resolution."""
        ref = p.ref
        if p.kind == "workflow":
            return self._fetch_with_cache(
                ref.owner, ref.repo, ref.ref, ref.path,
            )
        # Composite-action: try ``<path>/action.yml`` then
        # ``<path>/action.yaml``. The action's repo-relative path is
        # ``ref.path`` (empty string for repo-root actions, e.g.
        # ``actions/checkout``; ``lib`` for ``actions/setup-node/lib``).
        candidates: tuple[str, ...]
        if ref.path:
            base = ref.path.rstrip("/")
            candidates = (f"{base}/action.yml", f"{base}/action.yaml")
        else:
            candidates = ("action.yml", "action.yaml")
        for candidate in candidates:
            data = self._fetch_with_cache(
                ref.owner, ref.repo, ref.ref, candidate,
            )
            if data is not None:
                return data
        return None

    def _fetch_with_cache(
        self, owner: str, repo: str, ref: str, path: str,
    ) -> bytes | None:
        """Cache-aware single-path fetch. Internal helper."""
        if self.cache is not None:
            cache_hit = self.cache.get(owner, repo, ref, path)
            if cache_hit is not None:
                self.stats.cache_hits += 1
                return cache_hit
        data = self.fetcher.fetch(owner, repo, ref, path)
        if data is not None:
            self.stats.fetched += 1
            if self.cache is not None:
                self.cache.put(owner, repo, ref, path, data)
        return data

    def _build_workflow(
        self, pending: _Pending, raw: bytes,
    ) -> Workflow | None:
        try:
            text = raw.decode("utf-8", errors="replace")
        except UnicodeDecodeError:
            self.stats.failures.append(
                f"non-UTF8 callee body: {pending.ref.raw}"
            )
            return None
        try:
            doc = safe_load_yaml(text)
        except yaml.YAMLError as exc:
            first_line = str(exc).split("\n", 1)[0]
            self.stats.failures.append(
                f"YAML parse error in {pending.ref.raw}: {first_line}"
            )
            return None
        if not isinstance(doc, dict):
            return None
        if pending.kind == "action":
            return self._build_composite_workflow(pending, doc)
        synthetic_path = (
            f"{pending.caller_path} -> "
            f"{pending.ref.owner}/{pending.ref.repo}/"
            f"{pending.ref.path}@{pending.ref.ref}"
        )
        return Workflow(
            path=synthetic_path,
            data=doc,
            source_ref=(
                f"{pending.ref.owner}/{pending.ref.repo}/"
                f"{pending.ref.path}@{pending.ref.ref}"
            ),
            caller_path=pending.caller_path,
            inherited_permissions=pending.inherited_permissions,
            inherited_secret_names=pending.inherited_secret_names,
            inherits_secrets=pending.inherits_secrets,
        )

    def _build_composite_workflow(
        self, pending: _Pending, action_doc: dict[str, Any],
    ) -> Workflow | None:
        """Synthesize a Workflow from a composite action's body.

        The transformation is mechanical:

          * ``runs.using`` must be ``"composite"``. JavaScript and
            Docker actions are counted as skipped — their executable
            surface is bytecode / OCI image, not workflow YAML.
          * ``runs.steps`` becomes the body of a single fake job named
            ``__composite__`` with a synthetic ``runs-on``. The fake
            job structure means every existing GHA rule that iterates
            ``iter_jobs`` + ``iter_steps`` (the bulk of the rule pack)
            fires on the composite body without modification.
          * The synthetic workflow gets ``source_ref`` =
            ``composite:<owner>/<repo>/<path>@<sha>`` so reporters
            attribute findings to the composite action.

        Returns ``None`` for non-composite actions, for actions
        missing a ``runs.steps`` list, or for malformed bodies.
        """
        runs = action_doc.get("runs")
        if not isinstance(runs, dict):
            return None
        using = runs.get("using")
        if not isinstance(using, str) or using.lower() != "composite":
            # JavaScript (``node20``, ``node16``) and Docker actions
            # don't ship inspectable workflow YAML. Count and move on.
            self.stats.non_composite_actions_skipped += 1
            return None
        steps = runs.get("steps")
        if not isinstance(steps, list):
            return None
        synthetic_doc: dict[str, Any] = {
            "name": str(action_doc.get("name") or pending.ref.raw),
            # ``on:`` doesn't apply to composite actions; the rule
            # pack tolerates this absence (workflow_triggers returns
            # ``[]``). Setting an explicit synthetic value would
            # falsely trigger event-shaped rules.
            "jobs": {
                "__composite__": {
                    "runs-on": "ubuntu-latest",
                    "steps": steps,
                },
            },
        }
        attribution = (
            f"composite:{pending.ref.owner}/{pending.ref.repo}/"
            f"{pending.ref.path}@{pending.ref.ref}"
            if pending.ref.path else
            f"composite:{pending.ref.owner}/{pending.ref.repo}@"
            f"{pending.ref.ref}"
        )
        synthetic_path = f"{pending.caller_path} -> {attribution}"
        self.stats.composite_actions_resolved += 1
        return Workflow(
            path=synthetic_path,
            data=synthetic_doc,
            source_ref=attribution,
            caller_path=pending.caller_path,
            inherited_permissions=pending.inherited_permissions,
            inherited_secret_names=pending.inherited_secret_names,
            inherits_secrets=pending.inherits_secrets,
        )


def _synthesized_caller_path(wf: Workflow) -> str:
    """Return the caller chain for *wf*.

    For a top-level workflow this is just the on-disk path. For an
    already-resolved callee being used as a caller of *its* callees,
    the chain extends.
    """
    if wf.source_ref is None:
        return wf.path
    # ``wf.path`` is already the chain ``<caller> -> <callee>``; pass
    # it through so the next hop appends.
    return wf.path


def _secrets_visible_to_callee(
    job: dict[str, Any], caller_wf: Workflow,
) -> tuple[frozenset[str], bool]:
    """Compute what secrets cross into the callee.

    Returns ``(explicit_names, inherits_flag)`` where ``inherits_flag``
    is True iff the call site says ``secrets: inherit`` (or the
    caller itself was called with ``secrets: inherit``). The set of
    explicit names is what the caller mapped on the call site or what
    the caller itself inherited from upstream.
    """
    secrets = job.get("secrets")
    if secrets == "inherit":
        # Caller passes everything it has visibility into. We can
        # only enumerate what's syntactically visible; org-level
        # secrets aren't in the file.
        names: frozenset[str] = frozenset()
        # If the caller itself inherits, the chain is "everything".
        if caller_wf.inherits_secrets:
            return caller_wf.inherited_secret_names, True
        return names, True
    if isinstance(secrets, dict):
        # Explicit name → expression map. The names the callee can see
        # are the keys.
        return frozenset(str(k) for k in secrets), False
    # No secrets:, no inheritance.
    return frozenset(), False
